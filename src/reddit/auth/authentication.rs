use std::sync::Mutex;
use std::time::Instant;

use futures::prelude::*;
use futures::future::Shared;
use serde_json;

use reddit::api::Resource;
use reddit::auth::{Scope, ScopeSet};
use error::{SnooBuilderError, SnooError, SnooErrorKind};
use net::HttpClient;
use net::request::HttpRequestBuilder;
use net::response::HttpResponseFuture;

#[derive(Debug)]
pub struct Authenticator {
    app_secrets: AppSecrets,
    auth_flow: Mutex<Option<AuthFlow>>,
    bearer_token: Mutex<Shared<BearerTokenFuture>>,
}

impl Authenticator {
    pub fn new(
        app_secrets: AppSecrets,
        mut auth_flow: Option<AuthFlow>,
        bearer_token: Option<BearerToken>,
        http_client: &HttpClient,
    ) -> Result<Authenticator, SnooBuilderError> {
        let (auth_flow, bearer_token) = if let Some(bearer_token) = bearer_token {
            // because we have a bearer token, only keep password auth flows
            if auth_flow.is_some() && !auth_flow.as_ref().unwrap().is_password() {
                auth_flow.take();
            }

            (auth_flow, bearer_token.into())
        } else if let Some(auth_flow) = auth_flow {
            let bearer_token = BearerTokenFuture::new(http_client, &auth_flow, &app_secrets);
            // now that we've used the auth flow, only keep it if it's a password auth flow
            let auth_flow = if auth_flow.is_password() {
                Some(auth_flow)
            } else {
                None
            };

            (auth_flow, bearer_token)
        } else {
            return Err(SnooBuilderError::MissingAuthFlow);
        };

        Ok(Authenticator {
            app_secrets,
            auth_flow: Mutex::new(auth_flow),
            bearer_token: Mutex::new(bearer_token.shared()),
        })
    }

    pub fn bearer_token(&self, http_client: &HttpClient, renew: bool) -> Shared<BearerTokenFuture> {
        let mut auth_flow_guard = self.auth_flow
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let mut bearer_token_guard = self.bearer_token
            .lock()
            .unwrap_or_else(|error| error.into_inner());

        // renew the future if...
        match (bearer_token_guard.peek(), auth_flow_guard.as_ref()) {
            // bearer token and auth flow are present, bearer token is not renewable, and bearer
            // token is expired or renew is true
            (Some(Ok(ref bearer_token)), Some(_))
                if !bearer_token.is_refreshable() && (bearer_token.is_expired() || renew) =>
            {
                let auth_flow = auth_flow_guard.take().unwrap();
                *bearer_token_guard =
                    BearerTokenFuture::new(http_client, &auth_flow, &self.app_secrets).shared();

                if auth_flow.is_password() {
                    *auth_flow_guard = Some(auth_flow);
                }
            }
            // bearer token is present, bearer token is renewable, and bearer token is expired or
            // renew is true
            (Some(Ok(ref bearer_token)), _)
                if bearer_token.is_refreshable() && (bearer_token.is_expired() || renew) =>
            {
                let refresh_token = bearer_token.refresh_token().map(|r| r.to_owned()).unwrap();
                let auth_flow = AuthFlow::RefreshToken(refresh_token);
                *bearer_token_guard =
                    BearerTokenFuture::new(http_client, &auth_flow, &self.app_secrets).shared()
            }
            // auth flow is present and renew is true
            (_, Some(_)) if renew => {
                let auth_flow = auth_flow_guard.take().unwrap();
                *bearer_token_guard =
                    BearerTokenFuture::new(http_client, &auth_flow, &self.app_secrets).shared();

                if auth_flow.is_password() {
                    *auth_flow_guard = Some(auth_flow);
                }
            }
            // do nothing in any other circumstance
            _ => {}
        };

        bearer_token_guard.clone()
    }
}

/// A container to hold Reddit-generated authentication secrets.
#[derive(Clone, Debug)]
pub struct AppSecrets {
    client_id: String,
    client_secret: Option<String>,
}

impl AppSecrets {
    /// Creates a new container that holds the provided secrets.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// # use snoo::reddit::auth::AppSecrets;
    /// let secrets = AppSecrets::new("abc123", "xyz890");
    /// ```
    ///
    /// If a client secret is not available for your application, `None` can be passed instead.
    ///
    /// ```ignore
    /// # use snoo::reddit::auth::AppSecrets;
    /// let secrets = AppSecrets::new("abc123", None);
    /// ```
    pub fn new<S, O>(client_id: S, client_secret: O) -> AppSecrets
    where
        S: Into<String>,
        O: Into<Option<S>>,
    {
        AppSecrets {
            client_id: client_id.into(),
            client_secret: client_secret.into().map(|value| value.into()),
        }
    }

    /// Gets a slice of the entire client ID.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// # use snoo::reddit::auth::AppSecrets;
    /// let secrets = AppSecrets::new("abc123", None);
    /// assert_eq!(secrets.client_id(), "abc123")
    /// ```
    pub fn client_id(&self) -> &str {
        self.client_id.as_str()
    }

    /// Gets a slice of the entire client secret, if available.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// # use snoo::reddit::auth::AppSecrets;
    /// let secrets = AppSecrets::new("abc123", "def456");
    /// assert_eq!(secrets.client_secret(), Some("def456"));
    /// ```
    pub fn client_secret(&self) -> Option<&str> {
        self.client_secret.as_ref().map(|s| s.as_str())
    }
}

/// The method used for authentication. Application-only authentication methods are not supported.
///
/// More information about the authorization and authentication process can be found in Reddit's
/// [OAuth 2 documentation] on GitHub.
///
/// [OAuth 2 documentation]: https://github.com/reddit/reddit/wiki/OAuth2
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "snake_case", tag = "grant_type")]
pub enum AuthFlow {
    /// Authenticate using an authorization code retrieved from Reddit.
    Code {
        /// The authorization code retrieved from Reddit.
        code: String,
        /// The same redirect URI that is registered with Reddit.
        redirect_uri: String,
        /// A set of [scopes] to request during authentication.
        ///
        /// [scopes]: enum.Scope.html
        scope: ScopeSet,
    },
    /// Authenticate on behalf of a user with a username and password.
    Password {
        /// The user's password.
        password: String,
        /// The user's username.
        username: String,
        /// A set of [scopes] to request during authentication.
        ///
        /// [scopes]: enum.Scope.html
        scope: ScopeSet,
    },
    /// Authenticate using a refresh token.
    RefreshToken(String),
}

impl AuthFlow {
    pub fn is_code(&self) -> bool {
        match *self {
            AuthFlow::Code { .. } => true,
            _ => false,
        }
    }

    pub fn is_password(&self) -> bool {
        match *self {
            AuthFlow::Password { .. } => true,
            _ => false,
        }
    }

    pub fn is_refresh_token(&self) -> bool {
        match *self {
            AuthFlow::RefreshToken { .. } => true,
            _ => false,
        }
    }
}

/// The token that is generated by Reddit and used for authenticating API requests.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BearerToken {
    access_token: String,
    #[serde(default = "Instant::now", skip_deserializing, skip_serializing)]
    created_at: Instant,
    expires_in: usize,
    refresh_token: Option<String>,
    scope: ScopeSet,
}

impl BearerToken {
    pub fn new<A, R, S>(
        access_token: A,
        expires_in: usize,
        refresh_token: R,
        scope: S,
    ) -> BearerToken
    where
        A: Into<String>,
        R: Into<Option<A>>,
        S: IntoIterator<Item = Scope>,
    {
        BearerToken {
            access_token: access_token.into(),
            created_at: Instant::now(),
            expires_in,
            refresh_token: refresh_token.into().map(|token| token.into()),
            scope: scope.into_iter().collect(),
        }
    }

    /// Gets the access token.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// # use snoo::reddit::auth::{BearerToken, Scope, ScopeSet};
    /// let scope = [Scope::Identity]
    ///     .iter()
    ///     .cloned()
    ///     .collect::<ScopeSet>();
    /// let bearer_token = BearerToken::new(
    ///     "abc123",
    ///     3600,
    ///     None,
    ///     scope
    /// );
    /// assert_eq!(bearer_token.access_token(), "abc123");
    /// ```
    pub fn access_token(&self) -> &str {
        self.access_token.as_str()
    }

    /// Gets the number of seconds until the access token expires.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// # use snoo::reddit::auth::{BearerToken, Scope, ScopeSet};
    /// let scope = [Scope::Identity]
    ///     .iter()
    ///     .cloned()
    ///     .collect::<ScopeSet>();
    /// let bearer_token = BearerToken::new(
    ///     "abc123",
    ///     3600,
    ///     None,
    ///     scope
    /// );
    /// assert_eq!(bearer_token.expires_in(), 3600);
    /// ```
    pub fn expires_in(&self) -> usize {
        self.expires_in
    }

    /// Gets the refresh token, if available.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// # use snoo::reddit::auth::{BearerToken, Scope, ScopeSet};
    /// let scope = [Scope::Identity]
    ///     .iter()
    ///     .cloned()
    ///     .collect::<ScopeSet>();
    /// let bearer_token = BearerToken::new(
    ///     "abc123",
    ///     3600,
    ///     Some("def456"),
    ///     scope
    /// );
    /// assert_eq!(bearer_token.refresh_token(), Some("def456"));
    /// ```
    pub fn refresh_token(&self) -> Option<&str> {
        self.refresh_token.as_ref().map(String::as_ref)
    }

    /// Gets the scopes allowed by this bearer token.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// # use snoo::reddit::auth::{BearerToken, Scope, ScopeSet};
    /// let scope = [Scope::Identity]
    ///     .iter()
    ///     .cloned()
    ///     .collect::<ScopeSet>();
    /// let scope_clone = scope.clone();
    /// let bearer_token = BearerToken::new(
    ///     "abc123",
    ///     3600,
    ///     Some("def456"),
    ///     scope
    /// );
    /// assert_eq!(bearer_token.scope(), &scope_clone);
    /// ```
    pub fn scope(&self) -> &ScopeSet {
        &self.scope
    }

    /// Determines whether the access token has expired.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// # use snoo::reddit::auth::{BearerToken, Scope, ScopeSet};
    /// let scope = [Scope::Identity]
    ///     .iter()
    ///     .cloned()
    ///     .collect::<ScopeSet>();
    /// let bearer_token = BearerToken::new(
    ///     "abc123",
    ///     3600,
    ///     None,
    ///     scope
    /// );
    /// assert_eq!(bearer_token.is_expired(), false);
    /// ```
    pub fn is_expired(&self) -> bool {
        self.created_at.elapsed().as_secs() >= (self.expires_in as u64)
    }

    /// Determines the presence of a refresh token.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// # use snoo::reddit::auth::{BearerToken, Scope, ScopeSet};
    /// let scope = [Scope::Identity]
    ///     .iter()
    ///     .cloned()
    ///     .collect::<ScopeSet>();
    /// let bearer_token = BearerToken::new(
    ///     "abc123",
    ///     3600,
    ///     None,
    ///     scope
    /// );
    /// assert_eq!(bearer_token.is_refreshable(), false);
    /// ```
    pub fn is_refreshable(&self) -> bool {
        self.refresh_token.is_some()
    }

    pub fn matches_scope(&self, scope: Scope) -> bool {
        scope == Scope::All || self.scope.contains(scope) || self.scope.contains(Scope::All)
    }
}

pub type SharedBearerTokenFuture = Shared<BearerTokenFuture>;

// TODO: Document BearerTokenFuture
#[must_use = "futures do nothing unless polled"]
#[derive(Debug)]
pub enum BearerTokenFuture {
    #[doc(hidden)]
    Fixed(Option<BearerToken>),
    #[doc(hidden)]
    Future {
        error: Option<SnooError>,
        future: Option<HttpResponseFuture>,
    },
}

impl BearerTokenFuture {
    pub(crate) fn new(
        http_client: &HttpClient,
        auth_flow: &AuthFlow,
        app_secrets: &AppSecrets,
    ) -> BearerTokenFuture {
        let request = HttpRequestBuilder::post(Resource::AccessToken)
            .basic_auth(app_secrets)
            .form(auth_flow)
            .build();
        match request {
            Ok(request) => BearerTokenFuture::Future {
                error: None,
                future: Some(HttpResponseFuture::new(http_client.execute(request))),
            },
            Err(error) => BearerTokenFuture::Future {
                error: Some(error),
                future: None,
            },
        }
    }
}

impl From<BearerToken> for BearerTokenFuture {
    fn from(bearer_token: BearerToken) -> Self {
        BearerTokenFuture::Fixed(Some(bearer_token))
    }
}

impl Future for BearerTokenFuture {
    type Item = BearerToken;
    type Error = SnooError;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        match *self {
            BearerTokenFuture::Fixed(ref mut bearer_token) => {
                if let Some(inner_bearer_token) = bearer_token.take() {
                    return Ok(Async::Ready(inner_bearer_token));
                }
            }
            BearerTokenFuture::Future {
                ref mut error,
                ref mut future,
            } => {
                if let Some(inner_error) = error.take() {
                    return Err(inner_error);
                }

                if let Some(mut inner_future) = future.take() {
                    match inner_future.poll() {
                        Err(error) => return Err(error.into()),
                        Ok(Async::NotReady) => {
                            *future = Some(inner_future);
                            return Ok(Async::NotReady);
                        }
                        Ok(Async::Ready(response)) => {
                            let (_, status, _, body) = response;

                            if !status.is_success() {
                                return Err(SnooErrorKind::UnsuccessfulResponse(status.as_u16())
                                    .into());
                            }

                            return serde_json::from_slice::<BearerToken>(&body)
                                .map(|bearer_token| Async::Ready(bearer_token))
                                .map_err(|_| SnooErrorKind::InvalidResponse.into());
                        }
                    }
                }
            }
        }

        panic!("future has already completed!")
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;
    use super::*;

    #[test]
    fn bearer_token_is_expired() {
        let token = BearerToken {
            access_token: "abc123".to_owned(),
            created_at: Instant::now() - Duration::from_secs(3601),
            expires_in: 3600,
            refresh_token: None,
            scope: ScopeSet::new(),
        };
        assert!(token.is_expired())
    }

    #[test]
    fn bearer_token_is_not_expired() {
        let token = BearerToken::new("abc123", 3600, None, ScopeSet::new());
        assert!(!token.is_expired())
    }
}
