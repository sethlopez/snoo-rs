use std::sync::Mutex;
use std::time::Instant;

use futures::prelude::*;
use futures::future::Shared;
use serde_json;

use reddit::Resource;
use auth::{Scope, ScopeSet};
use error::{SnooBuilderError, SnooError, SnooErrorKind};
use http::{HttpClient, HttpRequestBuilder, RawHttpFuture};

#[derive(Debug)]
pub struct Authenticator {
    app_secrets: AppSecrets,
    auth_flow: Mutex<Option<AuthFlow>>,
    bearer_token: Mutex<Shared<BearerTokenFuture>>,
}

impl Authenticator {
    pub fn new(
        app_secrets: AppSecrets,
        auth_flow: Option<AuthFlow>,
        bearer_token: Option<BearerToken>,
        http_client: &HttpClient,
    ) -> Result<Authenticator, SnooBuilderError> {
        if let Some(bearer_token) = bearer_token {
            let auth_flow = if let Some(auth_flow) = auth_flow {
                if auth_flow.is_password() {
                    Some(auth_flow)
                } else {
                    None
                }
            } else {
                None
            };
            let bearer_token: BearerTokenFuture = bearer_token.into();
            Ok(Authenticator {
                app_secrets,
                auth_flow: Mutex::new(auth_flow),
                bearer_token: Mutex::new(bearer_token.shared()),
            })
        } else if let Some(auth_flow) = auth_flow {
            let bearer_token = BearerTokenFuture::new(http_client, &auth_flow, &app_secrets);
            let auth_flow = if auth_flow.is_password() {
                Some(auth_flow)
            } else {
                None
            };
            Ok(Authenticator {
                app_secrets,
                auth_flow: Mutex::new(auth_flow),
                bearer_token: Mutex::new(bearer_token.shared()),
            })
        } else {
            Err(SnooBuilderError::MissingAuthFlow)
        }
    }

    pub fn bearer_token(&self, http_client: &HttpClient, renew: bool) -> Shared<BearerTokenFuture> {
        let mut auth_flow_guard = self.auth_flow
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let mut bearer_token_guard = self.bearer_token
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let mut renewed = false;

        match (bearer_token_guard.peek(), auth_flow_guard.as_ref()) {
            // bearer token is expired and renewable, renew the future
            (Some(Ok(ref bearer_token)), _)
                if bearer_token.is_expired() && bearer_token.is_renewable() =>
            {
                let refresh_token = bearer_token.refresh_token().map(|r| r.to_owned()).unwrap();
                let auth_flow = AuthFlow::RefreshToken(refresh_token);
                *bearer_token_guard =
                    BearerTokenFuture::new(http_client, &auth_flow, &self.app_secrets).shared()
            }
            // bearer token is expired & not renewable, but we have an auth flow, renew the future
            (Some(Ok(ref bearer_token)), Some(_))
                if bearer_token.is_expired() && !bearer_token.is_renewable() =>
            {
                let auth_flow = auth_flow_guard.take().unwrap();
                *bearer_token_guard =
                    BearerTokenFuture::new(http_client, &auth_flow, &self.app_secrets).shared();

                if auth_flow.is_password() {
                    *auth_flow_guard = Some(auth_flow);
                }
            }
            // bearer token is not expired, auth flow is present and renew is true, renew the future
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

        // if we have an expired and renewable bearer token, renew it
        //        match bearer_token_guard.peek() {
        //            Some(Ok(ref bearer_token))
        //                if bearer_token.is_expired() && bearer_token.is_renewable() =>
        //            {
        //                let refresh_token = bearer_token.refresh_token().map(|r| r.to_owned()).unwrap();
        //                let auth_flow = AuthFlow::RefreshToken(refresh_token);
        //                *bearer_token_guard =
        //                    BearerTokenFuture::new(http_client, &auth_flow, &self.app_secrets).shared();
        //                renewed = true;
        //            }
        //            _ => {}
        //        };

        // if the bearer token hasn't been renewed already, renew is true, and we have an auth flow,
        // renew the token
        //        match *auth_flow_guard {
        //            Some(_) if !renewed && renew => {
        //                let auth_flow = auth_flow_guard.take().unwrap();
        //                *bearer_token_guard =
        //                    BearerTokenFuture::new(http_client, &auth_flow, &self.app_secrets).shared();
        //
        //                // a password auth flow should be placed back so it can be reused
        //                if auth_flow.is_password() {
        //                    *auth_flow_guard = Some(auth_flow);
        //                }
        //            }
        //            _ => {}
        //        };

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
    /// ```
    /// use snoo::auth::AppSecrets;
    /// let secrets = AppSecrets::new("abc123", "xyz890");
    /// ```
    ///
    /// If a client_secret is not available for your application, `None` can be passed instead.
    ///
    /// ```
    /// use snoo::auth::AppSecrets;
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

    pub fn client_id(&self) -> &str {
        self.client_id.as_str()
    }

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

    pub fn access_token(&self) -> &str {
        self.access_token.as_str()
    }

    pub fn expires_in(&self) -> usize {
        self.expires_in
    }

    pub fn refresh_token(&self) -> Option<&str> {
        self.refresh_token.as_ref().map(String::as_ref)
    }

    pub fn scope(&self) -> &ScopeSet {
        &self.scope
    }

    pub fn is_expired(&self) -> bool {
        self.created_at.elapsed().as_secs() >= (self.expires_in as u64)
    }

    pub fn is_renewable(&self) -> bool {
        self.refresh_token.is_some()
    }

    pub fn matches_scope(&self, scope: Scope) -> bool {
        scope == Scope::All || self.scope.contains(scope) || self.scope.contains(Scope::All)
    }
}

// TODO: Document BearerTokenFuture
#[must_use = "futures do nothing unless polled"]
#[derive(Debug)]
pub enum BearerTokenFuture {
    Fixed(Option<BearerToken>),
    Future {
        error: Option<SnooError>,
        future: Option<RawHttpFuture>,
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
                future: Some(RawHttpFuture::new(http_client.execute(request))),
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
