use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use futures::{Async, Future, Poll, Stream};
use futures::future::{Shared, SharedItem, SharedError};
use hyper::{Method, Request, StatusCode};
use hyper::client::FutureResponse;
use hyper::header::{Authorization, Basic, ContentType, UserAgent};
use serde_json;
use serde_urlencoded;

use reddit;
use auth::{Scope, ScopeSet};
use error::{SnooError, SnooErrorKind};
use http::{HttpClient, HttpRequestBuilder, RawHttpFuture};

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
    /// use snoo::auth::ApplicationSecrets;
    /// let secrets = ApplicationSecrets::new("abc123", "xyz890");
    /// ```
    ///
    /// If a client_secret is not available for your application, `None` can be passed instead.
    ///
    /// ```
    /// use snoo::auth::ApplicationSecrets;
    /// let secrets = ApplicationSecrets::new("abc123", None);
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

    pub fn to_basic_authorization_header(&self) -> Authorization<Basic> {
        Authorization(Basic {
            username: self.client_id.clone(),
            password: self.client_secret.clone(),
        })
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

#[derive(Clone, Debug, Deserialize)]
pub struct BearerToken {
    access_token: String,
    #[serde(default = "Instant::now", skip_deserializing)]
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

    pub fn is_refreshable(&self) -> bool {
        self.refresh_token.is_some()
    }

    pub fn matches_scope(&self, scope: Scope) -> bool {
        scope == Scope::All || self.scope.contains(scope) || self.scope.contains(Scope::All)
    }
}

#[must_use = "futures do nothing unless polled"]
pub struct BearerTokenFuture {
    future: Option<RawHttpFuture>,
    error: Option<SnooError>,
}

impl BearerTokenFuture {
    pub(crate) fn new(
        http_client: &HttpClient,
        authentication_flow: &AuthFlow,
        application_secrets: &AppSecrets,
    ) -> BearerTokenFuture {
        let request = HttpRequestBuilder::post(reddit::Resource::AccessToken)
            .basic_auth(&application_secrets)
            .form(authentication_flow)
            .build();
        let bearer_token_future = match request {
            Ok(request) => {
                BearerTokenFuture {
                    future: Some(RawHttpFuture::new(http_client.execute(request))),
                    error: None,
                }
            }
            Err(error) => {
                BearerTokenFuture {
                    future: None,
                    error: Some(error),
                }
            }
        };
        bearer_token_future
    }
}

impl Future for BearerTokenFuture {
    type Item = BearerToken;
    type Error = SnooError;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        if let Some(error) = self.error.take() {
            Err(error)
        } else if let Some(mut future) = self.future.take() {
            match future.poll() {
                Err(error) => Err(error.into()),
                Ok(Async::NotReady) => {
                    self.future = Some(future);
                    return Ok(Async::NotReady);
                }
                Ok(Async::Ready(response)) => {
                    let (status, headers, body) = response;

                    if !status.is_success() {
                        return Err(SnooErrorKind::UnsuccessfulResponse(status.as_u16()).into());
                    }

                    return serde_json::from_slice::<BearerToken>(&body)
                        .map(|bearer_token| Async::Ready(bearer_token))
                        .map_err(|_| SnooErrorKind::InvalidResponse.into());
                }
            }
        } else {
            panic!("future has already completed!")
        }
    }
}

#[cfg(test)]
mod tests {
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
