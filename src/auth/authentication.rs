use std::time::{Duration, Instant};

use futures::{Poll, Stream};
use reqwest::unstable::async::Client as ReqwestClient;

use auth::{Scope, ScopeSet};

pub struct AuthenticationStream {
    http_client: ReqwestClient,
    bearer_token: Option<BearerToken>,
}

impl AuthenticationStream {
    pub(crate) fn expire(&mut self) {
        self.bearer_token.take();
    }
}

impl Stream for AuthenticationStream {
    type Item = BearerToken;
    type Error = ();

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        unimplemented!()
    }
}

/// A container to hold Reddit-generated authentication secrets.
#[derive(Clone, Debug)]
pub struct ApplicationSecrets {
    client_id: String,
    client_secret: Option<String>,
}

impl ApplicationSecrets {
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
    pub fn new<S, O>(client_id: S, client_secret: O) -> ApplicationSecrets
    where
        S: Into<String>,
        O: Into<Option<S>>,
    {
        ApplicationSecrets {
            client_id: client_id.into(),
            client_secret: client_secret.into().map(|value| value.into()),
        }
    }
}


/// The method used for authentication. Application-only authentication methods are not supported.
///
/// More information about the authorization and authentication process can be found in Reddit's
/// [OAuth 2 documentation] on GitHub.
///
/// [OAuth 2 documentation]: https://github.com/reddit/reddit/wiki/OAuth2
#[derive(Clone, Debug)]
pub enum AuthenticationFlow {
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
    /// Authenticate using a refresh token.
    RefreshToken(String),
    /// Authenticate on behalf of a user with a username and password.
    UserCredentials {
        /// The user's password.
        password: String,
        /// The user's username.
        username: String,
        /// A set of [scopes] to request during authentication.
        ///
        /// [scopes]: enum.Scope.html
        scope: ScopeSet,
    },
}

#[derive(Clone, Debug, Deserialize)]
pub struct BearerToken {
    access_token: String,
    #[serde(default = "Instant::now", skip_deserializing)]
    created_at: Instant,
    expires_in: Duration,
    refresh_token: Option<String>,
    scope: ScopeSet,
}

impl BearerToken {
    pub fn new<A, R, S>(access_token: A, expires_in: u64, refresh_token: R, scope: S) -> BearerToken
    where
        A: Into<String>,
        R: Into<Option<A>>,
        S: IntoIterator<Item = Scope>,
    {
        BearerToken {
            access_token: access_token.into(),
            created_at: Instant::now(),
            expires_in: Duration::from_secs(expires_in),
            refresh_token: refresh_token.into().map(|token| token.into()),
            scope: scope.into_iter().collect(),
        }
    }

    pub fn access_token(&self) -> &str {
        self.access_token.as_str()
    }

    pub fn expires_in(&self) -> Duration {
        self.expires_in
    }

    pub fn refresh_token(&self) -> Option<&str> {
        self.refresh_token.as_ref().map(String::as_ref)
    }

    pub fn scope(&self) -> &ScopeSet {
        &self.scope
    }

    pub fn is_expired(&self) -> bool {
        self.created_at.elapsed() >= self.expires_in
    }

    pub fn is_refreshable(&self) -> bool {
        self.refresh_token.is_some()
    }

    pub fn matches_scope(&self, scope: Scope) -> bool {
        scope == Scope::All || self.scope.contains(scope) || self.scope.contains(Scope::All)
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
            expires_in: Duration::from_secs(3600),
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
