use serde_urlencoded;

use reddit::Resource;
use auth::{Scope, ScopeSet};

/// A builder for user authorization URLs.
///
/// Some authentication methods require authorization from a user. In order to gain this
/// authorization, a user must visit a specific URL and perform a confirmation action. Afterward,
/// the user is redirected to a URI provided by the app. Appended to the URI will be query
/// parameters containing the necessary information to obtain a bearer token on behalf of the user.
///
/// More information about the authorization and authentication process can be found in Reddit's
/// [OAuth 2 documentation] on GitHub.
///
/// [OAuth 2 documentation]: https://github.com/reddit/reddit/wiki/OAuth2
///
/// # Examples
///
/// ```
/// use snoo::auth::{AuthorizationResponseType, AuthorizationUrlBuilder};
///
/// let expected_url = "https://www.reddit.com/api/v1/authorize\
///     ?client_id=xxxxxxxxxxxxxx\
///     &duration=temporary\
///     &redirect_uri=https%3A%2F%2Fexample.com%2Fauthorized\
///     &response_type=code\
///     &scope=identity\
///     &state=random_state";
/// let authorization_url = AuthorizationUrlBuilder::default()
///     .client_id("xxxxxxxxxxxxxx")
///     .redirect_uri("https://example.com/authorized")
///     .state("random_state")
///     .build()
///     .unwrap();
///
/// assert_eq!(expected_url, authorization_url.as_str());
/// ```
#[derive(Clone, Debug)]
pub struct AuthorizationUrlBuilder {
    client_id: Option<String>,
    compact: bool,
    duration: AuthorizationDuration,
    redirect_uri: Option<String>,
    response_type: AuthorizationResponseType,
    scope: ScopeSet,
    state: Option<String>,
}

impl AuthorizationUrlBuilder {
    /// **Required.** Sets the client ID query parameter.
    ///
    /// The client ID can be found in the [user preferences] of
    /// the application owner.
    ///
    /// [user preferences]: https://www.reddit.com/prefs/apps/
    pub fn client_id<C>(mut self, client_id: C) -> Self
    where
        C: Into<String>,
    {
        self.client_id = Some(client_id.into());
        self
    }

    /// Sets whether or not the authorization URL should show a page catering to small screens.
    ///
    /// # Default Value
    ///
    /// By default, `compact` is set to `false`.
    pub fn compact(mut self, compact: bool) -> Self {
        self.compact = compact;
        self
    }

    /// Sets the authorization duration. This value is ignored for the token [response type].
    /// [Read more]
    ///
    /// # Default Value
    ///
    /// By default, `duration` is set to [`AuthorizationDuration::Temporary`].
    ///
    /// [response type]: enum.AuthorizationResponseType.html#variant.Token
    /// [Read more]: enum.AuthorizationDuration.html
    /// [`AuthorizationDuration::Temporary`]: enum.AuthorizationDuration.html#variant.Temporary
    pub fn duration(mut self, duration: AuthorizationDuration) -> Self {
        self.duration = duration;
        self
    }

    /// **Required.** Sets the URI that the user will be redirected to after granting authorization.
    ///
    /// This redirect URI must match the redirect URI registered for the application. If it does not
    /// match, the authorization request will fail.
    pub fn redirect_uri<U>(mut self, redirect_uri: U) -> Self
    where
        U: Into<String>,
    {
        self.redirect_uri = Some(redirect_uri.into());
        self
    }

    /// Sets the response type query parameter. [Read more]
    ///
    /// # Default Value
    ///
    /// By default, `response_type` is set to [`AuthorizationResponseType::Code`].
    ///
    /// [Read more]: enum.AuthorizationResponseType.html
    /// [`AuthorizationResponseType::Code`]: enum.AuthorizationResponseType.html#variant.Code
    pub fn response_type(mut self, response_type: AuthorizationResponseType) -> Self {
        self.response_type = response_type;
        self
    }

    /// Sets the scope of access. The scope determines what permissions are requested from the user
    /// when they visit the authorization URL.
    ///
    /// If `scope` is empty, the default value will be used, instead.
    ///
    /// # Default Value
    ///
    /// By default, `scope` only includes [`Scope::Identity`].
    ///
    /// [`Scope::Identity`]: enum.Scope.html#variant.Identity
    pub fn scope<I>(mut self, scopes: I) -> Self
    where
        I: IntoIterator<Item = Scope>,
    {
        let scopes: ScopeSet = scopes.into_iter().collect();

        if scopes.is_empty() {
            self.scope = ScopeSet::default();
        } else {
            self.scope = scopes;
        }

        self
    }

    /// **Required.** Sets the state for the authorization request. The state should be unique, and
    /// possibly random, for each authorization request.
    ///
    /// When a user is redirected to the redirect URI, this state value will be included as a
    /// query parameter. The application should verify that the state value included in the
    /// redirect URI matches the state value that was originally included in the authorization URL.
    pub fn state<S>(mut self, state: S) -> Self
    where
        S: Into<String>,
    {
        self.state = Some(state.into());
        self
    }

    /// Builds an authorization URL from the values provided.
    pub fn build(self) -> Result<String, AuthorizationUrlError> {
        let endpoint = if self.compact {
            Resource::AuthorizeCompact
        } else {
            Resource::Authorize
        };
        let client_id = self.client_id.ok_or_else(
            || AuthorizationUrlError::MissingClientId,
        )?;
        let duration = match self.response_type {
            AuthorizationResponseType::Code => Some(self.duration),
            _ => None,
        };
        let redirect_uri = self.redirect_uri.ok_or_else(|| {
            AuthorizationUrlError::MissingRedirectUri
        })?;
        let state = self.state.ok_or_else(
            || AuthorizationUrlError::MissingState,
        )?;
        let query_parameters = serde_urlencoded::to_string(QueryParameters {
            client_id,
            duration,
            redirect_uri,
            response_type: self.response_type,
            scope: self.scope,
            state,
        }).unwrap();
        let url = format!("{}?{}", endpoint, query_parameters);

        Ok(url)
    }
}

impl Default for AuthorizationUrlBuilder {
    fn default() -> AuthorizationUrlBuilder {
        AuthorizationUrlBuilder {
            client_id: None,
            compact: false,
            duration: AuthorizationDuration::Temporary,
            redirect_uri: None,
            response_type: AuthorizationResponseType::Code,
            scope: ScopeSet::default(),
            state: None,
        }
    }
}

/// Query parameters that are included in an authorization URL.
#[derive(Debug, Serialize)]
#[serde(rename_all = "lowercase")]
struct QueryParameters {
    client_id: String,
    duration: Option<AuthorizationDuration>,
    redirect_uri: String,
    response_type: AuthorizationResponseType,
    scope: ScopeSet,
    state: String,
}

/// The type of response expected after authorization.
///
/// After a user has authorized your application, Reddit will redirect the user to the redirect URI
/// registered for the application. The response type determines what information Reddit will append
/// to the redirect URI via query parameters. Your registered [application type] may determine the
/// response type that can be used.
///
/// [application type]: https://github.com/reddit/reddit/wiki/oauth2-app-types
#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthorizationResponseType {
    /// The `Code` response type tells Reddit to append a `code` query parameter containing a
    /// one-time use code that can then be exchanged for a bearer token during authentication.
    ///
    /// This response type can be used for all application types.
    Code,
    /// The `token` response type tells Reddit to append an `access_token`, `token_type`,
    /// `expires_in`, and `scope` query parameters. This allows the application to request
    /// authorization from a user and receive a bearer token in a single step.
    ///
    /// Only "installed" applications may use this response type.
    Token,
}

/// A duration for which an authorization is valid.
///
/// By default, a `Temporary` duration is used when requesting authorization.
#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthorizationDuration {
    /// The `Temporary` duration is useful when performing one-off actions for a user, such as
    /// analyzing their recent comments. Temporary bearer tokens do not include a refresh token. For
    /// authentication flows that require it, a user will need to authorize access again once a
    /// temporary bearer token is expired. Temporary bearer tokens expire after 1 hour.
    Temporary,
    /// The `Permanent` duration is useful when long-term access to a user's account is necessary,
    /// such as notifying a user when they receive a private message. Permanent bearer tokens
    /// include a refresh token that can be used to retrieve a new bearer token once the current one
    /// is expired. No further authorization from a user should be necessary.
    Permanent,
}

/// An error that may occur when building an authorization URL.
#[derive(Debug, Eq, Fail, PartialEq)]
pub enum AuthorizationUrlError {
    /// A client ID is required, but wasn't provided. [Read more]
    ///
    /// [Read more]: struct.AuthorizationUrlBuilder.html#method.client_id
    #[fail(display = "missing client ID")]
    MissingClientId,
    /// A redirect URI is required, but wasn't provided. [Read more]
    ///
    /// [Read more]: struct.AuthorizationUrlBuilder.html#method.redirect_uri
    #[fail(display = "missing redirect URI")]
    MissingRedirectUri,
    /// A state string is required, but wasn't provided. [Read more]
    ///
    /// [Read more]: struct.AuthorizationUrlBuilder.html#method.state
    #[fail(display = "missing state")]
    MissingState,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_authorization_code_url() {
        let actual = AuthorizationUrlBuilder::default()
            .client_id("abc123")
            .redirect_uri("https://example.com/authorized")
            .state("random_state")
            .build()
            .unwrap();
        let expected = "https://www.reddit.com/api/v1/authorize\
                ?client_id=abc123\
                &duration=temporary\
                &redirect_uri=https%3A%2F%2Fexample.com%2Fauthorized\
                &response_type=code\
                &scope=identity\
                &state=random_state";
        assert_eq!(actual.as_str(), expected);
    }

    #[test]
    fn builds_authorization_code_url_with_compact() {
        let actual = AuthorizationUrlBuilder::default()
            .client_id("abc123")
            .compact(true)
            .redirect_uri("https://example.com/authorized")
            .state("random_state")
            .build()
            .unwrap();
        let expected = "https://www.reddit.com/api/v1/authorize.compact\
                ?client_id=abc123\
                &duration=temporary\
                &redirect_uri=https%3A%2F%2Fexample.com%2Fauthorized\
                &response_type=code\
                &scope=identity\
                &state=random_state";
        assert_eq!(actual.as_str(), expected);
    }

    #[test]
    fn builds_authorization_code_url_with_custom_duration() {
        let actual = AuthorizationUrlBuilder::default()
            .client_id("abc123")
            .duration(AuthorizationDuration::Permanent)
            .redirect_uri("https://example.com/authorized")
            .state("random_state")
            .build()
            .unwrap();
        let expected = "https://www.reddit.com/api/v1/authorize\
                ?client_id=abc123\
                &duration=permanent\
                &redirect_uri=https%3A%2F%2Fexample.com%2Fauthorized\
                &response_type=code\
                &scope=identity\
                &state=random_state";
        assert_eq!(actual.as_str(), expected);
    }

    #[test]
    fn builds_authorization_code_url_with_custom_scope() {
        let actual = AuthorizationUrlBuilder::default()
            .client_id("abc123")
            .redirect_uri("https://example.com/authorized")
            .scope(vec![Scope::WikiEdit, Scope::WikiRead])
            .state("random_state")
            .build()
            .unwrap();
        let expected = "https://www.reddit.com/api/v1/authorize\
                ?client_id=abc123\
                &duration=temporary\
                &redirect_uri=https%3A%2F%2Fexample.com%2Fauthorized\
                &response_type=code\
                &scope=wikiedit+wikiread\
                &state=random_state";
        assert_eq!(actual.as_str(), expected);
    }

    #[test]
    fn builds_authorization_token_url() {
        let actual = AuthorizationUrlBuilder::default()
            .client_id("abc123")
            .redirect_uri("https://example.com/authorized")
            .response_type(AuthorizationResponseType::Token)
            .state("random_state")
            .build()
            .unwrap();
        let expected = "https://www.reddit.com/api/v1/authorize\
                ?client_id=abc123\
                &redirect_uri=https%3A%2F%2Fexample.com%2Fauthorized\
                &response_type=token\
                &scope=identity\
                &state=random_state";
        assert_eq!(actual.as_str(), expected);
    }

    #[test]
    fn builds_authorization_token_url_ignoring_duration() {
        let actual = AuthorizationUrlBuilder::default()
            .client_id("abc123")
            .duration(AuthorizationDuration::Permanent)
            .redirect_uri("https://example.com/authorized")
            .response_type(AuthorizationResponseType::Token)
            .state("random_state")
            .build()
            .unwrap();
        let expected = "https://www.reddit.com/api/v1/authorize\
                ?client_id=abc123\
                &redirect_uri=https%3A%2F%2Fexample.com%2Fauthorized\
                &response_type=token\
                &scope=identity\
                &state=random_state";
        assert_eq!(actual.as_str(), expected);
    }

    #[test]
    fn fails_building_authorization_code_url_without_client_id() {
        let actual = AuthorizationUrlBuilder::default()
            .redirect_uri("https://example.com/authorized")
            .state("random_state")
            .build();
        let expected = Err(AuthorizationUrlError::MissingClientId);
        assert_eq!(actual, expected);
    }

    #[test]
    fn fails_building_authorization_code_url_without_redirect_uri() {
        let actual = AuthorizationUrlBuilder::default()
            .client_id("abc123")
            .state("random_state")
            .build();
        let expected = Err(AuthorizationUrlError::MissingRedirectUri);
        assert_eq!(actual, expected);
    }

    #[test]
    fn fails_building_authorization_code_url_without_state() {
        let actual = AuthorizationUrlBuilder::default()
            .client_id("abc123")
            .redirect_uri("https://example.com/authorized")
            .build();
        let expected = Err(AuthorizationUrlError::MissingState);
        assert_eq!(actual, expected);
    }
}
