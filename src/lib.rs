extern crate failure;
#[macro_use]
extern crate failure_derive;
#[macro_use]
extern crate futures;
extern crate hyper;
extern crate hyper_tls;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;
extern crate serde_urlencoded;
extern crate tokio_core;

use std::borrow::Cow;
use std::sync::Arc;
use std::sync::Mutex;

use futures::Future;
use futures::future::Shared;

use auth::{AppSecrets, AuthFlow, Authenticator, BearerToken, BearerTokenFuture};
use http::HttpClient;
pub use http::SnooFuture;

mod reddit;
pub mod auth;
pub mod error;
mod http;

#[derive(Debug)]
pub struct Snoo {
    inner: Arc<RedditClient>,
}

impl Snoo {
    pub fn builder() -> SnooBuilder {
        SnooBuilder::default()
    }

    pub fn authorization_url_builder() -> auth::AuthUrlBuilder {
        auth::AuthUrlBuilder::default()
    }

    pub fn bearer_token(&self, force: bool) -> Shared<auth::BearerTokenFuture> {
        self.inner.bearer_token(force)
    }

    pub fn user<T>(&self, name: T)
    where
        T: Into<String>,
    {
        unimplemented!()
    }

    pub fn subreddit<T>(&self, name: T)
    where
        T: Into<String>,
    {
        unimplemented!()
    }

    pub fn submission<T>(&self, id: T)
    where
        T: Into<String>,
    {
        unimplemented!()
    }

    pub fn comment<T>(&self, id: T)
    where
        T: Into<String>,
    {
        unimplemented!()
    }

    pub fn message<T>(&self, id: T)
    where
        T: Into<String>,
    {
        unimplemented!()
    }
}

#[derive(Debug)]
struct RedditClient {
    authenticator: Authenticator,
    http_client: HttpClient,
}

impl RedditClient {
    pub fn bearer_token(&self, renew: bool) -> Shared<auth::BearerTokenFuture> {
        self.authenticator.bearer_token(&self.http_client, renew)
    }
}

// TODO: Add options for refreshing the bearer token and rate-limiting requests
#[derive(Debug, Default)]
pub struct SnooBuilder {
    app_secrets: Option<AppSecrets>,
    auth_flow: Option<AuthFlow>,
    bearer_token: Option<BearerToken>,
    user_agent: Option<String>,
}

impl SnooBuilder {
    pub fn app_secrets(mut self, app_secrets: AppSecrets) -> Self {
        self.app_secrets = Some(app_secrets);
        self
    }

    pub fn auth_flow(mut self, auth_flow: AuthFlow) -> Self {
        self.auth_flow = Some(auth_flow);
        self
    }

    pub fn bearer_token(mut self, token: BearerToken) -> Self {
        self.bearer_token = Some(token);
        self
    }

    pub fn user_agent(mut self, app_id: &str, app_version: &str, username: &str) -> Self {
        let user_agent = format!("snoo-rs:{}:{} (/u/{})", app_id, app_version, username);
        self.user_agent = Some(user_agent);
        self
    }

    pub fn build(
        self,
        handle: &tokio_core::reactor::Handle,
    ) -> Result<Snoo, error::SnooBuilderError> {
        let app_secrets = self.app_secrets
            .ok_or_else(|| error::SnooBuilderError::MissingAppSecrets)?;
        let user_agent = self.user_agent
            .ok_or_else(|| error::SnooBuilderError::MissingUserAgent)?;
        let http_client = HttpClient::new(user_agent, handle)?;
        let authenticator =
            Authenticator::new(app_secrets, self.auth_flow, self.bearer_token, &http_client)?;
        let reddit_client = RedditClient {
            authenticator,
            http_client,
        };
        let snoo = Snoo {
            inner: Arc::new(reddit_client),
        };

        Ok(snoo)
    }
}
