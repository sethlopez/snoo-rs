extern crate failure;
#[macro_use]
extern crate failure_derive;
extern crate futures;
extern crate reqwest;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;
extern crate serde_urlencoded;

use std::sync::Arc;

mod api;
pub mod auth;

pub struct Snoo {
    application_secrets: auth::ApplicationSecrets,
    authentication_flow: auth::AuthenticationFlow,
    bearer_token: Option<auth::BearerToken>,
    http_client: Arc<reqwest::unstable::async::Client>,
}

impl Snoo {
    pub fn builder() -> SnooBuilder {
        SnooBuilder::default()
    }

    pub fn authorization_url_builder() -> auth::AuthorizationUrlBuilder {
        auth::AuthorizationUrlBuilder::default()
    }

    pub fn authenticate(&self) {
        unimplemented!()
    }

    pub fn account<T>(&self, name: T)
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

#[derive(Debug, Default)]
pub struct SnooBuilder {
    client_id: Option<String>,
    client_secret: Option<String>,
    authentication_method: Option<auth::AuthenticationFlow>,
    bearer_token: Option<auth::BearerToken>,
}

impl SnooBuilder {
    pub fn authentication_method(mut self, method: auth::AuthenticationFlow) -> Self {
        self.authentication_method = Some(method);
        self
    }

    pub fn bearer_token(mut self, token: auth::BearerToken) -> Self {
        self.bearer_token = Some(token);
        self
    }

    pub fn client_id<T>(mut self, client_id: T) -> Self
    where
        T: Into<String>,
    {
        self.client_id = Some(client_id.into());
        self
    }

    pub fn client_secret<T>(mut self, client_secret: T) -> Self
    where
        T: Into<String>,
    {
        self.client_secret = Some(client_secret.into());
        self
    }

    pub fn build(
        self,
        application_id: &str,
        application_version: &str,
        reddit_username: &str,
    ) -> Snoo {
        let user_agent = format!(
            "snoo-rs:{}:{} (/u/{})",
            application_id,
            application_version,
            reddit_username
        );
        unimplemented!()
    }
}
