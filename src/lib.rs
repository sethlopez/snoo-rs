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

use std::sync::Arc;
use std::sync::Mutex;

use futures::Future;
use futures::future::Shared;

use http::HttpClient;

mod reddit;
pub mod auth;
mod error;
mod http;

pub struct Snoo {
    inner: Arc<SnooClient>,
}

impl Snoo {
    pub fn builder() -> SnooBuilder {
        SnooBuilder::default()
    }

    pub fn authorization_url_builder() -> auth::AuthorizationUrlBuilder {
        auth::AuthorizationUrlBuilder::default()
    }

    pub fn bearer_token(&self, force: bool) -> Shared<auth::BearerTokenFuture> {
        self.inner.authenticate(force)
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

struct SnooClient {
    app_secrets: auth::AppSecrets,
    auth_flow: auth::AuthFlow,
    bearer_token_future: Arc<Mutex<Shared<auth::BearerTokenFuture>>>,
    http_client: HttpClient,
}

impl SnooClient {
    pub fn new(
        app_secrets: auth::AppSecrets,
        auth_flow: auth::AuthFlow,
        http_client: HttpClient,
    ) -> SnooClient {
        let bearer_token_future =
            auth::BearerTokenFuture::new(&http_client, &auth_flow, &app_secrets);
        SnooClient {
            app_secrets,
            auth_flow,
            bearer_token_future: Arc::new(Mutex::new(bearer_token_future.shared())),
            http_client,
        }
    }

    pub fn authenticate(&self, force: bool) -> Shared<auth::BearerTokenFuture> {
        let mut bearer_token_mutex_guard =
            self.bearer_token_future.lock().unwrap_or_else(
                |error| error.into_inner(),
            );

        if force {
            *bearer_token_mutex_guard =
                auth::BearerTokenFuture::new(&self.http_client, &self.auth_flow, &self.app_secrets)
                    .shared();
        }

        bearer_token_mutex_guard.clone()
    }

    pub fn get(&self, resource: reddit::Resource) -> hyper::Request {
        unimplemented!()
    }

    pub fn post(&self, resource: reddit::Resource) -> hyper::Request {
        unimplemented!()
    }

    pub fn execute_request(&self, request: hyper::Request) {
        unimplemented!()
    }
}

#[derive(Debug, Default)]
pub struct SnooBuilder {
    client_id: Option<String>,
    client_secret: Option<String>,
    authentication_flow: Option<auth::AuthFlow>,
    bearer_token: Option<auth::BearerToken>,
    user_agent: Option<String>,
}

impl SnooBuilder {
    pub fn authentication_flow(mut self, method: auth::AuthFlow) -> Self {
        self.authentication_flow = Some(method);
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

    pub fn user_agent(mut self, app_id: &str, app_version: &str, username: &str) -> Self {
        let user_agent = format!("snoo-rs:{}:{} (/u/{})", app_id, app_version, username);
        self.user_agent = Some(user_agent);
        self
    }

    pub fn build(
        self,
        handle: &tokio_core::reactor::Handle,
    ) -> Result<Snoo, error::SnooBuilderError> {
        let authentication_flow = self.authentication_flow.ok_or_else(|| {
            error::SnooBuilderError::MissingAuthenticationFlow
        })?;
        let client_id = self.client_id.ok_or_else(
            || error::SnooBuilderError::MissingClientId,
        )?;
        let client_secret = self.client_secret;
        let user_agent = self.user_agent.ok_or_else(
            || error::SnooBuilderError::MissingUserAgent,
        )?;
        let http_client = HttpClient::new(user_agent, handle).map_err(|_| {
            error::SnooBuilderError::HyperError
        })?;
        let application_secrets = auth::AppSecrets::new(client_id, client_secret);
        let snoo_client = SnooClient::new(application_secrets, authentication_flow, http_client);
        let snoo = Snoo { inner: Arc::new(snoo_client) };

        Ok(snoo)
    }
}
