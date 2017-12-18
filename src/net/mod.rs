use std::sync::Arc;
use std::time::Instant;

use hyper::{Client as HyperClient, Request};
use hyper::client::{FutureResponse, HttpConnector};
use hyper::header::UserAgent;
use hyper_tls::HttpsConnector;
use tokio_core::reactor::Handle;

use error::SnooBuilderError;

pub mod request;
pub mod response;

#[derive(Debug)]
pub struct HttpClient {
    hyper_client: HyperClient<HttpsConnector<HttpConnector>>,
    user_agent: String,
}

impl HttpClient {
    pub fn new(handle: &Handle, user_agent: String) -> Result<HttpClient, SnooBuilderError> {
        let https_connector =
            HttpsConnector::new(1, handle).map_err(|_| SnooBuilderError::HyperError)?;
        let hyper_client = HyperClient::configure()
            .connector(https_connector)
            .build(handle);

        Ok(HttpClient {
            hyper_client,
            user_agent,
        })
    }

    pub fn execute(&self, mut request: Request) -> FutureResponse {
        request
            .headers_mut()
            .set(UserAgent::new(self.user_agent.clone()));
        self.hyper_client.request(request)
    }
}
