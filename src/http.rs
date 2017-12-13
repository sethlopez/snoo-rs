use hyper;
use hyper_tls;
use futures::prelude::*;
use futures::stream::Concat2;
use serde;
use serde_json;
use serde_urlencoded;
use tokio_core;

use reddit::Resource;
use auth::{AppSecrets, BearerToken};
use error::{SnooError, SnooErrorKind, SnooBuilderError};

pub type HyperClient = hyper::Client<hyper_tls::HttpsConnector<hyper::client::HttpConnector>>;

pub struct HttpClient {
    hyper_client: HyperClient,
    user_agent: String,
}

impl HttpClient {
    pub fn new(
        user_agent: String,
        handle: &tokio_core::reactor::Handle,
    ) -> Result<HttpClient, SnooBuilderError> {
        let https_connector = hyper_tls::HttpsConnector::new(1, handle).map_err(|_| {
            SnooBuilderError::HyperError.into()
        })?;
        let hyper_client = hyper::Client::configure()
            .connector(https_connector)
            .build(handle);

        Ok(HttpClient {
            hyper_client,
            user_agent,
        })
    }

    pub fn execute(&self, mut request: hyper::Request) -> hyper::client::FutureResponse {
        request.headers_mut().set(hyper::header::UserAgent::new(
            self.user_agent.clone(),
        ));
        self.hyper_client.request(request)
    }
}

pub struct HttpRequestBuilder {
    request: hyper::Request,
    error: Option<SnooError>,
}

impl HttpRequestBuilder {
    pub fn new(method: hyper::Method, resource: Resource) -> HttpRequestBuilder {
        let uri = resource.to_string().parse::<hyper::Uri>().unwrap();
        HttpRequestBuilder {
            request: hyper::Request::new(method, uri),
            error: None,
        }
    }

    pub fn get(resource: Resource) -> HttpRequestBuilder {
        HttpRequestBuilder::new(hyper::Method::Get, resource)
    }

    pub fn post(resource: Resource) -> HttpRequestBuilder {
        HttpRequestBuilder::new(hyper::Method::Post, resource)
    }

    pub fn put(resource: Resource) -> HttpRequestBuilder {
        HttpRequestBuilder::new(hyper::Method::Put, resource)
    }

    pub fn patch(resource: Resource) -> HttpRequestBuilder {
        HttpRequestBuilder::new(hyper::Method::Patch, resource)
    }

    pub fn delete(resource: Resource) -> HttpRequestBuilder {
        HttpRequestBuilder::new(hyper::Method::Delete, resource)
    }

    pub fn basic_auth(mut self, app_secrets: &AppSecrets) -> Self {
        self.request.headers_mut().set(
            hyper::header::Authorization(
                hyper::header::Basic {
                    username: app_secrets.client_id().to_owned(),
                    password: app_secrets.client_secret().clone().map(|s| s.to_owned()),
                },
            ),
        );
        self
    }

    pub fn bearer_auth(mut self, access_token: &str) -> Self {
        self.request.headers_mut().set(hyper::header::Authorization(
            hyper::header::Bearer { token: access_token.to_owned() },
        ));
        self
    }

    pub fn json<T>(mut self, body: T) -> Self
    where
        T: serde::Serialize,
    {
        match serde_json::to_string(&body) {
            Ok(serialized) => {
                self.request.headers_mut().set(
                    hyper::header::ContentType::json(),
                );
                self.request.set_body(serialized);
            }
            Err(error) => self.error = Some(error.into()),
        }
        self
    }

    pub fn form<T>(mut self, body: T) -> Self
    where
        T: serde::Serialize,
    {
        match serde_urlencoded::to_string(body) {
            Ok(serialized) => {
                self.request.headers_mut().set(
                    hyper::header::ContentType::form_url_encoded(),
                );
                self.request.set_body(serialized);
            }
            Err(error) => self.error = Some(error.into()),
        }
        self
    }

    pub fn build(mut self) -> Result<hyper::Request, SnooError> {
        if let Some(error) = self.error.take() {
            Err(error)
        } else {
            Ok(self.request)
        }
    }
}

#[must_use = "futures do nothing unless polled"]
pub struct RawHttpFuture {
    response_future: Option<hyper::client::FutureResponse>,
    status: Option<hyper::StatusCode>,
    headers: Option<hyper::Headers>,
    body_future: Option<Concat2<hyper::Body>>,
}

impl RawHttpFuture {
    pub fn new(response_future: hyper::client::FutureResponse) -> RawHttpFuture {
        RawHttpFuture {
            response_future: Some(response_future),
            status: None,
            headers: None,
            body_future: None,
        }
    }
}

impl Future for RawHttpFuture {
    type Item = (hyper::StatusCode, hyper::Headers, hyper::Chunk);
    type Error = hyper::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        // if there's a response future, poll it and set the status, header, and body fields
        if let Some(mut response_future) = self.response_future.take() {
            match response_future.poll() {
                Err(error) => return Err(error.into()),
                Ok(Async::NotReady) => {
                    self.response_future = Some(response_future);
                    return Ok(Async::NotReady);
                }
                Ok(Async::Ready(response)) => {
                    self.status = Some(response.status());
                    self.headers = Some(response.headers().clone());
                    self.body_future = Some(response.body().concat2());
                }
            }
        }

        // if there's a body future, concatenate it into a chunk and return everything
        if let Some(mut body_future) = self.body_future.take() {
            match body_future.poll() {
                Err(error) => return Err(error.into()),
                Ok(Async::NotReady) => {
                    self.body_future = Some(body_future);
                    return Ok(Async::NotReady);
                }
                Ok(Async::Ready(body)) => {
                    return Ok(Async::Ready((
                        self.status.take().unwrap(),
                        self.headers.take().unwrap(),
                        body,
                    )));
                }
            }
        } else {
            panic!("future has already completed")
        }
    }
}
