use hyper::{Method, Request, Uri};
use hyper::header::{Authorization, Basic, Bearer, ContentType};
use serde::Serialize;
use serde_json;
use serde_urlencoded;

use reddit::api::Resource;
use reddit::auth::AppSecrets;
use error::SnooError;

pub struct HttpRequestBuilder {
    error: Option<SnooError>,
    request: Request,
}

impl HttpRequestBuilder {
    pub fn new(method: Method, resource: Resource) -> HttpRequestBuilder {
        let uri = resource.to_string().parse::<Uri>().unwrap();
        HttpRequestBuilder {
            request: Request::new(method, uri),
            error: None,
        }
    }

    pub fn get(resource: Resource) -> HttpRequestBuilder {
        HttpRequestBuilder::new(Method::Get, resource)
    }

    pub fn post(resource: Resource) -> HttpRequestBuilder {
        HttpRequestBuilder::new(Method::Post, resource)
    }

    pub fn put(resource: Resource) -> HttpRequestBuilder {
        HttpRequestBuilder::new(Method::Put, resource)
    }

    pub fn patch(resource: Resource) -> HttpRequestBuilder {
        HttpRequestBuilder::new(Method::Patch, resource)
    }

    pub fn delete(resource: Resource) -> HttpRequestBuilder {
        HttpRequestBuilder::new(Method::Delete, resource)
    }

    pub fn basic_auth(mut self, app_secrets: &AppSecrets) -> Self {
        self.request.headers_mut().set(Authorization(Basic {
            username: app_secrets.client_id().to_owned(),
            password: app_secrets.client_secret().map(|s| s.to_owned()),
        }));
        self
    }

    pub fn bearer_auth(mut self, access_token: &str) -> Self {
        self.request.headers_mut().set(Authorization(Bearer {
            token: access_token.to_owned(),
        }));
        self
    }

    pub fn json<T>(mut self, body: T) -> Self
    where
        T: Serialize,
    {
        match serde_json::to_string(&body) {
            Ok(serialized) => {
                self.request.headers_mut().set(ContentType::json());
                self.request.set_body(serialized);
            }
            Err(error) => self.error = Some(error.into()),
        }
        self
    }

    pub fn form<T>(mut self, body: T) -> Self
    where
        T: Serialize,
    {
        match serde_urlencoded::to_string(body) {
            Ok(serialized) => {
                self.request
                    .headers_mut()
                    .set(ContentType::form_url_encoded());
                self.request.set_body(serialized);
            }
            Err(error) => self.error = Some(error.into()),
        }
        self
    }

    pub fn build(mut self) -> Result<Request, SnooError> {
        if let Some(error) = self.error.take() {
            Err(error)
        } else {
            Ok(self.request)
        }
    }
}
