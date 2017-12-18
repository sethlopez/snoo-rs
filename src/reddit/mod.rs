pub mod api;
pub mod auth;

use self::auth::{Authenticator, SharedBearerTokenFuture};
use net::HttpClient;

#[derive(Debug)]
pub struct RedditClient {
    authenticator: Authenticator,
    http_client: HttpClient,
}

impl RedditClient {
    pub fn new(authenticator: Authenticator, http_client: HttpClient) -> RedditClient {
        RedditClient {
            authenticator,
            http_client,
        }
    }

    pub fn bearer_token(&self, renew: bool) -> SharedBearerTokenFuture {
        self.authenticator.bearer_token(&self.http_client, renew)
    }
}
