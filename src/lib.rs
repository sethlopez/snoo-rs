extern crate failure;
#[macro_use]
extern crate failure_derive;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;
extern crate serde_urlencoded;

use auth::AuthorizationUrlBuilder;

mod api;
pub mod auth;

pub struct Snoo;

impl Snoo {
    pub fn authorization_url_builder() -> AuthorizationUrlBuilder {
        AuthorizationUrlBuilder::default()
    }

    pub fn authenticate(&self) {
        unimplemented!()
    }

    pub fn account(&self) {
        unimplemented!()
    }

    pub fn subreddit(&self) {
        unimplemented!()
    }

    pub fn submission(&self) {
        unimplemented!()
    }

    pub fn comment(&self) {
        unimplemented!()
    }

    pub fn message(&self) {
        unimplemented!()
    }
}
