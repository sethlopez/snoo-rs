extern crate futures;
extern crate snoo;
extern crate tokio_core;

use std::time::Instant;

use futures::prelude::*;
use futures::future::ok;
use snoo::Snoo;
use snoo::auth::{AuthFlow, Scope};

fn main() {
    let mut core = tokio_core::reactor::Core::new().unwrap();
    let snoo = Snoo::builder()
        .authentication_flow(AuthFlow::Password {
            username: "AllHail_Bot".to_owned(),
            password: "Gt48jajhJBO2P1%u".to_owned(),
            scope: [Scope::Identity].iter().cloned().collect(),
        })
        .client_id("s5luiC1dYnJQGw")
        .client_secret("9uH549kKwjUD-lhc70CPQ0iCkOY")
        .user_agent("snoo-rs", "v0.1.0", "pushECX")
        .build(&core.handle())
        .unwrap();

    let future_1 = snoo.bearer_token(false);
    let future_2 = snoo.bearer_token(false);
    let result = core.run(future_1.join(future_2));

    eprintln!("result = {:#?}", result);
}
