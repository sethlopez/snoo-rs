extern crate futures;
extern crate snoo;
extern crate structopt;
#[macro_use]
extern crate structopt_derive;
extern crate tokio_core;

use futures::prelude::*;
use snoo::auth::{AppSecrets, AuthFlow, BearerToken, Scope, ScopeSet};
use snoo::Snoo;
use structopt::StructOpt;

fn main() {
    let settings = Settings::from_args();
    // create the core with which we will run our futures
    let mut core = tokio_core::reactor::Core::new().unwrap();
    let snoo = Snoo::builder()
        .user_agent(
            "me.sethlopez.snoo.example.basic",
            env!("CARGO_PKG_VERSION"),
            &settings.username,
        )
        .app_secrets(AppSecrets::new(settings.client_id, settings.client_secret))
        .auth_flow(AuthFlow::Password {
            username: settings.username,
            password: settings.password,
            scope: [Scope::Identity].iter().cloned().collect::<ScopeSet>(),
        })
        .build(&core.handle())
        .unwrap();

    println!("snoo = {:#?}", snoo);

    let future_1 = snoo.bearer_token(false);
    let future_2 = snoo.bearer_token(false);

    println!("snoo = {:#?}", snoo);
    println!("result = {:#?}", core.run(future_1.join(future_2)));
}

#[derive(Debug, StructOpt)]
struct Settings {
    #[structopt(long = "client_id")]
    client_id: String,
    #[structopt(long = "client_secret")]
    client_secret: String,
    #[structopt(long = "password")]
    password: String,
    #[structopt(long = "username")]
    username: String,
}
