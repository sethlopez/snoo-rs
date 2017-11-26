extern crate snoo;
extern crate structopt;
#[macro_use]
extern crate structopt_derive;

use structopt::StructOpt;

fn main() {
    let settings = Settings::from_args();
    eprintln!("settings = {:#?}", settings);
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
