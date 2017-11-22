extern crate snoo;

use snoo::Snoo;

fn main() {
    let url = Snoo::authorization_url_builder()
        // client ID can be obtained from Reddit
        .client_id("xxx_client_id_xxx")
        // must be the URI registered with Reddit
        .redirect_uri("http://localhost:8000")
        // usually some randomly generated string
        .state("xxx_random_state_xxx")
        .build()
        .unwrap();

    println!(
        "Please visit the following URL to authorize this application: {}",
        url
    )
}
