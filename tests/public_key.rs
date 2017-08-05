#![feature(plugin)]
#![plugin(rocket_codegen)]

extern crate rocket;
extern crate rocket_security;

mod common;

use rocket::http::Status;

use rocket_security::Security;

use common::create_client;

#[test]
fn test_public_key_pin() {
    static PUBLIC_KEY_PIN: &str = r#"pin-sha256="cUPcTAZWKaASuYWhhneDttWpY3oBAkE3h2+soZS7sWs="; pin-sha256="M8HztCzM3elUxkcjR2S5P4hhyBNf6lHkmjAHKhpGPWE="; max-age=5184000; includeSubDomains; report-uri="https://www.example.org/hpkp-report"#;

    let security = Security::new().set_public_key_pin(PUBLIC_KEY_PIN);
    let client = create_client(security);

    let req = client.get("/");
    let response = req.dispatch();
    assert_eq!(response.status(), Status::Ok);
    let res_headers = response.headers();
    assert_ne!(res_headers.len(), 0);
    let public_key_pin = res_headers
        .get_one("Public-Key-Pins")
        .expect("no Public-Key-Pins header");
    assert_eq!(public_key_pin, PUBLIC_KEY_PIN);
}
