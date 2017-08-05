#![feature(plugin)]
#![plugin(rocket_codegen)]

extern crate rocket;
extern crate rocket_security;

mod common;

use rocket::http::Status;

use rocket_security::{Security, ReferrerPolicy};

use common::create_client;

#[test]
fn test_public_key_pin() {
    let security = Security::new().referrer_policy(ReferrerPolicy::UnsafeUrl);
    let client = create_client(security);

    let req = client.get("/");
    let response = req.dispatch();
    assert_eq!(response.status(), Status::Ok);
    let res_headers = response.headers();
    assert_ne!(res_headers.len(), 0);
    let referrer_policy = res_headers
        .get_one("Referrer-Policy")
        .expect("no Referrer-Policy header");
    assert_eq!(referrer_policy, "unsafe-url");
}
