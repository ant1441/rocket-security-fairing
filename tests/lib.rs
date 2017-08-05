#![feature(plugin)]
#![plugin(rocket_codegen)]

extern crate rocket;
extern crate rocket_security;

mod common;

use rocket::http::Status;

use rocket_security::Security;

use common::create_client;

#[test]
fn test_attaching() {
    let security = Security::new();
    let client = create_client(security);

    let req = client.get("/");
    let response = req.dispatch();
    assert_eq!(response.status(), Status::Ok);
}
