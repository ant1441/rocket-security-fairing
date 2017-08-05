#![feature(plugin)]
#![plugin(rocket_codegen)]

extern crate rocket;
extern crate rocket_security;

mod common;

use rocket::http::Status;

use rocket_security::{Security, XFrameOptions};

use common::create_client;

#[test]
fn test_frame_deny() {
    let security = Security::new().frame_deny();
    let client = create_client(security);

    let req = client.get("/");
    let response = req.dispatch();
    assert_eq!(response.status(), Status::Ok);
    let res_headers = response.headers();
    assert_ne!(res_headers.len(), 0);
    let frame_options_header = res_headers
        .get_one("X-Frame-Options")
        .expect("no X-Frame-Options header");
    assert_eq!(frame_options_header, "DENY");
}

#[test]
fn test_frame_options_deny() {
    static FRAME_OPTIONS: XFrameOptions = XFrameOptions::Deny;

    let security = Security::new().frame_options(&FRAME_OPTIONS);
    let client = create_client(security);

    let req = client.get("/");
    let response = req.dispatch();
    assert_eq!(response.status(), Status::Ok);
    let res_headers = response.headers();
    assert_ne!(res_headers.len(), 0);
    let frame_options_header = res_headers
        .get_one("X-Frame-Options")
        .expect("no X-Frame-Options header");
    assert_eq!(frame_options_header, "DENY");
}

#[test]
fn test_frame_options_sameorigin() {
    static FRAME_OPTIONS: XFrameOptions = XFrameOptions::SameOrigin;

    let security = Security::new().frame_options(&FRAME_OPTIONS);
    let client = create_client(security);

    let req = client.get("/");
    let response = req.dispatch();
    assert_eq!(response.status(), Status::Ok);
    let res_headers = response.headers();
    assert_ne!(res_headers.len(), 0);
    let frame_options_header = res_headers
        .get_one("X-Frame-Options")
        .expect("no X-Frame-Options header");
    assert_eq!(frame_options_header, "SAMEORIGIN");
}

#[test]
fn test_frame_options_allow_from() {
    static FRAME_OPTIONS: XFrameOptions = XFrameOptions::AllowFrom("https://example.com");

    let security = Security::new().frame_options(&FRAME_OPTIONS);
    let client = create_client(security);

    let req = client.get("/");
    let response = req.dispatch();
    assert_eq!(response.status(), Status::Ok);
    let res_headers = response.headers();
    assert_ne!(res_headers.len(), 0);
    let frame_options_header = res_headers
        .get_one("X-Frame-Options")
        .expect("no X-Frame-Options header");
    assert_eq!(frame_options_header, "ALLOW-FROM https://example.com");
}
