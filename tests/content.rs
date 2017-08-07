#![feature(plugin)]
#![plugin(rocket_codegen)]

extern crate rocket;
extern crate rocket_security;

mod common;

use rocket::http::Status;

use rocket_security::{Security, XSSProtection};

use common::create_client;

#[test]
fn test_content_type_nosniff() {
    let security = Security::new().no_sniff();
    let client = create_client(security);

    let req = client.get("/");
    let response = req.dispatch();
    assert_eq!(response.status(), Status::Ok);
    let res_headers = response.headers();
    assert_ne!(res_headers.len(), 0);
    let content_type_options = res_headers
        .get_one("X-Content-Type-Options")
        .expect("no X-Content-Type-Options header");
    assert_eq!(content_type_options, "nosniff");
}

#[test]
fn test_xss_protection_block() {
    let security = Security::new().xss_block();
    let client = create_client(security);

    let req = client.get("/");
    let response = req.dispatch();
    assert_eq!(response.status(), Status::Ok);
    let res_headers = response.headers();
    assert_ne!(res_headers.len(), 0);
    let xss_protection = res_headers
        .get_one("X-XSS-Protection")
        .expect("no X-XSS-Protection header");
    assert_eq!(xss_protection, "1; mode=block");
}

#[test]
fn test_xss_protection_custom_disabled() {
    static XSS_OPTION: XSSProtection = XSSProtection::Disabled;

    let security = Security::new().xss_filter(&XSS_OPTION);
    let client = create_client(security);

    let req = client.get("/");
    let response = req.dispatch();
    assert_eq!(response.status(), Status::Ok);
    let res_headers = response.headers();
    assert_ne!(res_headers.len(), 0);
    let xss_protection = res_headers
        .get_one("X-XSS-Protection")
        .expect("no X-XSS-Protection header");
    assert_eq!(xss_protection, "0");
}

#[test]
fn test_xss_protection_custom_enabled() {
    static XSS_OPTION: XSSProtection = XSSProtection::Enabled;

    let security = Security::new().xss_filter(&XSS_OPTION);
    let client = create_client(security);

    let req = client.get("/");
    let response = req.dispatch();
    assert_eq!(response.status(), Status::Ok);
    let res_headers = response.headers();
    assert_ne!(res_headers.len(), 0);
    let xss_protection = res_headers
        .get_one("X-XSS-Protection")
        .expect("no X-XSS-Protection header");
    assert_eq!(xss_protection, "1");
}

#[test]
fn test_xss_protection_custom_block() {
    static XSS_OPTION: XSSProtection = XSSProtection::Block;

    let security = Security::new().xss_filter(&XSS_OPTION);
    let client = create_client(security);

    let req = client.get("/");
    let response = req.dispatch();
    assert_eq!(response.status(), Status::Ok);
    let res_headers = response.headers();
    assert_ne!(res_headers.len(), 0);
    let xss_protection = res_headers
        .get_one("X-XSS-Protection")
        .expect("no X-XSS-Protection header");
    assert_eq!(xss_protection, "1; mode=block");
}

#[test]
fn test_xss_protection_custom_report() {
    static XSS_OPTION: XSSProtection = XSSProtection::Report("https://example.com/xss_report");

    let security = Security::new().xss_filter(&XSS_OPTION);
    let client = create_client(security);

    let req = client.get("/");
    let response = req.dispatch();
    assert_eq!(response.status(), Status::Ok);
    let res_headers = response.headers();
    assert_ne!(res_headers.len(), 0);
    let xss_protection = res_headers
        .get_one("X-XSS-Protection")
        .expect("no X-XSS-Protection header");
    assert_eq!(xss_protection, "1; report=https://example.com/xss_report");
}

#[test]
fn test_csp() {
    static CONTENT_SECURITY_POLICY: &str = "default-src 'self' *.trusted.com";

    let security = Security::new().set_raw_content_security_policy(&CONTENT_SECURITY_POLICY);
    let client = create_client(security);

    let req = client.get("/");
    let response = req.dispatch();
    assert_eq!(response.status(), Status::Ok);
    let res_headers = response.headers();
    assert_ne!(res_headers.len(), 0);
    let csp = res_headers
        .get_one("Content-Security-Policy")
        .expect("no Content-Security-Policy header");
    assert_eq!(csp, CONTENT_SECURITY_POLICY);
}
