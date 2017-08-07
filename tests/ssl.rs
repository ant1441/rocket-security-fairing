#![feature(plugin)]
#![plugin(rocket_codegen)]
// TODO: Need to figure out how to check rocket for SSL connection
// and/or have a `force_ssl` option?

extern crate rocket;
extern crate rocket_security;

mod common;

use rocket::http::{Header, Status};
use rocket::http::hyper::header::Host;

use rocket_security::Security;

use common::create_client;

// #[test]
#[allow(dead_code)]
fn test_ssl_redirect_no_ssl() {
    unimplemented!()
}

// #[test]
#[allow(dead_code)]
fn test_ssl_redirect_ssl() {
    unimplemented!()
}

#[test]
fn test_ssl_redirect_ssl_proxy_header() {
    let security = Security::new()
        .ssl_redirect()
        .add_ssl_proxy_header("X-Forwarded-Proto", "https");
    let client = create_client(security);

    let req = client
        .get("/")
        .header(Header::new("X-Forwarded-Proto", "https"))
        .header(Host {
                    hostname: "localhost".to_owned(),
                    port: 8000.into(),
                });
    let response = req.dispatch();
    assert_eq!(response.status(), Status::Ok);
}

#[test]
fn test_ssl_redirect_ssl_proxy_header_redirect() {
    let security = Security::new()
        .ssl_redirect()
        .add_ssl_proxy_header("X-Forwarded-Proto", "https");
    let client = create_client(security);

    let req = client
        .get("/")
        .header(Header::new("X-Forwarded-Proto", "http"))
        .header(Host {
                    hostname: "localhost".to_owned(),
                    port: 8000.into(),
                });
    let response = req.dispatch();
    assert_eq!(response.status(), Status::PermanentRedirect);
}

#[test]
fn test_ssl_redirect_ssl_proxy_headers() {
    use std::collections::HashMap;
    let mut proxy_headers = HashMap::new();
    proxy_headers.insert("X-Forwarded-Proto", "https");

    let security = Security::new()
        .ssl_redirect()
        .ssl_proxy_headers(proxy_headers);
    let client = create_client(security);

    let req = client
        .get("/")
        .header(Header::new("X-Forwarded-Proto", "https"))
        .header(Host {
                    hostname: "localhost".to_owned(),
                    port: 8000.into(),
                });
    let response = req.dispatch();
    assert_eq!(response.status(), Status::Ok);
}

#[test]
fn test_ssl_redirect_ssl_proxy_headers_additional_headers() {
    use std::collections::HashMap;
    let mut proxy_headers = HashMap::new();
    proxy_headers.insert("X-Forwarded-Proto", "https");

    let security = Security::new()
        .ssl_redirect()
        .ssl_proxy_headers(proxy_headers)
        .add_ssl_proxy_header("X-Forwarded-SSL", "TLS");
    let client = create_client(security);

    let req = client
        .get("/")
        .header(Header::new("X-Forwarded-SSL", "TLS"))
        .header(Host {
                    hostname: "localhost".to_owned(),
                    port: 8000.into(),
                });
    let response = req.dispatch();
    assert_eq!(response.status(), Status::Ok);
}
