#![feature(plugin)]
#![plugin(rocket_codegen)]

extern crate rocket;
extern crate rocket_security;

mod common;

use rocket::http::{Header, Status};
use rocket::http::hyper::header::Host;

use rocket_security::Security;

use common::create_client;

#[test]
fn test_allowed_hosts() {
    static ALLOWED_HOSTS: &[&str] = &["example.com", "localhost:8000"];

    let security = Security::new().allowed_hosts(&ALLOWED_HOSTS);
    let client = create_client(security);

    let req = client
        .get("/")
        .header(Host {
                    hostname: "localhost".to_owned(),
                    port: 8000.into(),
                });
    let response = req.dispatch();
    assert_eq!(response.status(), Status::Ok);
}

#[test]
fn test_not_allowed_hosts() {
    static ALLOWED_HOSTS: &[&str] = &["localhost:8000"];

    let security = Security::new().allowed_hosts(&ALLOWED_HOSTS);
    let client = create_client(security);

    let req = client
        .get("/")
        .header(Host {
                    hostname: "example.com".to_owned(),
                    port: None,
                });
    let mut response = req.dispatch();
    assert_eq!(response.status(), Status::BadRequest);
    assert!(response.body().is_none());
}

#[test]
fn test_not_allowed_hosts_no_host() {
    static ALLOWED_HOSTS: &[&str] = &["localhost:8000"];

    let security = Security::new().allowed_hosts(&ALLOWED_HOSTS);
    let client = create_client(security);

    let req = client.get("/");
    let mut response = req.dispatch();
    assert_eq!(response.status(), Status::BadRequest);
    assert!(response.body().is_none());
}

#[test]
fn test_allowed_hosts_with_host_proxy_header_no_proxy_header() {
    static ALLOWED_HOSTS: &[&str] = &["example.com"];
    static HOST_PROXY_HEADERS: &[&str] = &["X-Forwarded-Host", "X-Example-Host"];

    let security = Security::new()
        .allowed_hosts(&ALLOWED_HOSTS)
        .host_proxy_headers(HOST_PROXY_HEADERS);
    let client = create_client(security);

    let req = client
        .get("/")
        .header(Host {
                    hostname: "example.com".to_owned(),
                    port: None,
                });
    let response = req.dispatch();
    assert_eq!(response.status(), Status::Ok);
}

#[test]
fn test_not_allowed_hosts_with_host_proxy_header_no_proxy_header() {
    static ALLOWED_HOSTS: &[&str] = &["foo.example.com"];
    static HOST_PROXY_HEADERS: &[&str] = &["X-Forwarded-Host", "X-Example-Host"];

    let security = Security::new()
        .allowed_hosts(&ALLOWED_HOSTS)
        .host_proxy_headers(HOST_PROXY_HEADERS);
    let client = create_client(security);

    let req = client
        .get("/")
        .header(Host {
                    hostname: "example.com".to_owned(),
                    port: None,
                });
    let mut response = req.dispatch();
    assert_eq!(response.status(), Status::BadRequest);
    assert!(response.body().is_none());
}

#[test]
fn test_allowed_hosts_with_host_proxy_header() {
    static ALLOWED_HOSTS: &[&str] = &["foo.example.com"];
    static HOST_PROXY_HEADERS: &[&str] = &["X-Forwarded-Host", "X-Example-Host"];

    let security = Security::new()
        .allowed_hosts(&ALLOWED_HOSTS)
        .host_proxy_headers(HOST_PROXY_HEADERS);
    let client = create_client(security);

    let req = client
        .get("/")
        .header(Host {
                    hostname: "example.com".to_owned(),
                    port: None,
                })
        .header(Header::new("X-Forwarded-Host", "foo.example.com"));
    let mut response = req.dispatch();
    assert_eq!(response.status(), Status::Ok);
    assert!(response.body().is_some());
}

#[test]
fn test_allowed_hosts_with_host_proxy_header_allowed_proxy() {
    static ALLOWED_HOSTS: &[&str] = &["example.com"];
    static HOST_PROXY_HEADERS: &[&str] = &["X-Forwarded-Host", "X-Example-Host"];

    let security = Security::new()
        .allowed_hosts(&ALLOWED_HOSTS)
        .host_proxy_headers(HOST_PROXY_HEADERS);
    let client = create_client(security);

    let req = client
        .get("/")
        .header(Host {
                    hostname: "foo.example.com".to_owned(),
                    port: None,
                })
        .header(Header::new("X-Forwarded-Host", "example.com"));
    let mut response = req.dispatch();
    assert_eq!(response.status(), Status::Ok);
    assert!(response.body().is_some());
}

#[test]
fn test_not_allowed_hosts_with_host_proxy_header() {
    static ALLOWED_HOSTS: &[&str] = &["example.com"];
    static HOST_PROXY_HEADERS: &[&str] = &["X-Forwarded-Host", "X-Example-Host"];

    let security = Security::new()
        .allowed_hosts(&ALLOWED_HOSTS)
        .host_proxy_headers(HOST_PROXY_HEADERS);
    let client = create_client(security);

    let req = client
        .get("/")
        .header(Host {
                    hostname: "foo.example.com".to_owned(),
                    port: None,
                })
        .header(Header::new("X-Forwarded-Host", "bar.example.com"));
    let mut response = req.dispatch();
    assert_eq!(response.status(), Status::BadRequest);
    assert!(response.body().is_none());
}
