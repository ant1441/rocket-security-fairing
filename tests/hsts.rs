#![feature(plugin)]
#![plugin(rocket_codegen)]

extern crate rocket;
extern crate rocket_security;

mod common;

use rocket::http::Status;

use rocket_security::Security;

use common::create_client;

#[test]
fn test_no_hsts() {
    let security = Security::new();
    let client = create_client(security);

    let req = client.get("/");
    let response = req.dispatch();
    assert_eq!(response.status(), Status::Ok);
    let res_headers = response.headers();
    assert_eq!(res_headers.get_one("Strict-Transport-Security"),
               None,
               "Unexpected STS Header");
}

#[test]
fn test_hsts() {
    let security = Security::new().sts_seconds(256);
    let client = create_client(security);

    let req = client.get("/");
    let response = req.dispatch();
    assert_eq!(response.status(), Status::Ok);
    let res_headers = response.headers();
    assert_ne!(res_headers.len(), 0);
    let sts_header = res_headers
        .get_one("Strict-Transport-Security")
        .expect("no STS header");
    assert_eq!(sts_header, "max-age=256");
    assert!(!sts_header.contains("includeSubDomains"),
            "Unexpected STS subdomain: '{}'",
            sts_header);
    assert!(!sts_header.contains("preload"),
            "Unexpected STS preload: '{}'",
            sts_header);
}


#[test]
fn test_hsts_subdomain() {
    let security = Security::new().sts_seconds(256).sts_include_subdomains();
    let client = create_client(security);

    let req = client.get("/");
    let response = req.dispatch();
    assert_eq!(response.status(), Status::Ok);
    let res_headers = response.headers();
    assert_ne!(res_headers.len(), 0);
    let sts_header = res_headers
        .get_one("Strict-Transport-Security")
        .expect("no STS header");
    assert!(sts_header.contains("max-age=256"),
            "Invalid STS max-age: '{}'",
            sts_header);
    assert!(sts_header.contains("includeSubDomains"),
            "Invalid STS subdomain: '{}'",
            sts_header);
    assert!(!sts_header.contains("preload"),
            "Unexpected STS preload: '{}'",
            sts_header);
}

#[test]
fn test_hsts_preload() {
    let security = Security::new().sts_seconds(256).sts_preload();
    let client = create_client(security);

    let req = client.get("/");
    let response = req.dispatch();
    assert_eq!(response.status(), Status::Ok);
    let res_headers = response.headers();
    assert_ne!(res_headers.len(), 0);
    let sts_header = res_headers
        .get_one("Strict-Transport-Security")
        .expect("no STS header");
    assert!(sts_header.contains("max-age=256"),
            "Invalid STS max-age: '{}'",
            sts_header);
    assert!(!sts_header.contains("includeSubDomains"),
            "Unexpected STS subdomain: '{}'",
            sts_header);
    assert!(sts_header.contains("preload"),
            "Invalid STS preload: '{}'",
            sts_header);
}

#[test]
fn test_hsts_preload_subdomain() {
    let security = Security::new()
        .sts_seconds(256)
        .sts_preload()
        .sts_include_subdomains();
    let client = create_client(security);

    let req = client.get("/");
    let response = req.dispatch();
    assert_eq!(response.status(), Status::Ok);
    let res_headers = response.headers();
    assert_ne!(res_headers.len(), 0);
    let sts_header = res_headers
        .get_one("Strict-Transport-Security")
        .expect("no STS header");
    assert!(sts_header.contains("max-age=256"),
            "Invalid STS max-age: '{}'",
            sts_header);
    assert!(sts_header.contains("includeSubDomains"),
            "Invalid STS subdomain: '{}'",
            sts_header);
    assert!(sts_header.contains("preload"),
            "Invalid STS preload: '{}'",
            sts_header);
}
