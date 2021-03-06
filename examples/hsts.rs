#![feature(plugin)]
#![plugin(rocket_codegen)]

extern crate rocket;
extern crate rocket_security;

use rocket_security::Security;

#[get("/")]
fn index() -> &'static str {
    "Hello, world!"
}

fn main() {
    let security = Security::new()
        .sts_seconds(256)
        .sts_include_subdomains()
        .sts_preload();
    rocket::ignite()
        .attach(security)
        .mount("/", routes![index])
        .launch();
}
