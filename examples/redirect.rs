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
        .ssl_redirect()
        .ssl_temporary_redirect()
        .ssl_host("127.0.0.1:8000");
    rocket::ignite()
        .attach(security)
        .mount("/", routes![index])
        .launch();
}
