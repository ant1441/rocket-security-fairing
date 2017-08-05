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
    static ALLOWED_HOSTS: &[&str] = &["rocalhost:8000", "localhost:8000"];

    let security = Security::new().allowed_hosts(&ALLOWED_HOSTS);
    rocket::ignite()
        .attach(security)
        .mount("/", routes![index])
        .launch();
}
