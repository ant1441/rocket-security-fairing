# rocket-security-fairing

A fairing for the Rust web framework [Rocket](https://rocket.rs), inspired by the golang library [Secure](https://github.com/unrolled/secure).
rocket-security-fairing allows you to enable various options to increase the security of your application.

```rust
#![feature(plugin)]
#![plugin(rocket_codegen)]

extern crate rocket;
extern crate rocket_security;

#[get("/<name>/<age>")]
fn hello(name: String, age: u8) -> String {
    format!("Hello, {} year old named {}!", age, name)
}

fn main() {
    let security = rocket_security::Security::new()
        .ssl_redirect()
        .sts_seconds(31536000)
        .sts_include_subdomains()
        .frame_deny()
        .no_sniff()
        .xss_block()
        .set_raw_content_security_policy("default-src 'self'")
        .referrer_policy(rocket_security::ReferrerPolicy::Origin);
    rocket::ignite()
        .attach(security)
        .mount("/hello", routes![hello])
        .launch();
}
```
