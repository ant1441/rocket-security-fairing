use rocket;
use rocket::local::Client;
use rocket_security::Security;

#[get("/")]
fn index() -> &'static str {
    "Hello, world!"
}

pub(crate) fn create_client(security: Security<'static>) -> Client {
    let rocket = rocket::ignite()
        .attach(security)
        .mount("/", routes![index]);
    Client::new(rocket).expect("valid rocket instance")
}
