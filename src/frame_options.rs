use std::string::ToString;

#[derive(Debug, Clone)]
pub enum XFrameOptions<'a> {
    Deny,
    SameOrigin,
    AllowFrom(&'a str),
}

impl<'a> ToString for XFrameOptions<'a> {
    fn to_string(&self) -> String {
        use XFrameOptions::*;
        match *self {
            Deny => "DENY".to_string(),
            SameOrigin => "SAMEORIGIN".to_string(),
            AllowFrom(ref host) => format!("ALLOW-FROM {}", host),
        }
    }
}
