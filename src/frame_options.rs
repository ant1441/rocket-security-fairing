#[derive(Debug, Clone)]
pub enum XFrameOptions<'a> {
    Deny,
    SameOrigin,
    AllowFrom(&'a str),
}
