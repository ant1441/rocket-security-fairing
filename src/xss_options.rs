#[derive(Debug, Clone)]
pub enum XSSProtection<'a> {
    Disabled,
    Enabled,
    Block,
    Report(&'a str),
}
