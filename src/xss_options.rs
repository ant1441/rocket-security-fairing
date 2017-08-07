use std::string::ToString;

#[derive(Debug, Clone)]
pub enum XSSProtection<'a> {
    Disabled,
    Enabled,
    Block,
    Report(&'a str),
}

impl<'a> ToString for XSSProtection<'a> {
    fn to_string(&self) -> String {
        use XSSProtection::*;
        match *self {
            Disabled => "0".to_string(),
            Enabled => "1".to_string(),
            Block => "1; mode=block".to_string(),
            Report(ref target) => format!("1; report={}", target),
        }
    }
}
