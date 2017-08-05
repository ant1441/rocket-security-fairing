use std::string::ToString;

#[derive(Debug, Clone, Copy)]
pub enum ReferrerPolicy {
    NoReferrer,
    NoReferrerWhenDowngrade,
    Origin,
    OriginWhenCrossOrigin,
    SameOrigin,
    StrictOrigin,
    StrictOriginWhenCrossOrigin,
    UnsafeUrl,
}

impl ToString for ReferrerPolicy {
    fn to_string(&self) -> String {
        use ReferrerPolicy::*;
        match *self {
            NoReferrer => "no-referrer",
            NoReferrerWhenDowngrade => "no-referrer-when-downgrade",
            Origin => "origin",
            OriginWhenCrossOrigin => "origin-when-cross-origin",
            SameOrigin => "same-origin",
            StrictOrigin => "strict-origin",
            StrictOriginWhenCrossOrigin => "strict-origin-when-cross-origin",
            UnsafeUrl => "unsafe-url",
        }.to_string()
    }
}
