extern crate rocket;

use rocket::{Request, Response};
use rocket::fairing::{Fairing, Info, Kind};
use rocket::http::Status;
use rocket::http::hyper::header::Location;
use std::collections::HashMap;

mod builder;
mod frame_options;
mod xss_options;
mod referrer_policy;

pub use frame_options::XFrameOptions;
pub use xss_options::XSSProtection;
pub use referrer_policy::ReferrerPolicy;

// TODO: Use hyper's header, once is supports 'preload'
// use rocket::http::hyper::header::StrictTransportSecurity;
static STRICT_TRANSPORT_SECURITY: &str = "Strict-Transport-Security";

pub struct Security<'a> {
    enabled: bool, // [TODO]: Remove `enabled`
    /// allowed_hosts is a list of fully qualified domain names that are allowed. Default is empty list, which allows any and all host names.
    allowed_hosts: Option<&'a [&'a str]>,
    /// host_proxy_headers is a set of header keys that may hold a proxied hostname value for the request.
    host_proxy_headers: Option<&'a [&'a str]>,
    /// If ssl_redirect is set to true, then only allow HTTPS requests. Default is false.
    ssl_redirect: bool,
    /// If ssl_temporary_redirect is true, the a 302 will be used while redirecting. Default is false (301).
    ssl_temporary_redirect: bool,
    /// ssl_host is the host name that is used to redirect HTTP requests to HTTPS. Default is "", which indicates to use the same host.
    ssl_host: Option<&'a str>,
    // ssl_proxy_headers is set of header keys with associated values that would indicate a valid HTTPS request. Useful when using Nginx. Default is blank map.
    ssl_proxy_headers: Option<HashMap<&'a str, &'a str>>, // Option<&'a [&'a str]>, TODO: Type?
    /// sts_seconds is the max-age of the Strict-Transport-Security header. Default is 0, which would NOT include the header.
    sts_seconds: i32,
    /// If sts_include_subdomains is set to true, the `includeSubdomains` will be appended to the Strict-Transport-Security header. Default is false.
    sts_include_subdomains: bool,
    /// If sts_preload is set to true, the `preload` flag will be appended to the Strict-Transport-Security header. Default is false.
    sts_preload: bool,
    /// STS header is only included when the connection is HTTPS. If you want to force it to always be added, set to true. `IsDevelopment` still overrides this. Default is false.
    force_sts_header: bool,
    /// If frame_deny is set to true, adds the X-Frame-Options header with the value of `DENY`. Default is false.
    frame_deny: bool,
    /// frame_options allows the X-Frame-Options header value to be set with a custom value. This overrides the frame_deny option.
    frame_options: Option<&'a XFrameOptions<'a>>,
    /// If content_type_nosniff is true, adds the X-Content-Type-Options header with the value `nosniff`. Default is false.
    content_type_nosniff: bool,
    /// If browser_xss_filter is true, adds the X-XSS-Protection header with the value `1; mode=block`. Default is false.
    browser_xss_filter: bool,
    /// custom_browser_xss_value allows the X-XSS-Protection header value to be set with a custom value. This overrides the browser_xss_filter option.
    custom_browser_xss_value: Option<&'a XSSProtection<'a>>,
    /// content_security_policy allows the Content-Security-Policy header value to be set with a custom value.
    content_security_policy: Option<&'a str>, // [TODO]: Custom type?
    /// public_key sets HTTP Public Key Pinning to decrease the risk of MITM attacks with forged certificates.
    public_key: Option<&'a str>, // [TODO]: Custom type?
    /// referrer_policy enables the Referrer-Policy header with the value to be set with a custom value.
    referrer_policy: Option<ReferrerPolicy>,

}

impl<'a> Security<'a> {
    pub fn new() -> Self {
        Self {
            enabled: false,
            allowed_hosts: None,
            host_proxy_headers: None,
            ssl_redirect: false,
            ssl_temporary_redirect: false,
            ssl_host: None,
            ssl_proxy_headers: None,
            sts_seconds: 0,
            sts_include_subdomains: false,
            sts_preload: false,
            force_sts_header: false,
            frame_deny: false,
            frame_options: None,
            content_type_nosniff: false,
            browser_xss_filter: false,
            custom_browser_xss_value: None,
            content_security_policy: None,
            public_key: None,
            referrer_policy: None,
        }
    }
}

impl Fairing for Security<'static> {
    fn info(&self) -> Info {
        Info {
            name: "Security Fairing",
            kind: Kind::Response,
        }
    }

    fn on_response(&self, request: &Request, mut response: &mut Response) {
        if !self.enabled {
            return;
        }
        self.check_host(&request, &mut response);
        self.set_ssl(&request, &mut response);
        self.set_sts(&request, &mut response);
        self.set_frame_options(&request, &mut response);
        self.set_content_options(&request, &mut response);
        self.public_key_pin(&request, &mut response);
        self.set_referrer_policy(&request, &mut response);
    }
}

impl<'a> Security<'a> {
    fn is_ssl(&self, request: &Request) -> bool {
        if let Some(ref ssl_proxy_headers) = self.ssl_proxy_headers {
            let req_headers = request.headers();
            for (ssl_proxy_header, expected_value) in ssl_proxy_headers {
                for value in req_headers.get(ssl_proxy_header) {
                    if &value == expected_value {
                        // The value in the request equals the value we expect
                        return true;
                    }
                }
            }
        }
        self.rocket_is_ssl(request)
    }

    // TODO: Need to dig into rocket to figure this one out
    fn rocket_is_ssl(&self, _request: &Request) -> bool {
        true
    }

    /// Extract the given hostname from the request.
    /// Uses the host_proxy_headers if set and present.
    /// TODO: Should each host_proxy_header value be a comma seperated list?
    fn host<'r>(&self, request: &'r Request) -> Option<&'r str> {
        let headers = request.headers();
        if let Some(host_proxy_headers) = self.host_proxy_headers {
            for header in host_proxy_headers.iter().flat_map(|h| headers.get(h)) {
                return Some(header);
            }
        }
        headers.get_one("Host")
    }

    /// If a request has come in with a bad host, we want to construct a response telling the
    /// requestor this.
    /// TODO: Should this add a body? Should it strip out all the headers we don't specificially
    /// want?
    fn bad_host(&self, mut response: &mut Response) {
        response.set_status(Status::BadRequest);
        let _ = response.take_body();
    }

    /// Check if a host has been allowed.
    ///
    /// TODO: Should host_proxy_headers entirely mask the 'Host' header?
    /// eg. If I've set allowed_hosts to example.com, and we have Host: example.com and
    /// X-Forwarded-Host: foo.example.com, should that be allowed?
    fn check_host(&self, request: &Request, response: &mut Response) {
        if let Some(allowed_hosts) = self.allowed_hosts {
            // If we are filtering based on Hostname, get the host
            if let Some(host) = self.host(&request) {
                if !allowed_hosts.iter().any(|&allowed| allowed == host) {
                    return self.bad_host(response);
                }
            } else {
                // TODO: What to do if no host header? HTTP/1.0?
                return self.bad_host(response);
            }
        }
    }

    fn set_ssl(&self, request: &Request, response: &mut Response) {
        // If we are already SSL, we don't need to set this
        if self.is_ssl(&request) {
            return;
        }

        if self.ssl_redirect {
            let status = if self.ssl_temporary_redirect {
                Status::TemporaryRedirect
            } else {
                Status::PermanentRedirect
            };
            // Get the host to redirect to. ssl_host, if set, otherwise the request Host
            if let Some(host) = self.ssl_host
                   .or_else(|| request.headers().get_one("Host")) {
                response.set_header(Location(format!("https://{}{}", host, request.uri())));
                response.set_status(status);
                // Take the body out of the response
                let _ = response.take_body();
            } else {
                // TODO: What to do if no host header? HTTP/1.0?
                panic!("unable to find host header");
            }
        }
    }

    fn set_sts(&self, request: &Request, response: &mut Response) {
        // If we don't want to set STS, or the user already has then skip our logic
        if self.sts_seconds == 0 || response.headers().contains(STRICT_TRANSPORT_SECURITY) {
            return;
        }
        // If this request isn't SSL and the user isn't forcing it, don't set STS headers
        if !self.is_ssl(&request) && !self.force_sts_header {
            return;
        }

        let header_value = match (self.sts_include_subdomains, self.sts_preload) {
            (false, false) => format!("max-age={}", self.sts_seconds),
            (true, false) => format!("max-age={}; includeSubDomains", self.sts_seconds),
            (false, true) => format!("max-age={}; preload", self.sts_seconds),
            (true, true) => format!("max-age={}; includeSubDomains; preload", self.sts_seconds),
        };

        response.set_raw_header(STRICT_TRANSPORT_SECURITY, header_value);
    }

    fn set_frame_options(&self, _request: &Request, response: &mut Response) {
        if let Some(frame_options) = self.frame_options {
            match *frame_options {
                XFrameOptions::Deny => response.set_raw_header("X-Frame-Options", "DENY"),
                XFrameOptions::SameOrigin => {
                    response.set_raw_header("X-Frame-Options", "SAMEORIGIN")
                }
                XFrameOptions::AllowFrom(ref host) => {
                    response.set_raw_header("X-Frame-Options", format!("ALLOW-FROM {}", host))
                }
            };
        } else if self.frame_deny {
            response.set_raw_header("X-Frame-Options", "DENY");
        }
    }

    fn set_content_options(&self, _request: &Request, response: &mut Response) {
        if self.content_type_nosniff {
            response.set_raw_header("X-Content-Type-Options", "nosniff");
        }
        if let Some(xss_filter) = self.custom_browser_xss_value {
            match *xss_filter  {
                XSSProtection::Disabled => response.set_raw_header("X-XSS-Protection", "0"),
                XSSProtection::Enabled => response.set_raw_header("X-XSS-Protection", "1"),
                XSSProtection::Block => response.set_raw_header("X-XSS-Protection", "1; mode=block"),
                XSSProtection::Report(ref target) => response.set_raw_header("X-XSS-Protection", format!("1; report={}", target)),
            };
        } else if self.browser_xss_filter {
            response.set_raw_header("X-XSS-Protection", "1; mode=block");
        }
        if let Some(csp) = self.content_security_policy {
            response.set_raw_header("Content-Security-Policy", csp.to_owned());
        }
    }

    fn public_key_pin(&self, _request: &Request, response: &mut Response) {
        if let Some(key_pin) = self.public_key {
            response.set_raw_header("Public-Key-Pins", key_pin.to_owned());
        }
    }

    fn set_referrer_policy(&self, _request: &Request, response: &mut Response) {
        if let Some(policy) = self.referrer_policy {
            response.set_raw_header("Referrer-Policy", policy.to_string());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Security;

    #[test]
    fn test_new() {
        let _: Security = Security::new();
    }
}
