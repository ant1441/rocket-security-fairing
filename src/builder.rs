use super::{Security, XFrameOptions, XSSProtection, ReferrerPolicy};
use std::collections::HashMap;

impl<'a> Security<'a> {
    pub fn allowed_hosts(mut self, allowed_hosts: &'a [&'a str]) -> Self {
        self.enabled = true;
        self.allowed_hosts = Some(allowed_hosts);
        self
    }

    pub fn host_proxy_headers(mut self, headers: &'a [&'a str]) -> Self {
        self.enabled = true;
        self.host_proxy_headers = Some(headers);
        self
    }

    pub fn ssl_redirect(self) -> Self {
        self.set_ssl_redirect(true)
    }
    pub fn set_ssl_redirect(mut self, redirect: bool) -> Self {
        self.enabled = true;
        self.ssl_redirect = redirect;
        self
    }

    pub fn ssl_temporary_redirect(self) -> Self {
        self.set_ssl_temporary_redirect(true)
    }
    pub fn set_ssl_temporary_redirect(mut self, redirect: bool) -> Self {
        self.enabled = true;
        self.ssl_temporary_redirect = redirect;
        self
    }

    pub fn ssl_host(mut self, host: &'a str) -> Self {
        self.enabled = true;
        self.ssl_host = Some(host);
        self
    }

    pub fn ssl_proxy_headers(mut self, headers: HashMap<&'a str, &'a str>) -> Self {
        self.enabled = true;
        self.ssl_proxy_headers = Some(headers);
        self
    }

    pub fn add_ssl_proxy_header(mut self, name: &'a str, value: &'a str) -> Self {
        // TODO self.ssl_proxy_headers.map(|ref mut map| map.insert(name, value))
        if let Some(ref mut map) = self.ssl_proxy_headers {
            map.insert(name, value);
        } else {
            let mut map = HashMap::new();
            map.insert(name, value);
            self.ssl_proxy_headers = Some(map);
        }

        self
    }

    pub fn sts_seconds(self, seconds: i32) -> Self {
        self.set_sts_seconds(seconds)
    }
    pub fn set_sts_seconds(mut self, seconds: i32) -> Self {
        self.enabled = true;
        self.sts_seconds = seconds;
        self
    }

    pub fn sts_include_subdomains(self) -> Self {
        self.set_sts_include_subdomains(true)
    }
    pub fn set_sts_include_subdomains(mut self, include: bool) -> Self {
        self.enabled = true;
        self.sts_include_subdomains = include;
        self
    }

    pub fn sts_preload(self) -> Self {
        self.set_sts_preload(true)
    }
    pub fn set_sts_preload(mut self, preload: bool) -> Self {
        self.enabled = true;
        self.sts_preload = preload;
        self
    }

    pub fn force_sts_header(self) -> Self {
        self.set_force_sts_header(true)
    }
    pub fn set_force_sts_header(mut self, force: bool) -> Self {
        self.enabled = true;
        self.force_sts_header = force;
        self
    }

    pub fn frame_deny(mut self) -> Self {
        self.enabled = true;
        self.frame_deny = true;
        self
    }

    pub fn frame_options(mut self, option: &'a XFrameOptions<'a>) -> Self {
        self.enabled = true;
        self.frame_options = Some(option);
        self
    }

    pub fn no_sniff(mut self) -> Self {
        self.enabled = true;
        self.content_type_nosniff = true;
        self
    }

    pub fn xss_block(mut self) -> Self {
        self.enabled = true;
        self.browser_xss_filter = true;
        self
    }

    pub fn xss_filter(mut self, filter: &'a XSSProtection) -> Self {
        self.enabled = true;
        self.custom_browser_xss_value = Some(filter);
        self
    }

    pub fn set_raw_content_security_policy(mut self, policy: &'a str) -> Self {
        self.enabled = true;
        self.raw_content_security_policy = Some(policy);
        self
    }

    pub fn set_public_key_pin(mut self, public_key_pin: &'a str) -> Self {
        self.enabled = true;
        self.public_key = Some(public_key_pin);
        self
    }

    pub fn referrer_policy(mut self, policy: ReferrerPolicy) -> Self {
        self.enabled = true;
        self.referrer_policy = Some(policy);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::{Security, XFrameOptions, XSSProtection, ReferrerPolicy};

    #[test]
    fn test_builder() {
        let _: Security = Security::new().ssl_redirect();
    }

    #[test]
    fn test_all_builders() {
        static ALLOWED_HOSTS: &[&str] = &["rocalhost:8000", "localhost:8000"];
        static HOST_PROXY_HEADERS: &[&str] = &["X-Forwarded-Host"];
        static SSL_HOST: &str = "example.com";
        static FRAME_OPTIONS: XFrameOptions = XFrameOptions::Deny;
        static XSS_OPTION: XSSProtection = XSSProtection::Enabled;
        static PUBLIC_KEY_PIN: &str = r#"pin-sha256="cUPcTAZWKaASuYWhhneDttWpY3oBAkE3h2+soZS7sWs="; pin-sha256="M8HztCzM3elUxkcjR2S5P4hhyBNf6lHkmjAHKhpGPWE="; max-age=5184000; includeSubDomains; report-uri="https://www.example.org/hpkp-report"#;
        let referrer_policy = ReferrerPolicy::StrictOriginWhenCrossOrigin;

        let _: Security = Security::new()
            .allowed_hosts(ALLOWED_HOSTS)
            .host_proxy_headers(HOST_PROXY_HEADERS)
            .ssl_redirect()
            .ssl_temporary_redirect()
            .ssl_host(SSL_HOST)
            .add_ssl_proxy_header("X-Forwarded-Proto", "https")
            .sts_seconds(128)
            .sts_include_subdomains()
            .sts_preload()
            .force_sts_header()
            .frame_deny()
            .frame_options(&FRAME_OPTIONS)
            .no_sniff()
            .xss_filter(&XSS_OPTION)
            .set_raw_content_security_policy("default-src 'self'")
            .set_public_key_pin(&PUBLIC_KEY_PIN)
            .referrer_policy(referrer_policy);
    }

    #[test]
    fn test_ssl_proxy_header_builder_multiple() {
        let _: Security = Security::new()
            .add_ssl_proxy_header("X-Forwarded-Proto", "https")
            .add_ssl_proxy_header("X-Forwarded-TLS", "true");
    }
}
