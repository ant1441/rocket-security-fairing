use super::{Security, XFrameOptions, XSSProtection, ReferrerPolicy};
use std::collections::HashMap;

impl<'a> Security<'a> {
    /// Manually specify that this server is using SSL.
    ///
    /// # Example
    ///
    /// ```rust
    /// let security = rocket_security::Security::new().force_ssl();
    /// ```
    pub fn force_ssl(mut self) -> Self {
        self.enabled = true;
        self.force_ssl = true;
        self
    }

    /// Specify a list of hosts which are allowed to be served from this servers.
    ///
    /// As fairings must have a `static` lifetime, so must the `allowed_hosts`.
    ///
    /// # Example
    ///
    /// ```rust
    /// static ALLOWED_HOSTS: &[&str] = &["www.example.com"];
    /// let security = rocket_security::Security::new()
    ///     .allowed_hosts(&ALLOWED_HOSTS);
    /// ```
    pub fn allowed_hosts(mut self, allowed_hosts: &'a [&'a str]) -> Self {
        self.enabled = true;
        self.allowed_hosts = Some(allowed_hosts);
        self
    }

    /// Specify which headers include the proxied hostname, if any.
    ///
    /// For example, if you use NGINX as a reverse proxy, you can specify this header:
    ///
    /// ```nginx
    /// proxy_set_header X-Forwarded-Host $host:$server_port;
    /// ```
    ///
    /// # Example
    ///
    /// ```rust
    /// static HOST_PROXY_HEADERS: &[&str] = &["X-Forwarded-Host"];
    /// let security = rocket_security::Security::new()
    ///     .host_proxy_headers(&HOST_PROXY_HEADERS);
    /// ```
    pub fn host_proxy_headers(mut self, headers: &'a [&'a str]) -> Self {
        self.enabled = true;
        self.host_proxy_headers = Some(headers);
        self
    }

    /// Always redirect any non TLS requests to HTTPS.
    ///
    /// # Example
    ///
    /// ```rust
    /// let security = rocket_security::Security::new().ssl_redirect();
    /// ```
    pub fn ssl_redirect(self) -> Self {
        self.set_ssl_redirect(true)
    }
    /// Manually set the ssl redirect setting.
    ///
    /// # Example
    ///
    /// ```rust
    /// let security = rocket_security::Security::new().set_ssl_redirect(false);
    /// ```
    pub fn set_ssl_redirect(mut self, redirect: bool) -> Self {
        self.enabled = true;
        self.ssl_redirect = redirect;
        self
    }

    /// If set, then a 302 redirect will be used to redirect to HTTPS.
    ///
    /// # Example
    ///
    /// ```rust
    /// let security = rocket_security::Security::new().ssl_temporary_redirect();
    /// ```
    pub fn ssl_temporary_redirect(self) -> Self {
        self.set_ssl_temporary_redirect(true)
    }
    /// Manually set the temporary redirect setting.
    ///
    /// # Example
    ///
    /// ```rust
    /// let security = rocket_security::Security::new().set_ssl_temporary_redirect(false);
    /// ```
    pub fn set_ssl_temporary_redirect(mut self, redirect: bool) -> Self {
        self.enabled = true;
        self.ssl_temporary_redirect = redirect;
        self
    }

    /// Set the host which is redirected to when redirecting to HTTPS.
    ///
    /// # Example
    ///
    /// ```rust
    /// let security = rocket_security::Security::new().ssl_host("secure.example.com");
    /// ```
    pub fn ssl_host(mut self, host: &'a str) -> Self {
        self.enabled = true;
        self.ssl_host = Some(host);
        self
    }

    /// A mapping of headers and associated values which indicate a valid HTTPS request.
    ///
    /// For example, with NGINX you can specify:
    ///
    /// ```nginx
    /// proxy_set_header X-Forwarded-Proto $scheme;
    /// ```
    ///
    /// # Example
    ///
    /// ```rust
    /// use std::collections::HashMap;
    /// let mut proxy_headers = HashMap::new();
    /// proxy_headers.insert("X-Forwarded-Proto", "https");
    ///
    /// let security = rocket_security::Security::new().ssl_proxy_headers(proxy_headers);
    /// ```
    pub fn ssl_proxy_headers(mut self, headers: HashMap<&'a str, &'a str>) -> Self {
        self.enabled = true;
        self.ssl_proxy_headers = Some(headers);
        self
    }

    /// Add headers and associated values which indicate a valid HTTPS request.
    ///
    /// For example, with NGINX you can specify:
    ///
    /// ```nginx
    /// proxy_set_header X-Forwarded-Proto $scheme;
    /// ```
    ///
    /// # Example
    ///
    /// ```rust
    /// let security = rocket_security::Security::new().add_ssl_proxy_header("X-Forwarded-Proto", "https");
    /// ```
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

    /// Enable [HTTP Strict Transport
    /// Security](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security), with a max-age of `seconds`.
    ///
    /// # Example
    ///
    /// ```rust
    /// let security = rocket_security::Security::new().sts_seconds(31536000);
    /// ```
    pub fn sts_seconds(mut self, seconds: i32) -> Self {
        self.enabled = true;
        self.sts_seconds = seconds;
        self
    }

    /// Apply [HTTP Strict Transport
    /// Security](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security) to all subdomains.
    ///
    /// Requires [`sts_seconds`](struct.Security.html#method.sts_seconds) to have any effect.
    ///
    /// # Example
    ///
    /// ```rust
    /// let security = rocket_security::Security::new()
    ///     .sts_seconds(31536000)
    ///     .sts_include_subdomains();
    /// ```
    pub fn sts_include_subdomains(self) -> Self {
        self.set_sts_include_subdomains(true)
    }
    /// Manually set the HSTS subdomain setting.
    ///
    /// Requires [`sts_seconds`](struct.Security.html#method.sts_seconds) to have any effect.
    ///
    /// # Example
    ///
    /// ```rust
    /// let security = rocket_security::Security::new()
    ///     .sts_seconds(31536000)
    ///     .set_sts_include_subdomains(false);
    /// ```
    pub fn set_sts_include_subdomains(mut self, include: bool) -> Self {
        self.enabled = true;
        self.sts_include_subdomains = include;
        self
    }

    /// Specify that you with the domain to be included in the [HTTP Strict Transport
    /// Security](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security)
    /// preload list.
    ///
    /// See [Preloading Strict Transport
    /// Security](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security#Preloading_Strict_Transport_Security)
    /// for more details.
    ///
    /// Requires [`sts_seconds`](struct.Security.html#method.sts_seconds) and
    /// [`sts_include_subdomains`](struct.Security.html#method.sts_include_subdomains) to have
    /// meaning.
    ///
    /// # Example
    ///
    /// ```rust
    /// let security = rocket_security::Security::new()
    ///     .sts_seconds(31536000)
    ///     .sts_include_subdomains()
    ///     .sts_preload();
    /// ```
    pub fn sts_preload(self) -> Self {
        self.set_sts_preload(true)
    }
    /// Manually set the HSTS preload setting.
    ///
    /// Requires [`sts_seconds`](struct.Security.html#method.sts_seconds) and
    /// [`sts_include_subdomains`](struct.Security.html#method.sts_include_subdomains) to have
    /// meaning.
    ///
    /// # Example
    ///
    /// ```rust
    /// let security = rocket_security::Security::new()
    ///     .sts_seconds(31536000)
    ///     .sts_include_subdomains()
    ///     .set_sts_preload(false);
    /// ```
    pub fn set_sts_preload(mut self, preload: bool) -> Self {
        self.enabled = true;
        self.sts_preload = preload;
        self
    }

    /// Always send the [HTTP Strict Transport Security](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security)
    /// header, even if this is not a SSL connection.
    ///
    /// Requires at least [`sts_seconds`](struct.Security.html#method.sts_seconds) to have meaning.
    ///
    /// # Note
    ///
    /// Browsers will ignore an HSTS header sent over a plaintext connection.
    ///
    /// # Example
    ///
    /// ```rust
    /// let security = rocket_security::Security::new()
    ///     .sts_seconds(31536000)
    ///     .force_sts_header();
    /// ```
    pub fn force_sts_header(self) -> Self {
        self.set_force_sts_header(true)
    }
    /// Manually set the force HSTS setting.
    ///
    /// # Example
    ///
    /// ```rust
    /// let security = rocket_security::Security::new()
    ///     .sts_seconds(31536000)
    ///     .set_force_sts_header(false);
    /// ```
    pub fn set_force_sts_header(mut self, force: bool) -> Self {
        self.enabled = true;
        self.force_sts_header = force;
        self
    }

    /// Set the
    /// [X-Frame-Options](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options)
    /// header to 'DENY' to block any use of your page in a frame, iframe, or object.
    ///
    /// # Example
    ///
    /// ```rust
    /// let security = rocket_security::Security::new()
    ///     .frame_deny();
    /// ```
    pub fn frame_deny(mut self) -> Self {
        self.enabled = true;
        self.frame_deny = true;
        self
    }

    /// Set the
    /// [X-Frame-Options](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options)
    /// header to the given value to control the use of your page in a frame, iframe or object.
    ///
    /// See [`XFrameOptions`](enum.XFrameOptions.html).
    ///
    /// # Example
    ///
    /// ```rust
    /// let security = rocket_security::Security::new().frame_deny();
    /// ```
    pub fn frame_options(mut self, option: &'a XFrameOptions<'a>) -> Self {
        self.enabled = true;
        self.frame_options = Some(option);
        self
    }

    /// Set the
    /// [X-Content-Type-Options](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options)
    /// header to 'nosniff' to indicate that browsers should follow the MIME types specified in the
    /// Content-Type header.
    ///
    /// # Example
    ///
    /// ```rust
    /// let security = rocket_security::Security::new().no_sniff();
    /// ```
    pub fn no_sniff(mut self) -> Self {
        self.enabled = true;
        self.content_type_nosniff = true;
        self
    }

    /// Set the
    /// [X-XSS-Protection](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection)
    /// header to "1; mode=block" which stops supported browsers from loading pages when they
    /// detect reflected cross-site scripting (XSS) attacks.
    ///
    /// # Example
    ///
    /// ```rust
    /// let security = rocket_security::Security::new().xss_block();
    /// ```
    pub fn xss_block(mut self) -> Self {
        self.enabled = true;
        self.browser_xss_filter = true;
        self
    }

    /// Set the
    /// [X-XSS-Protection](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection)
    /// header to the given value.
    ///
    /// See [`XSSProtection`](enum.XSSProtection.html).
    ///
    /// # Example
    ///
    /// ```rust
    /// use rocket_security::XSSProtection;
    /// let xss_protection = XSSProtection::Report("https://example.com/xss_report");
    /// let security = rocket_security::Security::new()
    ///     .xss_filter(&xss_protection);
    /// ```
    pub fn xss_filter(mut self, filter: &'a XSSProtection) -> Self {
        self.enabled = true;
        self.custom_browser_xss_value = Some(filter);
        self
    }

    /// Set the
    /// [Content-Security-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy)
    /// header to a raw value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rocket_security::XSSProtection;
    /// let security = rocket_security::Security::new()
    ///     .set_raw_content_security_policy("default-src 'self' http://example.com; connect-src 'none';");
    /// ```
    pub fn set_raw_content_security_policy(mut self, policy: &'a str) -> Self {
        self.enabled = true;
        self.raw_content_security_policy = Some(policy);
        self
    }

    /// Set the
    /// [Public-Key-Pins](https://developer.mozilla.org/en-US/docs/Web/HTTP/Public_Key_Pinning)
    /// header to specify the given public key(s) with this server.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rocket_security::XSSProtection;
    /// let security = rocket_security::Security::new()
    ///     .set_public_key_pin(r#"pin-sha256="cUPcTAZWKaASuYWhhneDttWpY3oBAkE3h2+soZS7sWs="; pin-sha256="M8HztCzM3elUxkcjR2S5P4hhyBNf6lHkmjAHKhpGPWE="; max-age=5184000; includeSubDomains; report-uri="https://www.example.org/hpkp-report"#);
    /// ```
    pub fn set_public_key_pin(mut self, public_key_pin: &'a str) -> Self {
        self.enabled = true;
        self.public_key = Some(public_key_pin);
        self
    }

    /// Set the
    /// [Referrer-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy)
    /// header to the given [`ReferrerPolicy`](enum.ReferrerPolicy.html).
    ///
    /// # Example
    ///
    /// ```rust
    /// use rocket_security::ReferrerPolicy;
    /// let security = rocket_security::Security::new()
    ///     .referrer_policy(ReferrerPolicy::OriginWhenCrossOrigin);
    /// ```
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
