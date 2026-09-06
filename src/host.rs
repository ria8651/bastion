//! Hostname handling, in one place.
//!
//! Five call sites had grown their own version of "reduce this to a bare
//! hostname" — the admin form's `proxy_host` validator, the cookie-domain
//! validator, the proxied request's `Host`, `ORIGIN`'s host, and the
//! upstream-loop check. They disagreed in exactly the ways that matter:
//! whether a port was stripped, whether a trailing root dot was, whether the
//! comparison was case-sensitive. Two bugs already came out of that (a loop
//! check that used `ends_with`, a `Host` of `app.example.com.` missing its
//! service), and the next one would be a security bug, since several of these
//! values are compared against each other to make access decisions.

/// Reduce anything host-shaped to a bare, comparable hostname: no scheme, no
/// path, no port, no trailing root dot, lowercased.
///
/// IPv6 literals keep their brackets and are otherwise left alone — they are
/// never valid `proxy_host` values, and splitting one on `:` would mangle it.
pub fn bare(raw: &str) -> String {
    let mut s = raw.trim().to_ascii_lowercase();
    if let Some(rest) = s.split("://").nth(1) {
        s = rest.to_string();
    }
    s = s.split('/').next().unwrap_or("").to_string();
    if s.starts_with('[') {
        return match s.find(']') {
            Some(end) => s[..=end].to_string(),
            None => s,
        };
    }
    s.split(':')
        .next()
        .unwrap_or("")
        .trim_matches('.')
        .to_string()
}

/// [`bare`], rejecting anything that isn't a usable hostname.
pub fn validate(raw: &str, what: &str) -> Result<String, String> {
    let h = bare(raw);
    if h.is_empty() {
        return Err(format!("{} required", what));
    }
    if !h
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
    {
        return Err(format!("{} contains invalid characters", what));
    }
    Ok(h)
}

/// The bare host of a URL, or `None` if it doesn't parse or has no host.
pub fn of_url(url: &str) -> Option<String> {
    url::Url::parse(url)
        .ok()?
        .host_str()
        .map(|h| bare(h))
        .filter(|h| !h.is_empty())
}

/// Whether a `Domain=<domain>` cookie is sent to `host`, per RFC 6265 §5.1.3:
/// an exact match, or a subdomain separated by a real label boundary.
///
/// The boundary matters — `notexample.com` must not count as being under
/// `example.com`, which a bare `ends_with` would allow.
pub fn covers(domain: &str, host: &str) -> bool {
    host == domain || host.ends_with(&format!(".{}", domain))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bare_strips_everything_that_is_not_the_name() {
        assert_eq!(bare("App.Example.com"), "app.example.com");
        assert_eq!(bare("https://App.Example.com:8443/x?y"), "app.example.com");
        assert_eq!(bare("app.example.com."), "app.example.com");
        assert_eq!(bare(".app.example.com."), "app.example.com");
        assert_eq!(bare("app.example.com.:8081"), "app.example.com");
        assert_eq!(bare("  app.example.com  "), "app.example.com");
        assert_eq!(bare(""), "");
        // IPv6 literals survive intact rather than being split on ':'.
        assert_eq!(bare("[::1]:8080"), "[::1]");
    }

    #[test]
    fn validate_rejects_unusable_names() {
        assert_eq!(validate("App.Example.com", "host").unwrap(), "app.example.com");
        assert!(validate("", "host").is_err());
        assert!(validate("bad host.com", "host").is_err());
        assert!(validate("under_score.com", "host").is_err());
    }

    #[test]
    fn of_url_extracts_a_comparable_host() {
        assert_eq!(of_url("https://App.Example.com:443/x").as_deref(), Some("app.example.com"));
        assert_eq!(of_url("http://app.example.com.").as_deref(), Some("app.example.com"));
        assert_eq!(of_url("not a url"), None);
    }

    #[test]
    fn covers_requires_a_label_boundary() {
        assert!(covers("example.com", "example.com"));
        assert!(covers("example.com", "bastion.example.com"));
        assert!(!covers("example.com", "notexample.com"));
        assert!(!covers("ample.com", "example.com"));
        // A domain narrower than the host cannot hold its cookie.
        assert!(!covers("app.example.com", "example.com"));
    }
}
