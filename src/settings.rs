//! Instance-wide key/value config, stored in the DB alongside everything else.
//! Setting a key to an empty string deletes it, so "unset" and "empty" are the
//! same state and callers only ever deal with `Option<String>`.

use anyhow::Result;
use sqlx::SqlitePool;

/// Parent domain for the session cookie, e.g. `.example.com`. Required for
/// proxy mode: bastion authenticates on its own hostname but serves the app on
/// another, so a host-only cookie is never sent to the proxied host.
pub const COOKIE_DOMAIN: &str = "cookie_domain";

pub async fn get(pool: &SqlitePool, key: &str) -> Result<Option<String>> {
    let row: Option<(String,)> = sqlx::query_as("SELECT value FROM settings WHERE key = ?")
        .bind(key)
        .fetch_optional(pool)
        .await?;
    Ok(row.map(|(v,)| v).filter(|v| !v.is_empty()))
}

pub async fn set(pool: &SqlitePool, key: &str, value: &str) -> Result<()> {
    let value = value.trim();
    if value.is_empty() {
        sqlx::query("DELETE FROM settings WHERE key = ?")
            .bind(key)
            .execute(pool)
            .await?;
        return Ok(());
    }
    sqlx::query(
        "INSERT INTO settings (key, value) VALUES (?, ?)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = unixepoch()",
    )
    .bind(key)
    .bind(value)
    .execute(pool)
    .await?;
    Ok(())
}

/// Convenience wrapper — the cookie domain is read on every session
/// set/clear, and a failed lookup should degrade to host-only cookies rather
/// than break the login flow.
pub async fn cookie_domain(pool: &SqlitePool) -> Option<String> {
    match get(pool, COOKIE_DOMAIN).await {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(error = ?e, "cookie_domain lookup failed");
            None
        }
    }
}

/// Normalises user input into a cookie `Domain` attribute: strips a scheme,
/// port, path and any leading dot, then re-adds the dot. Returns an error
/// string if what's left isn't a plausible domain.
/// Normalise a cookie domain, checking it can actually hold bastion's session.
///
/// `bastion_host` is the host from `ORIGIN`; `None` when unpinned, in which
/// case the coverage check is skipped because there is nothing to check
/// against.
///
/// A browser silently discards a `Domain` that does not cover the host setting
/// it, so a domain like `other.com` set from `bastion.example.com` locks
/// everyone out of bastion entirely — and `login_page` then re-issues the
/// session under that dead domain and expires the working host-only copy, so
/// the admin loses their own session on the next page load. Recovery at that
/// point means editing SQLite by hand. Refusing up front is the whole defence.
pub fn normalize_cookie_domain(raw: &str, bastion_host: Option<&str>) -> Result<String, String> {
    if raw.trim().is_empty() {
        return Ok(String::new());
    }
    let s = crate::host::bare(raw);
    if s.is_empty() || !s.contains('.') {
        return Err("cookie domain must be a parent domain like example.com".into());
    }
    if !s
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
    {
        return Err("cookie domain contains invalid characters".into());
    }
    if is_public_suffix(&s) {
        return Err(format!(
            "{} is a public suffix — browsers refuse cookies scoped to one. \
             Use your own domain, like example.{}",
            s, s
        ));
    }
    if let Some(host) = bastion_host {
        let host = crate::host::bare(host);
        if !crate::host::covers(&s, &host) {
            return Err(format!(
                "bastion is served from {}, which is not under {} — a browser \
                 would discard the cookie and nobody could sign in. Use {} or a \
                 domain it sits under.",
                host,
                s,
                host.split_once('.').map(|(_, parent)| parent).unwrap_or(&host)
            ));
        }
    }
    Ok(format!(".{}", s))
}


/// Common multi-label public suffixes.
///
/// Browsers silently discard a cookie scoped to one of these, which surfaces as
/// "nobody is ever signed in on the proxied hosts" with nothing to go on — the
/// same symptom as not setting a cookie domain at all. Catching the plausible
/// typos at the point of entry beats debugging that later.
///
/// A heuristic, not the Public Suffix List: it covers what someone is likely to
/// type by mistake, and a miss only costs the confusing-failure case this is
/// here to avoid. Single-label suffixes like `com` are already rejected by the
/// `contains('.')` check above.
fn is_public_suffix(domain: &str) -> bool {
    const SUFFIXES: &[&str] = &[
        "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "net.uk", "sch.uk",
        "com.au", "net.au", "org.au", "edu.au", "gov.au", "id.au",
        "co.nz", "net.nz", "org.nz", "govt.nz", "ac.nz",
        "co.za", "org.za", "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp",
        "com.br", "com.cn", "com.mx", "com.sg", "com.tr", "co.in", "co.kr",
        "co.il", "com.ar", "com.tw", "com.hk", "com.pl", "com.ua",
        "github.io", "gitlab.io", "pages.dev", "workers.dev", "vercel.app",
        "netlify.app", "herokuapp.com", "azurewebsites.net", "cloudfront.net",
    ];
    SUFFIXES.iter().any(|s| *s == domain)
}

#[cfg(test)]
mod tests {
    use super::normalize_cookie_domain as norm_with_host;

    /// ORIGIN unpinned, so the coverage check is skipped.
    fn normalize_cookie_domain(raw: &str) -> Result<String, String> {
        norm_with_host(raw, None)
    }

    #[test]
    fn a_domain_that_cannot_hold_the_session_is_refused() {
        let host = Some("bastion.example.com");
        assert_eq!(norm_with_host("example.com", host).unwrap(), ".example.com");
        assert_eq!(
            norm_with_host("bastion.example.com", host).unwrap(),
            ".bastion.example.com"
        );

        // The lockout: a browser drops this cookie, nobody can sign in, and
        // login_page then expires the admin's last working host-only copy.
        let err = norm_with_host("other.com", host).unwrap_err();
        assert!(err.contains("not under"), "{}", err);

        // A label boundary is required — `ends_with` alone would accept this.
        assert!(norm_with_host("ample.com", host).is_err());
        // Narrower than bastion's own host cannot hold it either.
        assert!(norm_with_host("app.bastion.example.com", host).is_err());
    }

    #[test]
    fn cookie_domain_normalizes() {
        assert_eq!(normalize_cookie_domain("example.com").unwrap(), ".example.com");
        assert_eq!(normalize_cookie_domain(".example.com").unwrap(), ".example.com");
        assert_eq!(
            normalize_cookie_domain("https://Bastion.Example.com:8443/x").unwrap(),
            ".bastion.example.com"
        );
        assert_eq!(normalize_cookie_domain("   ").unwrap(), "");
        assert!(normalize_cookie_domain("localhost").is_err());
        assert!(normalize_cookie_domain("bad domain.com").is_err());
        assert_eq!(normalize_cookie_domain("example.com.").unwrap(), ".example.com");
    }

    #[test]
    fn public_suffixes_are_refused_with_a_reason() {
        // Browsers drop a cookie scoped to a public suffix without a word, and
        // the symptom — nobody ever signed in on the proxied hosts — looks
        // identical to not having set a cookie domain at all.
        for bad in ["co.uk", "com.au", ".co.uk", "https://CO.UK/", "github.io"] {
            let err = normalize_cookie_domain(bad).expect_err(bad);
            assert!(err.contains("public suffix"), "{} → {}", bad, err);
        }
        for good in ["example.co.uk", "example.com", "bastion.example.com"] {
            assert!(normalize_cookie_domain(good).is_ok(), "{}", good);
        }
    }
}
