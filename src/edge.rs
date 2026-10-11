//! Edge routes: every hostname bastion forwards, gated or not.
//!
//! A route is the network side — hostnames → upstream. `service_id`, when set,
//! puts a gate in front: only people granted that service get through, with
//! identity headers attached. Either way the request goes through
//! `proxy::forward`, so every route gets the same header hygiene — bastion's
//! session cookie and identity namespace stripped, hop-by-hop headers dropped,
//! the loop marker set. See `migrations/0007_routes.sql` and
//! `0008_routes_own_proxying.sql`.

use sqlx::SqlitePool;

pub struct Route {
    pub name: String,
    pub upstream: String,
    pub skip_verify: bool,
    /// The service gating it, if any.
    pub service_id: Option<i64>,
    /// Globs that skip the gate. Only read when `service_id` is set.
    pub public_paths: Option<String>,
}

/// The patterns that could match `host`, most specific first: the name
/// itself, then a wildcard at each parent. `a.b.c` → `a.b.c`, `*.b.c`, `*.c`.
fn candidates(host: &str) -> Vec<String> {
    let mut out = vec![host.to_string()];
    let mut rest = host;
    while let Some((_, parent)) = rest.split_once('.') {
        out.push(format!("*.{}", parent));
        rest = parent;
    }
    out
}

/// The route for a bare host, if any. Re-read per request, like everything
/// else bastion routes on, so an edit applies to the next request.
///
/// The most specific pattern is chosen *before* looking at whether it's
/// enabled, and a disabled winner means `None`. Filtering disabled routes out
/// first would let a name fall through to a wider wildcard: disable gated
/// `secret.example.com` and an open `*.example.com` would start serving it.
pub async fn lookup(pool: &SqlitePool, host: &str) -> Result<Option<Route>, sqlx::Error> {
    let cands = candidates(host);
    let placeholders = vec!["?"; cands.len()].join(", ");
    // Exact before wildcard, then the longest — i.e. most specific — wildcard.
    let sql = format!(
        "SELECT r.name, r.upstream_url, r.tls_skip_verify, r.service_id, r.public_paths, r.enabled
         FROM route_hosts h JOIN routes r ON r.id = h.route_id
         WHERE h.host IN ({placeholders})
         ORDER BY h.host LIKE '*.%', length(h.host) DESC
         LIMIT 1"
    );
    #[allow(clippy::type_complexity)]
    let mut q =
        sqlx::query_as::<_, (String, String, bool, Option<i64>, Option<String>, bool)>(&sql);
    for c in &cands {
        q = q.bind(c);
    }
    Ok(q.fetch_optional(pool).await?.filter(|row| row.5).map(
        |(name, upstream, skip_verify, service_id, public_paths, _)| Route {
            name,
            upstream,
            skip_verify,
            service_id,
            public_paths,
        },
    ))
}

/// Whether a host pattern covers `host`.
pub fn pattern_covers(pattern: &str, host: &str) -> bool {
    match pattern.strip_prefix("*.") {
        Some(parent) => host.len() > parent.len() + 1 && crate::host::covers(parent, host),
        None => pattern == host,
    }
}

/// Parse the admin form's hostname list: one per line (or comma-separated),
/// each either a bare name or `*.` followed by one.
pub fn parse_hosts(raw: &str) -> Result<Vec<String>, String> {
    let mut out: Vec<String> = Vec::new();
    for item in raw.lines().flat_map(|l| l.split(',')).map(str::trim) {
        if item.is_empty() || item.starts_with('#') {
            continue;
        }
        let host = match item.strip_prefix("*.") {
            Some(rest) => format!("*.{}", crate::host::validate(rest, "hostname")?),
            None if item.contains('*') => {
                return Err(format!(
                    "{}: a wildcard has to be a whole leading label, like *.example.com",
                    item
                ))
            }
            None => crate::host::validate(item, "hostname")?,
        };
        if !out.contains(&host) {
            out.push(host);
        }
    }
    if out.is_empty() {
        return Err("at least one hostname is required".into());
    }
    Ok(out)
}

/// Validate a route's upstream URL.
///
/// `https://` is allowed: the proxy client speaks TLS, verifying against the
/// webpki roots unless the route opts out. Refuses an upstream that would loop
/// straight back: one of the names being served, on a port that leads to
/// bastion.
///
/// The port matters. Those names resolve to bastion's box, but so does
/// everything else on it — `http://media.example.com:8096` is the app next
/// door, not bastion. It's a loop only on one of bastion's own ports, or on
/// 80/443, where a gateway in front would hand it straight back.
pub fn validate_upstream(
    raw: &str,
    served: &[String],
    own_ports: &[u16],
) -> Result<String, String> {
    let u = raw.trim().to_string();
    if u.is_empty() {
        return Err("upstream URL required".into());
    }
    let parsed = url::Url::parse(&u).map_err(|_| "upstream URL must be a valid URL".to_string())?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err("upstream URL must be http or https".into());
    }
    let Some(host) = crate::host::of_url(&u) else {
        return Err("upstream URL needs a host".into());
    };
    // Compare hosts, not string suffixes: `ends_with` called
    // http://myapp.example.com a loop against app.example.com, and missed the
    // real one at https://app.example.com:443/ because the port breaks the
    // suffix test.
    let port = parsed.port_or_known_default().unwrap_or(80);
    let reaches_bastion = matches!(port, 80 | 443) || own_ports.contains(&port);
    if reaches_bastion && served.iter().any(|p| pattern_covers(p, &host)) {
        return Err(format!(
            "upstream {} is this route's own address, so bastion would forward to itself. \
             The upstream is where the app itself listens, like http://127.0.0.1:8080.",
            u
        ));
    }
    Ok(u)
}

/// The route already answering on a host pattern, for refusing a second claim.
///
/// Two routes can't hold the same pattern — `route_hosts.host` is the primary
/// key — but the insert failing that way would surface as a 500. This says
/// which route has it. Overlap between *different* patterns is fine: an exact
/// name beats a wildcard covering it, and the most specific wildcard wins.
pub async fn host_owner(
    pool: &SqlitePool,
    host: &str,
    except_route: Option<i64>,
) -> Result<Option<String>, sqlx::Error> {
    let route: Option<(String,)> = sqlx::query_as(
        "SELECT r.name FROM route_hosts h JOIN routes r ON r.id = h.route_id
         WHERE h.host = ? AND r.id IS NOT ?",
    )
    .bind(host)
    .bind(except_route)
    .fetch_optional(pool)
    .await?;
    Ok(route.map(|(name,)| name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_disabled_route_does_not_fall_through_to_a_wider_wildcard() {
        let dir = std::env::temp_dir().join(format!("bastion-edge-{}", std::process::id()));
        let pool = crate::db::connect(dir.join("t.db").to_str().unwrap())
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO routes (id, name, upstream_url, enabled) VALUES
               (1, 'secret', 'http://127.0.0.1:1', 0),
               (2, 'everything', 'http://127.0.0.1:2', 1);
             INSERT INTO route_hosts (host, route_id) VALUES
               ('secret.example.com', 1), ('*.example.com', 2);",
        )
        .execute(&pool)
        .await
        .unwrap();

        // Disabled means 404 — not "served by the next pattern that matches".
        assert!(lookup(&pool, "secret.example.com").await.unwrap().is_none());
        assert_eq!(
            lookup(&pool, "other.example.com")
                .await
                .unwrap()
                .unwrap()
                .name,
            "everything"
        );

        sqlx::query("UPDATE routes SET enabled = 1 WHERE id = 1")
            .execute(&pool)
            .await
            .unwrap();
        assert_eq!(
            lookup(&pool, "secret.example.com")
                .await
                .unwrap()
                .unwrap()
                .name,
            "secret"
        );

        pool.close().await;
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn candidates_run_from_exact_to_widest() {
        assert_eq!(candidates("a.b.c"), vec!["a.b.c", "*.b.c", "*.c"]);
        assert_eq!(candidates("localhost"), vec!["localhost"]);
    }

    #[test]
    fn wildcards_need_a_label_in_front() {
        assert!(pattern_covers("*.apps.bink", "x.apps.bink"));
        assert!(pattern_covers("*.apps.bink", "a.b.apps.bink"));
        assert!(!pattern_covers("*.apps.bink", "apps.bink"));
        assert!(!pattern_covers("*.apps.bink", "xapps.bink"));
        assert!(pattern_covers("app.example.com", "app.example.com"));
        assert!(!pattern_covers("app.example.com", "x.app.example.com"));
    }

    #[test]
    fn hosts_parse_normalised_and_deduped() {
        assert_eq!(
            parse_hosts("Misc.Example.com\nmac.example.com, misc.example.com.\n\n*.Apps.Bink")
                .unwrap(),
            vec!["misc.example.com", "mac.example.com", "*.apps.bink"]
        );
        assert!(parse_hosts("").is_err());
        assert!(parse_hosts("a*.example.com").is_err());
        assert!(parse_hosts("*").is_err());
        assert!(parse_hosts("bad host").is_err());
    }

    #[test]
    fn upstreams_may_be_https_but_not_loops() {
        let served = vec!["crafty.example.com".to_string(), "*.apps.bink".to_string()];
        let v = |u: &str| validate_upstream(u, &served, &[5180]);
        assert!(v("https://192.168.1.7:8456").is_ok());
        assert!(v("http://127.0.0.1:8080").is_ok());
        assert!(v("ftp://x").is_err());
        assert!(v("").is_err());
        assert!(v("https://crafty.example.com:443/").is_err());
        assert!(v("http://x.apps.bink").is_err());
        assert!(v("http://crafty.example.com:5180").is_err());
        // Same name, another port: the app next door on bastion's box.
        assert!(v("http://crafty.example.com:8456").is_ok());
        // A different host that merely ends with the same text is not a loop.
        assert!(v("http://mycrafty.example.com").is_ok());
    }
}
