//! Who is on the other end of a connection, and how much of what the request
//! says about that to believe.
//!
//! `X-Forwarded-For` and `X-Forwarded-Proto` are just headers: anyone can send
//! them. They mean something only when the peer that sent them is a proxy we
//! put there. Behind a gateway that is the gateway; as the edge, it is nobody
//! on the internet. So the peer address is checked against `TRUSTED_PROXIES`
//! and the headers are read only when it matches.
//!
//! Before this existed, `X-Real-IP` was set from the socket peer — which behind
//! nginx is nginx — and an inbound `X-Forwarded-For` was appended to no matter
//! who sent it.

use std::net::IpAddr;

use axum::http::HeaderMap;

/// Set by the listener on every request, alongside `ConnectInfo`.
#[derive(Debug, Clone, Copy, Default)]
pub struct ConnMeta {
    /// Arrived on bastion's own TLS listener, so the scheme is known first-hand.
    pub tls: bool,
}

/// CIDR blocks whose forwarding headers are believed.
#[derive(Debug, Clone)]
pub struct Trusted(Vec<(IpAddr, u8)>);

/// Loopback and private ranges: a gateway in front of bastion is on the same
/// box or the same LAN. A LAN client can therefore choose the IP it is logged
/// as, which is the usual homelab trade; set `TRUSTED_PROXIES=none` to refuse.
const DEFAULT_TRUSTED: &str = "127.0.0.0/8, ::1/128, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, fc00::/7";

impl Trusted {
    /// From `TRUSTED_PROXIES`: comma-separated addresses or CIDRs, `none` for
    /// nothing, unset for [`DEFAULT_TRUSTED`].
    pub fn parse(raw: Option<&str>) -> Result<Trusted, String> {
        let raw = raw.map(str::trim).filter(|s| !s.is_empty()).unwrap_or(DEFAULT_TRUSTED);
        if raw.eq_ignore_ascii_case("none") {
            return Ok(Trusted(Vec::new()));
        }
        raw.split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(parse_cidr)
            .collect::<Result<_, _>>()
            .map(Trusted)
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        let ip = ip.to_canonical();
        self.0.iter().any(|(net, bits)| in_cidr(ip, *net, *bits))
    }

    /// For display: the blocks as configured.
    pub fn describe(&self) -> String {
        if self.0.is_empty() {
            return "none".into();
        }
        self.0
            .iter()
            .map(|(n, b)| format!("{}/{}", n, b))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

fn parse_cidr(s: &str) -> Result<(IpAddr, u8), String> {
    let (addr, bits) = match s.split_once('/') {
        Some((a, b)) => (a, Some(b)),
        None => (s, None),
    };
    let ip: IpAddr = addr
        .parse()
        .map_err(|_| format!("TRUSTED_PROXIES: {} is not an IP address", addr))?;
    let ip = ip.to_canonical();
    let max = if ip.is_ipv4() { 32 } else { 128 };
    let bits = match bits {
        Some(b) => b
            .parse::<u8>()
            .ok()
            .filter(|b| *b <= max)
            .ok_or_else(|| format!("TRUSTED_PROXIES: bad prefix length in {}", s))?,
        None => max,
    };
    Ok((ip, bits))
}

fn in_cidr(ip: IpAddr, net: IpAddr, bits: u8) -> bool {
    match (ip, net) {
        (IpAddr::V4(a), IpAddr::V4(n)) => {
            let mask = if bits == 0 { 0 } else { u32::MAX << (32 - bits) };
            u32::from(a) & mask == u32::from(n) & mask
        }
        (IpAddr::V6(a), IpAddr::V6(n)) => {
            let mask = if bits == 0 { 0 } else { u128::MAX << (128 - bits) };
            u128::from(a) & mask == u128::from(n) & mask
        }
        _ => false,
    }
}

/// What to tell an upstream about the client.
#[derive(Debug, PartialEq, Eq)]
pub struct Forwarded {
    /// Best knowledge of the real client: the socket peer, or, behind a
    /// trusted proxy, the address that proxy says it heard from.
    pub client: IpAddr,
    /// The `X-Forwarded-For` to send on: the trusted chain plus our peer.
    pub chain: String,
    /// The scheme the client used to reach the edge.
    pub proto: &'static str,
}

pub fn resolve(trusted: &Trusted, peer: IpAddr, headers: &HeaderMap, conn: ConnMeta) -> Forwarded {
    let peer = peer.to_canonical();
    let from_proxy = trusted.contains(peer);

    let proto = if conn.tls {
        "https"
    } else if from_proxy {
        match header(headers, "x-forwarded-proto").and_then(|v| v.split(',').next()).map(str::trim) {
            Some("https") => "https",
            _ => "http",
        }
    } else {
        "http"
    };

    if !from_proxy {
        return Forwarded { client: peer, chain: peer.to_string(), proto };
    }

    let inbound: Vec<String> = headers
        .get_all("x-forwarded-for")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    // Walk right to left: each hop appends what it saw, so the rightmost entry
    // not added by one of our own proxies is the first one we can't vouch for —
    // anything further left the client could have written itself.
    let mut client = None;
    for entry in inbound.iter().rev() {
        let Ok(ip) = entry.parse::<IpAddr>().map(|ip| ip.to_canonical()) else {
            break;
        };
        client = Some(ip);
        if !trusted.contains(ip) {
            break;
        }
    }
    let client = client
        .or_else(|| {
            header(headers, "x-real-ip")
                .and_then(|v| v.trim().parse::<IpAddr>().ok())
                .map(|ip| ip.to_canonical())
        })
        .unwrap_or(peer);

    let mut chain = inbound;
    chain.push(peer.to_string());
    Forwarded { client, chain: chain.join(", "), proto }
}

fn header<'a>(h: &'a HeaderMap, name: &str) -> Option<&'a str> {
    h.get(name).and_then(|v| v.to_str().ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut m = HeaderMap::new();
        for (k, v) in pairs {
            m.append(
                axum::http::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                v.parse().unwrap(),
            );
        }
        m
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn cidrs_parse_and_match() {
        let t = Trusted::parse(Some("192.168.1.0/24, 10.0.0.1, ::1")).unwrap();
        assert!(t.contains(ip("192.168.1.42")));
        assert!(!t.contains(ip("192.168.2.1")));
        assert!(t.contains(ip("10.0.0.1")));
        assert!(!t.contains(ip("10.0.0.2")));
        assert!(t.contains(ip("::1")));
        // A v4 peer on a dual-stack socket arrives v4-mapped.
        assert!(t.contains(ip("::ffff:192.168.1.9")));

        assert!(Trusted::parse(Some("none")).unwrap().0.is_empty());
        assert!(Trusted::parse(None).unwrap().contains(ip("172.20.0.3")));
        assert!(Trusted::parse(Some("192.168.1.0/33")).is_err());
        assert!(Trusted::parse(Some("nope")).is_err());
    }

    #[test]
    fn an_untrusted_peer_cannot_choose_its_address_or_scheme() {
        let t = Trusted::parse(Some("192.168.1.0/24")).unwrap();
        let f = resolve(
            &t,
            ip("203.0.113.7"),
            &h(&[("x-forwarded-for", "1.2.3.4"), ("x-real-ip", "1.2.3.4"), ("x-forwarded-proto", "https")]),
            ConnMeta::default(),
        );
        assert_eq!(f.client, ip("203.0.113.7"));
        // The forged chain is dropped, not appended to.
        assert_eq!(f.chain, "203.0.113.7");
        assert_eq!(f.proto, "http");
    }

    #[test]
    fn behind_a_trusted_gateway_the_client_is_the_hop_before_it() {
        let t = Trusted::parse(Some("192.168.1.0/24")).unwrap();
        // nginx: X-Forwarded-For = <whatever the client sent>, <client>.
        let f = resolve(
            &t,
            ip("192.168.1.2"),
            &h(&[("x-forwarded-for", "6.6.6.6, 198.51.100.4"), ("x-forwarded-proto", "https")]),
            ConnMeta::default(),
        );
        assert_eq!(f.client, ip("198.51.100.4"));
        assert_eq!(f.chain, "6.6.6.6, 198.51.100.4, 192.168.1.2");
        assert_eq!(f.proto, "https");

        // X-Real-IP only when there's no chain at all.
        let f = resolve(&t, ip("192.168.1.2"), &h(&[("x-real-ip", "198.51.100.9")]), ConnMeta::default());
        assert_eq!(f.client, ip("198.51.100.9"));
    }

    #[test]
    fn our_own_tls_listener_knows_its_scheme() {
        let t = Trusted::parse(Some("none")).unwrap();
        let f = resolve(&t, ip("203.0.113.7"), &h(&[("x-forwarded-proto", "http")]), ConnMeta { tls: true });
        assert_eq!(f.proto, "https");
    }
}
