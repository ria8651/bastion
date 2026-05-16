use maud::{html, Markup, PreEscaped, DOCTYPE};

use crate::models::UserCtx;

const STYLE: &str = include_str!("../static/style.css");
pub const LOGO_SVG: &str = include_str!("../static/logo-icon.svg");
const VERSION_TAG: &str = "v0.5";

pub fn layout(title: &str, body: Markup) -> Markup {
    html! {
        (DOCTYPE)
        html lang="en" {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width,initial-scale=1";
                title { (title) " — bastion" }
                link rel="icon" type="image/svg+xml" href="/favicon.svg";
                style { (PreEscaped(STYLE)) }
                script src="https://unpkg.com/htmx.org@2.0.4" defer {}
            }
            body.bastion hx-boost="true" {
                (body)
                div.toast-host #toast-host {}
                script { (PreEscaped(TOAST_SCRIPT)) }
            }
        }
    }
}

const TOAST_SCRIPT: &str = r#"
function extractError(html) {
  var m = html.match(/<div class="detail">([\s\S]*?)<\/div>/);
  if (m) return m[1].replace(/<[^>]*>/g, '').replace(/\s+/g, ' ').trim();
  return (html || '').replace(/<[^>]*>/g, '').replace(/\s+/g, ' ').trim().slice(0, 240);
}
document.body.addEventListener('htmx:responseError', function(e) {
  var x = e.detail.xhr;
  var msg = extractError(x.responseText) || x.statusText || 'request failed';
  showToast(x.status + ' — ' + msg);
});
document.body.addEventListener('htmx:sendError', function() {
  showToast('network error — could not reach bastion');
});
function showToast(msg) {
  var host = document.getElementById('toast-host');
  if (!host) return;
  host.innerHTML = '';
  var t = document.createElement('div');
  t.className = 'toast';
  var lbl = document.createElement('span');
  lbl.className = 'label';
  lbl.textContent = 'error';
  var body = document.createElement('span');
  body.textContent = msg;
  var x = document.createElement('span');
  x.className = 'close';
  x.textContent = '×';
  x.onclick = function() { host.innerHTML = ''; };
  t.appendChild(lbl); t.appendChild(body); t.appendChild(x);
  host.appendChild(t);
  setTimeout(function() { if (host.contains(t)) host.removeChild(t); }, 6000);
}
"#;

pub fn logo(size: u16) -> Markup {
    let style = format!("width:{0}px;height:{0}px;", size);
    html! {
        span.logo-icon style=(style) { (PreEscaped(LOGO_SVG)) }
    }
}

pub fn corner_mark(crumb: Option<&str>) -> Markup {
    html! {
        a.corner-mark href="/" {
            (logo(22))
            span.wordmark { "bastion" }
            @if let Some(c) = crumb {
                span.crumb { "/ " (c) }
            }
        }
    }
}

pub fn corner_meta(host: &str) -> Markup {
    html! {
        div.corner-meta {
            span { (VERSION_TAG) }
            span.dot { "·" }
            span { (host) }
        }
    }
}

/// Top horizontal strip: brand mark on the left, deployment meta on the right.
/// Constrained to the same max-width as the page body so the edges align.
pub fn page_chrome(crumb: Option<&str>, host: &str, narrow: bool) -> Markup {
    let class = if narrow { "page-chrome narrow" } else { "page-chrome" };
    html! {
        div class=(class) {
            (corner_mark(crumb))
            (corner_meta(host))
        }
    }
}

pub fn bottom_strip(extra: Option<&str>, narrow: bool) -> Markup {
    let class = if narrow { "bottom-strip narrow" } else { "bottom-strip" };
    html! {
        div class=(class) {
            "ria8651/bastion"
            @if let Some(e) = extra { " · " (e) }
        }
    }
}

/// Centered card shell used by /, /auth/login, /pending, and /denied. The card
/// body is responsible for its own headline / provider stack / footnote — this
/// helper supplies only the vertical centering and the semi-transparent brand
/// mark in the footer.
pub fn landing_page(title: &str, card_body: Markup) -> Markup {
    let body = html! {
        div.landing-center {
            div.landing-wrap { (card_body) }
        }
        div.brand-footer { (corner_mark(None)) }
    };
    layout(title, body)
}

pub fn pill(kind: &str, label: &str) -> Markup {
    let class = format!("pill {}", kind);
    html! { span class=(class) { (label) } }
}

pub fn status_pill(status: &str) -> Markup {
    pill(status, status)
}

pub fn initials(name: &str) -> String {
    let s: String = name.chars().take(2).collect();
    s.to_lowercase()
}

pub fn avatar(user: &UserCtx, size_class: &str) -> Markup {
    let class = if size_class.is_empty() {
        "avatar".to_string()
    } else {
        format!("avatar {}", size_class)
    };
    html! {
        span class=(class) {
            @if let Some(a) = &user.avatar {
                img src=(a) alt="" referrerpolicy="no-referrer";
            } @else {
                (initials(&user.username))
            }
        }
    }
}

/// Strip scheme + trailing slash to surface just the host[:port].
pub fn host_from_origin(origin: &str) -> &str {
    let s = origin
        .trim_start_matches("https://")
        .trim_start_matches("http://");
    s.trim_end_matches('/')
}

pub fn github_svg() -> Markup {
    let svg = r##"<svg viewBox="0 0 16 16" fill="currentColor" aria-hidden="true"><path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.01 8.01 0 0016 8c0-4.42-3.58-8-8-8z"/></svg>"##;
    html! { (PreEscaped(svg)) }
}

pub fn google_svg() -> Markup {
    // Google "G" mark, official 4-colour, viewBox 0 0 48 48.
    let svg = r##"<svg viewBox="0 0 48 48" aria-hidden="true"><path fill="#FFC107" d="M43.611 20.083H42V20H24v8h11.303c-1.649 4.657-6.08 8-11.303 8-6.627 0-12-5.373-12-12s5.373-12 12-12c3.059 0 5.842 1.154 7.961 3.039l5.657-5.657C34.046 6.053 29.268 4 24 4 12.955 4 4 12.955 4 24s8.955 20 20 20 20-8.955 20-20c0-1.341-.138-2.65-.389-3.917z"/><path fill="#FF3D00" d="M6.306 14.691l6.571 4.819C14.655 15.108 18.961 12 24 12c3.059 0 5.842 1.154 7.961 3.039l5.657-5.657C34.046 6.053 29.268 4 24 4 16.318 4 9.656 8.337 6.306 14.691z"/><path fill="#4CAF50" d="M24 44c5.166 0 9.86-1.977 13.409-5.192l-6.19-5.238C29.211 35.091 26.715 36 24 36c-5.202 0-9.619-3.317-11.283-7.946l-6.522 5.025C9.505 39.556 16.227 44 24 44z"/><path fill="#1976D2" d="M43.611 20.083H42V20H24v8h11.303c-.792 2.237-2.231 4.166-4.087 5.571.001-.001.002-.001.003-.002l6.19 5.238C36.971 39.205 44 34 44 24c0-1.341-.138-2.65-.389-3.917z"/></svg>"##;
    html! { (PreEscaped(svg)) }
}

pub fn provider_icon(provider: &str) -> Markup {
    match provider {
        "github" => github_svg(),
        "google" => google_svg(),
        _ => html! { span.mono { (provider) } },
    }
}

pub fn provider_display_name(provider: &str) -> &'static str {
    match provider {
        "github" => "GitHub",
        "google" => "Google",
        _ => "unknown",
    }
}

/// Sidebar tab identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminTab {
    Users,
    Requests,
    Services,
    Providers,
    Audit,
}

pub struct AdminCounts {
    pub users: Option<i64>,
    pub requests: Option<i64>,
    pub services: Option<i64>,
}

pub fn admin_shell(
    active: AdminTab,
    user: &UserCtx,
    host: &str,
    counts: AdminCounts,
    body: Markup,
) -> Markup {
    let title = match active {
        AdminTab::Users => "Users",
        AdminTab::Requests => "Access requests",
        AdminTab::Services => "Services",
        AdminTab::Providers => "Identity providers",
        AdminTab::Audit => "Audit log",
    };
    let shell = html! {
        div.admin-shell {
            aside.admin-sidebar {
                a.admin-brand href="/" {
                    (logo(24))
                    div {
                        div.name { "bastion" }
                        div.host { (host) }
                    }
                }
                nav.admin-nav {
                    (admin_nav_item("Users", "/admin/users", active == AdminTab::Users, counts.users))
                    (admin_nav_item("Access requests", "/admin/requests", active == AdminTab::Requests, counts.requests))
                    (admin_nav_item("Services", "/admin/services", active == AdminTab::Services, counts.services))
                    (admin_nav_item("Identity providers", "/admin/providers", active == AdminTab::Providers, None))
                    (admin_nav_item("Audit log", "/admin/audit", active == AdminTab::Audit, None))
                }
                div.admin-user {
                    (avatar(user, ""))
                    div.info {
                        div.uname { (user.username) }
                        div.role { @if user.is_admin { "admin" } @else { "user" } }
                    }
                    form method="post" action="/auth/logout" hx-boost="false" style="margin:0" {
                        button.btn.text.signout type="submit" title="sign out" { "sign out" }
                    }
                }
            }
            main.admin-main { (body) }
        }
    };
    layout(title, shell)
}

fn admin_nav_item(label: &str, href: &str, active: bool, count: Option<i64>) -> Markup {
    let class = if active { "admin-nav-item active" } else { "admin-nav-item" };
    html! {
        a class=(class) href=(href) {
            span { (label) }
            @if let Some(n) = count {
                span.count { (n) }
            }
        }
    }
}

pub fn admin_header(title: &str, meta: Option<&str>, action: Option<Markup>) -> Markup {
    html! {
        div.admin-header {
            div.titlewrap {
                h1 { (title) }
                @if let Some(m) = meta {
                    span.meta { (m) }
                }
            }
            @if let Some(a) = action { (a) }
        }
    }
}
