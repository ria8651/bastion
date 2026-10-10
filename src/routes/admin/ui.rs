//! Admin shell and the handful of components every admin page is built from.
//! Pages compose these rather than reaching for inline styles; anything a page
//! needs that isn't here belongs in `static/admin.css` with a class.

use maud::{html, Markup, PreEscaped};

use crate::models::UserCtx;
use crate::templates::{avatar, layout, logo, provider_icon, VERSION_TAG};

const ADMIN_STYLE: &str = include_str!("../../../static/admin.css");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Nav {
    Overview,
    Users,
    Requests,
    Services,
    Providers,
    Settings,
    Audit,
}

pub struct NavCounts {
    pub users: i64,
    pub pending_requests: i64,
    pub services: i64,
    pub pending_services: i64,
}

/// Everything the shell needs besides the page body.
pub struct Ctx {
    pub viewer: UserCtx,
    pub host: String,
    pub counts: NavCounts,
}

impl Ctx {
    pub fn page(&self, nav: Nav, title: &str, body: Markup) -> Markup {
        shell(self, nav, title, body)
    }
}

const MENU_SVG: &str = r#"<svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" aria-hidden="true"><path d="M3 5.5h14M3 10h14M3 14.5h14"/></svg>"#;

/// Escape closes the drawer. Guarded because hx-boost re-runs body scripts on
/// every navigation.
const NAV_KEYS: &str = "if(!window.__admNavKeys){window.__admNavKeys=1;\
document.addEventListener('keydown',function(e){var s=document.querySelector('.adm.nav-open');\
if(e.key==='Escape'&&s){s.classList.remove('nav-open');\
document.querySelectorAll('[data-nav-toggle]').forEach(function(b){b.setAttribute('aria-expanded','false')});}});}";

/// Toggles the drawer on narrow screens. Inline so it survives hx-boost body
/// swaps without re-binding; a swap also resets it closed, which is what a
/// navigation should do.
const TOGGLE_NAV: &str = "var s=this.closest('.adm')||document.querySelector('.adm');\
var o=s.classList.toggle('nav-open');\
document.querySelectorAll('[data-nav-toggle]').forEach(function(b){b.setAttribute('aria-expanded',o)});";

fn shell(ctx: &Ctx, active: Nav, title: &str, body: Markup) -> Markup {
    let c = &ctx.counts;
    let page = html! {
        style { (PreEscaped(ADMIN_STYLE)) }
        div.adm {
            header.adm-top {
                button.menu type="button" data-nav-toggle aria-label="Open navigation"
                    aria-controls="adm-side" aria-expanded="false" onclick=(TOGGLE_NAV) {
                    (PreEscaped(MENU_SVG))
                }
                a.brand href="/admin" { (logo(20)) span { "bastion" } }
            }
            div.adm-scrim onclick=(TOGGLE_NAV) {}
            aside.adm-side #adm-side {
                a.adm-brand href="/admin" {
                    (logo(24))
                    div {
                        div.name { "bastion" }
                        div.host { (ctx.host) }
                    }
                }
                nav.adm-nav aria-label="Main" {
                    (nav_item("Overview", "/admin", active == Nav::Overview, None))
                }
                nav.adm-nav aria-label="Access" {
                    div.label { "Access" }
                    (nav_item("Users", "/admin/users", active == Nav::Users, Some(Count::plain(c.users))))
                    (nav_item("Requests", "/admin/requests", active == Nav::Requests, Count::attn(c.pending_requests)))
                }
                nav.adm-nav aria-label="Apps" {
                    div.label { "Apps" }
                    (nav_item("Services", "/admin/services", active == Nav::Services,
                        Count::attn(c.pending_services).or(Some(Count::plain(c.services)))))
                }
                nav.adm-nav aria-label="System" {
                    div.label { "System" }
                    (nav_item("Identity providers", "/admin/providers", active == Nav::Providers, None))
                    (nav_item("Settings", "/admin/settings", active == Nav::Settings, None))
                    (nav_item("Audit log", "/admin/audit", active == Nav::Audit, None))
                }
                div.adm-me {
                    div.who {
                        (avatar(&ctx.viewer, ""))
                        span { (ctx.viewer.username) }
                    }
                    div.links {
                        a href="/" { "Your apps" }
                        a href="/account" { "Account" }
                        form method="post" action="/auth/logout" hx-boost="false" {
                            button type="submit" { "Sign out" }
                        }
                    }
                    div.ver { "bastion " (VERSION_TAG) }
                }
            }
            main.adm-main { (body) }
        }
        script { (PreEscaped(NAV_KEYS)) }
    };
    layout(title, page)
}

struct Count {
    n: i64,
    attn: bool,
}

impl Count {
    fn plain(n: i64) -> Count {
        Count { n, attn: false }
    }
    /// A count that only shows when something is waiting on an admin.
    fn attn(n: i64) -> Option<Count> {
        (n > 0).then_some(Count { n, attn: true })
    }
}

fn nav_item(label: &str, href: &str, active: bool, count: Option<Count>) -> Markup {
    html! {
        a href=(href) aria-current=[active.then_some("page")] {
            span { (label) }
            @if let Some(c) = count {
                @if c.attn {
                    span.n.attn title=(format!("{} waiting", c.n)) { (c.n) }
                } @else {
                    span.n { (c.n) }
                }
            }
        }
    }
}

// -------------------- Page structure --------------------

pub fn back(href: &str, label: &str) -> Markup {
    html! { a.back href=(href) { "← " (label) } }
}

/// Page title row. `lead` sits left of the title (an avatar or tile on detail
/// pages); `sub` is the mono line under it; `actions` floats right and wraps
/// beneath on narrow screens.
pub fn header(lead: Option<Markup>, title: &str, sub: Option<Markup>, actions: Option<Markup>) -> Markup {
    html! {
        div.ph {
            div.lead {
                @if let Some(l) = lead { (l) }
                div {
                    h1 { (title) }
                    @if let Some(s) = sub { div.sub { (s) } }
                }
            }
            @if let Some(a) = actions { div.actions { (a) } }
        }
    }
}

pub fn section(title: &str, count: Option<usize>, aside: Option<Markup>, body: Markup) -> Markup {
    html! {
        section.sec {
            div.sec-head {
                h2 {
                    (title)
                    @if let Some(n) = count { span.n { (n) } }
                }
                @if let Some(a) = aside { div.aside { (a) } }
            }
            (body)
        }
    }
}

pub fn empty(title: &str, sub: &str) -> Markup {
    html! {
        div.empty {
            div.t { (title) }
            @if !sub.is_empty() { div.s { (sub) } }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tone {
    Ok,
    Warn,
    Bad,
    Strong,
    Quiet,
    Plain,
}

impl Tone {
    fn class(self) -> &'static str {
        match self {
            Tone::Ok => "ok",
            Tone::Warn => "warn",
            Tone::Bad => "bad",
            Tone::Strong => "strong",
            Tone::Quiet => "quiet",
            Tone::Plain => "",
        }
    }
}

pub fn badge(tone: Tone, label: &str) -> Markup {
    html! { span class=(format!("badge {}", tone.class())) { (label) } }
}

/// Status badge with a dot, for the states that drive access decisions.
pub fn status_badge(status: &str) -> Markup {
    let tone = match status {
        "active" | "approved" | "granted" | "enabled" => Tone::Ok,
        "pending" => Tone::Warn,
        "denied" | "disabled" => Tone::Bad,
        _ => Tone::Plain,
    };
    html! { span class=(format!("badge dot {}", tone.class())) { (status) } }
}

pub fn notice(tone: Tone, body: Markup) -> Markup {
    html! { div class=(format!("notice {}", tone.class())) { div { (body) } } }
}

pub fn provider_icons(providers: &str) -> Markup {
    html! {
        span.icons {
            @for p in providers.split(',').filter(|p| !p.is_empty()) {
                span.ico title=(crate::templates::provider_display_name(p)) { (provider_icon(p)) }
            }
        }
    }
}

/// Two-letter monogram tile for things without an avatar (services).
pub fn tile(slug: &str, class: &str) -> Markup {
    let s: String = slug
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .take(2)
        .collect::<String>()
        .to_lowercase();
    html! { span class=(format!("tile {}", class)) { (s) } }
}

pub fn user_avatar(avatar_url: Option<&str>, username: &str, class: &str) -> Markup {
    html! {
        span class=(format!("avatar {}", class)) {
            @if let Some(a) = avatar_url {
                img src=(a) alt="" referrerpolicy="no-referrer";
            } @else {
                (crate::templates::initials(username))
            }
        }
    }
}

// -------------------- Forms --------------------

pub fn field(label: &str, hint: Option<&str>, input: Markup) -> Markup {
    html! {
        label.fld {
            span.l { (label) }
            (input)
            @if let Some(h) = hint { span.h { (h) } }
        }
    }
}

/// A one-button form. `stay` keeps the scroll position across the htmx swap,
/// for toggles in the middle of a long page where jumping to the top would
/// lose your place.
pub struct Post<'a> {
    pub action: &'a str,
    pub fields: &'a [(&'a str, &'a str)],
    pub label: &'a str,
    pub class: &'a str,
    pub confirm: Option<&'a str>,
    pub stay: bool,
}

impl<'a> Post<'a> {
    pub fn new(action: &'a str, label: &'a str) -> Self {
        Post { action, fields: &[], label, class: "btn sm", confirm: None, stay: false }
    }
    pub fn fields(mut self, f: &'a [(&'a str, &'a str)]) -> Self {
        self.fields = f;
        self
    }
    pub fn class(mut self, c: &'a str) -> Self {
        self.class = c;
        self
    }
    pub fn confirm(mut self, msg: &'a str) -> Self {
        self.confirm = Some(msg);
        self
    }
    pub fn stay(mut self) -> Self {
        self.stay = true;
        self
    }
    pub fn render(&self) -> Markup {
        html! {
            form method="post" action=(self.action)
                hx-swap=[self.stay.then_some("innerHTML show:none")]
                hx-confirm=[self.confirm] {
                @for (k, v) in self.fields {
                    input type="hidden" name=(k) value=(v);
                }
                button class=(self.class) type="submit" { (self.label) }
            }
        }
    }
}

/// On/off switch that posts a toggle. The visible state is the current one;
/// submitting flips it.
pub fn switch(action: &str, fields: &[(&str, &str)], on: bool, label: &str) -> Markup {
    html! {
        form method="post" action=(action) hx-swap="innerHTML show:none" {
            @for (k, v) in fields {
                input type="hidden" name=(k) value=(v);
            }
            button.switch type="submit" aria-pressed=(if on { "true" } else { "false" })
                aria-label=(label) title=(label) {}
        }
    }
}

/// A safe `next` for post-then-redirect handlers shared by several pages.
/// Only local admin paths: anything else is an open redirect.
pub fn next_or(next: Option<&str>, fallback: &str) -> String {
    match next {
        Some(n) if n.starts_with("/admin") && !n.contains("//") && !n.contains('\\') => n.to_string(),
        _ => fallback.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::next_or;

    #[test]
    fn next_only_allows_local_admin_paths() {
        assert_eq!(next_or(Some("/admin/users/3"), "/x"), "/admin/users/3");
        assert_eq!(next_or(Some("/admin"), "/x"), "/admin");
        assert_eq!(next_or(Some("https://evil.example/admin"), "/x"), "/x");
        assert_eq!(next_or(Some("//evil.example/admin"), "/x"), "/x");
        assert_eq!(next_or(Some("/admin//evil.example"), "/x"), "/x");
        assert_eq!(next_or(Some("/admin\\@evil"), "/x"), "/x");
        assert_eq!(next_or(Some("/account"), "/x"), "/x");
        assert_eq!(next_or(None, "/x"), "/x");
    }
}
