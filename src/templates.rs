use maud::{html, Markup, DOCTYPE, PreEscaped};

use crate::models::UserCtx;

const STYLE: &str = include_str!("../static/style.css");

pub fn layout(title: &str, user: Option<&UserCtx>, body: Markup) -> Markup {
    html! {
        (DOCTYPE)
        html lang="en" {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width,initial-scale=1";
                title { (title) " — bastion" }
                style { (PreEscaped(STYLE)) }
                script src="https://unpkg.com/htmx.org@2.0.4" defer {}
            }
            body hx-boost="true" {
                header.topbar {
                    a.brand href="/" { "bastion" }
                    nav.topnav {
                        @if let Some(u) = user {
                            @if let Some(a) = &u.avatar {
                                img.avatar src=(a) alt="" referrerpolicy="no-referrer";
                            }
                            span.username { (u.username) }
                            (status_pill(&u.status))
                            @if u.is_admin {
                                a.btn href="/admin" { "admin" }
                            }
                            form method="post" action="/auth/logout" hx-boost="false" {
                                button.btn type="submit" { "log out" }
                            }
                        } @else {
                            a.btn href="/auth/login" { "log in with GitHub" }
                        }
                    }
                }
                main { (body) }
            }
        }
    }
}

pub fn status_pill(status: &str) -> Markup {
    let class = match status {
        "active" => "pill good",
        "pending" => "pill warn",
        "denied" => "pill bad",
        _ => "pill",
    };
    html! { span class=(class) { (status) } }
}

pub fn admin_layout(title: &str, active: AdminTab, user: Option<&UserCtx>, body: Markup) -> Markup {
    let body = html! {
        nav.admin-tabs {
            (admin_tab("Overview", "/admin", active == AdminTab::Overview))
            (admin_tab("Requests", "/admin/requests", active == AdminTab::Requests))
            (admin_tab("Users", "/admin/users", active == AdminTab::Users))
            (admin_tab("Services", "/admin/services", active == AdminTab::Services))
        }
        section.admin-body { (body) }
    };
    layout(title, user, body)
}

fn admin_tab(label: &str, href: &str, active: bool) -> Markup {
    let class = if active { "admin-tab active" } else { "admin-tab" };
    html! { a class=(class) href=(href) { (label) } }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminTab {
    Overview,
    Requests,
    Users,
    Services,
}
