use axum::{response::IntoResponse, Extension};
use maud::html;

use crate::models::UserCtx;
use crate::templates::layout;

pub async fn index(user: Option<Extension<UserCtx>>) -> impl IntoResponse {
    let user = user.map(|Extension(u)| u);
    let body = html! {
        div.card {
            h1 { "bastion" }
            @match &user {
                None => {
                    p.muted { "Central GitHub-SSO auth service." }
                    p { a.btn.primary href="/auth/login" { "Log in with GitHub" } }
                }
                Some(u) if u.status == "pending" => {
                    p { "Hi " strong { (u.username) } "." }
                    p.muted { "Your account is awaiting admin approval." }
                    p { a.btn href="/pending" { "Status" } }
                }
                Some(u) if u.status == "denied" => {
                    p { "Sorry " strong { (u.username) } ", your account has been denied." }
                }
                Some(u) => {
                    p { "Signed in as " strong { (u.username) } "." }
                    @if u.is_admin {
                        p { a.btn href="/admin" { "Admin panel" } }
                    }
                }
            }
        }
    };
    layout("home", user.as_ref(), body)
}

pub async fn pending(user: Option<Extension<UserCtx>>) -> impl IntoResponse {
    let user = user.map(|Extension(u)| u);
    let body = html! {
        div.card {
            h1 { "Awaiting approval" }
            @match &user {
                Some(u) => {
                    p { strong { (u.username) } " — your account is pending an admin's review." }
                    p.muted { "You'll be able to access your apps once it's approved." }
                    form method="post" action="/auth/logout" hx-boost="false" {
                        button.btn type="submit" { "log out" }
                    }
                }
                None => {
                    p { "Not signed in. " a href="/auth/login" { "Sign in" } "." }
                }
            }
        }
    };
    layout("pending", user.as_ref(), body)
}

pub async fn denied(user: Option<Extension<UserCtx>>) -> impl IntoResponse {
    let user = user.map(|Extension(u)| u);
    let body = html! {
        div.card {
            h1 { "Access denied" }
            p.muted { "Contact an admin if you think this is wrong." }
        }
    };
    layout("denied", user.as_ref(), body)
}
