//! Grant lookups.
//!
//! "Is this user allowed into this service" was written out longhand in five
//! places — the proxy, the OAuth callback (twice), `/launch/:slug`,
//! `/auth/login`'s shortcut and `/api/introspect`. Every one of them is an
//! access-control decision, and five copies of the same predicate is five
//! chances for one to drift when the schema grows a column that ought to
//! disqualify a grant.

use sqlx::SqlitePool;

/// Whether `user_id` holds a grant on `service_id`.
pub async fn is_granted(
    pool: &SqlitePool,
    user_id: i64,
    service_id: i64,
) -> Result<bool, sqlx::Error> {
    let row: Option<(i64,)> =
        sqlx::query_as("SELECT user_id FROM grants WHERE user_id = ? AND service_id = ?")
            .bind(user_id)
            .bind(service_id)
            .fetch_optional(pool)
            .await?;
    Ok(row.is_some())
}

/// Whether `user_id` holds a grant on the service with this slug.
///
/// Joins rather than taking an id so the service's own liveness is part of the
/// same decision: a grant on a soft-deleted or unapproved service is not access.
pub async fn is_granted_slug(
    pool: &SqlitePool,
    user_id: i64,
    slug: &str,
) -> Result<bool, sqlx::Error> {
    let row: Option<(i64,)> = sqlx::query_as(
        "SELECT g.user_id FROM grants g
         JOIN services s ON s.id = g.service_id
         WHERE g.user_id = ? AND s.slug = ?
           AND s.status = 'approved' AND s.deleted_at IS NULL",
    )
    .bind(user_id)
    .bind(slug)
    .fetch_optional(pool)
    .await?;
    Ok(row.is_some())
}
