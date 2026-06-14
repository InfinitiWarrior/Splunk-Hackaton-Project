// auth/src/db/sessions.rs
use anyhow::Result;
use sqlx::PgPool;
use std::net::IpAddr;
use uuid::Uuid;
use crate::crypto;

#[derive(Debug, Clone)]
pub struct Session {
    pub id: Uuid,
    pub user_id: Uuid,
    pub token_hash: String,
    pub created_at: time::OffsetDateTime,
    pub expires_at: time::OffsetDateTime,
    pub ip: String,
    pub user_agent: String,
    pub device_fingerprint: String,
    pub auth_level: i32,
    pub level3_expires_at: Option<time::OffsetDateTime>,
    pub invalidated_at: Option<time::OffsetDateTime>,
}

pub async fn create(
    db: &PgPool,
    user_id: Uuid,
    ip: IpAddr,
    user_agent: &str,
    fingerprint: &str,
) -> Result<String> {
    let token = crypto::generate_token_hex();
    let token_hash = crypto::hash_token(&token)
        .map_err(|e| anyhow::anyhow!("Token hashing failed: {}", e))?;

    let ip_str = ip.to_string();
    let mut tx = db.begin().await?;

    sqlx::query(
        "UPDATE sessions SET invalidated_at = NOW(), invalidation_reason = 'new_login'
         WHERE user_id = $1 AND invalidated_at IS NULL"
    )
    .bind(user_id)
    .execute(&mut *tx)
    .await?;

    sqlx::query(
        "INSERT INTO sessions (user_id, token_hash, ip, user_agent, device_fingerprint, auth_level)
         VALUES ($1, $2, $3::inet, $4, $5, 1)"
    )
    .bind(user_id)
    .bind(&token_hash)
    .bind(&ip_str)
    .bind(user_agent)
    .bind(fingerprint)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    Ok(token)
}

pub async fn validate(
    db: &PgPool,
    token: &str,
    ip: IpAddr,
    user_agent: &str,
) -> Result<Option<Session>> {
    use sqlx::Row;

    let rows = sqlx::query(
        "SELECT id, user_id, token_hash, created_at, expires_at, ip::text as ip,
                user_agent, device_fingerprint, auth_level, level3_expires_at, invalidated_at
         FROM sessions
         WHERE invalidated_at IS NULL AND expires_at > NOW()
         ORDER BY created_at DESC LIMIT 1000"
    )
    .fetch_all(db)
    .await?;

    let ip_str = ip.to_string();

    for row in rows {
        let token_hash: String = row.get("token_hash");
        if !crypto::verify_token(token, &token_hash) {
            continue;
        }
        let stored_ip: String = row.get("ip");
        let stored_ip_clean = stored_ip.split('/').next().unwrap_or(&stored_ip);
        if stored_ip_clean != ip_str {
            tracing::warn!("Session IP mismatch: stored={}, request={}", stored_ip, ip_str);
            let id: Uuid = row.get("id");
            invalidate(db, id, "ip_mismatch").await?;
            return Ok(None);
        }
        let stored_ua: String = row.get("user_agent");
        if stored_ua != user_agent {
            tracing::warn!("Session UA mismatch");
            let id: Uuid = row.get("id");
            invalidate(db, id, "ua_mismatch").await?;
            return Ok(None);
        }
        return Ok(Some(Session {
            id: row.get("id"),
            user_id: row.get("user_id"),
            token_hash,
            created_at: row.get("created_at"),
            expires_at: row.get("expires_at"),
            ip: stored_ip,
            user_agent: stored_ua,
            device_fingerprint: row.get("device_fingerprint"),
            auth_level: row.get("auth_level"),
            level3_expires_at: row.get("level3_expires_at"),
            invalidated_at: row.get("invalidated_at"),
        }));
    }

    Ok(None)
}

pub async fn invalidate(db: &PgPool, session_id: Uuid, reason: &str) -> Result<()> {
    sqlx::query(
        "UPDATE sessions SET invalidated_at = NOW(), invalidation_reason = $1 WHERE id = $2"
    )
    .bind(reason)
    .bind(session_id)
    .execute(db)
    .await?;
    Ok(())
}

pub async fn elevate(db: &PgPool, session_id: Uuid, level: i32) -> Result<()> {
    if level == 3 {
        sqlx::query(
            "UPDATE sessions SET auth_level = $1, level3_expires_at = NOW() + INTERVAL '5 minutes' WHERE id = $2"
        )
        .bind(level)
        .bind(session_id)
        .execute(db)
        .await?;
    } else {
        sqlx::query(
            "UPDATE sessions SET auth_level = $1, level3_expires_at = NULL WHERE id = $2"
        )
        .bind(level)
        .bind(session_id)
        .execute(db)
        .await?;
    }
    Ok(())
}
