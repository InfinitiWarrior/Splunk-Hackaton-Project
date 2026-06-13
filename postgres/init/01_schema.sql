-- ============================================================
-- SOC Triage Auth Schema
-- ============================================================

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ── Users ─────────────────────────────────────────────────────
CREATE TABLE users (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username        TEXT NOT NULL UNIQUE,
    email           TEXT NOT NULL UNIQUE,
    password_hash   TEXT NOT NULL,                    -- argon2id
    totp_secret     TEXT,                             -- encrypted TOTP secret, NULL until enrolled
    totp_enrolled   BOOLEAN NOT NULL DEFAULT FALSE,
    role            TEXT NOT NULL DEFAULT 'analyst'   -- analyst | senior_analyst | admin
                    CHECK (role IN ('analyst', 'senior_analyst', 'admin')),
    active          BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_login      TIMESTAMPTZ,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    lockout_until   TIMESTAMPTZ,
    CONSTRAINT username_length CHECK (char_length(username) BETWEEN 3 AND 64),
    CONSTRAINT email_format CHECK (email ~* '^[^@]+@[^@]+\.[^@]+$')
);

CREATE INDEX idx_users_username ON users (username);
CREATE INDEX idx_users_email ON users (email);
CREATE INDEX idx_users_active ON users (active);

-- ── Sessions ──────────────────────────────────────────────────
CREATE TABLE sessions (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id             UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash          TEXT NOT NULL UNIQUE,         -- argon2id hash of 32-byte CSPRNG token
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at          TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '30 minutes',
    ip                  INET NOT NULL,
    user_agent          TEXT NOT NULL,
    device_fingerprint  TEXT NOT NULL,
    auth_level          INTEGER NOT NULL DEFAULT 1    -- 1=read, 2=investigate, 3=respond
                        CHECK (auth_level IN (1, 2, 3)),
    level3_expires_at   TIMESTAMPTZ,                  -- L3 drops back to L2 after 5 minutes
    invalidated_at      TIMESTAMPTZ,                  -- set when session is killed
    invalidation_reason TEXT
);

CREATE INDEX idx_sessions_token_hash ON sessions (token_hash);
CREATE INDEX idx_sessions_user_id ON sessions (user_id);
CREATE INDEX idx_sessions_expires_at ON sessions (expires_at);

-- Only one active session per user
CREATE UNIQUE INDEX idx_sessions_one_per_user
    ON sessions (user_id)
    WHERE invalidated_at IS NULL;

-- ── Action tokens (SAT) ───────────────────────────────────────
CREATE TABLE action_tokens (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash      TEXT NOT NULL UNIQUE,             -- argon2id hash of 32-byte CSPRNG token
    action_type     TEXT NOT NULL,                    -- disable_user | suspend_user | revoke_sessions | block_user etc.
    target          TEXT NOT NULL,                    -- user_id or resource being acted upon
    reason          TEXT NOT NULL
                    CHECK (char_length(reason) >= 20),-- minimum 20 chars enforced at DB level too
    issued_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '60 seconds',
    consumed_at     TIMESTAMPTZ,                      -- set when token is used
    approver_id     UUID REFERENCES users(id),        -- four-eyes: second user who approved
    approved_at     TIMESTAMPTZ,
    session_id      UUID NOT NULL REFERENCES sessions(id) ON DELETE CASCADE
);

CREATE INDEX idx_action_tokens_token_hash ON action_tokens (token_hash);
CREATE INDEX idx_action_tokens_user_id ON action_tokens (user_id);
CREATE INDEX idx_action_tokens_expires_at ON action_tokens (expires_at);

-- ── Devices ───────────────────────────────────────────────────
CREATE TABLE devices (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    fingerprint     TEXT NOT NULL,
    name            TEXT,                             -- user-given device name
    approved_at     TIMESTAMPTZ,
    approved_by     UUID REFERENCES users(id),        -- admin or self-approval
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen       TIMESTAMPTZ,
    UNIQUE (user_id, fingerprint)
);

CREATE INDEX idx_devices_user_id ON devices (user_id);
CREATE INDEX idx_devices_fingerprint ON devices (fingerprint);

-- ── IP allowlist ──────────────────────────────────────────────
CREATE TABLE ip_allowlist (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cidr        CIDR NOT NULL UNIQUE,
    description TEXT,
    created_by  UUID REFERENCES users(id),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ── Failed login tracking ─────────────────────────────────────
CREATE TABLE failed_logins (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ip          INET NOT NULL,
    username    TEXT,                                 -- may be NULL if username not found
    attempted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    user_agent  TEXT
);

CREATE INDEX idx_failed_logins_ip ON failed_logins (ip);
CREATE INDEX idx_failed_logins_attempted_at ON failed_logins (attempted_at);
CREATE INDEX idx_failed_logins_username ON failed_logins (username) WHERE username IS NOT NULL;