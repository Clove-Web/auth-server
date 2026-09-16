-- migrations/0001_init.sql
-- Copyright (c) 2026 Clove Nytrix Doughmination Twilight
-- Licensed under the DASL-1.2 Licence.
--
-- Timestamps are unix seconds. Every secret that is only ever compared
-- (session ids, codes, refresh tokens, login links, client secrets) is stored
-- as a SHA-256 hex digest, never in plaintext.

CREATE TABLE users (
  id              TEXT PRIMARY KEY,               -- the OIDC `sub`
  username        TEXT NOT NULL UNIQUE COLLATE NOCASE,
  name            TEXT,
  email           TEXT,
  email_verified  INTEGER NOT NULL DEFAULT 0,
  picture         TEXT,
  password_hash   TEXT,
  totp_secret     TEXT,                           -- encrypted, set once confirmed
  totp_pending    TEXT,                           -- encrypted, awaiting first code
  totp_last_step  INTEGER NOT NULL DEFAULT 0,     -- replay guard
  disabled        INTEGER NOT NULL DEFAULT 0,
  created_at      INTEGER NOT NULL,
  updated_at      INTEGER NOT NULL,
  last_login_at   INTEGER
);

CREATE TABLE groups (
  name        TEXT PRIMARY KEY,
  description TEXT NOT NULL DEFAULT '',
  created_at  INTEGER NOT NULL
);

CREATE TABLE user_groups (
  user_id    TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  group_name TEXT NOT NULL REFERENCES groups (name) ON DELETE CASCADE,
  PRIMARY KEY (user_id, group_name)
);

CREATE INDEX user_groups_group ON user_groups (group_name);

CREATE TABLE passkeys (
  id           TEXT PRIMARY KEY,                  -- credential id, base64url
  user_id      TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  public_key   TEXT NOT NULL,                     -- COSE key, base64url
  counter      INTEGER NOT NULL DEFAULT 0,
  transports   TEXT NOT NULL DEFAULT '[]',
  device_type  TEXT NOT NULL,
  backed_up    INTEGER NOT NULL DEFAULT 0,
  name         TEXT NOT NULL,
  created_at   INTEGER NOT NULL,
  last_used_at INTEGER
);

CREATE INDEX passkeys_user ON passkeys (user_id);

CREATE TABLE sessions (
  id_hash      TEXT PRIMARY KEY,
  user_id      TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  csrf         TEXT NOT NULL,
  auth_time    INTEGER NOT NULL,
  amr          TEXT NOT NULL,                     -- JSON array
  ip           TEXT,
  user_agent   TEXT,
  created_at   INTEGER NOT NULL,
  last_seen_at INTEGER NOT NULL,
  expires_at   INTEGER NOT NULL
);

CREATE INDEX sessions_user ON sessions (user_id);
CREATE INDEX sessions_expiry ON sessions (expires_at);

-- Half-finished password logins waiting on a TOTP code.
CREATE TABLE pending_logins (
  id_hash    TEXT PRIMARY KEY,
  user_id    TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  return_to  TEXT NOT NULL,
  attempts   INTEGER NOT NULL DEFAULT 0,
  expires_at INTEGER NOT NULL
);

CREATE TABLE webauthn_challenges (
  id         TEXT PRIMARY KEY,
  challenge  TEXT NOT NULL,
  purpose    TEXT NOT NULL,                       -- 'login' | 'register'
  user_id    TEXT REFERENCES users (id) ON DELETE CASCADE,
  expires_at INTEGER NOT NULL
);

CREATE TABLE login_links (
  token_hash TEXT PRIMARY KEY,
  user_id    TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  created_by TEXT,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);

CREATE INDEX login_links_user ON login_links (user_id);

CREATE TABLE clients (
  id                        TEXT PRIMARY KEY,
  name                      TEXT NOT NULL,
  secret_hash               TEXT,                 -- NULL = public client (PKCE)
  redirect_uris             TEXT NOT NULL,        -- JSON array
  post_logout_redirect_uris TEXT NOT NULL,        -- JSON array
  allowed_groups            TEXT NOT NULL,        -- JSON array, empty = everyone
  created_at                INTEGER NOT NULL,
  updated_at                INTEGER NOT NULL
);

CREATE TABLE auth_codes (
  code_hash             TEXT PRIMARY KEY,
  client_id             TEXT NOT NULL REFERENCES clients (id) ON DELETE CASCADE,
  user_id               TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  redirect_uri          TEXT NOT NULL,
  scope                 TEXT NOT NULL,
  nonce                 TEXT,
  code_challenge        TEXT,
  auth_time             INTEGER NOT NULL,
  amr                   TEXT NOT NULL,
  expires_at            INTEGER NOT NULL
);

CREATE TABLE refresh_tokens (
  token_hash TEXT PRIMARY KEY,
  family_id  TEXT NOT NULL,
  client_id  TEXT NOT NULL REFERENCES clients (id) ON DELETE CASCADE,
  user_id    TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  scope      TEXT NOT NULL,
  auth_time  INTEGER NOT NULL,
  amr        TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  used_at    INTEGER,
  revoked_at INTEGER
);

CREATE INDEX refresh_tokens_family ON refresh_tokens (family_id);
CREATE INDEX refresh_tokens_user ON refresh_tokens (user_id);

CREATE TABLE signing_keys (
  kid         TEXT PRIMARY KEY,
  alg         TEXT NOT NULL,
  private_jwk TEXT NOT NULL,                      -- encrypted
  public_jwk  TEXT NOT NULL,
  created_at  INTEGER NOT NULL,
  retired_at  INTEGER                             -- NULL = signing with it
);

CREATE TABLE rate_limits (
  key          TEXT PRIMARY KEY,
  count        INTEGER NOT NULL,
  window_start INTEGER NOT NULL
);

CREATE TABLE audit_log (
  id       INTEGER PRIMARY KEY AUTOINCREMENT,
  at       INTEGER NOT NULL,
  actor_id TEXT,
  action   TEXT NOT NULL,
  target   TEXT,
  ip       TEXT,
  detail   TEXT
);

CREATE INDEX audit_log_at ON audit_log (at);
