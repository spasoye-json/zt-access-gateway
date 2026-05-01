-- Phase 7: MFA challenge lifecycle (MFA-01, MFA-07)

CREATE TABLE IF NOT EXISTS mfa_challenges (
  challenge_id text PRIMARY KEY,
  user_id      text NOT NULL,
  created_at   timestamptz NOT NULL DEFAULT NOW(),
  expires_at   timestamptz NOT NULL
);

CREATE INDEX IF NOT EXISTS mfa_challenges_user_created
  ON mfa_challenges (user_id, created_at);

CREATE TABLE IF NOT EXISTS mfa_tokens (
  jti              text PRIMARY KEY,
  user_id          text NOT NULL,
  fingerprint_hash text NOT NULL,
  issued_at        timestamptz NOT NULL DEFAULT NOW(),
  expires_at       timestamptz NOT NULL,
  revoked_at       timestamptz
);

CREATE INDEX IF NOT EXISTS mfa_tokens_user_expires
  ON mfa_tokens (user_id, expires_at);

CREATE TABLE IF NOT EXISTS user_secrets (
  user_id               text PRIMARY KEY,
  totp_secret_encrypted text NOT NULL,
  created_at            timestamptz NOT NULL DEFAULT NOW()
);
