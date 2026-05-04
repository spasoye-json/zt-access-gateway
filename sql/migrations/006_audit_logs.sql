-- Phase 9: Audit + Metrics — audit_logs table (AUDT-01, AUDT-02)

CREATE TABLE IF NOT EXISTS audit_logs (
  id               BIGSERIAL PRIMARY KEY,
  user_id          TEXT NOT NULL,
  resource         TEXT NOT NULL,
  action           TEXT NOT NULL,
  decision         TEXT NOT NULL CHECK (decision IN ('allow', 'challenge', 'deny')),
  trust_score      NUMERIC(4,3),
  ja4h_fingerprint TEXT,
  ip_address       TEXT,
  user_agent       TEXT,
  request_id       TEXT,
  event_type       TEXT,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS audit_logs_user_id    ON audit_logs (user_id);
CREATE INDEX IF NOT EXISTS audit_logs_decision   ON audit_logs (decision);
CREATE INDEX IF NOT EXISTS audit_logs_created_at ON audit_logs (created_at DESC);
