-- Phase 4: trust telemetry (wide scalar columns per D-17)

CREATE TABLE IF NOT EXISTS trust_signals (
  user_id text NOT NULL,
  device_id text NOT NULL,
  ip text NOT NULL,
  ja4h text,
  first_seen_at timestamptz NOT NULL DEFAULT now(),
  last_seen_at timestamptz NOT NULL DEFAULT now(),
  allow_count int NOT NULL DEFAULT 0,
  hour_histogram int[] NOT NULL DEFAULT array_fill(0, ARRAY[24])::int[],
  rate_ema double precision NOT NULL DEFAULT 0,
  rate_ema_var double precision NOT NULL DEFAULT 0,
  anomaly_observations int NOT NULL DEFAULT 0,
  PRIMARY KEY (user_id, device_id, ip)
);

CREATE TABLE IF NOT EXISTS trust_activity (
  id bigserial PRIMARY KEY,
  user_id text NOT NULL,
  ja4h text,
  ip text,
  device_id text NOT NULL,
  score double precision NOT NULL,
  decision text NOT NULL,
  ts timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS trust_activity_user_ts ON trust_activity (user_id, ts DESC);
