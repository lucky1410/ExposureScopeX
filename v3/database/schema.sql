CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TYPE assessment_mode AS ENUM ('light', 'medium', 'aggressive');
CREATE TYPE lifecycle_status AS ENUM (
  'created', 'queued', 'running', 'complete', 'partial', 'failed', 'cancelled'
);
CREATE TYPE stage_status AS ENUM (
  'queued', 'running', 'succeeded', 'failed', 'timed_out', 'skipped', 'blocked', 'cancelled'
);

CREATE TABLE assessments (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL CHECK (length(name) BETWEEN 1 AND 160),
  target text NOT NULL CHECK (length(target) BETWEEN 1 AND 2048),
  mode assessment_mode NOT NULL,
  authorization_confirmed boolean NOT NULL DEFAULT false,
  status lifecycle_status NOT NULL DEFAULT 'created',
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE assessment_scopes (
  assessment_id uuid PRIMARY KEY REFERENCES assessments(id) ON DELETE CASCADE,
  source_format text NOT NULL CHECK (source_format IN ('csv', 'json')),
  source_sha256 char(64) NOT NULL,
  authorization_id text NOT NULL,
  authorization_expires_at timestamptz NOT NULL,
  credential_reference text,
  scope jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE scans (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  assessment_id uuid NOT NULL REFERENCES assessments(id),
  plan_version text NOT NULL,
  plan jsonb NOT NULL,
  status lifecycle_status NOT NULL DEFAULT 'queued',
  started_at timestamptz,
  finished_at timestamptz,
  cancel_requested_at timestamptz,
  failure_reason text,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE stage_runs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_id uuid NOT NULL REFERENCES scans(id),
  position integer NOT NULL CHECK (position >= 0),
  adapter text NOT NULL,
  required boolean NOT NULL DEFAULT true,
  status stage_status NOT NULL DEFAULT 'queued',
  attempt integer NOT NULL DEFAULT 0,
  timeout_seconds integer NOT NULL CHECK (timeout_seconds BETWEEN 1 AND 86400),
  lease_owner text,
  lease_expires_at timestamptz,
  heartbeat_at timestamptz,
  started_at timestamptz,
  finished_at timestamptz,
  error_code text,
  error_detail text,
  live_output text NOT NULL DEFAULT '',
  last_output_at timestamptz,
  output_sequence bigint NOT NULL DEFAULT 0,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (scan_id, position)
);

CREATE INDEX stage_claim_idx ON stage_runs (status, position, created_at)
  WHERE status = 'queued';

CREATE TABLE scan_coverage (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_id uuid NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  stage_run_id uuid REFERENCES stage_runs(id) ON DELETE SET NULL,
  case_id text NOT NULL,
  methodology_version text NOT NULL,
  profile text NOT NULL CHECK (profile IN ('light', 'medium', 'aggressive')),
  family text NOT NULL,
  adapter text NOT NULL,
  title text NOT NULL,
  required boolean NOT NULL,
  status text NOT NULL DEFAULT 'planned' CHECK (status IN (
    'planned', 'running', 'completed', 'failed', 'timed_out',
    'skipped', 'blocked', 'cancelled'
  )),
  reason text,
  started_at timestamptz,
  finished_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (scan_id, case_id)
);

CREATE INDEX scan_coverage_scan_idx ON scan_coverage (scan_id, family, case_id);

CREATE TABLE artifacts (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_id uuid NOT NULL REFERENCES scans(id),
  stage_run_id uuid REFERENCES stage_runs(id),
  kind text NOT NULL,
  storage_key text NOT NULL UNIQUE,
  media_type text NOT NULL,
  sha256 char(64) NOT NULL,
  size_bytes bigint NOT NULL CHECK (size_bytes >= 0),
  captured_at timestamptz NOT NULL,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE findings (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_id uuid NOT NULL REFERENCES scans(id),
  stage_run_id uuid NOT NULL REFERENCES stage_runs(id),
  source_artifact_id uuid NOT NULL REFERENCES artifacts(id),
  fingerprint char(64) NOT NULL,
  title text NOT NULL,
  severity text NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
  confidence integer NOT NULL CHECK (confidence BETWEEN 0 AND 100),
  target text NOT NULL,
  description text NOT NULL,
  remediation text NOT NULL,
  evidence jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (scan_id, fingerprint)
);

CREATE TABLE finding_assurance (
  finding_id uuid PRIMARY KEY REFERENCES findings(id) ON DELETE CASCADE,
  canonical_observation_key text,
  validation_status text NOT NULL DEFAULT 'candidate' CHECK (validation_status IN (
    'candidate', 'confirmed', 'rejected', 'inconclusive'
  )),
  evidence_integrity text NOT NULL DEFAULT 'not_evaluated' CHECK (evidence_integrity IN (
    'not_evaluated', 'passed', 'failed'
  )),
  oracle_status text NOT NULL DEFAULT 'not_evaluated' CHECK (oracle_status IN (
    'not_evaluated', 'passed', 'failed'
  )),
  validation_artifact_id uuid REFERENCES artifacts(id) ON DELETE SET NULL,
  rationale text,
  validated_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX finding_assurance_key_idx
  ON finding_assurance (canonical_observation_key, validation_status);

CREATE TABLE reports (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_id uuid NOT NULL REFERENCES scans(id),
  status text NOT NULL CHECK (status IN ('final', 'partial', 'failed', 'cancelled', 'blocked')),
  manifest jsonb NOT NULL,
  generated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (scan_id)
);

CREATE TABLE scan_events (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  scan_id uuid NOT NULL REFERENCES scans(id),
  event_type text NOT NULL,
  payload jsonb NOT NULL DEFAULT '{}'::jsonb,
  occurred_at timestamptz NOT NULL DEFAULT now()
);

-- Agent control-plane tables are installed by backend migrations because they
-- reference authentication tables that are also migration-managed.
