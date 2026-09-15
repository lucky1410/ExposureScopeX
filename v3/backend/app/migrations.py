from .db import pool

MIGRATIONS = [
    (
        "001_auth_sessions",
        """
        CREATE TABLE IF NOT EXISTS users (
          id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
          email text NOT NULL UNIQUE,
          display_name text NOT NULL,
          password_hash bytea NOT NULL,
          password_salt bytea NOT NULL,
          role text NOT NULL CHECK (role IN ('owner', 'admin', 'analyst', 'viewer')),
          active boolean NOT NULL DEFAULT true,
          created_at timestamptz NOT NULL DEFAULT now()
        );

        CREATE TABLE IF NOT EXISTS sessions (
          id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
          user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          token_hash char(64) NOT NULL UNIQUE,
          expires_at timestamptz NOT NULL,
          created_at timestamptz NOT NULL DEFAULT now(),
          last_seen_at timestamptz NOT NULL DEFAULT now()
        );

        CREATE INDEX IF NOT EXISTS sessions_expiry_idx ON sessions (expires_at);
        """,
    ),
    (
        "002_agent_control_plane",
        """
        CREATE TABLE IF NOT EXISTS agent_handoffs (
          id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
          assessment_id uuid NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
          scan_id uuid NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
          producer_agent text NOT NULL,
          consumer_agent text NOT NULL,
          message_type text NOT NULL CHECK (message_type IN (
            'observation', 'work_request', 'validation_decision', 'exception', 'result'
          )),
          contract_version text NOT NULL,
          scope_digest char(64) NOT NULL,
          idempotency_key text NOT NULL UNIQUE,
          correlation_id uuid NOT NULL,
          causation_id uuid,
          payload_schema text NOT NULL,
          payload jsonb NOT NULL,
          evidence jsonb NOT NULL DEFAULT '[]'::jsonb,
          confidence double precision CHECK (confidence BETWEEN 0 AND 1),
          safety_class text NOT NULL,
          status text NOT NULL DEFAULT 'pending' CHECK (status IN (
            'pending', 'approved', 'rejected', 'dispatched', 'completed', 'failed'
          )),
          policy_decision jsonb,
          created_at timestamptz NOT NULL DEFAULT now(),
          decided_at timestamptz
        );

        CREATE INDEX IF NOT EXISTS agent_handoffs_scan_idx
          ON agent_handoffs (scan_id, created_at);
        CREATE INDEX IF NOT EXISTS agent_handoffs_pending_idx
          ON agent_handoffs (status, created_at) WHERE status = 'pending';

        CREATE TABLE IF NOT EXISTS agent_evaluations (
          id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
          name text NOT NULL,
          evaluated_agent_id text NOT NULL,
          evaluated_agent_version text NOT NULL,
          evaluator_agent_id text NOT NULL DEFAULT 'ai_quality_evaluator',
          evaluator_version text NOT NULL,
          dataset_version text NOT NULL,
          input_manifest jsonb NOT NULL,
          metrics jsonb NOT NULL,
          release_decision text NOT NULL CHECK (release_decision IN ('pass', 'fail')),
          created_by uuid NOT NULL REFERENCES users(id),
          created_at timestamptz NOT NULL DEFAULT now()
        );

        CREATE INDEX IF NOT EXISTS agent_evaluations_agent_idx
          ON agent_evaluations (evaluated_agent_id, created_at DESC);
        """,
    ),
    (
        "003_authenticated_assessments",
        """
        CREATE TABLE IF NOT EXISTS assessment_authentication (
          assessment_id uuid PRIMARY KEY REFERENCES assessments(id) ON DELETE CASCADE,
          login_url text NOT NULL,
          username_ciphertext bytea NOT NULL,
          password_ciphertext bytea NOT NULL,
          username_selector text NOT NULL,
          password_selector text NOT NULL,
          submit_selector text NOT NULL,
          created_at timestamptz NOT NULL DEFAULT now(),
          updated_at timestamptz NOT NULL DEFAULT now()
        );
        """,
    ),
    (
        "004_finding_impact",
        """
        ALTER TABLE findings ADD COLUMN IF NOT EXISTS business_impact text;
        """,
    ),
    (
        "005_assessment_assurance",
        """
        CREATE TABLE IF NOT EXISTS scan_coverage (
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

        CREATE INDEX IF NOT EXISTS scan_coverage_scan_idx
          ON scan_coverage (scan_id, family, case_id);

        INSERT INTO scan_coverage (
          scan_id, stage_run_id, case_id, methodology_version, profile,
          family, adapter, title, required, status, reason, started_at, finished_at
        )
        SELECT
          sr.scan_id,
          sr.id,
          CASE sr.adapter
            WHEN 'scope_preflight' THEN 'ESX-SCOPE-001'
            WHEN 'http_profile' THEN 'ESX-HTTP-001'
            WHEN 'tls_service_discovery' THEN 'ESX-SERVICE-001'
            WHEN 'authenticated_crawl' THEN 'ESX-CRAWL-001'
            WHEN 'standards_discovery' THEN 'ESX-STANDARDS-001'
            WHEN 'security_headers' THEN 'ESX-HEADERS-001'
            WHEN 'nuclei_baseline' THEN 'ESX-NUCLEI-BASELINE-001'
            WHEN 'evidence_validation' THEN 'ESX-EVIDENCE-001'
          END,
          '1.0.0-draft',
          a.mode::text,
          CASE sr.adapter
            WHEN 'scope_preflight' THEN 'scope_authorization'
            WHEN 'http_profile' THEN 'attack_surface'
            WHEN 'tls_service_discovery' THEN 'service_tls_http_configuration'
            WHEN 'authenticated_crawl' THEN 'attack_surface'
            WHEN 'standards_discovery' THEN 'attack_surface'
            WHEN 'security_headers' THEN 'service_tls_http_configuration'
            WHEN 'nuclei_baseline' THEN 'attack_surface'
            WHEN 'evidence_validation' THEN 'evidence_validation'
          END,
          sr.adapter,
          CASE sr.adapter
            WHEN 'scope_preflight' THEN 'Authorization and target scope preflight'
            WHEN 'http_profile' THEN 'HTTP reachability and response profile'
            WHEN 'tls_service_discovery' THEN 'Service and TLS discovery'
            WHEN 'authenticated_crawl' THEN 'Same-origin route and authenticated-state inventory'
            WHEN 'standards_discovery' THEN 'Published security and API metadata discovery'
            WHEN 'security_headers' THEN 'HTTP security policy header assessment'
            WHEN 'nuclei_baseline' THEN 'Approved signed non-intrusive template baseline'
            WHEN 'evidence_validation' THEN 'Evidence integrity validation'
          END,
          sr.required,
          CASE sr.status::text
            WHEN 'queued' THEN 'planned'
            WHEN 'succeeded' THEN 'completed'
            ELSE sr.status::text
          END,
          sr.error_detail,
          sr.started_at,
          sr.finished_at
        FROM stage_runs sr
        JOIN scans s ON s.id = sr.scan_id
        JOIN assessments a ON a.id = s.assessment_id
        WHERE sr.adapter IN (
          'scope_preflight', 'http_profile', 'tls_service_discovery',
          'authenticated_crawl', 'standards_discovery', 'security_headers',
          'nuclei_baseline', 'evidence_validation'
        )
        ON CONFLICT (scan_id, case_id) DO NOTHING;

        CREATE TABLE IF NOT EXISTS finding_assurance (
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
          rationale text,
          validated_at timestamptz,
          created_at timestamptz NOT NULL DEFAULT now(),
          updated_at timestamptz NOT NULL DEFAULT now()
        );

        CREATE INDEX IF NOT EXISTS finding_assurance_key_idx
          ON finding_assurance (canonical_observation_key, validation_status);

        INSERT INTO finding_assurance (
          finding_id, canonical_observation_key, validation_status,
          evidence_integrity, oracle_status, rationale
        )
        SELECT
          f.id,
          CASE
            WHEN f.evidence->>'evidence_type' = 'http_response_header_absence'
              AND COALESCE(f.evidence->>'header_name', '') <> ''
              THEN 'http.header.absent:' || lower(f.evidence->>'header_name')
            WHEN COALESCE(f.evidence->>'template_id', '') <> ''
              THEN 'nuclei.template:' || lower(f.evidence->>'template_id')
            ELSE NULL
          END,
          'candidate', 'not_evaluated', 'not_evaluated',
          'Backfilled from a historical finding; rerun independent validation before confirmation.'
        FROM findings f
        ON CONFLICT (finding_id) DO NOTHING;
        """,
    ),
    (
        "006_assurance_replay_artifact",
        """
        ALTER TABLE finding_assurance
          ADD COLUMN IF NOT EXISTS validation_artifact_id uuid REFERENCES artifacts(id) ON DELETE SET NULL;
        """,
    ),
    (
        "007_stage_live_output",
        """
        ALTER TABLE stage_runs ADD COLUMN IF NOT EXISTS live_output text NOT NULL DEFAULT '';
        ALTER TABLE stage_runs ADD COLUMN IF NOT EXISTS last_output_at timestamptz;
        ALTER TABLE stage_runs ADD COLUMN IF NOT EXISTS output_sequence bigint NOT NULL DEFAULT 0;
        """,
    ),
    (
        "008_assessment_scope_files",
        """
        CREATE TABLE IF NOT EXISTS assessment_scopes (
          assessment_id uuid PRIMARY KEY REFERENCES assessments(id) ON DELETE CASCADE,
          source_format text NOT NULL CHECK (source_format IN ('csv', 'json')),
          source_sha256 char(64) NOT NULL,
          authorization_id text NOT NULL,
          authorization_expires_at timestamptz NOT NULL,
          credential_reference text,
          scope jsonb NOT NULL,
          created_at timestamptz NOT NULL DEFAULT now()
        );
        CREATE INDEX IF NOT EXISTS assessment_scopes_expiry_idx
          ON assessment_scopes (authorization_expires_at);
        """,
    ),
    (
        "009_report_terminal_states",
        """
        ALTER TABLE reports DROP CONSTRAINT IF EXISTS reports_status_check;
        ALTER TABLE reports
          ADD CONSTRAINT reports_status_check
          CHECK (status IN ('final', 'partial', 'failed', 'cancelled', 'blocked'));
        """,
    ),
    (
        "010_scan_cancellation",
        """
        ALTER TABLE scans ADD COLUMN IF NOT EXISTS cancel_requested_at timestamptz;
        """,
    ),
    (
        "011_evaluation_inconclusive_decision",
        """
        ALTER TABLE agent_evaluations
          DROP CONSTRAINT IF EXISTS agent_evaluations_release_decision_check;
        ALTER TABLE agent_evaluations
          ADD CONSTRAINT agent_evaluations_release_decision_check
          CHECK (release_decision IN ('pass', 'fail', 'inconclusive'));
        """,
    ),
    (
        "012_semantic_evaluation_runs",
        """
        CREATE TABLE IF NOT EXISTS semantic_evaluation_runs (
          id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
          name text NOT NULL,
          subject_id text NOT NULL,
          subject_version text NOT NULL,
          dataset_version text NOT NULL,
          data_classification text NOT NULL CHECK (data_classification IN (
            'synthetic', 'public', 'internal', 'restricted'
          )),
          provider text NOT NULL,
          requested_model text NOT NULL,
          prompt_version text NOT NULL,
          status text NOT NULL DEFAULT 'running' CHECK (status IN (
            'running', 'completed', 'failed'
          )),
          input_manifest jsonb NOT NULL,
          result jsonb,
          error_code text,
          error_detail text,
          created_by uuid NOT NULL REFERENCES users(id),
          created_at timestamptz NOT NULL DEFAULT now(),
          completed_at timestamptz
        );

        CREATE INDEX IF NOT EXISTS semantic_evaluation_runs_subject_idx
          ON semantic_evaluation_runs (subject_id, created_at DESC);
        CREATE INDEX IF NOT EXISTS semantic_evaluation_runs_status_idx
          ON semantic_evaluation_runs (status, created_at DESC);
        """,
    ),
    (
        "013_evaluation_reports",
        """
        CREATE TABLE IF NOT EXISTS evaluation_reports (
          id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
          evaluation_id uuid NOT NULL REFERENCES agent_evaluations(id) ON DELETE CASCADE,
          report_format text NOT NULL CHECK (report_format IN ('docx', 'pdf')),
          renderer_version text NOT NULL,
          source_sha256 char(64) NOT NULL,
          content_sha256 char(64) NOT NULL,
          storage_key text NOT NULL UNIQUE,
          size_bytes bigint NOT NULL CHECK (size_bytes >= 0),
          generated_by uuid NOT NULL REFERENCES users(id),
          generated_at timestamptz NOT NULL DEFAULT now(),
          UNIQUE (evaluation_id, report_format, renderer_version)
        );

        CREATE INDEX IF NOT EXISTS evaluation_reports_evaluation_idx
          ON evaluation_reports (evaluation_id, generated_at DESC);
        """,
    ),
    (
        "014_evaluator_enterprise_workspaces",
        """
        CREATE TABLE IF NOT EXISTS organizations (
          id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
          name text NOT NULL CHECK (length(name) BETWEEN 2 AND 160),
          slug text NOT NULL UNIQUE CHECK (slug ~ '^[a-z0-9-]{3,64}$'),
          owner_user_id uuid NOT NULL UNIQUE REFERENCES users(id) ON DELETE RESTRICT,
          active boolean NOT NULL DEFAULT true,
          created_at timestamptz NOT NULL DEFAULT now()
        );

        CREATE TABLE IF NOT EXISTS organization_memberships (
          organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
          user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          role text NOT NULL CHECK (role IN ('owner', 'admin', 'analyst', 'viewer')),
          joined_at timestamptz NOT NULL DEFAULT now(),
          PRIMARY KEY (organization_id, user_id)
        );

        CREATE INDEX IF NOT EXISTS organization_memberships_user_idx
          ON organization_memberships (user_id, organization_id);

        INSERT INTO organizations (name, slug, owner_user_id)
        SELECT
          left(u.display_name || ' Workspace', 160),
          'legacy-' || replace(u.id::text, '-', ''),
          u.id
        FROM users u
        LEFT JOIN organizations o ON o.owner_user_id = u.id
        WHERE o.id IS NULL;

        INSERT INTO organization_memberships (organization_id, user_id, role)
        SELECT
          o.id,
          o.owner_user_id,
          CASE u.role WHEN 'owner' THEN 'owner' WHEN 'admin' THEN 'admin'
                      WHEN 'analyst' THEN 'analyst' ELSE 'viewer' END
        FROM organizations o
        JOIN users u ON u.id = o.owner_user_id
        ON CONFLICT (organization_id, user_id) DO NOTHING;

        CREATE TABLE IF NOT EXISTS evaluator_projects (
          id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
          organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
          key text NOT NULL CHECK (key ~ '^[a-z][a-z0-9-]{1,62}$'),
          name text NOT NULL CHECK (length(name) BETWEEN 2 AND 160),
          description text NOT NULL DEFAULT '',
          status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'archived')),
          created_by uuid NOT NULL REFERENCES users(id),
          created_at timestamptz NOT NULL DEFAULT now(),
          UNIQUE (organization_id, key)
        );

        INSERT INTO evaluator_projects (organization_id, key, name, description, created_by)
        SELECT o.id, 'default', 'Default Evaluation Program',
               'Migrated default evaluator project.', o.owner_user_id
        FROM organizations o
        ON CONFLICT (organization_id, key) DO NOTHING;

        CREATE TABLE IF NOT EXISTS evaluator_datasets (
          id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
          project_id uuid NOT NULL REFERENCES evaluator_projects(id) ON DELETE CASCADE,
          name text NOT NULL CHECK (length(name) BETWEEN 2 AND 160),
          version text NOT NULL CHECK (length(version) BETWEEN 1 AND 100),
          classification text NOT NULL CHECK (classification IN ('synthetic', 'public', 'internal', 'restricted')),
          source_sha256 char(64) NOT NULL,
          source_reference text NOT NULL,
          status text NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'approved', 'retired')),
          created_by uuid NOT NULL REFERENCES users(id),
          approved_by uuid REFERENCES users(id),
          approved_at timestamptz,
          created_at timestamptz NOT NULL DEFAULT now(),
          UNIQUE (project_id, version)
        );

        ALTER TABLE agent_evaluations
          ADD COLUMN IF NOT EXISTS organization_id uuid REFERENCES organizations(id),
          ADD COLUMN IF NOT EXISTS project_id uuid REFERENCES evaluator_projects(id),
          ADD COLUMN IF NOT EXISTS dataset_id uuid REFERENCES evaluator_datasets(id);
        ALTER TABLE semantic_evaluation_runs
          ADD COLUMN IF NOT EXISTS organization_id uuid REFERENCES organizations(id),
          ADD COLUMN IF NOT EXISTS project_id uuid REFERENCES evaluator_projects(id),
          ADD COLUMN IF NOT EXISTS dataset_id uuid REFERENCES evaluator_datasets(id);

        UPDATE agent_evaluations e
        SET organization_id = m.organization_id
        FROM organization_memberships m
        WHERE m.user_id = e.created_by AND e.organization_id IS NULL;
        UPDATE semantic_evaluation_runs e
        SET organization_id = m.organization_id
        FROM organization_memberships m
        WHERE m.user_id = e.created_by AND e.organization_id IS NULL;

        INSERT INTO evaluator_datasets (
          project_id, name, version, classification, source_sha256,
          source_reference, status, created_by, approved_by, approved_at
        )
        SELECT DISTINCT ON (e.organization_id, e.dataset_version)
          p.id,
          left(e.dataset_version || ' historical dataset', 160),
          e.dataset_version,
          'synthetic',
          encode(digest('historical:' || e.organization_id::text || ':' || e.dataset_version, 'sha256'), 'hex'),
          'Historical evaluator record imported during workspace migration.',
          'approved',
          e.created_by,
          e.created_by,
          now()
        FROM agent_evaluations e
        JOIN evaluator_projects p ON p.organization_id = e.organization_id AND p.key = 'default'
        WHERE e.organization_id IS NOT NULL
        ORDER BY e.organization_id, e.dataset_version, e.created_at;

        UPDATE agent_evaluations e
        SET project_id = p.id
        FROM evaluator_projects p
        WHERE e.organization_id = p.organization_id AND p.key = 'default' AND e.project_id IS NULL;
        UPDATE agent_evaluations e
        SET dataset_id = d.id
        FROM evaluator_projects p, evaluator_datasets d
        WHERE e.project_id = p.id
          AND d.project_id = p.id
          AND d.version = e.dataset_version
          AND e.dataset_id IS NULL;
        UPDATE semantic_evaluation_runs e
        SET project_id = p.id
        FROM evaluator_projects p
        WHERE e.organization_id = p.organization_id AND p.key = 'default' AND e.project_id IS NULL;

        ALTER TABLE agent_evaluations
          ALTER COLUMN organization_id SET NOT NULL,
          ALTER COLUMN project_id SET NOT NULL,
          ALTER COLUMN dataset_id SET NOT NULL;
        ALTER TABLE semantic_evaluation_runs
          ALTER COLUMN organization_id SET NOT NULL,
          ALTER COLUMN project_id SET NOT NULL;

        CREATE INDEX IF NOT EXISTS agent_evaluations_workspace_idx
          ON agent_evaluations (organization_id, project_id, created_at DESC);
        CREATE INDEX IF NOT EXISTS semantic_evaluation_runs_workspace_idx
          ON semantic_evaluation_runs (organization_id, project_id, created_at DESC);

        CREATE TABLE IF NOT EXISTS evaluator_audit_events (
          id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
          organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
          actor_id uuid NOT NULL REFERENCES users(id),
          event_type text NOT NULL,
          target_type text NOT NULL,
          target_id uuid,
          payload jsonb NOT NULL DEFAULT '{}'::jsonb,
          occurred_at timestamptz NOT NULL DEFAULT now()
        );

        CREATE INDEX IF NOT EXISTS evaluator_audit_events_workspace_idx
          ON evaluator_audit_events (organization_id, occurred_at DESC);

        -- Evaluator decisions and their governance history are append-only.
        -- Corrections require a new evaluation rather than altering past release evidence.
        CREATE OR REPLACE FUNCTION esx_prevent_evaluator_record_mutation()
        RETURNS trigger AS $$
        BEGIN
          RAISE EXCEPTION 'evaluator records are immutable; create a new evaluation or report revision';
        END;
        $$ LANGUAGE plpgsql;

        CREATE OR REPLACE FUNCTION esx_protect_evaluator_dataset_provenance()
        RETURNS trigger AS $$
        BEGIN
          IF NEW.project_id IS DISTINCT FROM OLD.project_id
             OR NEW.name IS DISTINCT FROM OLD.name
             OR NEW.version IS DISTINCT FROM OLD.version
             OR NEW.classification IS DISTINCT FROM OLD.classification
             OR NEW.source_sha256 IS DISTINCT FROM OLD.source_sha256
             OR NEW.source_reference IS DISTINCT FROM OLD.source_reference
             OR NEW.created_by IS DISTINCT FROM OLD.created_by
             OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
            RAISE EXCEPTION 'evaluator dataset provenance is immutable; register a new dataset version';
          END IF;
          RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;

        DROP TRIGGER IF EXISTS evaluator_datasets_provenance_immutable ON evaluator_datasets;
        CREATE TRIGGER evaluator_datasets_provenance_immutable
          BEFORE UPDATE ON evaluator_datasets
          FOR EACH ROW EXECUTE FUNCTION esx_protect_evaluator_dataset_provenance();

        DROP TRIGGER IF EXISTS agent_evaluations_immutable ON agent_evaluations;
        CREATE TRIGGER agent_evaluations_immutable
          BEFORE UPDATE OR DELETE ON agent_evaluations
          FOR EACH ROW EXECUTE FUNCTION esx_prevent_evaluator_record_mutation();

        DROP TRIGGER IF EXISTS evaluation_reports_immutable ON evaluation_reports;
        CREATE TRIGGER evaluation_reports_immutable
          BEFORE UPDATE OR DELETE ON evaluation_reports
          FOR EACH ROW EXECUTE FUNCTION esx_prevent_evaluator_record_mutation();

        DROP TRIGGER IF EXISTS evaluator_audit_events_immutable ON evaluator_audit_events;
        CREATE TRIGGER evaluator_audit_events_immutable
          BEFORE UPDATE OR DELETE ON evaluator_audit_events
          FOR EACH ROW EXECUTE FUNCTION esx_prevent_evaluator_record_mutation();
        """,
    ),
    (
        "015_evaluator_live_adapters",
        """
        CREATE TABLE IF NOT EXISTS evaluator_live_adapters (
          id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
          organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
          project_id uuid NOT NULL REFERENCES evaluator_projects(id) ON DELETE CASCADE,
          name text NOT NULL CHECK (length(name) BETWEEN 2 AND 160),
          adapter_type text NOT NULL CHECK (adapter_type IN ('http_json_v1')),
          endpoint_url text NOT NULL CHECK (length(endpoint_url) BETWEEN 12 AND 512),
          endpoint_sha256 char(64) NOT NULL,
          credential_ciphertext bytea NOT NULL,
          status text NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'approved', 'disabled')),
          created_by uuid NOT NULL REFERENCES users(id),
          approved_by uuid REFERENCES users(id),
          approved_at timestamptz,
          disabled_by uuid REFERENCES users(id),
          disabled_at timestamptz,
          created_at timestamptz NOT NULL DEFAULT now(),
          UNIQUE (project_id, name),
          UNIQUE (project_id, endpoint_sha256)
        );

        CREATE INDEX IF NOT EXISTS evaluator_live_adapters_workspace_idx
          ON evaluator_live_adapters (organization_id, project_id, status, created_at DESC);

        CREATE OR REPLACE FUNCTION esx_protect_evaluator_live_adapter()
        RETURNS trigger AS $$
        BEGIN
          IF NEW.organization_id IS DISTINCT FROM OLD.organization_id
             OR NEW.project_id IS DISTINCT FROM OLD.project_id
             OR NEW.name IS DISTINCT FROM OLD.name
             OR NEW.adapter_type IS DISTINCT FROM OLD.adapter_type
             OR NEW.endpoint_url IS DISTINCT FROM OLD.endpoint_url
             OR NEW.endpoint_sha256 IS DISTINCT FROM OLD.endpoint_sha256
             OR NEW.credential_ciphertext IS DISTINCT FROM OLD.credential_ciphertext
             OR NEW.created_by IS DISTINCT FROM OLD.created_by
             OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
            RAISE EXCEPTION 'live adapter configuration is immutable; register a replacement adapter';
          END IF;
          IF OLD.status = 'disabled' AND NEW.status IS DISTINCT FROM 'disabled' THEN
            RAISE EXCEPTION 'disabled live adapters cannot be re-enabled; register a replacement adapter';
          END IF;
          IF OLD.status = 'draft' AND NEW.status = 'approved'
             AND NEW.approved_by IS NOT NULL AND NEW.approved_at IS NOT NULL
             AND NEW.disabled_by IS NULL AND NEW.disabled_at IS NULL THEN
            RETURN NEW;
          END IF;
          IF OLD.status IN ('draft', 'approved') AND NEW.status = 'disabled'
             AND NEW.disabled_by IS NOT NULL AND NEW.disabled_at IS NOT NULL THEN
            RETURN NEW;
          END IF;
          RAISE EXCEPTION 'invalid live adapter lifecycle transition';
        END;
        $$ LANGUAGE plpgsql;

        DROP TRIGGER IF EXISTS evaluator_live_adapters_immutable ON evaluator_live_adapters;
        CREATE TRIGGER evaluator_live_adapters_immutable
          BEFORE UPDATE OR DELETE ON evaluator_live_adapters
          FOR EACH ROW EXECUTE FUNCTION esx_protect_evaluator_live_adapter();
        """,
    ),
    (
        "016_evaluator_client_runner_integrations",
        """
        CREATE TABLE IF NOT EXISTS evaluator_client_identities (
          id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
          organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
          project_id uuid NOT NULL REFERENCES evaluator_projects(id) ON DELETE CASCADE,
          name text NOT NULL CHECK (length(name) BETWEEN 2 AND 160),
          identity_type text NOT NULL CHECK (identity_type IN ('ed25519')),
          public_key text NOT NULL CHECK (length(public_key) BETWEEN 40 AND 128),
          key_fingerprint char(64) NOT NULL,
          status text NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'approved', 'disabled')),
          created_by uuid NOT NULL REFERENCES users(id),
          approved_by uuid REFERENCES users(id),
          approved_at timestamptz,
          disabled_by uuid REFERENCES users(id),
          disabled_at timestamptz,
          created_at timestamptz NOT NULL DEFAULT now(),
          UNIQUE (project_id, name),
          UNIQUE (project_id, key_fingerprint)
        );

        CREATE TABLE IF NOT EXISTS evaluator_github_integrations (
          id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
          organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
          project_id uuid NOT NULL REFERENCES evaluator_projects(id) ON DELETE CASCADE,
          name text NOT NULL CHECK (length(name) BETWEEN 2 AND 160),
          repository text NOT NULL CHECK (repository ~ '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$'),
          workflow_ref text NOT NULL CHECK (length(workflow_ref) BETWEEN 20 AND 512),
          oidc_audience text NOT NULL CHECK (length(oidc_audience) BETWEEN 2 AND 160),
          status text NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'approved', 'disabled')),
          created_by uuid NOT NULL REFERENCES users(id),
          approved_by uuid REFERENCES users(id),
          approved_at timestamptz,
          disabled_by uuid REFERENCES users(id),
          disabled_at timestamptz,
          created_at timestamptz NOT NULL DEFAULT now(),
          UNIQUE (project_id, name),
          UNIQUE (project_id, repository, workflow_ref)
        );

        CREATE TABLE IF NOT EXISTS evaluator_client_submissions (
          id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
          organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
          project_id uuid NOT NULL REFERENCES evaluator_projects(id) ON DELETE CASCADE,
          evaluation_id uuid NOT NULL UNIQUE REFERENCES agent_evaluations(id) ON DELETE RESTRICT,
          package_id uuid NOT NULL UNIQUE,
          package_sha256 char(64) NOT NULL,
          auth_type text NOT NULL CHECK (auth_type IN ('ed25519', 'github_actions_oidc')),
          client_identity_id uuid REFERENCES evaluator_client_identities(id) ON DELETE RESTRICT,
          github_integration_id uuid REFERENCES evaluator_github_integrations(id) ON DELETE RESTRICT,
          source_attestation jsonb NOT NULL,
          received_at timestamptz NOT NULL DEFAULT now(),
          CHECK (
            (auth_type = 'ed25519' AND client_identity_id IS NOT NULL AND github_integration_id IS NULL)
            OR
            (auth_type = 'github_actions_oidc' AND github_integration_id IS NOT NULL AND client_identity_id IS NULL)
          )
        );

        CREATE INDEX IF NOT EXISTS evaluator_client_identities_workspace_idx
          ON evaluator_client_identities (organization_id, project_id, status, created_at DESC);
        CREATE INDEX IF NOT EXISTS evaluator_github_integrations_workspace_idx
          ON evaluator_github_integrations (organization_id, project_id, status, created_at DESC);
        CREATE INDEX IF NOT EXISTS evaluator_client_submissions_workspace_idx
          ON evaluator_client_submissions (organization_id, project_id, received_at DESC);

        CREATE OR REPLACE FUNCTION esx_protect_evaluator_client_identity()
        RETURNS trigger AS $$
        BEGIN
          IF NEW.organization_id IS DISTINCT FROM OLD.organization_id
             OR NEW.project_id IS DISTINCT FROM OLD.project_id
             OR NEW.name IS DISTINCT FROM OLD.name
             OR NEW.identity_type IS DISTINCT FROM OLD.identity_type
             OR NEW.public_key IS DISTINCT FROM OLD.public_key
             OR NEW.key_fingerprint IS DISTINCT FROM OLD.key_fingerprint
             OR NEW.created_by IS DISTINCT FROM OLD.created_by
             OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
            RAISE EXCEPTION 'client identity configuration is immutable; register a replacement identity';
          END IF;
          IF OLD.status = 'disabled' AND NEW.status IS DISTINCT FROM 'disabled' THEN
            RAISE EXCEPTION 'disabled client identities cannot be re-enabled; register a replacement identity';
          END IF;
          IF OLD.status = 'draft' AND NEW.status = 'approved'
             AND NEW.approved_by IS NOT NULL AND NEW.approved_at IS NOT NULL
             AND NEW.disabled_by IS NULL AND NEW.disabled_at IS NULL THEN
            RETURN NEW;
          END IF;
          IF OLD.status IN ('draft', 'approved') AND NEW.status = 'disabled'
             AND NEW.disabled_by IS NOT NULL AND NEW.disabled_at IS NOT NULL THEN
            RETURN NEW;
          END IF;
          RAISE EXCEPTION 'invalid client identity lifecycle transition';
        END;
        $$ LANGUAGE plpgsql;

        CREATE OR REPLACE FUNCTION esx_protect_evaluator_github_integration()
        RETURNS trigger AS $$
        BEGIN
          IF NEW.organization_id IS DISTINCT FROM OLD.organization_id
             OR NEW.project_id IS DISTINCT FROM OLD.project_id
             OR NEW.name IS DISTINCT FROM OLD.name
             OR NEW.repository IS DISTINCT FROM OLD.repository
             OR NEW.workflow_ref IS DISTINCT FROM OLD.workflow_ref
             OR NEW.oidc_audience IS DISTINCT FROM OLD.oidc_audience
             OR NEW.created_by IS DISTINCT FROM OLD.created_by
             OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
            RAISE EXCEPTION 'GitHub integration configuration is immutable; register a replacement integration';
          END IF;
          IF OLD.status = 'disabled' AND NEW.status IS DISTINCT FROM 'disabled' THEN
            RAISE EXCEPTION 'disabled GitHub integrations cannot be re-enabled; register a replacement integration';
          END IF;
          IF OLD.status = 'draft' AND NEW.status = 'approved'
             AND NEW.approved_by IS NOT NULL AND NEW.approved_at IS NOT NULL
             AND NEW.disabled_by IS NULL AND NEW.disabled_at IS NULL THEN
            RETURN NEW;
          END IF;
          IF OLD.status IN ('draft', 'approved') AND NEW.status = 'disabled'
             AND NEW.disabled_by IS NOT NULL AND NEW.disabled_at IS NOT NULL THEN
            RETURN NEW;
          END IF;
          RAISE EXCEPTION 'invalid GitHub integration lifecycle transition';
        END;
        $$ LANGUAGE plpgsql;

        DROP TRIGGER IF EXISTS evaluator_client_identities_immutable ON evaluator_client_identities;
        CREATE TRIGGER evaluator_client_identities_immutable
          BEFORE UPDATE ON evaluator_client_identities
          FOR EACH ROW EXECUTE FUNCTION esx_protect_evaluator_client_identity();

        DROP TRIGGER IF EXISTS evaluator_github_integrations_immutable ON evaluator_github_integrations;
        CREATE TRIGGER evaluator_github_integrations_immutable
          BEFORE UPDATE ON evaluator_github_integrations
          FOR EACH ROW EXECUTE FUNCTION esx_protect_evaluator_github_integration();

        DROP TRIGGER IF EXISTS evaluator_client_submissions_immutable ON evaluator_client_submissions;
        CREATE TRIGGER evaluator_client_submissions_immutable
          BEFORE UPDATE OR DELETE ON evaluator_client_submissions
          FOR EACH ROW EXECUTE FUNCTION esx_prevent_evaluator_record_mutation();
        """,
    ),
    (
        "017_approved_subdomain_followups",
        """
        CREATE TABLE IF NOT EXISTS subdomain_assessment_origins (
          child_assessment_id uuid PRIMARY KEY REFERENCES assessments(id) ON DELETE CASCADE,
          parent_assessment_id uuid NOT NULL REFERENCES assessments(id) ON DELETE RESTRICT,
          source_artifact_id uuid NOT NULL REFERENCES artifacts(id) ON DELETE RESTRICT,
          source_artifact_sha256 char(64) NOT NULL,
          hostname text NOT NULL,
          approved_by uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
          created_at timestamptz NOT NULL DEFAULT now()
        );

        CREATE INDEX IF NOT EXISTS subdomain_assessment_origins_parent_idx
          ON subdomain_assessment_origins (parent_assessment_id, created_at DESC);

        CREATE OR REPLACE FUNCTION esx_prevent_subdomain_origin_mutation()
        RETURNS trigger AS $$
        BEGIN
          RAISE EXCEPTION 'subdomain approval provenance is immutable';
        END;
        $$ LANGUAGE plpgsql;

        DROP TRIGGER IF EXISTS subdomain_assessment_origins_immutable ON subdomain_assessment_origins;
        CREATE TRIGGER subdomain_assessment_origins_immutable
          BEFORE UPDATE OR DELETE ON subdomain_assessment_origins
          FOR EACH ROW EXECUTE FUNCTION esx_prevent_subdomain_origin_mutation();
        """,
    ),
    (
        "018_assessment_asset_inventory",
        """
        CREATE TABLE IF NOT EXISTS assessment_assets (
          id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
          assessment_id uuid NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
          hostname text NOT NULL,
          canonical_target text NOT NULL,
          asset_type text NOT NULL DEFAULT 'hostname' CHECK (asset_type IN ('hostname', 'ip_address', 'web_application')),
          discovery_sources jsonb NOT NULL DEFAULT '[]'::jsonb,
          discovery_evidence jsonb NOT NULL DEFAULT '{}'::jsonb,
          ownership_status text NOT NULL CHECK (ownership_status IN ('client_declared', 'candidate', 'approved', 'excluded')),
          ownership_confidence integer NOT NULL CHECK (ownership_confidence BETWEEN 0 AND 100),
          assessment_status text NOT NULL DEFAULT 'not_assessed' CHECK (assessment_status IN ('not_assessed', 'approved_for_assessment', 'queued', 'assessed', 'blocked')),
          review_note text,
          reviewed_by uuid REFERENCES users(id) ON DELETE SET NULL,
          reviewed_at timestamptz,
          first_seen_at timestamptz NOT NULL DEFAULT now(),
          last_seen_at timestamptz NOT NULL DEFAULT now(),
          created_at timestamptz NOT NULL DEFAULT now(),
          updated_at timestamptz NOT NULL DEFAULT now(),
          UNIQUE (assessment_id, hostname)
        );

        CREATE INDEX IF NOT EXISTS assessment_assets_assessment_idx
          ON assessment_assets (assessment_id, ownership_status, assessment_status, last_seen_at DESC);

        CREATE TABLE IF NOT EXISTS assessment_asset_scans (
          assessment_asset_id uuid NOT NULL REFERENCES assessment_assets(id) ON DELETE CASCADE,
          scan_id uuid NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
          created_at timestamptz NOT NULL DEFAULT now(),
          PRIMARY KEY (assessment_asset_id, scan_id)
        );

        CREATE INDEX IF NOT EXISTS assessment_asset_scans_scan_idx
          ON assessment_asset_scans (scan_id);

        INSERT INTO assessment_assets (
          assessment_id, hostname, canonical_target, asset_type, discovery_sources,
          discovery_evidence, ownership_status, ownership_confidence, assessment_status
        )
        SELECT
          a.id,
          lower(regexp_replace(split_part(a.target, '://', 2), '[:/?#].*$', '')),
          a.target,
          'web_application',
          jsonb_build_array('client_declared_seed'),
          jsonb_build_object('target', a.target, 'source', 'client_declared_seed'),
          'client_declared',
          100,
          CASE WHEN a.authorization_confirmed THEN 'approved_for_assessment' ELSE 'not_assessed' END
        FROM assessments a
        WHERE lower(regexp_replace(split_part(a.target, '://', 2), '[:/?#].*$', '')) <> ''
        ON CONFLICT (assessment_id, hostname) DO NOTHING;

        INSERT INTO assessment_asset_scans (assessment_asset_id, scan_id)
        SELECT aa.id, s.id
        FROM assessment_assets aa
        JOIN scans s ON s.assessment_id = aa.assessment_id
        WHERE aa.canonical_target = (SELECT target FROM assessments WHERE id = aa.assessment_id)
        ON CONFLICT DO NOTHING;
        """,
    ),
    (
        "019_exposure_management_foundation",
        """
        -- Assessment records predate organization workspaces.  Associate historical
        -- work with the owner's workspace before adding organization-scoped controls.
        ALTER TABLE assessments
          ADD COLUMN IF NOT EXISTS organization_id uuid REFERENCES organizations(id),
          ADD COLUMN IF NOT EXISTS created_by uuid REFERENCES users(id),
          ADD COLUMN IF NOT EXISTS service_tier text NOT NULL DEFAULT 'external_baseline'
            CHECK (service_tier IN ('external_baseline', 'authorized_deep'));

        UPDATE assessments a
        SET organization_id = workspace.organization_id,
            created_by = workspace.owner_user_id
        FROM LATERAL (
          SELECT o.id AS organization_id, o.owner_user_id
          FROM organizations o
          ORDER BY o.created_at
          LIMIT 1
        ) workspace
        WHERE a.organization_id IS NULL;

        ALTER TABLE assessments
          ALTER COLUMN organization_id SET NOT NULL,
          ALTER COLUMN created_by SET NOT NULL;
        CREATE INDEX IF NOT EXISTS assessments_organization_idx
          ON assessments (organization_id, created_at DESC);
        ALTER TABLE assessment_assets
          ADD COLUMN IF NOT EXISTS exposure_asset_id uuid;

        CREATE TABLE IF NOT EXISTS exposure_assets (
          id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
          organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
          hostname text NOT NULL,
          canonical_target text NOT NULL,
          asset_type text NOT NULL CHECK (asset_type IN ('hostname', 'ip_address', 'web_application', 'api')),
          ownership_status text NOT NULL CHECK (ownership_status IN ('candidate', 'client_declared', 'verified', 'excluded')),
          ownership_confidence integer NOT NULL CHECK (ownership_confidence BETWEEN 0 AND 100),
          ownership_evidence jsonb NOT NULL DEFAULT '{}'::jsonb,
          discovery_sources jsonb NOT NULL DEFAULT '[]'::jsonb,
          lifecycle_status text NOT NULL DEFAULT 'active' CHECK (lifecycle_status IN ('active', 'retired')),
          first_seen_at timestamptz NOT NULL DEFAULT now(),
          last_seen_at timestamptz NOT NULL DEFAULT now(),
          last_verified_at timestamptz,
          reviewed_by uuid REFERENCES users(id) ON DELETE SET NULL,
          reviewed_at timestamptz,
          created_at timestamptz NOT NULL DEFAULT now(),
          updated_at timestamptz NOT NULL DEFAULT now(),
          UNIQUE (organization_id, hostname)
        );
        CREATE INDEX IF NOT EXISTS exposure_assets_workspace_idx
          ON exposure_assets (organization_id, ownership_status, lifecycle_status, last_seen_at DESC);

        ALTER TABLE assessment_assets
          ADD CONSTRAINT assessment_assets_exposure_asset_fk
          FOREIGN KEY (exposure_asset_id) REFERENCES exposure_assets(id) ON DELETE SET NULL;
        CREATE INDEX IF NOT EXISTS assessment_assets_exposure_asset_idx
          ON assessment_assets (exposure_asset_id);

        CREATE TABLE IF NOT EXISTS exposure_asset_observations (
          id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
          organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
          asset_id uuid NOT NULL REFERENCES exposure_assets(id) ON DELETE CASCADE,
          source text NOT NULL,
          source_reference text,
          payload_sha256 char(64) NOT NULL,
          payload jsonb NOT NULL DEFAULT '{}'::jsonb,
          observed_at timestamptz NOT NULL DEFAULT now(),
          created_at timestamptz NOT NULL DEFAULT now(),
          UNIQUE (asset_id, source, payload_sha256)
        );
        CREATE INDEX IF NOT EXISTS exposure_asset_observations_asset_idx
          ON exposure_asset_observations (asset_id, observed_at DESC);

        CREATE TABLE IF NOT EXISTS exposure_asset_relations (
          id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
          organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
          source_asset_id uuid NOT NULL REFERENCES exposure_assets(id) ON DELETE CASCADE,
          target_asset_id uuid NOT NULL REFERENCES exposure_assets(id) ON DELETE CASCADE,
          relation_type text NOT NULL CHECK (relation_type IN ('subdomain_of', 'redirects_to', 'served_by', 'api_of')),
          confidence integer NOT NULL CHECK (confidence BETWEEN 0 AND 100),
          evidence jsonb NOT NULL DEFAULT '{}'::jsonb,
          first_seen_at timestamptz NOT NULL DEFAULT now(),
          last_seen_at timestamptz NOT NULL DEFAULT now(),
          UNIQUE (source_asset_id, target_asset_id, relation_type),
          CHECK (source_asset_id <> target_asset_id)
        );

        CREATE TABLE IF NOT EXISTS exposure_asset_events (
          id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
          organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
          asset_id uuid NOT NULL REFERENCES exposure_assets(id) ON DELETE CASCADE,
          event_type text NOT NULL,
          actor_id uuid REFERENCES users(id) ON DELETE SET NULL,
          payload jsonb NOT NULL DEFAULT '{}'::jsonb,
          occurred_at timestamptz NOT NULL DEFAULT now()
        );
        CREATE INDEX IF NOT EXISTS exposure_asset_events_workspace_idx
          ON exposure_asset_events (organization_id, occurred_at DESC);

        CREATE TABLE IF NOT EXISTS exposure_findings (
          id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
          organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
          asset_id uuid REFERENCES exposure_assets(id) ON DELETE SET NULL,
          fingerprint char(64) NOT NULL,
          title text NOT NULL,
          severity text NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
          validation_status text NOT NULL DEFAULT 'candidate' CHECK (validation_status IN ('candidate', 'confirmed', 'rejected', 'inconclusive')),
          lifecycle_status text NOT NULL DEFAULT 'open' CHECK (lifecycle_status IN ('open', 'accepted_risk', 'dismissed', 'resolved', 'needs_revalidation')),
          first_seen_scan_id uuid REFERENCES scans(id) ON DELETE SET NULL,
          last_seen_scan_id uuid REFERENCES scans(id) ON DELETE SET NULL,
          first_seen_at timestamptz NOT NULL DEFAULT now(),
          last_seen_at timestamptz NOT NULL DEFAULT now(),
          resolved_at timestamptz,
          lifecycle_note text,
          updated_by uuid REFERENCES users(id) ON DELETE SET NULL,
          updated_at timestamptz NOT NULL DEFAULT now(),
          UNIQUE (organization_id, fingerprint)
        );
        CREATE INDEX IF NOT EXISTS exposure_findings_workspace_idx
          ON exposure_findings (organization_id, lifecycle_status, severity, last_seen_at DESC);

        CREATE TABLE IF NOT EXISTS exposure_finding_events (
          id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
          organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
          finding_id uuid NOT NULL REFERENCES exposure_findings(id) ON DELETE CASCADE,
          event_type text NOT NULL,
          actor_id uuid REFERENCES users(id) ON DELETE SET NULL,
          payload jsonb NOT NULL DEFAULT '{}'::jsonb,
          occurred_at timestamptz NOT NULL DEFAULT now()
        );
        CREATE INDEX IF NOT EXISTS exposure_finding_events_finding_idx
          ON exposure_finding_events (finding_id, occurred_at DESC);

        CREATE TABLE IF NOT EXISTS validation_corpora (
          id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
          organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
          name text NOT NULL CHECK (length(name) BETWEEN 2 AND 160),
          version text NOT NULL CHECK (length(version) BETWEEN 1 AND 100),
          classification text NOT NULL CHECK (classification IN ('synthetic', 'public', 'internal', 'restricted')),
          source_reference text NOT NULL,
          source_sha256 char(64) NOT NULL,
          status text NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'approved', 'retired')),
          created_by uuid NOT NULL REFERENCES users(id),
          approved_by uuid REFERENCES users(id),
          approved_at timestamptz,
          created_at timestamptz NOT NULL DEFAULT now(),
          UNIQUE (organization_id, name, version)
        );

        CREATE TABLE IF NOT EXISTS validation_corpus_cases (
          id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
          corpus_id uuid NOT NULL REFERENCES validation_corpora(id) ON DELETE CASCADE,
          case_key text NOT NULL,
          expected_outcome text NOT NULL CHECK (expected_outcome IN ('finding_expected', 'no_finding_expected')),
          family text NOT NULL,
          severity text CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
          metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
          created_at timestamptz NOT NULL DEFAULT now(),
          UNIQUE (corpus_id, case_key)
        );

        CREATE TABLE IF NOT EXISTS exposure_monitors (
          id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
          organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
          assessment_id uuid NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
          asset_id uuid REFERENCES exposure_assets(id) ON DELETE SET NULL,
          cadence_hours integer NOT NULL CHECK (cadence_hours BETWEEN 24 AND 720),
          status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'paused', 'blocked')),
          next_run_at timestamptz NOT NULL,
          last_run_at timestamptz,
          last_scan_id uuid REFERENCES scans(id) ON DELETE SET NULL,
          last_error text,
          created_by uuid NOT NULL REFERENCES users(id),
          created_at timestamptz NOT NULL DEFAULT now(),
          updated_at timestamptz NOT NULL DEFAULT now(),
          UNIQUE (assessment_id)
        );
        CREATE INDEX IF NOT EXISTS exposure_monitors_due_idx
          ON exposure_monitors (status, next_run_at) WHERE status = 'active';

        CREATE TABLE IF NOT EXISTS exposure_monitor_runs (
          id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
          monitor_id uuid NOT NULL REFERENCES exposure_monitors(id) ON DELETE CASCADE,
          scan_id uuid REFERENCES scans(id) ON DELETE SET NULL,
          status text NOT NULL CHECK (status IN ('queued', 'started', 'completed', 'skipped', 'blocked', 'failed')),
          detail text,
          created_at timestamptz NOT NULL DEFAULT now()
        );
        CREATE INDEX IF NOT EXISTS exposure_monitor_runs_monitor_idx
          ON exposure_monitor_runs (monitor_id, created_at DESC);

        CREATE TABLE IF NOT EXISTS exposure_integrations (
          id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
          organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
          name text NOT NULL CHECK (length(name) BETWEEN 2 AND 160),
          integration_type text NOT NULL CHECK (integration_type IN ('webhook', 'siem', 'cloud_inventory', 'dns_attestation')),
          status text NOT NULL DEFAULT 'configured' CHECK (status IN ('configured', 'active', 'paused', 'disabled')),
          endpoint_ciphertext bytea,
          secret_ciphertext bytea,
          event_types jsonb NOT NULL DEFAULT '[]'::jsonb,
          configuration jsonb NOT NULL DEFAULT '{}'::jsonb,
          created_by uuid NOT NULL REFERENCES users(id),
          created_at timestamptz NOT NULL DEFAULT now(),
          updated_at timestamptz NOT NULL DEFAULT now(),
          UNIQUE (organization_id, name)
        );

        CREATE TABLE IF NOT EXISTS exposure_delivery_events (
          id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
          integration_id uuid NOT NULL REFERENCES exposure_integrations(id) ON DELETE CASCADE,
          organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
          event_type text NOT NULL,
          idempotency_key char(64) NOT NULL UNIQUE,
          payload jsonb NOT NULL,
          status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'delivered', 'failed', 'abandoned')),
          attempts integer NOT NULL DEFAULT 0,
          next_attempt_at timestamptz NOT NULL DEFAULT now(),
          last_error text,
          delivered_at timestamptz,
          created_at timestamptz NOT NULL DEFAULT now(),
          updated_at timestamptz NOT NULL DEFAULT now()
        );
        CREATE INDEX IF NOT EXISTS exposure_delivery_events_due_idx
          ON exposure_delivery_events (status, next_attempt_at) WHERE status = 'pending';

        CREATE TABLE IF NOT EXISTS exposure_audit_events (
          id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
          organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
          actor_id uuid REFERENCES users(id) ON DELETE SET NULL,
          event_type text NOT NULL,
          target_type text NOT NULL,
          target_id uuid,
          payload jsonb NOT NULL DEFAULT '{}'::jsonb,
          occurred_at timestamptz NOT NULL DEFAULT now()
        );
        CREATE INDEX IF NOT EXISTS exposure_audit_events_workspace_idx
          ON exposure_audit_events (organization_id, occurred_at DESC);

        INSERT INTO exposure_assets (
          organization_id, hostname, canonical_target, asset_type, ownership_status,
          ownership_confidence, ownership_evidence, discovery_sources, first_seen_at, last_seen_at
        )
        SELECT DISTINCT ON (a.organization_id, aa.hostname)
          a.organization_id, aa.hostname, aa.canonical_target,
          CASE WHEN aa.asset_type IN ('hostname', 'ip_address', 'web_application') THEN aa.asset_type ELSE 'hostname' END,
          CASE aa.ownership_status WHEN 'excluded' THEN 'excluded' WHEN 'approved' THEN 'verified'
               WHEN 'client_declared' THEN 'client_declared' ELSE 'candidate' END,
          aa.ownership_confidence, aa.discovery_evidence, aa.discovery_sources,
          aa.first_seen_at, aa.last_seen_at
        FROM assessment_assets aa
        JOIN assessments a ON a.id = aa.assessment_id
        ORDER BY a.organization_id, aa.hostname, aa.last_seen_at DESC
        ON CONFLICT (organization_id, hostname) DO NOTHING;

        UPDATE assessment_assets aa
        SET exposure_asset_id = ea.id
        FROM assessments a, exposure_assets ea
        WHERE a.id = aa.assessment_id
          AND ea.organization_id = a.organization_id
          AND ea.hostname = aa.hostname
          AND aa.exposure_asset_id IS NULL;

        CREATE OR REPLACE FUNCTION esx_prevent_exposure_event_mutation()
        RETURNS trigger AS $$
        BEGIN
          RAISE EXCEPTION 'exposure history is append-only; create a new lifecycle event';
        END;
        $$ LANGUAGE plpgsql;

        DROP TRIGGER IF EXISTS exposure_asset_events_immutable ON exposure_asset_events;
        CREATE TRIGGER exposure_asset_events_immutable BEFORE UPDATE OR DELETE ON exposure_asset_events
          FOR EACH ROW EXECUTE FUNCTION esx_prevent_exposure_event_mutation();
        DROP TRIGGER IF EXISTS exposure_finding_events_immutable ON exposure_finding_events;
        CREATE TRIGGER exposure_finding_events_immutable BEFORE UPDATE OR DELETE ON exposure_finding_events
          FOR EACH ROW EXECUTE FUNCTION esx_prevent_exposure_event_mutation();
        DROP TRIGGER IF EXISTS exposure_audit_events_immutable ON exposure_audit_events;
        CREATE TRIGGER exposure_audit_events_immutable BEFORE UPDATE OR DELETE ON exposure_audit_events
          FOR EACH ROW EXECUTE FUNCTION esx_prevent_exposure_event_mutation();
        """,
    ),
]


async def migrate() -> None:
    async with pool().acquire() as conn:
        await conn.execute(
            """
            CREATE TABLE IF NOT EXISTS schema_migrations (
              version text PRIMARY KEY,
              applied_at timestamptz NOT NULL DEFAULT now()
            )
            """
        )
        for version, sql in MIGRATIONS:
            async with conn.transaction():
                applied = await conn.fetchval(
                    "SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version = $1)",
                    version,
                )
                if applied:
                    continue
                await conn.execute(sql)
                await conn.execute(
                    "INSERT INTO schema_migrations (version) VALUES ($1)", version
                )
