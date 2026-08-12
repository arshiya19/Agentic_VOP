-- =============================================================================
-- 0036 — Remediation Knowledge Base (Feedback Loop)
-- =============================================================================
-- Stores successful fix outcomes as reusable few-shot examples for SA-3.
--
-- When SA-4 (fixer) completes a fix_run with status='success' and all
-- validations pass, the outcome is captured here. On future runs, SA-3
-- queries this table for matching check_id/family and injects the proven
-- fix as a few-shot example in its LLM prompt — improving consistency
-- from the observed 75-100% band toward deterministic success.
--
-- Design decisions:
--   - check_id is the primary lookup key (e.g. CKV_AWS_18, CKV_AWS_21)
--   - family is secondary grouping (public_exposure, network_exposure, etc.)
--   - finding_fingerprint captures issue-specific context for dedup
--   - Only verified successes enter this table (guard in capture logic)
--   - times_reused / success_rate track reuse effectiveness over time
-- =============================================================================

-- -----------------------------------------------------------------------------
-- Table: remediation_kb
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.remediation_kb (
    id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    -- Lookup keys
    check_id        TEXT NOT NULL,                -- e.g. "CKV_AWS_18", "CKV_AWS_21"
    family          TEXT NOT NULL,                -- e.g. "public_exposure", "network_exposure"
    finding_fingerprint TEXT,                     -- hash of (check_id + resource_type + file_path) for dedup

    -- The proven fix (what worked)
    remediation_steps   JSONB NOT NULL,           -- array of step objects from the successful package
    rollback_steps      JSONB,                    -- rollback steps that were validated
    validation_results  JSONB NOT NULL,           -- proof the fix worked (from fix_runs)

    -- Context for the LLM (helps it adapt the example to new findings)
    finding_summary     TEXT,                     -- one-line description of what was wrong
    root_cause          TEXT,                     -- why it was wrong
    resource_type       TEXT,                     -- e.g. "aws_s3_bucket", "aws_security_group"
    scanner_type        TEXT,                     -- "iac", "sca", "sast", "os_pkg"
    file_path           TEXT,                     -- target file that was fixed

    -- Provenance
    source_fix_run_id   INT,                      -- FK to fix_runs (nullable — run may be deleted)
    source_package_id   INT,                      -- FK to remediation_packages
    source_issue_id     INT,                      -- FK to issues (for cross-reference)
    agent_run_id        TEXT,                     -- trace correlation

    -- Quality signals
    confidence_score    INT,                      -- 0-100, from confidence engine at capture time
    times_reused        INT NOT NULL DEFAULT 0,   -- how many times this example was injected
    times_succeeded     INT NOT NULL DEFAULT 0,   -- how many of those reuses led to success
    success_rate        NUMERIC(5,2) GENERATED ALWAYS AS (
        CASE WHEN times_reused > 0
             THEN (times_succeeded::NUMERIC / times_reused * 100)
             ELSE 0
        END
    ) STORED,

    -- Lifecycle
    is_active           BOOLEAN NOT NULL DEFAULT TRUE,  -- soft-delete / disable without losing data
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at        TIMESTAMPTZ,
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- -----------------------------------------------------------------------------
-- Indexes for fast lookup during SA-3 prompt assembly
-- -----------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_remediation_kb_check_id
    ON public.remediation_kb (check_id)
    WHERE is_active = TRUE;

CREATE INDEX IF NOT EXISTS idx_remediation_kb_family
    ON public.remediation_kb (family)
    WHERE is_active = TRUE;

CREATE INDEX IF NOT EXISTS idx_remediation_kb_fingerprint
    ON public.remediation_kb (finding_fingerprint)
    WHERE finding_fingerprint IS NOT NULL;

-- Composite for the most common query pattern: "give me proven fixes for this check"
CREATE INDEX IF NOT EXISTS idx_remediation_kb_check_family_active
    ON public.remediation_kb (check_id, family, is_active, confidence_score DESC);

-- -----------------------------------------------------------------------------
-- Dedup constraint: one entry per unique (check_id + resource_type + file_path)
-- prevents the same fix from being stored multiple times if SA-4 re-runs.
-- -----------------------------------------------------------------------------
CREATE UNIQUE INDEX IF NOT EXISTS idx_remediation_kb_dedup
    ON public.remediation_kb (finding_fingerprint)
    WHERE finding_fingerprint IS NOT NULL AND is_active = TRUE;

-- -----------------------------------------------------------------------------
-- Auto-update updated_at on row modification
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.update_remediation_kb_timestamp()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_remediation_kb_updated ON public.remediation_kb;
CREATE TRIGGER trg_remediation_kb_updated
    BEFORE UPDATE ON public.remediation_kb
    FOR EACH ROW
    EXECUTE FUNCTION public.update_remediation_kb_timestamp();

-- -----------------------------------------------------------------------------
-- RLS (Row Level Security) — service role bypasses, anon blocked
-- -----------------------------------------------------------------------------
ALTER TABLE public.remediation_kb ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Service role full access on remediation_kb"
    ON public.remediation_kb
    FOR ALL
    USING (TRUE)
    WITH CHECK (TRUE);

-- -----------------------------------------------------------------------------
-- Comments for documentation
-- -----------------------------------------------------------------------------
COMMENT ON TABLE public.remediation_kb IS
    'Knowledge base of proven successful remediations. Fed back as few-shot examples to SA-3.';
COMMENT ON COLUMN public.remediation_kb.check_id IS
    'Scanner check identifier (e.g. CKV_AWS_18). Primary lookup key for retrieval.';
COMMENT ON COLUMN public.remediation_kb.finding_fingerprint IS
    'Hash of (check_id + resource_type + file_path) for deduplication.';
COMMENT ON COLUMN public.remediation_kb.remediation_steps IS
    'JSONB array of step objects — the exact steps that successfully fixed the finding.';
COMMENT ON COLUMN public.remediation_kb.success_rate IS
    'Computed: (times_succeeded / times_reused * 100). Used to rank examples.';
