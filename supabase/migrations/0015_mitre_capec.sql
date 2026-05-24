-- =============================================================================
-- Agentic_VOP — MITRE CAPEC catalog (Phase 2 of MITRE integration)
-- =============================================================================
-- Adds the ~600-row CAPEC catalog (Common Attack Pattern Enumeration).
-- Bridges CWE → ATT&CK: each CAPEC entry references the ATT&CK techniques
-- it maps to via `related_attack_techniques`.
--
-- Refresh log piggybacks on `mitre_refresh_log` (already supports
-- source='capec' via the CHECK constraint in 0014).
--
-- Apply: paste into Supabase Dashboard SQL Editor for project agentic-vop-dev.
-- =============================================================================


CREATE TABLE IF NOT EXISTS mitre_capec (
  capec_id                   text PRIMARY KEY,                 -- e.g. "CAPEC-63"
  name                       text NOT NULL,                    -- "Cross-Site Scripting"
  abstraction                text,                             -- "Standard" | "Meta" | "Detailed"
  status                     text,                             -- "Draft" | "Stable"
  description                text,
  likelihood_of_attack       text,                             -- "Low" | "Medium" | "High"
  typical_severity           text,                             -- "Low" | "Medium" | "High" | "Very High"
  execution_flow             jsonb NOT NULL DEFAULT '[]'::jsonb,
                                                               -- [{step, phase, description, techniques[]}]
  prerequisites              text[] NOT NULL DEFAULT '{}',
  skills_required            jsonb NOT NULL DEFAULT '[]'::jsonb,
                                                               -- [{level, description}]
  resources_required         text,
  consequences               jsonb NOT NULL DEFAULT '[]'::jsonb,
  mitigations                text[] NOT NULL DEFAULT '{}',     -- CAPEC mitigations are flat-text bullets
  related_weaknesses         text[] NOT NULL DEFAULT '{}',     -- CWE ids the pattern targets
  related_attack_techniques  text[] NOT NULL DEFAULT '{}',     -- ATT&CK technique ids (the join)
  mitre_version              text,
  fetched_at                 timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_mitre_capec_name ON mitre_capec(name);

COMMENT ON TABLE mitre_capec IS
  'MITRE CAPEC attack-pattern catalog. CWE.related_capec joins here; capec.related_attack_techniques joins to mitre_attack.';


-- =============================================================================
-- RLS — match the rest of the schema.
-- =============================================================================
ALTER TABLE mitre_capec ENABLE ROW LEVEL SECURITY;
CREATE POLICY "auth read" ON mitre_capec FOR SELECT TO authenticated USING (true);
