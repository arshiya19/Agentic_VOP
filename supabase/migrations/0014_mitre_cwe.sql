-- =============================================================================
-- Agentic_VOP — MITRE CWE catalog
-- =============================================================================
-- Adds two tables that together give Sub-Agent 2 access to the full MITRE
-- CWE detail (consequences, mitigations, related CAPEC patterns) beyond the
-- bare CWE id we get from NVD.
--
--   1. mitre_cwe          — the ~900-row catalog. Refreshed monthly by
--                            POST /admin/mitre/refresh.
--   2. mitre_refresh_log  — one row per refresh attempt. SHA-256 of the
--                            downloaded zip lets us skip no-op runs.
--
-- Apply: paste into Supabase Dashboard SQL Editor for project agentic-vop-dev.
-- =============================================================================


-- =============================================================================
-- 1. mitre_cwe — full CWE detail
-- =============================================================================
CREATE TABLE IF NOT EXISTS mitre_cwe (
  cwe_id                 text PRIMARY KEY,                -- e.g. "CWE-79"
  name                   text NOT NULL,                   -- "Cross-site Scripting"
  abstraction            text,                            -- "Base" | "Class" | "Variant" | ...
  status                 text,                            -- "Draft" | "Incomplete" | "Stable"
  description            text,                            -- short description from MITRE
  extended_description   text,                            -- long-form description
  likelihood_of_exploit  text,                            -- "Low" | "Medium" | "High"
  consequences           jsonb NOT NULL DEFAULT '[]'::jsonb,
                                                          -- [{scope:[], impact:[], note}]
  mitigations            jsonb NOT NULL DEFAULT '[]'::jsonb,
                                                          -- [{phase:[], description, effectiveness}]
  related_capec          text[] NOT NULL DEFAULT '{}',    -- ["CAPEC-86", "CAPEC-19"]
  mitre_version          text,                            -- e.g. "4.18"
  fetched_at             timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_mitre_cwe_name ON mitre_cwe(name);

COMMENT ON TABLE mitre_cwe IS
  'Full MITRE CWE catalog. Refreshed monthly. Sub-Agent 2 JOINs on cwe_id.';


-- =============================================================================
-- 2. mitre_refresh_log — refresh audit trail + hash cache
-- =============================================================================
CREATE TABLE IF NOT EXISTS mitre_refresh_log (
  id            bigserial PRIMARY KEY,
  source        text NOT NULL CHECK (source IN ('cwe','capec','attack')),
  sha256        text NOT NULL,
  status        text NOT NULL CHECK (status IN ('unchanged','updated','failed')),
  cwes_processed integer,
  mitre_version  text,
  error_message text,
  created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_mitre_refresh_log_source_time
  ON mitre_refresh_log(source, created_at DESC);

COMMENT ON TABLE mitre_refresh_log IS
  'One row per refresh attempt. Latest sha256 per source is checked to skip no-op runs.';


-- =============================================================================
-- Row-Level Security — match the rest of the schema (authenticated read).
-- Backend (service_role) bypasses RLS for writes.
-- =============================================================================
ALTER TABLE mitre_cwe          ENABLE ROW LEVEL SECURITY;
ALTER TABLE mitre_refresh_log  ENABLE ROW LEVEL SECURITY;

CREATE POLICY "auth read" ON mitre_cwe         FOR SELECT TO authenticated USING (true);
CREATE POLICY "auth read" ON mitre_refresh_log FOR SELECT TO authenticated USING (true);


-- =============================================================================
-- Sub-Agent 2 prompt v1.1 — teach the LLM about the new `mitre` block.
-- The only diff vs v1.0 is the INPUT/RULES sections referencing MITRE CWE.
-- =============================================================================
UPDATE prompt_db SET is_active = false WHERE agent = 'sub-agent-2';

INSERT INTO prompt_db (agent, version, model, prompt_text, parameters, is_active) VALUES (
  'sub-agent-2',
  'v1.1',
  'gpt-4o-mini',
  $PROMPT$
You are Sub-Agent 2 — Enrichment Specialist for Agentic_VOP.

ROLE
Given one canonical vulnerability Issue plus enrichment data fetched from
external sources (EPSS, CISA KEV, NVD, MITRE CWE), produce a final risk
decision: derived_risk score, the reasoning behind it, likelihood + impact
estimates, and a concrete remediation suggestion.

INPUT (each call) is JSON with these fields:
  issue:
    severity         — "Info" | "Low" | "Medium" | "High" | "Critical"
    cve_id           — string or null
    title            — short description
    description      — longer description, may be null
    asset_identity   — JSON of asset fields
    package          — { name, installed_version, fixed_version, ecosystem } or null
  enrichment:
    epss_score       — float 0-1 (probability of exploit) or null
    epss_percentile  — float 0-1 (rank vs all CVEs) or null
    in_kev           — bool (CISA Known Exploited Vulnerabilities)
    nvd:
      cwe_id                    — string or null
      cvss_attack_vector        — "NETWORK" | "ADJACENT" | "LOCAL" | "PHYSICAL" | null
      cvss_attack_complexity    — "LOW" | "HIGH" | null
      cvss_privileges_required  — "NONE" | "LOW" | "HIGH" | null
      cvss_user_interaction     — "NONE" | "REQUIRED" | null
    mitre:
      name                  — full CWE name (e.g. "Cross-site Scripting")
      description           — short MITRE description of the weakness
      extended_description  — longer-form description, may be null
      likelihood_of_exploit — "Low" | "Medium" | "High" | null
      consequences          — array of { scope[], impact[], note }
      mitigations           — array of { phase[], description, effectiveness }
      related_capec         — array of CAPEC ids (e.g. ["CAPEC-86"])

OUTPUT (call emit_enrichment_decision exactly once with these fields)
  derived_risk            — float 0-100 (higher = more urgent)
  risk_explanation        — 1-2 sentences explaining the score, citing actual signals
  likelihood              — float 0.0-1.0 (your estimate of exploit likelihood)
  impact                  — float 0.0-1.0 (your estimate of damage if exploited)
  remediation_suggestion  — 1-2 sentences with a concrete fix

GUIDELINES for derived_risk
  Critical severity + EPSS > 0.5 + KEV-listed              → 90-100
  Critical/High severity + EPSS 0.1-0.5                    → 70-89
  Medium with no exploitation signals                       → 30-50
  Low/Info with no exploitation signals                     → 0-25
  KEV alone (regardless of severity) raises minimum to 70
  High EPSS (>0.7) raises minimum to 60
  MITRE likelihood_of_exploit "High" raises minimum to 55
  Adjust within bands using attack_vector (NETWORK > LOCAL),
  privileges_required (NONE > HIGH), user_interaction (NONE > REQUIRED).

RULES
1. risk_explanation must reference ACTUAL signals — e.g., "EPSS 78%, KEV-listed,
   NETWORK attack vector, MITRE marks this as High likelihood-of-exploit" — not
   generic statements.
2. remediation_suggestion must be specific. If a fixed_version is in the package
   object, use it ("Upgrade lodash to 4.17.21"). If MITRE mitigations are
   present, prefer the one whose phase matches where this would be fixed
   (Implementation > Architecture and Design > Operation).
3. Never invent enrichment data not present in the input. If mitre is empty,
   ignore it.
4. Call emit_enrichment_decision exactly once.

GUARDRAILS
- Do not call external APIs directly.
- Do not write to the database.
$PROMPT$,
  jsonb_build_object('temperature', 0.2, 'max_tokens', 800),
  true
)
ON CONFLICT (agent, version) DO UPDATE SET
  model = EXCLUDED.model, prompt_text = EXCLUDED.prompt_text,
  parameters = EXCLUDED.parameters, is_active = EXCLUDED.is_active;
