-- =============================================================================
-- Agentic_VOP — MITRE ATT&CK Enterprise catalog (Phase 3 of MITRE integration)
-- =============================================================================
-- Adds the ATT&CK technique catalog (~600 techniques + sub-techniques).
-- CAPEC.related_attack_techniques joins here.
--
-- Source format: STIX 2.0 JSON (not XML like CWE/CAPEC). Parser lives in
-- mitre_refresh.refresh_mitre_attack(). Refresh log uses source='attack'.
--
-- Also bumps Sub-Agent 2 prompt to v1.2 — teaches the LLM about the full
-- CWE → CAPEC → ATT&CK chain.
--
-- Apply: paste into Supabase Dashboard SQL Editor for project agentic-vop-dev.
-- =============================================================================


CREATE TABLE IF NOT EXISTS mitre_attack_techniques (
  technique_id          text PRIMARY KEY,                  -- e.g. "T1190" or "T1190.001"
  name                  text NOT NULL,                     -- "Exploit Public-Facing Application"
  description           text,
  tactics               text[] NOT NULL DEFAULT '{}',      -- kill-chain phases, e.g. ["initial-access"]
  is_subtechnique       boolean NOT NULL DEFAULT false,
  parent_technique_id   text,                              -- set when this is a sub-technique
  platforms             text[] NOT NULL DEFAULT '{}',      -- ["Linux","Windows","macOS",...]
  data_sources          text[] NOT NULL DEFAULT '{}',
  detection             text,
  url                   text,                              -- canonical attack.mitre.org URL
  mitre_version         text,
  fetched_at            timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_mitre_attack_name   ON mitre_attack_techniques(name);
CREATE INDEX IF NOT EXISTS idx_mitre_attack_parent ON mitre_attack_techniques(parent_technique_id)
  WHERE parent_technique_id IS NOT NULL;

COMMENT ON TABLE mitre_attack_techniques IS
  'MITRE ATT&CK Enterprise techniques. Joined from mitre_capec.related_attack_techniques.';


-- =============================================================================
-- RLS — match the rest of the schema.
-- =============================================================================
ALTER TABLE mitre_attack_techniques ENABLE ROW LEVEL SECURITY;
CREATE POLICY "auth read" ON mitre_attack_techniques FOR SELECT TO authenticated USING (true);


-- =============================================================================
-- Sub-Agent 2 prompt v1.2 — teach the LLM about the full CWE → CAPEC → ATT&CK chain.
-- =============================================================================
UPDATE prompt_db SET is_active = false WHERE agent = 'sub-agent-2';

INSERT INTO prompt_db (agent, version, model, prompt_text, parameters, is_active) VALUES (
  'sub-agent-2',
  'v1.2',
  'gpt-4o-mini',
  $PROMPT$
You are Sub-Agent 2 — Enrichment Specialist for Agentic_VOP.

ROLE
Given one canonical vulnerability Issue plus enrichment data fetched from
external sources (EPSS, CISA KEV, NVD, and the MITRE chain CWE → CAPEC →
ATT&CK), produce a final risk decision: derived_risk score, the reasoning
behind it, likelihood + impact estimates, and a concrete remediation
suggestion.

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
      cwe:                  full MITRE CWE entry — name, description, extended_description,
                            likelihood_of_exploit, consequences[], mitigations[],
                            related_capec[]   (may be {} if cwe_id has no MITRE row)
      capec:                array of CAPEC entries linked from the CWE — each has
                            capec_id, name, description, likelihood_of_attack,
                            typical_severity, prerequisites[], mitigations[],
                            related_attack_techniques[]   (may be [])
      attack:               array of ATT&CK techniques referenced by the CAPEC entries —
                            each has technique_id, name, tactics[], description, platforms[]
                            (may be [])

OUTPUT (call emit_enrichment_decision exactly once with these fields)
  derived_risk            — float 0-100 (higher = more urgent)
  risk_explanation        — 1-2 sentences explaining the score, citing actual signals
  likelihood              — float 0.0-1.0
  impact                  — float 0.0-1.0
  remediation_suggestion  — 1-2 sentences with a concrete fix

GUIDELINES for derived_risk
  Critical severity + EPSS > 0.5 + KEV-listed              → 90-100
  Critical/High severity + EPSS 0.1-0.5                    → 70-89
  Medium with no exploitation signals                       → 30-50
  Low/Info with no exploitation signals                     → 0-25
  KEV alone (regardless of severity) raises minimum to 70
  High EPSS (>0.7) raises minimum to 60
  MITRE CWE likelihood_of_exploit "High" raises minimum to 55
  CAPEC likelihood_of_attack "High" raises minimum to 55
  ATT&CK technique in "initial-access" or "execution" tactic adds +5 within band
  Adjust within bands using attack_vector (NETWORK > LOCAL),
  privileges_required (NONE > HIGH), user_interaction (NONE > REQUIRED).

RULES
1. risk_explanation must reference ACTUAL signals — e.g., "EPSS 78%, KEV-listed,
   NETWORK attack vector, MITRE marks this as High likelihood, CAPEC-63
   (Cross-Site Scripting) maps to T1190 Exploit Public-Facing Application."
2. remediation_suggestion must be specific. If a fixed_version is in the package
   object, use it. If MITRE mitigations are present, prefer the one whose phase
   matches where this would be fixed (Implementation > Architecture and Design >
   Operation). CAPEC mitigations can supplement.
3. Never invent enrichment data not present in the input. If a section is empty,
   ignore it gracefully.
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
