-- =============================================================================
-- Agentic_VOP — Promote MITRE chain signals onto the `issues` table
-- =============================================================================
-- Adds 9 nullable columns to `issues` that any future prioritization-engine
-- formula or remediation-engine routing logic needs to query fast.
--
-- Source-of-truth stays in the 3 catalog tables (mitre_cwe, mitre_capec,
-- mitre_attack_techniques). The 9 columns are a denormalized projection so
-- scoring/filtering doesn't need to chain JOINs at read time.
--
-- Tier 1 — scoring signals (7 cols):
--   cwe_likelihood_of_exploit          ← mitre_cwe.likelihood_of_exploit
--   capec_ids                          ← mitre_cwe.related_capec
--   capec_max_likelihood_of_attack     ← MAX across linked CAPECs
--   capec_max_typical_severity         ← MAX across linked CAPECs
--   attack_technique_ids               ← aggregated from CAPECs
--   attack_tactics                     ← deduped across techniques
--   attack_platforms                   ← deduped across techniques
--
-- Tier 2 — remediation routing (2 cols):
--   cwe_abstraction                    ← mitre_cwe.abstraction
--   cwe_mitigation_phases              ← derived from mitigations[].phase
--
-- Apply: paste into Supabase Dashboard SQL Editor.
-- =============================================================================


-- ---- 1. Add the 9 columns (all nullable; populated by Sub-Agent 2) ----
ALTER TABLE issues ADD COLUMN IF NOT EXISTS cwe_likelihood_of_exploit      text;
ALTER TABLE issues ADD COLUMN IF NOT EXISTS cwe_abstraction                text;
ALTER TABLE issues ADD COLUMN IF NOT EXISTS cwe_mitigation_phases          text[] NOT NULL DEFAULT '{}';
ALTER TABLE issues ADD COLUMN IF NOT EXISTS capec_ids                      text[] NOT NULL DEFAULT '{}';
ALTER TABLE issues ADD COLUMN IF NOT EXISTS capec_max_likelihood_of_attack text;
ALTER TABLE issues ADD COLUMN IF NOT EXISTS capec_max_typical_severity     text;
ALTER TABLE issues ADD COLUMN IF NOT EXISTS attack_technique_ids           text[] NOT NULL DEFAULT '{}';
ALTER TABLE issues ADD COLUMN IF NOT EXISTS attack_tactics                 text[] NOT NULL DEFAULT '{}';
ALTER TABLE issues ADD COLUMN IF NOT EXISTS attack_platforms               text[] NOT NULL DEFAULT '{}';


-- ---- 2. CHECK constraints — same value sets as the source catalogs ----
ALTER TABLE issues DROP CONSTRAINT IF EXISTS issues_cwe_likelihood_of_exploit_check;
ALTER TABLE issues ADD CONSTRAINT issues_cwe_likelihood_of_exploit_check
  CHECK (cwe_likelihood_of_exploit IS NULL
         OR cwe_likelihood_of_exploit IN ('Low','Medium','High'));

ALTER TABLE issues DROP CONSTRAINT IF EXISTS issues_cwe_abstraction_check;
ALTER TABLE issues ADD CONSTRAINT issues_cwe_abstraction_check
  CHECK (cwe_abstraction IS NULL
         OR cwe_abstraction IN ('Base','Class','Variant','Compound','Pillar'));

ALTER TABLE issues DROP CONSTRAINT IF EXISTS issues_capec_max_likelihood_of_attack_check;
ALTER TABLE issues ADD CONSTRAINT issues_capec_max_likelihood_of_attack_check
  CHECK (capec_max_likelihood_of_attack IS NULL
         OR capec_max_likelihood_of_attack IN ('Low','Medium','High'));

ALTER TABLE issues DROP CONSTRAINT IF EXISTS issues_capec_max_typical_severity_check;
ALTER TABLE issues ADD CONSTRAINT issues_capec_max_typical_severity_check
  CHECK (capec_max_typical_severity IS NULL
         OR capec_max_typical_severity IN ('Low','Medium','High','Very High'));


-- ---- 3. GIN indexes on the 4 array columns ----
-- These power fast filter/aggregate queries like
--   WHERE 'initial-access' = ANY(attack_tactics)
--   WHERE capec_ids && ARRAY['CAPEC-63']
CREATE INDEX IF NOT EXISTS idx_issues_capec_ids_gin
  ON issues USING GIN(capec_ids);
CREATE INDEX IF NOT EXISTS idx_issues_attack_technique_ids_gin
  ON issues USING GIN(attack_technique_ids);
CREATE INDEX IF NOT EXISTS idx_issues_attack_tactics_gin
  ON issues USING GIN(attack_tactics);
CREATE INDEX IF NOT EXISTS idx_issues_attack_platforms_gin
  ON issues USING GIN(attack_platforms);

-- Btree for the categorical text fields (cheap, useful for GROUP BY in dashboards)
CREATE INDEX IF NOT EXISTS idx_issues_cwe_likelihood_of_exploit
  ON issues(cwe_likelihood_of_exploit)
  WHERE cwe_likelihood_of_exploit IS NOT NULL;


-- =============================================================================
-- 4. Backfill — populate the 9 columns for all existing issues by joining
-- through the catalog tables. One transaction; safe to re-run (UPDATE is
-- idempotent because the joins always produce the same result).
-- =============================================================================

-- 4a. CWE-derived fields (likelihood, abstraction, mitigation phases)
UPDATE issues i
SET cwe_likelihood_of_exploit = c.likelihood_of_exploit,
    cwe_abstraction           = c.abstraction,
    -- Pull unique phase names out of the mitigations jsonb array.
    -- Each mitigation is {phase:[...], description, effectiveness}; we
    -- flatten + dedupe the phases.
    cwe_mitigation_phases     = COALESCE(
      (SELECT array_agg(DISTINCT phase ORDER BY phase)
       FROM mitre_cwe c2,
            jsonb_array_elements(c2.mitigations) m,
            jsonb_array_elements_text(m -> 'phase') phase
       WHERE c2.cwe_id = i.cwe_id),
      ARRAY[]::text[]
    )
FROM mitre_cwe c
WHERE c.cwe_id = i.cwe_id;

-- 4b. CAPEC fields (ids array + aggregated max severity/likelihood across linked CAPECs)
UPDATE issues i
SET capec_ids                     = COALESCE(c.related_capec, ARRAY[]::text[]),
    capec_max_likelihood_of_attack = (
      SELECT CASE max(
        CASE cp.likelihood_of_attack
          WHEN 'High' THEN 3 WHEN 'Medium' THEN 2 WHEN 'Low' THEN 1 ELSE 0
        END)
        WHEN 3 THEN 'High' WHEN 2 THEN 'Medium' WHEN 1 THEN 'Low'
      END
      FROM mitre_capec cp
      WHERE cp.capec_id = ANY(c.related_capec)
    ),
    capec_max_typical_severity = (
      SELECT CASE max(
        CASE cp.typical_severity
          WHEN 'Very High' THEN 4 WHEN 'High' THEN 3
          WHEN 'Medium'    THEN 2 WHEN 'Low'  THEN 1 ELSE 0
        END)
        WHEN 4 THEN 'Very High' WHEN 3 THEN 'High'
        WHEN 2 THEN 'Medium'    WHEN 1 THEN 'Low'
      END
      FROM mitre_capec cp
      WHERE cp.capec_id = ANY(c.related_capec)
    )
FROM mitre_cwe c
WHERE c.cwe_id = i.cwe_id;

-- 4c. ATT&CK fields (technique ids + deduped tactics + deduped platforms)
UPDATE issues i
SET attack_technique_ids = COALESCE((
      SELECT array_agg(DISTINCT t)
      FROM mitre_capec cp,
           unnest(cp.related_attack_techniques) t
      WHERE cp.capec_id = ANY(i.capec_ids)
    ), ARRAY[]::text[]),
    attack_tactics = COALESCE((
      SELECT array_agg(DISTINCT tac)
      FROM mitre_capec cp
      JOIN mitre_attack_techniques at
        ON at.technique_id = ANY(cp.related_attack_techniques),
           unnest(at.tactics) tac
      WHERE cp.capec_id = ANY(i.capec_ids)
    ), ARRAY[]::text[]),
    attack_platforms = COALESCE((
      SELECT array_agg(DISTINCT pl)
      FROM mitre_capec cp
      JOIN mitre_attack_techniques at
        ON at.technique_id = ANY(cp.related_attack_techniques),
           unnest(at.platforms) pl
      WHERE cp.capec_id = ANY(i.capec_ids)
    ), ARRAY[]::text[])
WHERE array_length(i.capec_ids, 1) > 0;


-- =============================================================================
-- Sanity check queries (run after applying to verify the backfill worked):
-- =============================================================================
--   -- Per-column population:
--   SELECT
--     count(*) FILTER (WHERE cwe_likelihood_of_exploit IS NOT NULL)        AS has_cwe_likelihood,
--     count(*) FILTER (WHERE cwe_abstraction IS NOT NULL)                  AS has_cwe_abstraction,
--     count(*) FILTER (WHERE array_length(cwe_mitigation_phases,1) > 0)    AS has_mitigation_phases,
--     count(*) FILTER (WHERE array_length(capec_ids,1) > 0)                AS has_capec,
--     count(*) FILTER (WHERE array_length(attack_technique_ids,1) > 0)     AS has_attack,
--     count(*) FILTER (WHERE array_length(attack_tactics,1) > 0)           AS has_tactics
--   FROM issues;
--
--   -- Spot-check one CWE-79 issue:
--   SELECT id, cwe_id, cwe_likelihood_of_exploit, cwe_abstraction,
--          cwe_mitigation_phases, capec_ids, capec_max_typical_severity,
--          attack_tactics, attack_platforms
--   FROM issues
--   WHERE cwe_id = 'CWE-79'
--   LIMIT 3;
