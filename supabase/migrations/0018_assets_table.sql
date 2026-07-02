-- =============================================================================
-- Agentic_VOP — Assets / Mini-CMDB
-- =============================================================================
-- Adds an `assets` table fitted to the actual shape of our findings (which are
-- application/project-level, not host/VM-level). Seeded with 5 hand-crafted
-- mock rows that match the projects our scanners currently report:
--
--   juice-shop, data-pipeline, java-service, web-frontend, vuln-test
--
-- Each row is enriched with the fields that drive the Dashboard's Exposure
-- Map widgets:
--   - exposure              → Internet Facing card
--   - business_criticality  → Crown Jewel Apps card
--   - compliance_tags       → Regulatory Impact card
--
-- A LEFT JOIN view (issue_with_asset) handles the mapping from
-- issues.asset_identity → assets.name (with alias fallback) so the frontend
-- can query the joined shape directly.
--
-- Apply: paste into Supabase Dashboard SQL Editor.
-- =============================================================================


-- =============================================================================
-- 1. assets — the mini-CMDB
-- =============================================================================
-- Column order mirrors the team's reference CMDB layout for the first seven
-- columns (ci_id/hostname/ip_address/asset_type/environment/business_owner/
-- contact_email), then appends Agentic_VOP-specific fields after.
--
-- DROP+CREATE used because Postgres can't reorder existing columns in place,
-- and the data here is mock-only (seed below re-inserts the 5 rows). Safe
-- to re-run any number of times.
-- =============================================================================
DROP TABLE IF EXISTS assets CASCADE;

CREATE TABLE assets (
  -- ---- Reference CMDB order (same first 7 columns as the team's existing convention) ----
  asset_id              text PRIMARY KEY,                 -- "ASSET-001" (analog of ci_id)
  hostname              text,                             -- e.g. "juice-shop.example.com"
  ip_address            text,                             -- e.g. "203.0.113.42"
  asset_type            text CHECK (asset_type IN
                          ('application','service','repository','package','infrastructure')),
  environment           text CHECK (environment IN
                          ('production','staging','development','qa','sandbox')),
  business_owner        text,                             -- team name
  contact_email         text,

  -- ---- Agentic_VOP additions: identity + aliases (for issue↔asset matching) ----
  name                  text NOT NULL UNIQUE,             -- canonical: "juice-shop"
  aliases               text[] NOT NULL DEFAULT '{}',
                                                          -- alt slugs that map to this asset
                                                          -- e.g. ["vuln-test@1.0.0", "siricher/vuln-test-dependabot"]
  application_name      text,                             -- human-friendly display name
  description           text,
  repo_url              text,                             -- canonical source-repo URL when relevant

  -- ---- Dashboard Exposure Map drivers ----
  exposure              text CHECK (exposure IN ('public','internal')),
  business_criticality  smallint CHECK (business_criticality BETWEEN 1 AND 5),
  data_classification   text CHECK (data_classification IN
                          ('public','internal','confidential','restricted')),
  compliance_tags       text[] NOT NULL DEFAULT '{}',     -- e.g. ['PCI-DSS','HIPAA']

  -- ---- Ownership detail ----
  owner_team            text,                             -- same as business_owner today; split kept for future

  -- ---- Lifecycle ----
  last_seen_at          timestamptz,                      -- updated when a scan finds issues on this asset
  created_at            timestamptz NOT NULL DEFAULT now(),
  updated_at            timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_assets_environment        ON assets(environment);
CREATE INDEX IF NOT EXISTS idx_assets_exposure           ON assets(exposure);
CREATE INDEX IF NOT EXISTS idx_assets_criticality        ON assets(business_criticality DESC NULLS LAST);
CREATE INDEX IF NOT EXISTS idx_assets_aliases_gin        ON assets USING GIN(aliases);
CREATE INDEX IF NOT EXISTS idx_assets_compliance_gin     ON assets USING GIN(compliance_tags);
CREATE INDEX IF NOT EXISTS idx_assets_hostname           ON assets(hostname)   WHERE hostname   IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_assets_ip_address         ON assets(ip_address) WHERE ip_address IS NOT NULL;

COMMENT ON TABLE assets IS
  'Mini-CMDB. One row per application/service/repo. Drives Dashboard Exposure Map + asset attribution on issues.';


-- updated_at trigger reuses the function from the initial schema migration.
-- DROP first so re-running the migration after a partial run doesn't fail.
DROP TRIGGER IF EXISTS trg_assets_updated_at ON assets;
CREATE TRIGGER trg_assets_updated_at
  BEFORE UPDATE ON assets
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();


-- =============================================================================
-- 2. issue_with_asset — convenience view that resolves asset_identity to an asset
-- =============================================================================
-- Match priority:
--   a) issue.asset_identity->>'project' matches asset.name OR asset.aliases
--   b) issue.asset_identity->>'repo'    matches asset.name OR asset.aliases
-- Returns NULL asset fields when no match (frontend renders as "Unattributed").
-- =============================================================================
-- All asset-derived columns are prefixed `asset_` so they don't collide with
-- the issues table's own columns (issues already has exposure,
-- business_criticality, asset_owner from the original schema, even though
-- they're typically NULL in practice).
CREATE OR REPLACE VIEW issue_with_asset AS
SELECT
  i.*,
  a.asset_id,
  a.name                 AS asset_name,
  a.application_name     AS asset_application_name,
  a.asset_type           AS asset_type,
  a.environment          AS asset_environment,
  a.exposure             AS asset_exposure,
  a.business_criticality AS asset_business_criticality,
  a.data_classification  AS asset_data_classification,
  a.compliance_tags      AS asset_compliance_tags,
  a.business_owner       AS asset_business_owner,
  a.contact_email        AS asset_contact_email,
  a.hostname             AS asset_hostname,
  a.ip_address           AS asset_ip_address
FROM issues i
LEFT JOIN assets a ON
  -- match by project (osv, snyk, sonarqube)
  (
    (i.asset_identity->>'project') IS NOT NULL AND
    (
      a.name = (i.asset_identity->>'project')
      OR (i.asset_identity->>'project') = ANY(a.aliases)
    )
  )
  -- match by repo (dependabot)
  OR (
    (i.asset_identity->>'repo') IS NOT NULL AND
    (
      a.name = (i.asset_identity->>'repo')
      OR (i.asset_identity->>'repo') = ANY(a.aliases)
    )
  )
  -- match by hostname (future infra scanners: Tenable, Qualys)
  OR (
    (i.asset_identity->>'hostname') IS NOT NULL AND
    a.hostname = (i.asset_identity->>'hostname')
  )
  -- match by IP (same audience)
  OR (
    (i.asset_identity->>'ipv4') IS NOT NULL AND
    a.ip_address = (i.asset_identity->>'ipv4')
  );

COMMENT ON VIEW issue_with_asset IS
  'Issues joined to their resolved asset (via project or repo + alias fallback). NULL asset fields = unattributed.';


-- =============================================================================
-- 3. RLS — match the rest of the schema
-- =============================================================================
ALTER TABLE assets ENABLE ROW LEVEL SECURITY;
CREATE POLICY "auth read" ON assets FOR SELECT TO authenticated USING (true);


-- =============================================================================
-- 4. Seed — 5 mock assets covering the 6 distinct projects in current data
-- =============================================================================
-- Designed to make the Dashboard Exposure Map tell a coherent story:
--   - juice-shop:    PUBLIC + crown jewel + PCI scope    → the headline risk
--   - data-pipeline: INTERNAL + crown jewel + HIPAA/SOC2 → important but not internet-facing
--   - java-service:  INTERNAL + mid-criticality + SOC2   → staging environment example
--   - web-frontend:  PUBLIC + mid-criticality + GDPR     → public ≠ always crown jewel
--   - vuln-test:     INTERNAL + sandbox                  → noisy but low-risk
-- =============================================================================

-- Mock hostname/IP values use documentation/reserved ranges so they look
-- realistic but are guaranteed not to collide with real systems:
--   203.0.113.0/24  → IETF TEST-NET-3 (looks "public")
--   10.x.y.z        → RFC 1918 private (looks "internal")
INSERT INTO assets (
  asset_id, name, aliases, asset_type, application_name, description, repo_url,
  hostname, ip_address,
  environment, exposure, business_criticality, data_classification, compliance_tags,
  business_owner, owner_team, contact_email
) VALUES
  ( 'ASSET-001',
    'juice-shop',
    ARRAY['Manali-code_juice-shopp'],
    'application',
    'OWASP Juice Shop',
    'OWASP Juice Shop — intentionally vulnerable e-commerce demo (Node.js + Angular).',
    'github.com/juice-shop/juice-shop',
    'juice-shop.example.com',
    '203.0.113.42',
    'production',
    'public',
    5,
    'confidential',
    ARRAY['PCI-DSS'],
    'Payments Team',
    'Payments Team',
    'payments@company.com'
  ),
  ( 'ASSET-002',
    'data-pipeline',
    ARRAY[]::text[],
    'service',
    'Data Pipeline',
    'ETL service that moves customer + health records into the warehouse.',
    NULL,
    'data-pipeline-prod.internal',
    '10.0.5.12',
    'production',
    'internal',
    5,
    'restricted',
    ARRAY['HIPAA','SOC2'],
    'Data Platform Team',
    'Data Platform Team',
    'data-platform@company.com'
  ),
  ( 'ASSET-003',
    'java-service',
    ARRAY[]::text[],
    'service',
    'Java Backend Service',
    'Backend API serving the mobile app.',
    NULL,
    'java-service-staging.internal',
    '10.0.6.21',
    'staging',
    'internal',
    4,
    'internal',
    ARRAY['SOC2'],
    'Backend Team',
    'Backend Team',
    'backend@company.com'
  ),
  ( 'ASSET-004',
    'web-frontend',
    ARRAY[]::text[],
    'application',
    'Marketing Web Frontend',
    'Public marketing site — Next.js.',
    NULL,
    'www.example.com',
    '203.0.113.10',
    'production',
    'public',
    3,
    'public',
    ARRAY['GDPR'],
    'Marketing Web Team',
    'Marketing Web Team',
    'webteam@company.com'
  ),
  ( 'ASSET-005',
    'vuln-test',
    ARRAY['vuln-test@1.0.0', 'siricher/vuln-test-dependabot'],
    'repository',
    'Vulnerability Test Sandbox',
    'Internal sandbox for testing vulnerability detection pipelines.',
    'github.com/siricher/vuln-test-dependabot',
    'vuln-test-sandbox.internal',
    '10.0.99.7',
    'development',
    'internal',
    1,
    'internal',
    ARRAY[]::text[],
    'Security Lab',
    'Security Lab',
    'secops@company.com'
  )
ON CONFLICT (asset_id) DO UPDATE SET
  name                  = EXCLUDED.name,
  aliases               = EXCLUDED.aliases,
  asset_type            = EXCLUDED.asset_type,
  application_name      = EXCLUDED.application_name,
  description           = EXCLUDED.description,
  repo_url              = EXCLUDED.repo_url,
  hostname              = EXCLUDED.hostname,
  ip_address            = EXCLUDED.ip_address,
  environment           = EXCLUDED.environment,
  exposure              = EXCLUDED.exposure,
  business_criticality  = EXCLUDED.business_criticality,
  data_classification   = EXCLUDED.data_classification,
  compliance_tags       = EXCLUDED.compliance_tags,
  business_owner        = EXCLUDED.business_owner,
  owner_team            = EXCLUDED.owner_team,
  contact_email         = EXCLUDED.contact_email,
  updated_at            = now();


-- =============================================================================
-- 5. Backfill last_seen_at from existing issues (one-time)
-- =============================================================================
UPDATE assets a
SET last_seen_at = sub.most_recent
FROM (
  SELECT
    COALESCE(
      a2.asset_id,
      NULL
    ) AS aid,
    max(i.created_at) AS most_recent
  FROM issues i
  JOIN assets a2 ON
    (
      (i.asset_identity->>'project') IS NOT NULL AND
      (a2.name = (i.asset_identity->>'project') OR (i.asset_identity->>'project') = ANY(a2.aliases))
    )
    OR (
      (i.asset_identity->>'repo') IS NOT NULL AND
      (a2.name = (i.asset_identity->>'repo') OR (i.asset_identity->>'repo') = ANY(a2.aliases))
    )
  GROUP BY a2.asset_id
) sub
WHERE a.asset_id = sub.aid;


-- =============================================================================
-- Sanity checks you can run after applying:
-- =============================================================================
--   -- Coverage: how many issues did the JOIN attribute vs leave unattributed?
--   SELECT
--     (asset_id IS NOT NULL) AS attributed,
--     count(*)               AS issues
--   FROM issue_with_asset
--   GROUP BY 1;
--
--   -- Findings per asset:
--   SELECT asset_name, count(*) AS findings
--   FROM issue_with_asset
--   WHERE asset_id IS NOT NULL
--   GROUP BY asset_name
--   ORDER BY findings DESC;
--
--   -- Internet-Facing widget preview:
--   SELECT count(DISTINCT asset_id) AS public_assets, count(*) AS findings
--   FROM issue_with_asset WHERE asset_exposure = 'public';
--
--   -- Crown-Jewel widget preview:
--   SELECT count(DISTINCT asset_id) AS crown_jewel_assets, count(*) AS findings
--   FROM issue_with_asset WHERE asset_business_criticality >= 4;
--
--   -- Regulatory Impact widget preview:
--   SELECT unnest(asset_compliance_tags) AS tag, count(DISTINCT asset_id) AS assets, count(*) AS findings
--   FROM issue_with_asset WHERE asset_compliance_tags <> '{}'
--   GROUP BY tag;
