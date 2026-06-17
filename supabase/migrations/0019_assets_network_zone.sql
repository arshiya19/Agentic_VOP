-- =============================================================================
-- Agentic_VOP — Add network_zone to assets
-- =============================================================================
-- Drives the Dashboard's threat-based Exposure Map row (Internet / Extranet /
-- Intranet). Real values will come from CMDB integration later; the 5 seed
-- rows below are mock assignments fitted to each asset's plausible network
-- position.
--
-- Apply: paste into Supabase Dashboard SQL Editor.
-- =============================================================================

ALTER TABLE assets ADD COLUMN IF NOT EXISTS network_zone text;

-- Bound to the standard 3-zone model. Allows NULL so unmocked assets sort to
-- the bottom rather than miscategorize.
ALTER TABLE assets
  DROP CONSTRAINT IF EXISTS assets_network_zone_check;
ALTER TABLE assets
  ADD  CONSTRAINT assets_network_zone_check
       CHECK (network_zone IS NULL OR network_zone IN ('internet','extranet','intranet'));

CREATE INDEX IF NOT EXISTS idx_assets_network_zone ON assets(network_zone) WHERE network_zone IS NOT NULL;

COMMENT ON COLUMN assets.network_zone IS
  'Where the asset sits in the network (internet/extranet/intranet). Drives the threat-zone Exposure Map cards.';


-- Mock seeds — order of priority: internet > extranet > intranet.
UPDATE assets SET network_zone = 'internet' WHERE asset_id = 'ASSET-001';  -- juice-shop (public demo)
UPDATE assets SET network_zone = 'intranet' WHERE asset_id = 'ASSET-002';  -- data-pipeline (internal ETL)
UPDATE assets SET network_zone = 'extranet' WHERE asset_id = 'ASSET-003';  -- java-service (mobile-app backend → API gateway)
UPDATE assets SET network_zone = 'internet' WHERE asset_id = 'ASSET-004';  -- web-frontend (public marketing)
UPDATE assets SET network_zone = 'intranet' WHERE asset_id = 'ASSET-005';  -- vuln-test (sandbox)


-- Refresh the view to expose network_zone alongside the other asset fields.
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
  a.ip_address           AS asset_ip_address,
  a.network_zone         AS asset_network_zone
FROM issues i
LEFT JOIN assets a ON
  (
    (i.asset_identity->>'project') IS NOT NULL AND
    (
      a.name = (i.asset_identity->>'project')
      OR (i.asset_identity->>'project') = ANY(a.aliases)
    )
  )
  OR (
    (i.asset_identity->>'repo') IS NOT NULL AND
    (
      a.name = (i.asset_identity->>'repo')
      OR (i.asset_identity->>'repo') = ANY(a.aliases)
    )
  )
  OR (
    (i.asset_identity->>'hostname') IS NOT NULL AND
    a.hostname = (i.asset_identity->>'hostname')
  )
  OR (
    (i.asset_identity->>'ipv4') IS NOT NULL AND
    a.ip_address = (i.asset_identity->>'ipv4')
  );
