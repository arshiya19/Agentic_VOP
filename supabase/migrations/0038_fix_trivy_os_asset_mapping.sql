-- =============================================================================
-- Fix Trivy-OS asset mapping
-- =============================================================================
-- Trivy-OS findings have asset_identity.hostname = "ip-172-31-2-190 (ubuntu 20.04)"
-- and asset_identity.name with the same value. But ASSET-016 (vuln-lab-os-image)
-- has hostname = "vop-vuln-lab-env1-instance" — no match.
--
-- Fix:
--   1. Add the Trivy-OS hostname to ASSET-016's aliases so current findings match.
--   2. Update the issue_with_asset view to ALSO match asset_identity->>'name'
--      against aliases. This covers any scanner that uses the 'name' key
--      (Trivy-OS, Trivy-Image, etc.) and doesn't rely only on project/repo.
-- =============================================================================

-- 1. Add the Trivy-OS hostname as an alias on ASSET-016
UPDATE assets
SET aliases = array_append(aliases, 'ip-172-31-2-190 (ubuntu 20.04)'),
    updated_at = now()
WHERE asset_id = 'ASSET-016'
  AND NOT ('ip-172-31-2-190 (ubuntu 20.04)' = ANY(aliases));

-- 2. Recreate the view with an additional match on asset_identity->>'name'
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
  -- Match by project field (Checkov, IaC scanners)
  (
    (i.asset_identity->>'project') IS NOT NULL AND
    (
      a.name = (i.asset_identity->>'project')
      OR (i.asset_identity->>'project') = ANY(a.aliases)
    )
  )
  -- Match by repo field (Dependabot, GitHub scanners)
  OR (
    (i.asset_identity->>'repo') IS NOT NULL AND
    (
      a.name = (i.asset_identity->>'repo')
      OR (i.asset_identity->>'repo') = ANY(a.aliases)
    )
  )
  -- Match by name field (Trivy-OS, Trivy-Image, generic scanners)
  OR (
    (i.asset_identity->>'name') IS NOT NULL AND
    (
      a.name = (i.asset_identity->>'name')
      OR (i.asset_identity->>'name') = ANY(a.aliases)
    )
  )
  -- Match by hostname field (Qualys, Nessus, host-based scanners)
  OR (
    (i.asset_identity->>'hostname') IS NOT NULL AND
    (
      a.hostname = (i.asset_identity->>'hostname')
      OR (i.asset_identity->>'hostname') = ANY(a.aliases)
    )
  )
  -- Match by IP address
  OR (
    (i.asset_identity->>'ipv4') IS NOT NULL AND
    a.ip_address = (i.asset_identity->>'ipv4')
  );

COMMENT ON VIEW issue_with_asset IS
  'Issues joined to their resolved asset. Matches on project, repo, name, hostname (including aliases), and IP. NULL asset fields = unattributed.';
