-- =============================================================================
-- Agentic_VOP — Extend the assets seed from 5 → 10 rows
-- =============================================================================
-- Adds 5 more mock assets so the CMDB feels like a real enterprise inventory:
--
--   ASSET-006  payments-api         (service, prod, public via API gateway, crit 5, extranet, PCI+SOC2)
--   ASSET-007  mongo-prod-01        (infrastructure, prod, internal,           crit 5, intranet, HIPAA+SOC2)
--   ASSET-008  admin-portal         (application,    prod, internal,           crit 4, intranet, SOC2)
--   ASSET-009  customer-portal      (application,    prod, public,             crit 3, internet, GDPR+SOC2)
--   ASSET-010  ci-jenkins-01        (infrastructure, dev,  internal,           crit 2, intranet, none)
--
-- Why these specific picks:
--   - 2 more crown jewels  (payments-api + mongo-prod-01) → Crown Jewel card more realistic
--   - First `infrastructure` assets in the CMDB (mongo, ci-jenkins) → exercise the
--     hostname/IP join path in `issue_with_asset` for future host-based scanners
--   - More compliance variety (PCI+SOC2, HIPAA+SOC2, SOC2-only, GDPR+SOC2, none)
--   - All three network zones populated more evenly
--
-- Note on findings coverage:
--   These 5 new assets have NO existing issues in your current data (no scanner
--   has reported findings against `payments-api`, `mongo-prod-01`, etc.). They
--   show as "0 findings" assets on the dashboard — which is actually realistic
--   for an enterprise CMDB (most assets aren't covered by every scanner).
--
-- Apply: paste into Supabase Dashboard SQL Editor.
-- =============================================================================

INSERT INTO assets (
  asset_id, hostname, ip_address, asset_type, environment, business_owner, contact_email,
  name, aliases, application_name, description, repo_url,
  exposure, business_criticality, data_classification, compliance_tags,
  owner_team, network_zone
) VALUES
  ( 'ASSET-006',
    'payments-api.example.com',
    '203.0.113.55',
    'service',
    'production',
    'Payments Team',
    'payments@company.com',
    'payments-api',
    ARRAY[]::text[],
    'Payments API',
    'Customer-facing payment processing API. Handles card transactions, settlements, refunds.',
    'github.com/example/payments-api',
    'public',
    5,
    'restricted',
    ARRAY['PCI-DSS','SOC2'],
    'Payments Team',
    'extranet'
  ),
  ( 'ASSET-007',
    'mongo-prod-01.internal',
    '10.0.5.50',
    'infrastructure',
    'production',
    'Data Platform Team',
    'data-platform@company.com',
    'mongo-prod-01',
    ARRAY[]::text[],
    'Production MongoDB Cluster',
    'Primary production MongoDB cluster. Hosts customer + patient records used by data-pipeline.',
    NULL,
    'internal',
    5,
    'restricted',
    ARRAY['HIPAA','SOC2'],
    'Data Platform Team',
    'intranet'
  ),
  ( 'ASSET-008',
    'admin.internal',
    '10.0.7.10',
    'application',
    'production',
    'Internal Tools Team',
    'internal-tools@company.com',
    'admin-portal',
    ARRAY[]::text[],
    'Internal Admin Portal',
    'Employee admin portal for user management, role assignment, support ticket review.',
    'github.com/example/admin-portal',
    'internal',
    4,
    'confidential',
    ARRAY['SOC2'],
    'Internal Tools Team',
    'intranet'
  ),
  ( 'ASSET-009',
    'portal.example.com',
    '203.0.113.20',
    'application',
    'production',
    'Customer Experience Team',
    'cx-team@company.com',
    'customer-portal',
    ARRAY[]::text[],
    'Customer Self-Service Portal',
    'Public customer-facing portal for account management, billing, profile updates.',
    'github.com/example/customer-portal',
    'public',
    3,
    'confidential',
    ARRAY['GDPR','SOC2'],
    'Customer Experience Team',
    'internet'
  ),
  ( 'ASSET-010',
    'ci-jenkins-01.internal',
    '10.0.99.20',
    'infrastructure',
    'development',
    'DevOps Team',
    'devops@company.com',
    'ci-jenkins-01',
    ARRAY[]::text[],
    'Jenkins Build Runner',
    'Internal CI/CD runner for build + test pipelines. Not customer-facing.',
    NULL,
    'internal',
    2,
    'internal',
    ARRAY[]::text[],
    'DevOps Team',
    'intranet'
  )
ON CONFLICT (asset_id) DO UPDATE SET
  hostname             = EXCLUDED.hostname,
  ip_address           = EXCLUDED.ip_address,
  asset_type           = EXCLUDED.asset_type,
  environment          = EXCLUDED.environment,
  business_owner       = EXCLUDED.business_owner,
  contact_email        = EXCLUDED.contact_email,
  name                 = EXCLUDED.name,
  aliases              = EXCLUDED.aliases,
  application_name     = EXCLUDED.application_name,
  description          = EXCLUDED.description,
  repo_url             = EXCLUDED.repo_url,
  exposure             = EXCLUDED.exposure,
  business_criticality = EXCLUDED.business_criticality,
  data_classification  = EXCLUDED.data_classification,
  compliance_tags      = EXCLUDED.compliance_tags,
  owner_team           = EXCLUDED.owner_team,
  network_zone         = EXCLUDED.network_zone,
  updated_at           = now();


-- =============================================================================
-- Sanity check queries you can run after applying:
-- =============================================================================
--   -- Confirm row count + distribution:
--   SELECT asset_type, count(*) FROM assets GROUP BY asset_type ORDER BY count(*) DESC;
--   SELECT environment, count(*) FROM assets GROUP BY environment ORDER BY count(*) DESC;
--   SELECT network_zone, count(*) FROM assets GROUP BY network_zone ORDER BY count(*) DESC;
--   SELECT business_criticality, count(*) FROM assets GROUP BY business_criticality ORDER BY business_criticality DESC;
--
--   -- Compliance scope coverage:
--   SELECT unnest(compliance_tags) AS tag, count(*) AS assets
--   FROM assets WHERE compliance_tags <> '{}'
--   GROUP BY tag ORDER BY assets DESC;
--
--   -- All 10 assets at a glance:
--   SELECT asset_id, name, asset_type, environment, exposure,
--          business_criticality, network_zone, compliance_tags
--   FROM assets ORDER BY asset_id;
