-- =============================================================================
-- 0034 — Materialize runtime metadata as columns on issues
--
-- Phase 1.5 of the Remediation Engine spec §13. Promotes the
-- issue_with_runtime view (migration 0033) into real columns on the issues
-- table so they can be queried + indexed directly.
--
-- Three parts:
--   1. ADD columns (nullable, default NULL — fully additive)
--   2. BACKFILL from raw_findings using the same JSONB extraction the view uses
--   3. BEFORE INSERT trigger that runs the same extraction for new rows
--
-- Safety: the trigger function wraps extraction in EXCEPTION WHEN OTHERS THEN
-- NULL so any failure leaves runtime_* fields NULL but NEVER blocks the
-- INSERT. The existing Sub-Agent 1 pipeline is untouched — no Python changes,
-- no prompt changes.
--
-- The 0033 view stays in place; it now selects the same data via a different
-- path and remains useful for debugging / cross-checking the trigger.
-- =============================================================================

-- -----------------------------------------------------------------------------
-- 1. Columns
-- -----------------------------------------------------------------------------
ALTER TABLE issues
  ADD COLUMN IF NOT EXISTS runtime_hostname        text,
  ADD COLUMN IF NOT EXISTS runtime_ipv4            text,
  ADD COLUMN IF NOT EXISTS runtime_os_raw          text,
  ADD COLUMN IF NOT EXISTS runtime_os_family       text,
  ADD COLUMN IF NOT EXISTS runtime_distro_version  text,
  ADD COLUMN IF NOT EXISTS runtime_purl            text,
  ADD COLUMN IF NOT EXISTS runtime_image_id        text;

COMMENT ON COLUMN issues.runtime_hostname       IS 'Resolved hostname from asset_identity or raw_findings (Nessus/Qualys/Burp).';
COMMENT ON COLUMN issues.runtime_ipv4           IS 'Resolved IPv4 from asset_identity or raw_findings (Nessus/Qualys).';
COMMENT ON COLUMN issues.runtime_os_raw         IS 'Raw OS string as the scanner reported it (e.g. "Ubuntu 22.04.4 LTS").';
COMMENT ON COLUMN issues.runtime_os_family      IS 'Normalized OS family (ubuntu/debian/rhel/centos/amzn/windows/macos/alpine). Wave-grouping key per Remediation spec §8.';
COMMENT ON COLUMN issues.runtime_distro_version IS 'Distro version from Grype matchDetails. NULL for non-container scanners.';
COMMENT ON COLUMN issues.runtime_purl           IS 'Package URL (e.g. pkg:deb/debian/openssl@3.0.7) — proto-signature for spec §4.';
COMMENT ON COLUMN issues.runtime_image_id       IS 'Container image identifier. Empty today; populates once file_upload connector preserves parent context.';

-- -----------------------------------------------------------------------------
-- 2. Backfill from raw_findings
-- -----------------------------------------------------------------------------
UPDATE issues i SET
  runtime_hostname = COALESCE(
    i.asset_identity ->> 'hostname',
    rf.raw #>> '{host,hostname}',
    rf.raw #>> '{HOST,DNS}'
  ),
  runtime_ipv4 = COALESCE(
    i.asset_identity ->> 'ipv4',
    i.asset_identity ->> 'ip',
    rf.raw #>> '{host,ipv4}',
    rf.raw #>> '{HOST,IP}'
  ),
  runtime_os_raw = COALESCE(
    i.asset_identity ->> 'operating_system',
    rf.raw #>> '{host,operating_system}',
    rf.raw #>> '{HOST,OPERATING_SYSTEM}',
    rf.raw #>> '{matchDetails,0,searchedBy,distro,type}'
  ),
  runtime_distro_version = rf.raw #>> '{matchDetails,0,searchedBy,distro,version}',
  runtime_purl = COALESCE(
    i.asset_identity ->> 'package_purl',
    rf.raw #>> '{artifact,purl}'
  ),
  runtime_image_id = i.asset_identity ->> 'image_id'
FROM raw_findings rf
WHERE rf.id = i.raw_finding_id;

-- Derive os_family separately so we don't repeat the COALESCE.
UPDATE issues SET
  runtime_os_family = CASE
    WHEN runtime_os_raw ILIKE '%ubuntu%'       THEN 'ubuntu'
    WHEN runtime_os_raw ILIKE '%debian%'       THEN 'debian'
    WHEN runtime_os_raw ILIKE '%red hat%'
      OR runtime_os_raw ILIKE '%rhel%'         THEN 'rhel'
    WHEN runtime_os_raw ILIKE '%centos%'       THEN 'centos'
    WHEN runtime_os_raw ILIKE '%amazon linux%' THEN 'amzn'
    WHEN runtime_os_raw ILIKE '%windows%'      THEN 'windows'
    WHEN runtime_os_raw ILIKE '%macos%'        THEN 'macos'
    WHEN runtime_os_raw ILIKE '%alpine%'
      OR runtime_os_raw = 'alpine'             THEN 'alpine'
    ELSE NULL
  END
WHERE runtime_os_raw IS NOT NULL;

-- -----------------------------------------------------------------------------
-- 3. Trigger: keep new rows populated. Defensive — any failure leaves
--    runtime_* NULL but the INSERT always succeeds.
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION populate_issue_runtime_fields()
RETURNS TRIGGER AS $$
DECLARE
  raw_body jsonb;
BEGIN
  BEGIN
    SELECT raw INTO raw_body FROM raw_findings WHERE id = NEW.raw_finding_id;
  EXCEPTION WHEN OTHERS THEN
    raw_body := NULL;
  END;

  BEGIN
    NEW.runtime_hostname := COALESCE(
      NEW.asset_identity ->> 'hostname',
      raw_body #>> '{host,hostname}',
      raw_body #>> '{HOST,DNS}'
    );

    NEW.runtime_ipv4 := COALESCE(
      NEW.asset_identity ->> 'ipv4',
      NEW.asset_identity ->> 'ip',
      raw_body #>> '{host,ipv4}',
      raw_body #>> '{HOST,IP}'
    );

    NEW.runtime_os_raw := COALESCE(
      NEW.asset_identity ->> 'operating_system',
      raw_body #>> '{host,operating_system}',
      raw_body #>> '{HOST,OPERATING_SYSTEM}',
      raw_body #>> '{matchDetails,0,searchedBy,distro,type}'
    );

    NEW.runtime_distro_version := raw_body #>> '{matchDetails,0,searchedBy,distro,version}';

    NEW.runtime_purl := COALESCE(
      NEW.asset_identity ->> 'package_purl',
      raw_body #>> '{artifact,purl}'
    );

    NEW.runtime_image_id := NEW.asset_identity ->> 'image_id';

    NEW.runtime_os_family := CASE
      WHEN NEW.runtime_os_raw ILIKE '%ubuntu%'       THEN 'ubuntu'
      WHEN NEW.runtime_os_raw ILIKE '%debian%'       THEN 'debian'
      WHEN NEW.runtime_os_raw ILIKE '%red hat%'
        OR NEW.runtime_os_raw ILIKE '%rhel%'         THEN 'rhel'
      WHEN NEW.runtime_os_raw ILIKE '%centos%'       THEN 'centos'
      WHEN NEW.runtime_os_raw ILIKE '%amazon linux%' THEN 'amzn'
      WHEN NEW.runtime_os_raw ILIKE '%windows%'      THEN 'windows'
      WHEN NEW.runtime_os_raw ILIKE '%macos%'        THEN 'macos'
      WHEN NEW.runtime_os_raw ILIKE '%alpine%'
        OR NEW.runtime_os_raw = 'alpine'             THEN 'alpine'
      ELSE NULL
    END;
  EXCEPTION WHEN OTHERS THEN
    -- Any extraction failure leaves runtime_* NULL but never blocks the insert.
    NULL;
  END;

  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_issues_populate_runtime ON issues;
CREATE TRIGGER trg_issues_populate_runtime
  BEFORE INSERT ON issues
  FOR EACH ROW
  EXECUTE FUNCTION populate_issue_runtime_fields();

-- -----------------------------------------------------------------------------
-- 4. Partial indexes for fast grouping queries on the new columns
-- -----------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_issues_runtime_os_family ON issues(runtime_os_family) WHERE runtime_os_family IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_issues_runtime_hostname  ON issues(runtime_hostname)  WHERE runtime_hostname  IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_issues_runtime_purl      ON issues(runtime_purl)      WHERE runtime_purl      IS NOT NULL;
