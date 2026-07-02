-- =============================================================================
-- 0033 — issue_with_runtime view (Phase 0 of the Remediation Engine spec §13)
--
-- Surfaces runtime / platform metadata that already exists in raw_findings
-- but isn't structured on the issues table:
--   - hostname / ipv4         (host scanners — Nessus, Qualys, Burp)
--   - os family + raw string  (Nessus, Qualys)
--   - distro version          (Grype matchDetails)
--   - purl                    (Grype artifact — normalized package identity)
--   - image_id                (forward-compat — empty today, will populate once
--                              the file_upload connector preserves parent
--                              context for Trivy/Grype)
--
-- Pure additive — no write-path changes, no schema changes to issues/assets,
-- no Sub-Agent 1 prompt changes. Reversible: DROP VIEW issue_with_runtime.
--
-- Coverage at creation time (1,860 issues):
--   runtime_hostname    892 / 1860  (48%)
--   runtime_ipv4        708 / 1860  (38%)
--   runtime_os_family   705 / 1860  (38%) — 7 distinct families
--   runtime_purl        ~270        (15%) — Grype findings
--
-- Read-time JSONB extraction. At current scale (~2k issues) latency is
-- negligible. If/when we hit millions, promote these columns onto the
-- issues table proper and backfill (Phase 1.5).
-- =============================================================================

CREATE OR REPLACE VIEW issue_with_runtime AS
WITH ext AS (
  SELECT
    i.*,
    COALESCE(
      i.asset_identity ->> 'hostname',
      rf.raw #>> '{host,hostname}',
      rf.raw #>> '{HOST,DNS}'
    )                                                       AS runtime_hostname,

    COALESCE(
      i.asset_identity ->> 'ipv4',
      i.asset_identity ->> 'ip',
      rf.raw #>> '{host,ipv4}',
      rf.raw #>> '{HOST,IP}'
    )                                                       AS runtime_ipv4,

    COALESCE(
      i.asset_identity ->> 'operating_system',
      rf.raw #>> '{host,operating_system}',
      rf.raw #>> '{HOST,OPERATING_SYSTEM}',
      rf.raw #>> '{matchDetails,0,searchedBy,distro,type}'
    )                                                       AS runtime_os_raw,

    rf.raw #>> '{matchDetails,0,searchedBy,distro,version}' AS runtime_distro_version,

    COALESCE(
      i.asset_identity ->> 'package_purl',
      rf.raw #>> '{artifact,purl}'
    )                                                       AS runtime_purl,

    i.asset_identity ->> 'image_id'                         AS runtime_image_id
  FROM issues i
  LEFT JOIN raw_findings rf ON rf.id = i.raw_finding_id
)
SELECT
  ext.*,
  CASE
    WHEN ext.runtime_os_raw ILIKE '%ubuntu%'        THEN 'ubuntu'
    WHEN ext.runtime_os_raw ILIKE '%debian%'        THEN 'debian'
    WHEN ext.runtime_os_raw ILIKE '%red hat%'
      OR ext.runtime_os_raw ILIKE '%rhel%'          THEN 'rhel'
    WHEN ext.runtime_os_raw ILIKE '%centos%'        THEN 'centos'
    WHEN ext.runtime_os_raw ILIKE '%amazon linux%'  THEN 'amzn'
    WHEN ext.runtime_os_raw ILIKE '%windows%'       THEN 'windows'
    WHEN ext.runtime_os_raw ILIKE '%macos%'         THEN 'macos'
    WHEN ext.runtime_os_raw ILIKE '%alpine%'
      OR ext.runtime_os_raw = 'alpine'              THEN 'alpine'
    ELSE NULL
  END AS runtime_os_family
FROM ext;

COMMENT ON VIEW issue_with_runtime IS
  'Issues with runtime/platform metadata extracted from raw_findings at read '
  'time. Read-only, derived. Drives runtime-based grouping on the /remediation '
  'page. See Remediation Engine spec §13.';
