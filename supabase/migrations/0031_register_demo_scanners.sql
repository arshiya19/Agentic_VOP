-- =============================================================================
-- 0031 — Register 3 new scanners for demo data ingestion via file_upload
--
-- Adds: nessus (host/network), grype (container), burp-suite (web app DAST).
-- Each tool is registered with protocol=FILE + connector_type=file_upload so
-- the existing /admin/scanners/{tool}/upload endpoint accepts JSON files for
-- them. The upload endpoint writes file_pointer/file_filename/file_format
-- into metadata when the user uploads.
--
-- Apply: paste into Supabase Dashboard SQL Editor, or run via supabase CLI.
-- =============================================================================

INSERT INTO connection_registry (
  tool, protocol, auth_type, endpoint, auth_ref, timeout_sec, enabled, metadata
) VALUES
  (
    'nessus',
    'FILE',
    'none',
    '',
    'file:nessus',
    30,
    true,
    jsonb_build_object(
      'connector_type', 'file_upload',
      'file_format',    'json',
      'note',           'Tenable Nessus scan export. Upload a JSON file with a top-level "vulnerabilities" array.'
    )
  ),
  (
    'grype',
    'FILE',
    'none',
    '',
    'file:grype',
    30,
    true,
    jsonb_build_object(
      'connector_type', 'file_upload',
      'file_format',    'json',
      'response_path',  'matches',
      'note',           'Anchore Grype container scan output (grype -o json). Top-level "matches" array.'
    )
  ),
  (
    'burp-suite',
    'FILE',
    'none',
    '',
    'file:burp-suite',
    30,
    true,
    jsonb_build_object(
      'connector_type', 'file_upload',
      'file_format',    'json',
      'response_path',  'issue_events',
      'note',           'Burp Suite issue export. Top-level "issue_events" array.'
    )
  )
ON CONFLICT (tool) DO UPDATE SET
  protocol    = EXCLUDED.protocol,
  auth_type   = EXCLUDED.auth_type,
  auth_ref    = EXCLUDED.auth_ref,
  timeout_sec = EXCLUDED.timeout_sec,
  enabled     = EXCLUDED.enabled,
  -- preserve any file_pointer the user has already uploaded
  metadata    = connection_registry.metadata || EXCLUDED.metadata,
  updated_at  = now();
