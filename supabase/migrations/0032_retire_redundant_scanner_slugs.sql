-- =============================================================================
-- 0032 — Retire `nessus` and `qualys-vuln` registry rows
--
-- These two slugs were added in 0031 / earlier as separate file_upload
-- registrations, but the catalog already has tiles for the same products
-- under different slugs:
--   nessus       -> use 'Tenable Nessus' tile (slug: tenable-nessus-vuln)
--   qualys-vuln  -> use 'Qualys VMDR' tile   (slug: qualys-vmdr-vuln)
--
-- Both `nessus` and `qualys-vuln` currently have 0 issues in the issues
-- table, so deleting their registry rows is safe — no orphan data.
--
-- Apply: paste into Supabase Dashboard SQL Editor.
-- =============================================================================

DELETE FROM connection_registry
WHERE tool IN ('nessus', 'qualys-vuln');
