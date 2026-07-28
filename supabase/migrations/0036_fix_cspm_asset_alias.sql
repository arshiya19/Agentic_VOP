-- Add "/main.tf" to the aliases of the CSPM Terraform asset so the
-- issue_with_asset view correctly resolves Checkov findings whose
-- asset_identity.project = "/main.tf" to this asset.
--
-- Background: The Checkov scanner on the vuln-lab EC2 instance scans
-- /opt/lab/main.tf and Sub-Agent 1 normalizes the project field to
-- "/main.tf". The asset only has "/cspm-lab.tf" as a file-path alias,
-- so all 11 Checkov findings end up unattributed (asset_id = NULL in the
-- issue_with_asset view). Adding "/main.tf" resolves this.

UPDATE assets
SET aliases = array_append(aliases, '/main.tf'),
    updated_at = now()
WHERE asset_id = 'ASSET-015'
  AND NOT ('/main.tf' = ANY(aliases));
