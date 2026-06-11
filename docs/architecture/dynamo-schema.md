# DynamoDB Schema Design

## Table Configuration

| Property | Value |
|----------|-------|
| Table name | `sisyfix-{env}-vulnerability-intelligence` |
| Partition key | `pk` (String) |
| Sort key | `sk` (String) |
| Billing mode | PAY_PER_REQUEST (on-demand) |
| Encryption | AWS-managed (aws/dynamodb) |
| PITR | Enabled in prod, disabled in dev |
| Deletion protection | Enabled in prod, disabled in dev |

## Key Patterns

The table uses a single-table design where different entity types share the same table, distinguished by key prefixes.

| Entity | pk | sk | Description |
|--------|-----|-----|-------------|
| CVE Intelligence | `CVE#{cve_id}` | `INTEL` | Full intelligence record for a CVE |
| CWE/MITRE Mapping | `CWE#{cwe_id}` | `MITRE` | MITRE ATT&CK mapping for a CWE |
| Sync Checkpoint | `SYSTEM#SYNC` | `{source}` | Per-source sync state (e.g., `NVD`) |
| Backfill Checkpoint | `SYSTEM#BACKFILL` | `{source}` | Backfill progress tracking |

## Item Schemas

### CVE Intelligence Item

The primary item type. One per CVE.

```json
{
  "pk": "CVE#CVE-2024-1234",
  "sk": "INTEL",
  "cve_id": "CVE-2024-1234",
  "resolution": "resolved",
  "nvd": {
    "cvss_v31_score": 7.5,
    "cvss_v31_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
    "cvss_v31_severity": "HIGH",
    "cvss_attack_vector": "NETWORK",
    "cvss_attack_complexity": "LOW",
    "cvss_privileges_required": "NONE",
    "cvss_user_interaction": "NONE",
    "cwe_ids": ["CWE-79", "CWE-89"],
    "affected_products": [
      {"vendor": "apache", "product": "httpd", "versions": "[2.4.0, 2.4.51)"}
    ],
    "description": "A vulnerability in...",
    "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-1234"],
    "published_date": "2024-01-15T10:00:00.000",
    "last_modified_date": "2024-01-16T12:00:00.000"
  },
  "epss": null,
  "kev": null,
  "mitre": null,
  "metadata": {
    "sources_present": ["nvd"],
    "version": 1,
    "created_at": "2024-01-16T12:00:00Z",
    "updated_at": "2024-01-16T12:00:00Z"
  }
}
```

**Field descriptions:**

| Field | Type | Description |
|-------|------|-------------|
| `resolution` | String | `resolved` (data available), `not_found` (confirmed absent) |
| `nvd` | Map / null | NVD intelligence data; null if source hasn't been loaded |
| `epss` | Map / null | Future: EPSS probability score |
| `kev` | Map / null | Future: CISA KEV catalog entry |
| `mitre` | Map / null | Future: MITRE ATT&CK technique mapping |
| `metadata.sources_present` | List | Which sources have contributed data |
| `metadata.version` | Number | Schema version, incremented on structural changes |
| `metadata.created_at` | String | ISO 8601 UTC, when item was first created |
| `metadata.updated_at` | String | ISO 8601 UTC, when item was last modified |

### Sync Checkpoint Item

One per intelligence source. Tracks the last successful sync state.

```json
{
  "pk": "SYSTEM#SYNC",
  "sk": "NVD",
  "last_successful_sync": "2024-01-16T12:00:00Z",
  "meta_sha256": "a1b2c3d4e5f6..."
}
```

### Backfill Progress Checkpoint

Tracks which years have been loaded during backfill.

```json
{
  "pk": "SYSTEM#BACKFILL",
  "sk": "NVD",
  "last_completed_year": 2023,
  "completed_at": "2024-01-10T15:30:00Z"
}
```

### CWE/MITRE Mapping Item

Future use — maps CWE weaknesses to MITRE ATT&CK techniques.

```json
{
  "pk": "CWE#CWE-79",
  "sk": "MITRE",
  "cwe_id": "CWE-79",
  "name": "Improper Neutralization of Input During Web Page Generation",
  "description": "The software does not neutralize or incorrectly neutralizes...",
  "mitigations": ["Input validation", "Output encoding"]
}
```

## Access Patterns

| Access Pattern | Key Condition | Used By |
|---------------|--------------|---------|
| Get single CVE | `pk = CVE#{id}` AND `sk = INTEL` | Intelligence Service `get_cve_intelligence` |
| Batch get CVEs | Multiple `pk = CVE#{id}` AND `sk = INTEL` | Intelligence Service `batch_get_cve_intelligence` |
| Get CWE mapping | `pk = CWE#{id}` AND `sk = MITRE` | Intelligence Service `get_mitre_for_cwes` |
| Read sync checkpoint | `pk = SYSTEM#SYNC` AND `sk = NVD` | Sync Lambda (start of run) |
| Write sync checkpoint | `pk = SYSTEM#SYNC` AND `sk = NVD` | Sync Lambda (after successful write) |
| Read backfill progress | `pk = SYSTEM#BACKFILL` AND `sk = NVD` | Backfill CLI (resume) |
| Write backfill progress | `pk = SYSTEM#BACKFILL` AND `sk = NVD` | Backfill CLI (after each year) |

## Conditional Writes

The system uses conditional expressions to prevent overwriting newer data:

```
ConditionExpression: attribute_not_exists(pk) OR metadata.updated_at < :new_ts
```

This ensures that if two sources write to the same item concurrently, the newer write always wins.

## Future Extension

Adding a new intelligence source (e.g., EPSS) requires:

1. A new Lambda that writes to the `epss` field of existing CVE items
2. A new checkpoint item (`pk=SYSTEM#SYNC, sk=EPSS`)
3. The `metadata.sources_present` list gets `"epss"` appended
4. No schema changes to the table itself — that's the power of single-table design
