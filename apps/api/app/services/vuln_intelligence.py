"""Vulnerability intelligence service backed by DynamoDB.

Provides fast CVE/CWE lookups via DynamoDB BatchGetItem, replacing direct
NVD API calls with sub-200ms local repository lookups. Also supports
write-back of NVD API fallback data so future lookups hit the cache.

Requirements: 8.1–8.5, 9.1–9.8
"""

from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from decimal import Decimal

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)

# Maximum number of IDs allowed in a single batch request.
MAX_BATCH_SIZE = 100

# Maximum retries for UnprocessedKeys in BatchGetItem.
MAX_RETRIES = 3

# Default threshold for cache misses before emitting CloudWatch metric.
MAX_SYNC_CACHE_MISSES = int(os.environ.get("MAX_SYNC_CACHE_MISSES", "10"))


@dataclass
class NvdIntelligence:
    """NVD intelligence data for a single CVE."""

    cvss_v31_score: float | None
    cvss_v31_vector: str | None
    cvss_v31_severity: str | None
    cvss_attack_vector: str | None
    cvss_attack_complexity: str | None
    cvss_privileges_required: str | None
    cvss_user_interaction: str | None
    cwe_ids: list[str]
    affected_products: list[dict]
    description: str | None
    references: list[str]
    published_date: str | None
    last_modified_date: str | None


@dataclass
class MitreMapping:
    """MITRE ATT&CK mapping for a CWE."""

    cwe_id: str
    name: str
    description: str | None
    mitigations: list[str]


@dataclass
class CveIntelligence:
    """Intelligence result for a single CVE lookup.

    resolution values:
      - "resolved": full intelligence data available
      - "not_found": CVE confirmed absent from NVD
      - "lookup_failed": DynamoDB error or cache miss
    """

    cve_id: str
    resolution: str
    nvd: NvdIntelligence | None
    epss: dict | None = None
    kev: dict | None = None
    mitre: dict | None = None
    sources_present: list[str] = field(default_factory=list)


class VulnIntelligenceService:
    """Intelligence service backed by DynamoDB with write-back support.

    Uses BatchGetItem for efficient retrieval. All DynamoDB errors are caught
    and returned as resolution="lookup_failed" — never raises unhandled
    exceptions to the caller.

    Supports writing NVD API fallback data back to DynamoDB so that
    subsequent lookups hit the cache instead of the NVD API.

    Requirements: 9.1–9.8
    """

    def __init__(self, table_name: str, region: str = "us-east-1"):
        self._table_name = table_name
        self._region = region
        self._client = boto3.client("dynamodb", region_name=region)
        self._resource = boto3.resource("dynamodb", region_name=region)
        self._table = self._resource.Table(table_name)
        self._cloudwatch = boto3.client("cloudwatch", region_name=region)
        self._miss_count = 0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_cve_intelligence(self, cve_id: str) -> CveIntelligence | None:
        """Look up a single CVE.

        Returns CveIntelligence with resolution="resolved" if found,
        CveIntelligence with resolution="lookup_failed" if not found or error.

        Requirement 9.1: Returns CveIntelligence or None.
        Requirement 8.1: Cache miss returns lookup_failed within 200ms.
        Requirement 9.8: Never raises unhandled exception.
        """
        try:
            response = self._client.get_item(
                TableName=self._table_name,
                Key={
                    "pk": {"S": f"CVE#{cve_id}"},
                    "sk": {"S": "INTEL"},
                },
            )
        except (ClientError, Exception) as exc:
            logger.error("DynamoDB get_item failed for %s: %s", cve_id, exc)
            return self._make_lookup_failed(cve_id)

        item = response.get("Item")
        if item is None:
            # Cache miss — item not in table
            self._record_miss()
            return self._make_lookup_failed(cve_id)

        return self._parse_cve_item(item, cve_id)

    def batch_get_cve_intelligence(self, cve_ids: list[str]) -> dict[str, CveIntelligence | None]:
        """Batch lookup up to 100 CVE IDs.

        Raises ValueError if >100 IDs provided.
        Returns a dict mapping each CVE ID to CveIntelligence or None.

        Requirements: 9.2, 9.4, 9.6, 9.8, 8.5
        """
        if len(cve_ids) > MAX_BATCH_SIZE:
            raise ValueError(f"Batch size {len(cve_ids)} exceeds maximum of {MAX_BATCH_SIZE}")

        if not cve_ids:
            return {}

        # Build keys for BatchGetItem
        keys = [{"pk": {"S": f"CVE#{cve_id}"}, "sk": {"S": "INTEL"}} for cve_id in cve_ids]

        try:
            items = self._batch_get_items(keys)
        except Exception as exc:
            logger.error("DynamoDB batch_get failed: %s", exc)
            # Return lookup_failed for all IDs
            return {cve_id: self._make_lookup_failed(cve_id) for cve_id in cve_ids}

        # Build result mapping
        results: dict[str, CveIntelligence | None] = {}
        found_ids: set[str] = set()

        for item in items:
            cve_id = self._extract_string(item.get("cve_id"))
            if cve_id:
                found_ids.add(cve_id)
                results[cve_id] = self._parse_cve_item(item, cve_id)

        # Mark cache misses
        for cve_id in cve_ids:
            if cve_id not in found_ids:
                self._record_miss()
                results[cve_id] = self._make_lookup_failed(cve_id)

        return results

    def get_mitre_for_cwes(self, cwe_ids: list[str]) -> dict[str, MitreMapping | None]:
        """Batch lookup up to 100 CWE IDs.

        Raises ValueError if >100 IDs provided.
        Returns a dict mapping each CWE ID to MitreMapping or None.

        Requirements: 9.3, 9.6
        """
        if len(cwe_ids) > MAX_BATCH_SIZE:
            raise ValueError(f"Batch size {len(cwe_ids)} exceeds maximum of {MAX_BATCH_SIZE}")

        if not cwe_ids:
            return {}

        # Build keys for BatchGetItem
        keys = [{"pk": {"S": f"CWE#{cwe_id}"}, "sk": {"S": "MITRE"}} for cwe_id in cwe_ids]

        try:
            items = self._batch_get_items(keys)
        except Exception as exc:
            logger.error("DynamoDB batch_get for CWEs failed: %s", exc)
            return {cwe_id: None for cwe_id in cwe_ids}

        # Build result mapping
        results: dict[str, MitreMapping | None] = {}
        found_ids: set[str] = set()

        for item in items:
            cwe_id = self._extract_string(item.get("cwe_id"))
            if not cwe_id:
                # Try extracting from pk: "CWE#CWE-79" -> "CWE-79"
                pk = self._extract_string(item.get("pk"))
                if pk and pk.startswith("CWE#"):
                    cwe_id = pk[4:]

            if cwe_id:
                found_ids.add(cwe_id)
                results[cwe_id] = self._parse_mitre_item(item, cwe_id)

        # Mark missing CWEs as None
        for cwe_id in cwe_ids:
            if cwe_id not in found_ids:
                results[cwe_id] = None

        return results

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _batch_get_items(self, keys: list[dict]) -> list[dict]:
        """Execute BatchGetItem with retry for UnprocessedKeys.

        Retries up to MAX_RETRIES times with exponential backoff (1s, 2s, 4s).
        Requirement 9.4.
        """
        all_items: list[dict] = []
        request_keys = keys

        for attempt in range(MAX_RETRIES + 1):
            response = self._client.batch_get_item(
                RequestItems={self._table_name: {"Keys": request_keys}}
            )

            # Collect returned items
            table_items = response.get("Responses", {}).get(self._table_name, [])
            all_items.extend(table_items)

            # Check for unprocessed keys
            unprocessed = (
                response.get("UnprocessedKeys", {}).get(self._table_name, {}).get("Keys", [])
            )

            if not unprocessed:
                break

            if attempt < MAX_RETRIES:
                # Exponential backoff: 1s, 2s, 4s
                delay = 2**attempt
                logger.warning(
                    "BatchGetItem has %d unprocessed keys, retrying in %ds (attempt %d/%d)",
                    len(unprocessed),
                    delay,
                    attempt + 1,
                    MAX_RETRIES,
                )
                time.sleep(delay)
                request_keys = unprocessed
            else:
                # Exhausted retries — log but don't raise
                logger.error(
                    "BatchGetItem still has %d unprocessed keys after %d retries",
                    len(unprocessed),
                    MAX_RETRIES,
                )

        return all_items

    def _parse_cve_item(self, item: dict, cve_id: str) -> CveIntelligence:
        """Parse a DynamoDB CVE item into CveIntelligence dataclass."""
        try:
            resolution = self._extract_string(item.get("resolution")) or "lookup_failed"
            nvd_data = self._extract_map(item.get("nvd"))
            sources_present = self._extract_string_list(
                item.get("metadata", {}).get("M", {}).get("sources_present")
            )

            nvd = None
            if nvd_data:
                nvd = NvdIntelligence(
                    cvss_v31_score=self._extract_number(nvd_data.get("cvss_v31_score")),
                    cvss_v31_vector=self._extract_string(nvd_data.get("cvss_v31_vector")),
                    cvss_v31_severity=self._extract_string(nvd_data.get("cvss_v31_severity")),
                    cvss_attack_vector=self._extract_string(nvd_data.get("cvss_attack_vector")),
                    cvss_attack_complexity=self._extract_string(
                        nvd_data.get("cvss_attack_complexity")
                    ),
                    cvss_privileges_required=self._extract_string(
                        nvd_data.get("cvss_privileges_required")
                    ),
                    cvss_user_interaction=self._extract_string(
                        nvd_data.get("cvss_user_interaction")
                    ),
                    cwe_ids=self._extract_string_list(nvd_data.get("cwe_ids")),
                    affected_products=self._extract_list_of_maps(nvd_data.get("affected_products")),
                    description=self._extract_string(nvd_data.get("description")),
                    references=self._extract_string_list(nvd_data.get("references")),
                    published_date=self._extract_string(nvd_data.get("published_date")),
                    last_modified_date=self._extract_string(nvd_data.get("last_modified_date")),
                )

            epss = self._extract_map(item.get("epss"))
            kev = self._extract_map(item.get("kev"))
            mitre = self._extract_map(item.get("mitre"))

            return CveIntelligence(
                cve_id=cve_id,
                resolution=resolution,
                nvd=nvd,
                epss=epss if epss else None,
                kev=kev if kev else None,
                mitre=mitre if mitre else None,
                sources_present=sources_present,
            )
        except Exception as exc:
            logger.error("Failed to parse CVE item %s: %s", cve_id, exc)
            return self._make_lookup_failed(cve_id)

    def _parse_mitre_item(self, item: dict, cwe_id: str) -> MitreMapping:
        """Parse a DynamoDB CWE/MITRE item into MitreMapping dataclass."""
        return MitreMapping(
            cwe_id=cwe_id,
            name=self._extract_string(item.get("name")) or "",
            description=self._extract_string(item.get("description")),
            mitigations=self._extract_string_list(item.get("mitigations")),
        )

    def _make_lookup_failed(self, cve_id: str) -> CveIntelligence:
        """Create a CveIntelligence with resolution=lookup_failed.

        Requirement 8.1: Cache miss returns lookup_failed, nvd=None, sources_present=[].
        """
        return CveIntelligence(
            cve_id=cve_id,
            resolution="lookup_failed",
            nvd=None,
            epss=None,
            kev=None,
            mitre=None,
            sources_present=[],
        )

    def _record_miss(self) -> None:
        """Track cache misses and emit CloudWatch metric when threshold exceeded.

        Requirement 8.4: Emit CacheMissesLookupFailed when misses > MAX_SYNC_CACHE_MISSES.
        """
        self._miss_count += 1
        if self._miss_count > MAX_SYNC_CACHE_MISSES:
            try:
                self._cloudwatch.put_metric_data(
                    Namespace="Sisyfix/Intelligence",
                    MetricData=[
                        {
                            "MetricName": "CacheMissesLookupFailed",
                            "Value": self._miss_count,
                            "Unit": "Count",
                        }
                    ],
                )
                logger.warning(
                    "Cache misses (%d) exceeded threshold (%d), emitted CacheMissesLookupFailed metric",
                    self._miss_count,
                    MAX_SYNC_CACHE_MISSES,
                )
            except Exception as exc:
                # Don't let metric emission failure affect the service
                logger.error("Failed to emit CacheMissesLookupFailed metric: %s", exc)

    # ------------------------------------------------------------------
    # Write-back: store NVD API fallback data into DynamoDB
    # ------------------------------------------------------------------

    def write_back_cves(self, nvd_api_responses: list[dict]) -> int:
        """Write NVD API response items back to DynamoDB for future cache hits.

        Takes raw NVD 2.0 API response objects (the 'vulnerabilities[].cve' shape)
        and writes them as resolved intelligence items. Uses unconditional put —
        the Lambda sync pipeline will overwrite with newer data if it runs later.

        Args:
            nvd_api_responses: List of raw NVD 2.0 vulnerability objects.
                Each should have the shape: {"cve": {"id": "CVE-...", ...}}

        Returns:
            Number of items successfully written.
        """
        if not nvd_api_responses:
            return 0

        timestamp = datetime.now(UTC).isoformat()
        written = 0

        for vuln_json in nvd_api_responses:
            try:
                item = self._transform_nvd_to_dynamo_item(vuln_json, timestamp)
                if item is None:
                    continue

                # Convert floats to Decimal for DynamoDB Table resource
                cleaned = self._prepare_for_dynamo(item)
                self._table.put_item(Item=cleaned)
                written += 1
            except ClientError as exc:
                logger.error(
                    "Write-back failed for %s: %s",
                    vuln_json.get("cve", {}).get("id", "unknown"),
                    exc,
                )
            except Exception as exc:
                logger.error(
                    "Write-back transform/write error: %s",
                    exc,
                )

        logger.info("Write-back completed: %d/%d items written", written, len(nvd_api_responses))
        return written

    @staticmethod
    def _transform_nvd_to_dynamo_item(vuln_json: dict, timestamp: str) -> dict | None:
        """Transform a raw NVD 2.0 vulnerability object into DynamoDB item format.

        Mirrors the schema used by lambdas/nvd_sync/transformer.py so that
        items written here are indistinguishable from Lambda-synced items.

        Returns None if the input is invalid (missing CVE ID).
        """
        cve = vuln_json.get("cve")
        if not isinstance(cve, dict):
            return None

        cve_id = cve.get("id")
        if not cve_id or not isinstance(cve_id, str):
            return None

        # --- Extract CVSS v3.1 metrics ---
        cvss_score = None
        cvss_vector = None
        cvss_severity = None
        cvss_attack_vector = None
        cvss_attack_complexity = None
        cvss_privileges_required = None
        cvss_user_interaction = None

        metrics = cve.get("metrics")
        if isinstance(metrics, dict):
            # Prefer v3.1, fall back to v3.0
            cvss_list = metrics.get("cvssMetricV31") or metrics.get("cvssMetricV30")
            if isinstance(cvss_list, list) and len(cvss_list) > 0:
                first_metric = cvss_list[0]
                if isinstance(first_metric, dict):
                    cvss_data = first_metric.get("cvssData")
                    if isinstance(cvss_data, dict):
                        cvss_score = cvss_data.get("baseScore")
                        cvss_vector = cvss_data.get("vectorString")
                        cvss_severity = cvss_data.get("baseSeverity")
                        cvss_attack_vector = cvss_data.get("attackVector")
                        cvss_attack_complexity = cvss_data.get("attackComplexity")
                        cvss_privileges_required = cvss_data.get("privilegesRequired")
                        cvss_user_interaction = cvss_data.get("userInteraction")

        # --- Extract CWE IDs ---
        cwe_ids: list[str] = []
        weaknesses = cve.get("weaknesses")
        if isinstance(weaknesses, list):
            for weakness in weaknesses:
                if not isinstance(weakness, dict):
                    continue
                descriptions = weakness.get("description")
                if not isinstance(descriptions, list):
                    continue
                for desc in descriptions:
                    if isinstance(desc, dict) and desc.get("lang") == "en":
                        value = desc.get("value")
                        if isinstance(value, str) and value:
                            cwe_ids.append(value)

        # --- Extract English description ---
        description = None
        descriptions = cve.get("descriptions")
        if isinstance(descriptions, list):
            for desc in descriptions:
                if isinstance(desc, dict) and desc.get("lang") == "en":
                    value = desc.get("value")
                    if isinstance(value, str):
                        description = value
                        break

        # --- Extract reference URLs ---
        references: list[str] = []
        refs = cve.get("references")
        if isinstance(refs, list):
            for ref in refs:
                if isinstance(ref, dict):
                    url = ref.get("url")
                    if isinstance(url, str) and url:
                        references.append(url)

        # --- Extract dates ---
        published_date = cve.get("published") if isinstance(cve.get("published"), str) else None
        last_modified_date = (
            cve.get("lastModified") if isinstance(cve.get("lastModified"), str) else None
        )

        return {
            "pk": f"CVE#{cve_id}",
            "sk": "INTEL",
            "cve_id": cve_id,
            "resolution": "resolved",
            "nvd": {
                "cvss_v31_score": cvss_score,
                "cvss_v31_vector": cvss_vector,
                "cvss_v31_severity": cvss_severity,
                "cvss_attack_vector": cvss_attack_vector,
                "cvss_attack_complexity": cvss_attack_complexity,
                "cvss_privileges_required": cvss_privileges_required,
                "cvss_user_interaction": cvss_user_interaction,
                "cwe_ids": cwe_ids,
                "affected_products": [],
                "description": description,
                "references": references,
                "published_date": published_date,
                "last_modified_date": last_modified_date,
            },
            "epss": None,
            "kev": None,
            "mitre": None,
            "metadata": {
                "sources_present": ["nvd"],
                "source": "api-write-back",
                "version": 1,
                "created_at": timestamp,
                "updated_at": timestamp,
            },
        }

    @staticmethod
    def _prepare_for_dynamo(item: dict) -> dict:
        """Recursively prepare an item for DynamoDB Table resource write.

        Converts float to Decimal and removes None values.
        """
        cleaned = {}
        for key, value in item.items():
            if value is None:
                continue
            cleaned[key] = VulnIntelligenceService._convert_value(value)
        return cleaned

    @staticmethod
    def _convert_value(value):
        """Convert a single value for DynamoDB compatibility."""
        if value is None:
            return None
        if isinstance(value, float):
            return Decimal(str(value))
        if isinstance(value, int) and not isinstance(value, bool):
            return value
        if isinstance(value, dict):
            return VulnIntelligenceService._prepare_for_dynamo(value)
        if isinstance(value, list):
            return [VulnIntelligenceService._convert_value(v) for v in value if v is not None]
        return value

    # ------------------------------------------------------------------
    # DynamoDB type extraction helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_string(value: dict | None) -> str | None:
        """Extract a string from a DynamoDB typed attribute {'S': '...'}."""
        if value is None:
            return None
        if isinstance(value, dict):
            if "S" in value:
                return value["S"]
            if "NULL" in value:
                return None
        return None

    @staticmethod
    def _extract_number(value: dict | None) -> float | None:
        """Extract a number from a DynamoDB typed attribute {'N': '...'}."""
        if value is None:
            return None
        if isinstance(value, dict):
            if "N" in value:
                try:
                    return float(value["N"])
                except (ValueError, TypeError):
                    return None
            if "NULL" in value:
                return None
        return None

    @staticmethod
    def _extract_map(value: dict | None) -> dict | None:
        """Extract a map from a DynamoDB typed attribute {'M': {...}}."""
        if value is None:
            return None
        if isinstance(value, dict):
            if "M" in value:
                return value["M"]
            if "NULL" in value:
                return None
        return None

    @staticmethod
    def _extract_string_list(value: dict | None) -> list[str]:
        """Extract a list of strings from a DynamoDB typed attribute {'L': [...]}."""
        if value is None:
            return []
        if isinstance(value, dict):
            if "L" in value:
                return [
                    item.get("S", "")
                    for item in value["L"]
                    if isinstance(item, dict) and "S" in item
                ]
            if "NULL" in value:
                return []
        return []

    @staticmethod
    def _extract_list_of_maps(value: dict | None) -> list[dict]:
        """Extract a list of maps from a DynamoDB typed attribute {'L': [{'M': {...}}, ...]}."""
        if value is None:
            return []
        if isinstance(value, dict):
            if "L" in value:
                result = []
                for item in value["L"]:
                    if isinstance(item, dict) and "M" in item:
                        result.append(item["M"])
                return result
            if "NULL" in value:
                return []
        return []
