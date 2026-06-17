"""Integration tests for the VulnIntelligenceService with DynamoDB.

Tests query patterns against moto-mocked DynamoDB with seeded intelligence data.
Verifies correct resolution behavior for single and batch lookups,
cache miss handling, and error resilience.

Requirements: 8.1–8.5, 9.1–9.8
"""

from __future__ import annotations

import time
from unittest.mock import patch

import boto3
import pytest
from moto import mock_aws

from app.services.vuln_intelligence import (
    CveIntelligence,
    MitreMapping,
    NvdIntelligence,
    VulnIntelligenceService,
)


# ---------------------------------------------------------------------------
# Test fixtures and helpers
# ---------------------------------------------------------------------------

TABLE_NAME = "sisyfix-dev-vulnerability-intelligence"
REGION = "us-east-1"


def _make_cve_dynamo_item(cve_id: str, *, has_cvss: bool = True) -> dict:
    """Create a DynamoDB CVE intelligence item in wire format (typed attributes)."""
    nvd_map = {
        "cvss_v31_score": {"N": "7.5"} if has_cvss else {"NULL": True},
        "cvss_v31_vector": {"S": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}
        if has_cvss
        else {"NULL": True},
        "cvss_v31_severity": {"S": "HIGH"} if has_cvss else {"NULL": True},
        "cvss_attack_vector": {"S": "NETWORK"} if has_cvss else {"NULL": True},
        "cvss_attack_complexity": {"S": "LOW"} if has_cvss else {"NULL": True},
        "cvss_privileges_required": {"S": "NONE"} if has_cvss else {"NULL": True},
        "cvss_user_interaction": {"S": "NONE"} if has_cvss else {"NULL": True},
        "cwe_ids": {"L": [{"S": "CWE-79"}, {"S": "CWE-89"}]},
        "affected_products": {
            "L": [
                {
                    "M": {
                        "vendor": {"S": "apache"},
                        "product": {"S": "httpd"},
                        "versions": {"S": "[2.4.0, 2.4.51)"},
                    }
                }
            ]
        },
        "description": {"S": f"Test vulnerability for {cve_id}"},
        "references": {"L": [{"S": "https://nvd.nist.gov/vuln/detail/" + cve_id}]},
        "published_date": {"S": "2024-01-15T10:00:00.000"},
        "last_modified_date": {"S": "2024-01-16T12:00:00.000"},
    }

    return {
        "pk": {"S": f"CVE#{cve_id}"},
        "sk": {"S": "INTEL"},
        "cve_id": {"S": cve_id},
        "resolution": {"S": "resolved"},
        "nvd": {"M": nvd_map},
        "epss": {"NULL": True},
        "kev": {"NULL": True},
        "mitre": {"NULL": True},
        "metadata": {
            "M": {
                "sources_present": {"L": [{"S": "nvd"}]},
                "version": {"N": "1"},
                "created_at": {"S": "2024-01-15T10:00:00Z"},
                "updated_at": {"S": "2024-01-16T12:00:00Z"},
            }
        },
    }


def _make_cwe_mitre_item(cwe_id: str) -> dict:
    """Create a DynamoDB CWE/MITRE item in wire format."""
    return {
        "pk": {"S": f"CWE#{cwe_id}"},
        "sk": {"S": "MITRE"},
        "cwe_id": {"S": cwe_id},
        "name": {"S": f"Test Weakness {cwe_id}"},
        "description": {"S": f"Description for {cwe_id}"},
        "mitigations": {"L": [{"S": "Input validation"}, {"S": "Output encoding"}]},
    }


@pytest.fixture
def dynamodb_table():
    """Set up moto-mocked DynamoDB with Intelligence_Table and seed data."""
    with mock_aws():
        # Create table
        client = boto3.client("dynamodb", region_name=REGION)
        client.create_table(
            TableName=TABLE_NAME,
            KeySchema=[
                {"AttributeName": "pk", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "pk", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
            ],
            BillingMode="PAY_PER_REQUEST",
        )

        # Seed CVE items
        for i in range(1, 6):
            client.put_item(
                TableName=TABLE_NAME,
                Item=_make_cve_dynamo_item(f"CVE-2024-{i:04d}"),
            )

        # Seed a CVE without CVSS data
        client.put_item(
            TableName=TABLE_NAME,
            Item=_make_cve_dynamo_item("CVE-2024-NO-CVSS", has_cvss=False),
        )

        # Seed MITRE/CWE items
        for cwe in ["CWE-79", "CWE-89", "CWE-22"]:
            client.put_item(
                TableName=TABLE_NAME,
                Item=_make_cwe_mitre_item(cwe),
            )

        yield client


@pytest.fixture
def service(dynamodb_table):
    """Create an intelligence service instance pointed at the mocked table."""
    return VulnIntelligenceService(table_name=TABLE_NAME, region=REGION)


# ---------------------------------------------------------------------------
# Single CVE lookup tests
# ---------------------------------------------------------------------------


class TestSingleCveLookup:
    """Tests for get_cve_intelligence single-item lookups."""

    def test_returns_resolved_for_existing_cve(self, service):
        """Test that existing CVE returns CveIntelligence with resolution=resolved."""
        result = service.get_cve_intelligence("CVE-2024-0001")

        assert result is not None
        assert isinstance(result, CveIntelligence)
        assert result.cve_id == "CVE-2024-0001"
        assert result.resolution == "resolved"
        assert result.nvd is not None
        assert isinstance(result.nvd, NvdIntelligence)
        assert result.nvd.cvss_v31_score == 7.5
        assert result.nvd.cvss_v31_severity == "HIGH"
        assert result.nvd.description == "Test vulnerability for CVE-2024-0001"
        assert "nvd" in result.sources_present

    def test_returns_lookup_failed_for_nonexistent_cve(self, service):
        """Test that missing CVE returns lookup_failed resolution."""
        result = service.get_cve_intelligence("CVE-9999-0001")

        assert result is not None
        assert result.cve_id == "CVE-9999-0001"
        assert result.resolution == "lookup_failed"
        assert result.nvd is None
        assert result.sources_present == []

    def test_returns_cve_without_cvss_data(self, service):
        """Test that CVE without CVSS data returns null CVSS fields."""
        result = service.get_cve_intelligence("CVE-2024-NO-CVSS")

        assert result is not None
        assert result.resolution == "resolved"
        assert result.nvd is not None
        assert result.nvd.cvss_v31_score is None
        assert result.nvd.cvss_v31_vector is None
        assert result.nvd.cvss_v31_severity is None

    def test_single_lookup_performance_under_200ms(self, service):
        """Test that single lookup completes within 200ms."""
        start = time.perf_counter()
        service.get_cve_intelligence("CVE-2024-0001")
        elapsed_ms = (time.perf_counter() - start) * 1000

        # moto is fast; this validates the code path doesn't have
        # unnecessary overhead. Under real DynamoDB, sub-200ms is expected.
        assert elapsed_ms < 200, f"Single lookup took {elapsed_ms:.1f}ms"


# ---------------------------------------------------------------------------
# Batch CVE lookup tests
# ---------------------------------------------------------------------------


class TestBatchCveLookup:
    """Tests for batch_get_cve_intelligence batch lookups."""

    def test_batch_returns_resolved_for_existing_cves(self, service):
        """Test batch lookup returns correct results for multiple existing CVEs."""
        cve_ids = [f"CVE-2024-{i:04d}" for i in range(1, 4)]
        results = service.batch_get_cve_intelligence(cve_ids)

        assert len(results) == 3
        for cve_id in cve_ids:
            assert cve_id in results
            result = results[cve_id]
            assert result is not None
            assert result.resolution == "resolved"
            assert result.cve_id == cve_id

    def test_batch_mixed_existing_and_missing(self, service):
        """Test batch with mix of cached and uncached CVE IDs."""
        cve_ids = ["CVE-2024-0001", "CVE-9999-0001", "CVE-2024-0003", "CVE-9999-0002"]
        results = service.batch_get_cve_intelligence(cve_ids)

        assert len(results) == 4

        # Existing CVEs should be resolved
        assert results["CVE-2024-0001"].resolution == "resolved"
        assert results["CVE-2024-0003"].resolution == "resolved"

        # Missing CVEs should be lookup_failed
        assert results["CVE-9999-0001"].resolution == "lookup_failed"
        assert results["CVE-9999-0002"].resolution == "lookup_failed"

    def test_batch_rejects_more_than_100_ids(self, service):
        """Test that batch lookup raises ValueError for >100 IDs."""
        cve_ids = [f"CVE-2024-{i:04d}" for i in range(101)]

        with pytest.raises(ValueError, match="exceeds maximum of 100"):
            service.batch_get_cve_intelligence(cve_ids)

    def test_batch_empty_list_returns_empty_dict(self, service):
        """Test that empty batch returns empty dict."""
        results = service.batch_get_cve_intelligence([])
        assert results == {}

    def test_batch_lookup_performance_100_items(self, dynamodb_table):
        """Test that batch lookup of up to 100 items completes within reasonable time.

        Note: The 200ms SLA applies to real DynamoDB under normal conditions.
        With moto (in-process mock), we allow up to 1000ms due to serialization
        overhead. Real-world latency is validated via live integration testing.
        """
        # Seed 100 items
        for i in range(6, 101):
            dynamodb_table.put_item(
                TableName=TABLE_NAME,
                Item=_make_cve_dynamo_item(f"CVE-2024-{i:04d}"),
            )

        service = VulnIntelligenceService(table_name=TABLE_NAME, region=REGION)
        cve_ids = [f"CVE-2024-{i:04d}" for i in range(1, 101)]

        start = time.perf_counter()
        results = service.batch_get_cve_intelligence(cve_ids)
        elapsed_ms = (time.perf_counter() - start) * 1000

        # With moto all items should be found
        resolved_count = sum(1 for r in results.values() if r and r.resolution == "resolved")
        assert resolved_count == 100
        # moto overhead makes this slower than real DynamoDB; use relaxed threshold
        assert elapsed_ms < 1000, f"Batch lookup of 100 took {elapsed_ms:.1f}ms (moto)"

    def test_batch_all_missing_returns_all_lookup_failed(self, service):
        """Test that batch with all non-existent IDs returns all lookup_failed."""
        cve_ids = [f"CVE-9999-{i:04d}" for i in range(1, 11)]
        results = service.batch_get_cve_intelligence(cve_ids)

        assert len(results) == 10
        for cve_id in cve_ids:
            assert results[cve_id].resolution == "lookup_failed"
            assert results[cve_id].nvd is None
            assert results[cve_id].sources_present == []


# ---------------------------------------------------------------------------
# CWE / MITRE lookup tests
# ---------------------------------------------------------------------------


class TestMitreCweLookup:
    """Tests for get_mitre_for_cwes lookups."""

    def test_returns_mitre_mapping_for_existing_cwes(self, service):
        """Test CWE lookup returns correct MitreMapping objects."""
        results = service.get_mitre_for_cwes(["CWE-79", "CWE-89"])

        assert len(results) == 2
        assert "CWE-79" in results
        assert "CWE-89" in results

        mapping = results["CWE-79"]
        assert isinstance(mapping, MitreMapping)
        assert mapping.cwe_id == "CWE-79"
        assert mapping.name == "Test Weakness CWE-79"
        assert "Input validation" in mapping.mitigations

    def test_returns_none_for_missing_cwes(self, service):
        """Test CWE lookup returns None for non-existent CWE IDs."""
        results = service.get_mitre_for_cwes(["CWE-79", "CWE-999"])

        assert results["CWE-79"] is not None
        assert results["CWE-999"] is None

    def test_cwe_rejects_more_than_100_ids(self, service):
        """Test that CWE lookup raises ValueError for >100 IDs."""
        cwe_ids = [f"CWE-{i}" for i in range(101)]

        with pytest.raises(ValueError, match="exceeds maximum of 100"):
            service.get_mitre_for_cwes(cwe_ids)

    def test_cwe_empty_list_returns_empty_dict(self, service):
        """Test that empty CWE list returns empty dict."""
        results = service.get_mitre_for_cwes([])
        assert results == {}


# ---------------------------------------------------------------------------
# Error resilience tests
# ---------------------------------------------------------------------------


class TestErrorResilience:
    """Tests for graceful handling of DynamoDB failures."""

    def test_dynamo_error_returns_lookup_failed_no_exception(self, dynamodb_table):
        """Test that DynamoDB errors produce lookup_failed, not unhandled exceptions."""
        service = VulnIntelligenceService(table_name=TABLE_NAME, region=REGION)

        # Simulate DynamoDB error by patching the client
        with patch.object(service._client, "get_item", side_effect=Exception("Connection refused")):
            result = service.get_cve_intelligence("CVE-2024-0001")

        assert result is not None
        assert result.resolution == "lookup_failed"
        assert result.nvd is None

    def test_batch_dynamo_error_returns_all_lookup_failed(self, dynamodb_table):
        """Test that batch DynamoDB errors produce lookup_failed for all IDs."""
        service = VulnIntelligenceService(table_name=TABLE_NAME, region=REGION)

        with patch.object(
            service._client,
            "batch_get_item",
            side_effect=Exception("Internal server error"),
        ):
            results = service.batch_get_cve_intelligence(["CVE-2024-0001", "CVE-2024-0002"])

        assert len(results) == 2
        for _cve_id, result in results.items():
            assert result.resolution == "lookup_failed"
            assert result.nvd is None

    def test_cache_miss_metric_emitted_above_threshold(self, dynamodb_table):
        """Test that CacheMissesLookupFailed metric is emitted when threshold exceeded."""
        service = VulnIntelligenceService(table_name=TABLE_NAME, region=REGION)

        # Override threshold for testing
        with patch("app.services.vuln_intelligence.MAX_SYNC_CACHE_MISSES", 2):
            # Create a new service to pick up the patched value
            service._miss_count = 0

            # Perform lookups for non-existent CVEs to trigger misses
            with patch.object(service._cloudwatch, "put_metric_data") as mock_cw:
                for i in range(5):
                    service.get_cve_intelligence(f"CVE-9999-{i:04d}")

                # Metric should have been emitted (misses > threshold of 2)
                assert mock_cw.called


# ---------------------------------------------------------------------------
# Data integrity tests
# ---------------------------------------------------------------------------


class TestDataIntegrity:
    """Tests for correct data extraction from DynamoDB items."""

    def test_nvd_fields_correctly_extracted(self, service):
        """Test all NVD intelligence fields are correctly parsed."""
        result = service.get_cve_intelligence("CVE-2024-0001")

        assert result is not None
        nvd = result.nvd
        assert nvd is not None

        # CVSS fields
        assert nvd.cvss_v31_score == 7.5
        assert "CVSS:3.1" in nvd.cvss_v31_vector
        assert nvd.cvss_v31_severity == "HIGH"
        assert nvd.cvss_attack_vector == "NETWORK"
        assert nvd.cvss_attack_complexity == "LOW"
        assert nvd.cvss_privileges_required == "NONE"
        assert nvd.cvss_user_interaction == "NONE"

        # Lists
        assert "CWE-79" in nvd.cwe_ids
        assert "CWE-89" in nvd.cwe_ids
        assert len(nvd.affected_products) >= 1
        assert len(nvd.references) >= 1

        # Scalar fields
        assert nvd.description is not None
        assert nvd.published_date is not None
        assert nvd.last_modified_date is not None

    def test_sources_present_field_populated(self, service):
        """Test that sources_present reflects available data sources."""
        result = service.get_cve_intelligence("CVE-2024-0001")

        assert result is not None
        assert "nvd" in result.sources_present
