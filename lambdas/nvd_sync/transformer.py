"""Pure transformation function for NVD 2.0 CVE JSON → DynamoDB item format.

This module contains a single pure function that converts raw NVD 2.0 CVE
JSON objects into the Intelligence_Table item schema. It performs no I/O
and raises TransformError on invalid input.
"""

from __future__ import annotations

from lambdas.shared.exceptions import TransformError


def transform_nvd_cve(cve_json: dict, timestamp: str) -> dict:
    """Transform a single NVD 2.0 CVE JSON object into DynamoDB item format.

    Args:
        cve_json: Raw NVD 2.0 CVE JSON object from feed or API.
            Expected structure: {"cve": {"id": "CVE-...", ...}}
        timestamp: ISO 8601 invocation timestamp for metadata fields.

    Returns:
        DynamoDB item dict with pk, sk, cve_id, resolution, nvd, epss,
        kev, mitre, and metadata.

    Raises:
        TransformError: If cve_json is missing CVE ID or is structurally invalid.
    """
    # --- Validate top-level structure ---
    if not isinstance(cve_json, dict):
        raise TransformError(
            source="NVD",
            operation="transform_nvd_cve",
            message="Input is not a dict",
        )

    cve = cve_json.get("cve")
    if not isinstance(cve, dict):
        raise TransformError(
            source="NVD",
            operation="transform_nvd_cve",
            message="Missing or invalid 'cve' object in input",
        )

    cve_id = cve.get("id")
    if not cve_id or not isinstance(cve_id, str):
        raise TransformError(
            source="NVD",
            operation="transform_nvd_cve",
            message="Missing or invalid CVE ID",
        )

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
        cvss_v31_list = metrics.get("cvssMetricV31")
        if isinstance(cvss_v31_list, list) and len(cvss_v31_list) > 0:
            first_metric = cvss_v31_list[0]
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
                if not isinstance(desc, dict):
                    continue
                if desc.get("lang") == "en":
                    value = desc.get("value")
                    if isinstance(value, str) and value:
                        cwe_ids.append(value)

    # --- Extract affected products from configurations ---
    affected_products: list[dict] = []
    configurations = cve.get("configurations")
    if isinstance(configurations, list):
        for config in configurations:
            if not isinstance(config, dict):
                continue
            nodes = config.get("nodes")
            if not isinstance(nodes, list):
                continue
            for node in nodes:
                if not isinstance(node, dict):
                    continue
                cpe_matches = node.get("cpeMatch")
                if not isinstance(cpe_matches, list):
                    continue
                for match in cpe_matches:
                    if not isinstance(match, dict):
                        continue
                    criteria = match.get("criteria")
                    if not isinstance(criteria, str):
                        continue
                    product_entry = _parse_cpe(criteria, match)
                    if product_entry is not None:
                        affected_products.append(product_entry)

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
    published_date = (
        cve.get("published") if isinstance(cve.get("published"), str) else None
    )
    last_modified_date = (
        cve.get("lastModified") if isinstance(cve.get("lastModified"), str) else None
    )

    # --- Assemble DynamoDB item ---
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
            "affected_products": affected_products,
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
            "version": 1,
            "created_at": timestamp,
            "updated_at": timestamp,
        },
    }


def _parse_cpe(criteria: str, match: dict) -> dict | None:
    """Parse a CPE 2.3 string into a product entry with version info.

    CPE format: cpe:2.3:part:vendor:product:version:update:edition:language:...

    Args:
        criteria: The CPE 2.3 formatted string.
        match: The cpeMatch object containing version range fields.

    Returns:
        A dict with vendor, product, and versions keys, or None if
        the CPE string cannot be parsed.
    """
    parts = criteria.split(":")
    # A valid CPE 2.3 string has at least 5 components:
    # cpe:2.3:part:vendor:product
    if len(parts) < 5:
        return None

    vendor = parts[3] if parts[3] != "*" else None
    product = parts[4] if parts[4] != "*" else None

    if vendor is None and product is None:
        return None

    versions = _build_version_string(match)

    return {
        "vendor": vendor,
        "product": product,
        "versions": versions,
    }


def _build_version_string(match: dict) -> str:
    """Build a human-readable version range string from cpeMatch fields.

    Handles versionStartIncluding, versionStartExcluding,
    versionEndIncluding, and versionEndExcluding fields.

    Args:
        match: The cpeMatch object from the NVD configuration.

    Returns:
        A version range string, e.g. "[1.0, 2.0)" or "*" if no
        version constraints exist.
    """
    start_inc = match.get("versionStartIncluding")
    start_exc = match.get("versionStartExcluding")
    end_inc = match.get("versionEndIncluding")
    end_exc = match.get("versionEndExcluding")

    if not any([start_inc, start_exc, end_inc, end_exc]):
        return "*"

    # Build interval notation
    if start_inc:
        start = f"[{start_inc}"
    elif start_exc:
        start = f"({start_exc}"
    else:
        start = "(*"

    if end_inc:
        end = f"{end_inc}]"
    elif end_exc:
        end = f"{end_exc})"
    else:
        end = "*)"

    return f"{start}, {end}"
