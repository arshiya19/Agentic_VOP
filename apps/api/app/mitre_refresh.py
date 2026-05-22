"""MITRE catalog refresh — CWE, CAPEC, and ATT&CK.

Three public functions, one for each MITRE dataset:
  - refresh_mitre_cwe()    → CWE (Common Weakness Enumeration), XML zip
  - refresh_mitre_capec()  → CAPEC (Common Attack Pattern Enumeration), XML zip
  - refresh_mitre_attack() → ATT&CK (adversary techniques), STIX JSON

Each one follows the same shape:
  1. Download from MITRE's canonical URL
  2. SHA-256 the bytes; compare against the latest successful refresh log
     entry for that source. Skip on unchanged.
  3. Parse the dataset's native format (XML for CWE/CAPEC, JSON for ATT&CK)
  4. UPSERT into the matching table
  5. Write a row to mitre_refresh_log

Triggered by:
  - POST /admin/mitre/refresh         (CWE)
  - POST /admin/mitre/refresh-capec   (CAPEC)
  - POST /admin/mitre/refresh-attack  (ATT&CK)
  Same endpoints will be hit by cron / pg_cron monthly.

Why lxml for CWE/CAPEC: stdlib's xml.etree handles the namespaces awkwardly
and is slow on the catalogs. lxml's iterparse keeps memory flat.
"""

from __future__ import annotations

import hashlib
import io
import json
import zipfile
from datetime import UTC, datetime

import httpx
from lxml import etree

from .db import supabase_admin


_CWE_ZIP_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
# CAPEC is served as plain XML (no zip), unlike CWE — different MITRE site layout.
_CAPEC_XML_URL = "https://capec.mitre.org/data/xml/capec_latest.xml"
_ATTACK_JSON_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
    "enterprise-attack/enterprise-attack.json"
)

_CWE_NS = {"cwe": "http://cwe.mitre.org/cwe-7"}
_CAPEC_NS = {"capec": "http://capec.mitre.org/capec-3"}


def refresh_mitre_cwe() -> dict:
    """Download MITRE CWE, hash-check, and UPSERT rows on change."""
    return _run_refresh(
        source="cwe",
        download_fn=lambda: _download_bytes(_CWE_ZIP_URL),
        parse_fn=_parse_cwe_zip,
        table="mitre_cwe",
        pk="cwe_id",
    )


def refresh_mitre_capec() -> dict:
    """Download MITRE CAPEC, hash-check, and UPSERT rows on change."""
    return _run_refresh(
        source="capec",
        download_fn=lambda: _download_bytes(_CAPEC_XML_URL),
        parse_fn=_parse_capec_xml,
        table="mitre_capec",
        pk="capec_id",
    )


def refresh_mitre_attack() -> dict:
    """Download MITRE ATT&CK Enterprise STIX bundle and UPSERT techniques."""
    return _run_refresh(
        source="attack",
        download_fn=lambda: _download_bytes(_ATTACK_JSON_URL),
        parse_fn=_parse_attack_stix,
        table="mitre_attack_techniques",
        pk="technique_id",
    )


# ---------------------------------------------------------------------------
# Shared refresh pipeline — download → hash-check → parse → UPSERT → log
# ---------------------------------------------------------------------------


def _run_refresh(
    *,
    source: str,
    download_fn,
    parse_fn,
    table: str,
    pk: str,
) -> dict:
    """One-size-fits-all refresh runner. Same shape for CWE / CAPEC / ATT&CK."""
    sb = supabase_admin()

    try:
        raw_bytes = download_fn()
    except Exception as e:
        return _log_and_return(
            sb, source=source, status="failed", sha256="", error_message=f"download failed: {e}"
        )

    sha256 = hashlib.sha256(raw_bytes).hexdigest()

    # Hash check: was the most recent successful run for this source identical?
    last = (
        sb.table("mitre_refresh_log")
        .select("sha256,status")
        .eq("source", source)
        .in_("status", ["unchanged", "updated"])
        .order("created_at", desc=True)
        .limit(1)
        .execute()
        .data
    )
    if last and last[0]["sha256"] == sha256:
        return _log_and_return(sb, source=source, status="unchanged", sha256=sha256)

    try:
        rows, version = parse_fn(raw_bytes)
    except Exception as e:
        return _log_and_return(
            sb,
            source=source,
            status="failed",
            sha256=sha256,
            error_message=f"parse failed: {e}",
        )

    if not rows:
        return _log_and_return(
            sb,
            source=source,
            status="failed",
            sha256=sha256,
            error_message="parser returned zero rows",
        )

    # Stamp fetched_at + version on every row before the UPSERT.
    now_iso = datetime.now(UTC).isoformat()
    for r in rows:
        r["fetched_at"] = now_iso
        r["mitre_version"] = version

    # UPSERT in batches — Supabase REST has a payload-size limit.
    batch_size = 200
    for i in range(0, len(rows), batch_size):
        sb.table(table).upsert(rows[i : i + batch_size], on_conflict=pk).execute()

    return _log_and_return(
        sb,
        source=source,
        status="updated",
        sha256=sha256,
        cwes_processed=len(rows),  # column is named cwes_processed but is generic
        mitre_version=version,
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _download_bytes(url: str) -> bytes:
    """Generic HTTPS download with a sensible timeout. Used for all 3 sources."""
    with httpx.Client(timeout=120, follow_redirects=True) as client:
        resp = client.get(url)
        resp.raise_for_status()
        return resp.content


def _safe_xml_root(xml_bytes: bytes):
    """Parse XML with external entities + DTDs disabled (defense-in-depth)."""
    parser = etree.XMLParser(
        resolve_entities=False, no_network=True, load_dtd=False, dtd_validation=False
    )
    return etree.fromstring(xml_bytes, parser=parser)  # noqa: S320 — defused parser configured above


def _extract_xml_from_zip(zip_bytes: bytes) -> bytes:
    """MITRE distributes both CWE and CAPEC as a zip with a single XML inside."""
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
        xml_name = next((n for n in zf.namelist() if n.lower().endswith(".xml")), None)
        if xml_name is None:
            raise ValueError("no .xml file inside MITRE zip")
        with zf.open(xml_name) as f:
            return f.read()


def _text(node) -> str | None:
    """Flatten an XML element's text (including nested xhtml) to a single string."""
    if node is None:
        return None
    flat = "".join(node.itertext()).strip()
    return flat or None


# ---------------------------------------------------------------------------
# CWE parser
# ---------------------------------------------------------------------------


def _parse_cwe_zip(zip_bytes: bytes) -> tuple[list[dict], str | None]:
    """Unzip CWE catalog, parse XML, return (rows, mitre_version)."""
    root = _safe_xml_root(_extract_xml_from_zip(zip_bytes))
    mitre_version = root.get("Version") or root.get("CatalogVersion")

    rows: list[dict] = []
    for weak in root.iterfind("cwe:Weaknesses/cwe:Weakness", _CWE_NS):
        cwe_num = weak.get("ID")
        if not cwe_num:
            continue
        rows.append(
            {
                "cwe_id": f"CWE-{cwe_num}",
                "name": weak.get("Name") or "",
                "abstraction": weak.get("Abstraction"),
                "status": weak.get("Status"),
                "description": _text(weak.find("cwe:Description", _CWE_NS)),
                "extended_description": _text(weak.find("cwe:Extended_Description", _CWE_NS)),
                "likelihood_of_exploit": _text(weak.find("cwe:Likelihood_Of_Exploit", _CWE_NS)),
                "consequences": _parse_cwe_consequences(weak),
                "mitigations": _parse_cwe_mitigations(weak),
                "related_capec": _parse_cwe_related_capec(weak),
            }
        )
    return rows, mitre_version


def _parse_cwe_consequences(weak) -> list[dict]:
    out: list[dict] = []
    for c in weak.iterfind("cwe:Common_Consequences/cwe:Consequence", _CWE_NS):
        out.append(
            {
                "scope": [s for s in (_text(s) for s in c.iterfind("cwe:Scope", _CWE_NS)) if s],
                "impact": [i for i in (_text(i) for i in c.iterfind("cwe:Impact", _CWE_NS)) if i],
                "note": _text(c.find("cwe:Note", _CWE_NS)),
            }
        )
    return out


def _parse_cwe_mitigations(weak) -> list[dict]:
    out: list[dict] = []
    for m in weak.iterfind("cwe:Potential_Mitigations/cwe:Mitigation", _CWE_NS):
        out.append(
            {
                "phase": [p for p in (_text(p) for p in m.iterfind("cwe:Phase", _CWE_NS)) if p],
                "description": _text(m.find("cwe:Description", _CWE_NS)),
                "effectiveness": _text(m.find("cwe:Effectiveness", _CWE_NS)),
            }
        )
    return out


def _parse_cwe_related_capec(weak) -> list[str]:
    out: list[str] = []
    for ap in weak.iterfind("cwe:Related_Attack_Patterns/cwe:Related_Attack_Pattern", _CWE_NS):
        capec_id = ap.get("CAPEC_ID")
        if capec_id:
            out.append(f"CAPEC-{capec_id}")
    return out


# ---------------------------------------------------------------------------
# CAPEC parser
# ---------------------------------------------------------------------------


def _parse_capec_xml(xml_bytes: bytes) -> tuple[list[dict], str | None]:
    """Parse CAPEC catalog XML (served plain, not zipped). Returns (rows, mitre_version)."""
    root = _safe_xml_root(xml_bytes)
    mitre_version = root.get("Version") or root.get("CatalogVersion")

    rows: list[dict] = []
    for ap in root.iterfind("capec:Attack_Patterns/capec:Attack_Pattern", _CAPEC_NS):
        capec_num = ap.get("ID")
        if not capec_num:
            continue
        rows.append(
            {
                "capec_id": f"CAPEC-{capec_num}",
                "name": ap.get("Name") or "",
                "abstraction": ap.get("Abstraction"),
                "status": ap.get("Status"),
                "description": _text(ap.find("capec:Description", _CAPEC_NS)),
                "likelihood_of_attack": _text(ap.find("capec:Likelihood_Of_Attack", _CAPEC_NS)),
                "typical_severity": _text(ap.find("capec:Typical_Severity", _CAPEC_NS)),
                "execution_flow": _parse_capec_execution_flow(ap),
                "prerequisites": _parse_capec_prerequisites(ap),
                "skills_required": _parse_capec_skills(ap),
                "resources_required": _text(ap.find("capec:Resources_Required", _CAPEC_NS)),
                "consequences": _parse_capec_consequences(ap),
                "mitigations": _parse_capec_mitigations(ap),
                "related_weaknesses": _parse_capec_related_weaknesses(ap),
                "related_attack_techniques": _parse_capec_related_attack(ap),
            }
        )
    return rows, mitre_version


def _parse_capec_execution_flow(ap) -> list[dict]:
    out: list[dict] = []
    for step in ap.iterfind("capec:Execution_Flow/capec:Attack_Step", _CAPEC_NS):
        out.append(
            {
                "step": _text(step.find("capec:Step", _CAPEC_NS)),
                "phase": _text(step.find("capec:Phase", _CAPEC_NS)),
                "description": _text(step.find("capec:Description", _CAPEC_NS)),
            }
        )
    return out


def _parse_capec_prerequisites(ap) -> list[str]:
    out: list[str] = []
    for p in ap.iterfind("capec:Prerequisites/capec:Prerequisite", _CAPEC_NS):
        t = _text(p)
        if t:
            out.append(t)
    return out


def _parse_capec_skills(ap) -> list[dict]:
    out: list[dict] = []
    for s in ap.iterfind("capec:Skills_Required/capec:Skill", _CAPEC_NS):
        out.append({"level": s.get("Level"), "description": _text(s)})
    return out


def _parse_capec_consequences(ap) -> list[dict]:
    out: list[dict] = []
    for c in ap.iterfind("capec:Consequences/capec:Consequence", _CAPEC_NS):
        out.append(
            {
                "scope": [s for s in (_text(s) for s in c.iterfind("capec:Scope", _CAPEC_NS)) if s],
                "impact": [
                    i for i in (_text(i) for i in c.iterfind("capec:Impact", _CAPEC_NS)) if i
                ],
                "note": _text(c.find("capec:Note", _CAPEC_NS)),
            }
        )
    return out


def _parse_capec_mitigations(ap) -> list[str]:
    """CAPEC mitigations are bulleted text; we flatten each to a single string."""
    out: list[str] = []
    for m in ap.iterfind("capec:Mitigations/capec:Mitigation", _CAPEC_NS):
        t = _text(m)
        if t:
            out.append(t)
    return out


def _parse_capec_related_weaknesses(ap) -> list[str]:
    out: list[str] = []
    for w in ap.iterfind("capec:Related_Weaknesses/capec:Related_Weakness", _CAPEC_NS):
        cwe_id = w.get("CWE_ID")
        if cwe_id:
            out.append(f"CWE-{cwe_id}")
    return out


def _parse_capec_related_attack(ap) -> list[str]:
    """Pull ATT&CK technique ids from Taxonomy_Mappings entries with Name='ATTACK'."""
    out: list[str] = []
    for tm in ap.iterfind("capec:Taxonomy_Mappings/capec:Taxonomy_Mapping", _CAPEC_NS):
        if (tm.get("Taxonomy_Name") or "").upper() != "ATTACK":
            continue
        entry_id = _text(tm.find("capec:Entry_ID", _CAPEC_NS))
        if not entry_id:
            continue
        # Sub-techniques are encoded with a "." inside the Entry_ID (e.g. "1190.001").
        out.append(f"T{entry_id}")
    return out


# ---------------------------------------------------------------------------
# ATT&CK parser (STIX 2.x JSON)
# ---------------------------------------------------------------------------


def _parse_attack_stix(json_bytes: bytes) -> tuple[list[dict], str | None]:
    """Parse Enterprise ATT&CK STIX bundle. Returns (rows, mitre_version)."""
    bundle = json.loads(json_bytes.decode("utf-8"))
    objects = bundle.get("objects") or []

    # Version lives on the x-mitre-collection object if present.
    mitre_version: str | None = None
    for obj in objects:
        if obj.get("type") == "x-mitre-collection":
            mitre_version = obj.get("x_mitre_version") or obj.get("modified")
            break

    rows: list[dict] = []
    for obj in objects:
        if obj.get("type") != "attack-pattern":
            continue
        # Revoked / deprecated entries are kept by MITRE for stable IDs but we
        # don't want them in our active catalog.
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue

        technique_id: str | None = None
        canonical_url: str | None = None
        for ref in obj.get("external_references") or []:
            if ref.get("source_name") == "mitre-attack":
                technique_id = ref.get("external_id")
                canonical_url = ref.get("url")
                break
        if not technique_id:
            continue

        tactics = [
            ph.get("phase_name")
            for ph in obj.get("kill_chain_phases") or []
            if ph.get("kill_chain_name") == "mitre-attack" and ph.get("phase_name")
        ]
        is_sub = bool(obj.get("x_mitre_is_subtechnique"))
        parent_id = technique_id.split(".")[0] if (is_sub and "." in technique_id) else None

        rows.append(
            {
                "technique_id": technique_id,
                "name": obj.get("name") or "",
                "description": obj.get("description"),
                "tactics": tactics,
                "is_subtechnique": is_sub,
                "parent_technique_id": parent_id,
                "platforms": obj.get("x_mitre_platforms") or [],
                "data_sources": obj.get("x_mitre_data_sources") or [],
                "detection": obj.get("x_mitre_detection"),
                "url": canonical_url,
            }
        )

    return rows, mitre_version


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------


def _log_and_return(
    sb,
    *,
    source: str,
    status: str,
    sha256: str,
    cwes_processed: int | None = None,
    mitre_version: str | None = None,
    error_message: str | None = None,
) -> dict:
    """Write a row to mitre_refresh_log and return the same payload to the caller."""
    payload = {
        "source": source,
        "sha256": sha256,
        "status": status,
        "cwes_processed": cwes_processed,  # generic count, despite the legacy column name
        "mitre_version": mitre_version,
        "error_message": error_message,
    }
    try:
        sb.table("mitre_refresh_log").insert(payload).execute()
    except Exception:  # nosec B110 — best-effort logging  # noqa: S110
        pass
    return {
        "status": status,
        "cwes_processed": cwes_processed,
        "mitre_version": mitre_version,
        "sha256": sha256,
        "error_message": error_message,
    }
