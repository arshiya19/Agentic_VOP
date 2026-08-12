"""Ticketing connector — creates incidents/tickets in external systems.

Phase-1 focus: ServiceNow (Table API for incident creation).

Architecture:
  - `create_ticket()` is the public entry point, dispatches to the correct
    provider based on the ticketing_connections row.
  - Each provider has a `_create_<provider>_ticket()` function that handles
    the API call and returns the external ticket ID + URL.
  - Uses the same `request_with_retry` pattern as other connectors for
    resilient HTTP calls.

ServiceNow integration uses the Table API:
  POST /api/now/table/incident
  Auth: Basic (username + password) or OAuth (not implemented yet)
  Docs: https://developer.servicenow.com/dev.do#!/reference/api/latest/rest/c_TableAPI
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
from typing import Any

import httpx

from ...config import settings
from ..http_utils import request_with_retry

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Severity → ServiceNow priority/urgency/impact mapping
# ServiceNow uses: 1=Critical, 2=High, 3=Moderate, 4=Low, 5=Planning
# ---------------------------------------------------------------------------
_SEVERITY_TO_SNOW_PRIORITY = {
    "Critical": "1",
    "High": "2",
    "Medium": "3",
    "Low": "4",
    "Info": "5",
}

_SEVERITY_TO_SNOW_URGENCY = {
    "Critical": "1",
    "High": "2",
    "Medium": "2",
    "Low": "3",
    "Info": "3",
}

_SEVERITY_TO_SNOW_IMPACT = {
    "Critical": "1",
    "High": "2",
    "Medium": "2",
    "Low": "3",
    "Info": "3",
}


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------


class TicketCreationResult:
    """Result of a ticket creation attempt."""

    def __init__(
        self,
        success: bool,
        external_ticket_id: str | None = None,
        external_ticket_url: str | None = None,
        error: str | None = None,
    ):
        self.success = success
        self.external_ticket_id = external_ticket_id
        self.external_ticket_url = external_ticket_url
        self.error = error


def create_ticket(
    *,
    provider: str,
    connection_config: dict,
    title: str,
    description: str,
    severity: str = "Medium",
    labels: list[str] | None = None,
    extra_fields: dict[str, Any] | None = None,
) -> TicketCreationResult:
    """Create a ticket in the specified provider.

    Args:
        provider: One of 'servicenow', 'webhook' (extensible to jira, azure_devops, etc.)
        connection_config: Provider-specific config from ticketing_connections.config
                          (merged with env-var settings where applicable)
        title: Ticket title / short description
        description: Full ticket body (markdown or plain text)
        severity: Issue severity — mapped to provider-specific priority
        labels: Optional tags/labels for the ticket
        extra_fields: Provider-specific fields to merge into the payload

    Returns:
        TicketCreationResult with success/failure + external references.
    """
    dispatch = {
        "servicenow": _create_servicenow_ticket,
        "webhook": _create_webhook_ticket,
    }

    handler = dispatch.get(provider)
    if not handler:
        return TicketCreationResult(
            success=False,
            error=f"Unsupported ticketing provider: {provider!r}. "
            f"Supported: {list(dispatch.keys())}",
        )

    try:
        return handler(
            config=connection_config,
            title=title,
            description=description,
            severity=severity,
            labels=labels or [],
            extra_fields=extra_fields or {},
        )
    except Exception as exc:  # noqa: BLE001
        logger.exception("Ticket creation failed for provider=%s", provider)
        return TicketCreationResult(
            success=False,
            error=f"{type(exc).__name__}: {str(exc)[:300]}",
        )


# ---------------------------------------------------------------------------
# ServiceNow — Table API (incident creation)
# ---------------------------------------------------------------------------


def _resolve_servicenow_config(config: dict) -> dict:
    """Merge connection_config with env-var fallbacks.

    Priority: connection_config > env vars > empty string.
    """
    return {
        "instance_url": (config.get("instance_url") or settings.servicenow_instance_url).rstrip(
            "/"
        ),
        "username": config.get("username") or settings.servicenow_username,
        "password": config.get("password") or settings.servicenow_password,
        "client_id": config.get("client_id") or settings.servicenow_client_id,
        "client_secret": config.get("client_secret") or settings.servicenow_client_secret,
        "assignment_group": (
            config.get("assignment_group") or settings.servicenow_assignment_group
        ),
        "caller_id": config.get("caller_id", ""),
        "category": config.get("category", "Security"),
        "subcategory": config.get("subcategory", "Vulnerability"),
    }


def _create_servicenow_ticket(
    *,
    config: dict,
    title: str,
    description: str,
    severity: str,
    labels: list[str],
    extra_fields: dict[str, Any],
) -> TicketCreationResult:
    """Create an incident in ServiceNow via the Table API.

    POST https://<instance>/api/now/table/incident
    """
    resolved = _resolve_servicenow_config(config)

    instance_url = resolved["instance_url"]
    username = resolved["username"]
    password = resolved["password"]

    if not instance_url:
        return TicketCreationResult(
            success=False,
            error="ServiceNow instance_url not configured. "
            "Set SERVICENOW_INSTANCE_URL env var or configure in ticketing_connections.",
        )
    if not username or not password:
        return TicketCreationResult(
            success=False,
            error="ServiceNow credentials not configured. "
            "Set SERVICENOW_USERNAME + SERVICENOW_PASSWORD env vars "
            "or configure in ticketing_connections.",
        )

    # Build the incident payload
    payload: dict[str, Any] = {
        "short_description": title[:160],  # SNOW limit
        "description": description[:4000],  # Keep it reasonable
        "priority": _SEVERITY_TO_SNOW_PRIORITY.get(severity, "3"),
        "urgency": _SEVERITY_TO_SNOW_URGENCY.get(severity, "2"),
        "impact": _SEVERITY_TO_SNOW_IMPACT.get(severity, "2"),
        "category": resolved["category"],
        "subcategory": resolved["subcategory"],
    }

    if resolved["assignment_group"]:
        payload["assignment_group"] = resolved["assignment_group"]
    if resolved["caller_id"]:
        payload["caller_id"] = resolved["caller_id"]

    # Append labels as a comma-separated string in the "u_tags" field
    # (common custom field) or fall back to work_notes
    if labels:
        # Many SNOW instances have a custom u_tags field; if not, harmless
        payload["u_tags"] = ", ".join(labels)

    # Merge any provider-specific overrides
    payload.update(extra_fields)

    url = f"{instance_url}/api/now/table/incident"

    # Try Basic Auth first (works on older SNOW instances), fall back to OAuth
    with httpx.Client(timeout=30, follow_redirects=True) as client:
        try:
            # Attempt Basic Auth
            response = client.post(
                url,
                auth=(username, password),
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                },
                json=payload,
            )

            # If Basic Auth is blocked, try OAuth2 password grant
            if response.status_code == 401:
                client_id = resolved["client_id"]
                client_secret = resolved["client_secret"]

                if not client_id or not client_secret:
                    resp_text = response.text[:300]
                    return TicketCreationResult(
                        success=False,
                        error=f"ServiceNow Basic Auth failed and no OAuth credentials configured: {resp_text[:150]}",
                    )

                # Get OAuth token
                token_resp = client.post(
                    f"{instance_url}/oauth_token.do",
                    data={
                        "grant_type": "password",
                        "client_id": client_id,
                        "client_secret": client_secret,
                        "username": username,
                        "password": password,
                    },
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )
                if token_resp.status_code != 200:
                    resp_text = token_resp.text[:300]
                    return TicketCreationResult(
                        success=False,
                        error=f"ServiceNow OAuth failed ({token_resp.status_code}): {resp_text[:150]}",
                    )

                access_token = token_resp.json().get("access_token")
                if not access_token:
                    return TicketCreationResult(
                        success=False, error="No access_token in OAuth response"
                    )

                # Retry with Bearer token
                response = client.post(
                    url,
                    headers={
                        "Content-Type": "application/json",
                        "Accept": "application/json",
                        "Authorization": f"Bearer {access_token}",
                    },
                    json=payload,
                )

            if response.status_code in (401, 403):
                resp_text = response.text[:300]
                logger.error("ServiceNow %s: %s", response.status_code, resp_text)
                return TicketCreationResult(
                    success=False,
                    error=f"ServiceNow returned {response.status_code}: {resp_text[:150]}",
                )
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            resp_text = exc.response.text[:500] if exc.response else "no response body"
            logger.error(
                "ServiceNow API error %s: %s",
                exc.response.status_code if exc.response else "?",
                resp_text,
            )
            return TicketCreationResult(
                success=False,
                error=f"ServiceNow returned {exc.response.status_code}: {resp_text[:200]}",
            )

    # Parse the response
    data = response.json()
    result = data.get("result", {})
    sys_id = result.get("sys_id", "")
    number = result.get("number", "")  # e.g. "INC0012345"

    # Build the URL to the incident
    ticket_url = f"{instance_url}/nav_to.do?uri=incident.do?sys_id={sys_id}" if sys_id else ""

    return TicketCreationResult(
        success=True,
        external_ticket_id=number or sys_id,
        external_ticket_url=ticket_url,
    )


# ---------------------------------------------------------------------------
# Webhook — generic JSON POST (for Slack, Teams, custom integrations)
# ---------------------------------------------------------------------------


def _create_webhook_ticket(
    *,
    config: dict,
    title: str,
    description: str,
    severity: str,
    labels: list[str],
    extra_fields: dict[str, Any],
) -> TicketCreationResult:
    """POST a JSON payload to a configured webhook URL.

    Supports optional HMAC-SHA256 signing via X-Signature-256 header.
    """
    webhook_url = config.get("webhook_url") or settings.ticketing_webhook_url
    signing_secret = config.get("webhook_secret") or settings.ticketing_webhook_secret

    if not webhook_url:
        return TicketCreationResult(
            success=False,
            error="Webhook URL not configured. "
            "Set TICKETING_WEBHOOK_URL env var or configure in ticketing_connections.",
        )

    payload = {
        "event": "ticket.created",
        "title": title,
        "description": description,
        "severity": severity,
        "priority": _SEVERITY_TO_SNOW_PRIORITY.get(severity, "3"),
        "labels": labels,
        **extra_fields,
    }

    body_bytes = json.dumps(payload, separators=(",", ":")).encode()

    headers: dict[str, str] = {
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

    # HMAC signing if secret is configured
    if signing_secret:
        signature = hmac.HMAC(
            signing_secret.encode(),
            body_bytes,
            hashlib.sha256,
        ).hexdigest()
        headers["X-Signature-256"] = f"sha256={signature}"

    with httpx.Client(timeout=30) as client:
        response = request_with_retry(
            client,
            "POST",
            webhook_url,
            headers=headers,
            json=payload,
            timeout=30,
            max_attempts=3,
        )

    # Try to extract an ID from the response (provider-dependent)
    try:
        resp_data = response.json()
        external_id = (
            resp_data.get("id")
            or resp_data.get("ticket_id")
            or resp_data.get("number")
            or resp_data.get("key")
        )
        external_url = resp_data.get("url") or resp_data.get("html_url")
    except Exception:  # noqa: BLE001
        external_id = None
        external_url = None

    return TicketCreationResult(
        success=True,
        external_ticket_id=str(external_id) if external_id else None,
        external_ticket_url=external_url,
    )


# ---------------------------------------------------------------------------
# Helpers — ticket content formatting
# ---------------------------------------------------------------------------


def format_ticket_description(
    *,
    package: dict,
    issue: dict | None = None,
) -> str:
    """Format a remediation package into a ServiceNow-friendly description.

    Produces a structured text body with finding details, root cause,
    remediation steps, and rollback info.
    """
    lines: list[str] = []

    lines.append(f"Finding: {package.get('finding', 'N/A')}")
    lines.append(f"Root Cause: {package.get('root_cause', 'N/A')}")
    lines.append(f"Impact: {package.get('impact', 'N/A')}")
    lines.append(f"Family: {package.get('family', 'N/A')}")
    lines.append("")

    # Issue context
    if issue:
        lines.append("--- Issue Details ---")
        lines.append(f"Issue ID: {issue.get('id')}")
        lines.append(f"CVE: {issue.get('cve_id') or 'N/A'}")
        lines.append(f"CWE: {issue.get('cwe_id') or 'N/A'}")
        lines.append(f"Severity: {issue.get('severity') or 'N/A'}")
        lines.append(f"Priority: {issue.get('priority') or 'N/A'}")
        lines.append(f"Source: {issue.get('source') or 'N/A'}")
        lines.append("")

    # Recommended pathway steps
    pathways = package.get("pathways") or []
    rec_idx = package.get("recommended_pathway_index", 0)
    if pathways and rec_idx < len(pathways):
        pathway = pathways[rec_idx]
        lines.append("--- Remediation Steps ---")
        for i, step in enumerate(pathway.get("remediation_steps") or [], 1):
            step_text = step.get("step", "") if isinstance(step, dict) else str(step)
            lines.append(f"{i}. {step_text[:500]}")
        lines.append("")

        # Rollback info
        rollback = pathway.get("rollback_plan") or {}
        if rollback.get("supported"):
            lines.append("--- Rollback Plan ---")
            lines.append(f"Objective: {rollback.get('objective', 'N/A')}")
            for i, step in enumerate(rollback.get("steps") or [], 1):
                step_text = step.get("step", "") if isinstance(step, dict) else str(step)
                lines.append(f"{i}. {step_text[:300]}")
            lines.append("")

        # Confidence
        confidence = pathway.get("confidence_score")
        if confidence is not None:
            lines.append(f"Confidence Score: {confidence}/100")

    lines.append("---")
    lines.append("Auto-generated by Agentic VOP Remediation Pipeline")

    return "\n".join(lines)


def build_ticket_title(package: dict, issue: dict | None = None) -> str:
    """Build a concise ticket title from the remediation package."""
    parts: list[str] = []

    # Prefix with severity if available
    if issue and issue.get("severity"):
        parts.append(f"[{issue['severity']}]")

    # CVE if available
    if issue and issue.get("cve_id"):
        parts.append(issue["cve_id"])

    # Finding summary (truncated)
    finding = package.get("finding", "Security vulnerability remediation")
    parts.append(finding[:100])

    title = " ".join(parts)
    return title[:160]  # ServiceNow short_description limit
