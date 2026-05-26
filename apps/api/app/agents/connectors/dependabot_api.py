"""GitHub Dependabot connector.

Fetches Dependabot vulnerability alerts from the GitHub REST API v3.
Returns one record per open alert, augmented with the repo name so
Sub-Agent 1 can populate asset_identity without re-joining.

Configuration (all under connection_registry):
  endpoint          : GitHub API base URL (default https://api.github.com)
  auth_ref          : 'env://GITHUB_TOKEN' — Personal Access Token or
                      GitHub App installation token. Requires the
                      'security_events' scope (or 'repo' for private repos).
  metadata:
    account_type    : 'org' (default) | 'user'
    org             : GitHub org name or username (also read from GITHUB_ORG env var)
    repo_limit      : max repos to scan per run (default 50)
    per_page        : alerts per page, 1-100 (default 100)

Watermark behavior:
  If last_fetched_at is provided, only alerts whose updated_at is strictly
  newer than the watermark are emitted. GitHub does not support server-side
  filtering on updated_at, so we fetch all open alerts and filter client-side.
  This is acceptable because Dependabot alert counts per repo are typically
  small (hundreds, not millions).

Alert states:
  We only fetch alerts in state 'open'. Dismissed/fixed alerts are skipped
  because they represent resolved findings. If you want to ingest dismissed
  alerts for audit purposes, remove the state filter in _fetch_repo_alerts().
"""

from __future__ import annotations

import os
from datetime import datetime
from typing import Iterator

import httpx

from ...config import settings
from ..http_utils import request_with_retry


_DEFAULT_BASE_URL = "https://api.github.com"
_DEFAULT_REPO_LIMIT = 50
_DEFAULT_PER_PAGE = 100


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------


def _token() -> str:
    """Resolve the GitHub token from settings or environment."""
    token = getattr(settings, "github_token", "") or os.environ.get("GITHUB_TOKEN", "")
    if not token:
        raise RuntimeError(
            "Missing GITHUB_TOKEN. Add it to apps/api/.env and ensure "
            "config.py exposes it as github_token."
        )
    return token


def _headers() -> dict[str, str]:
    return {
        "Authorization": f"Bearer {_token()}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }


# ---------------------------------------------------------------------------
# Watermark
# ---------------------------------------------------------------------------


def _parse_iso(ts: str | None) -> datetime | None:
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except Exception:  # nosec B110
        return None


# ---------------------------------------------------------------------------
# Pagination helper
# ---------------------------------------------------------------------------


def _paginate(
    client: httpx.Client,
    url: str,
    params: dict,
    *,
    run_id: str | None,
) -> Iterator[dict]:
    """Follow GitHub's Link header pagination, yielding one item at a time."""
    next_url: str | None = url
    current_params: dict | None = params

    while next_url:
        resp = request_with_retry(
            client,
            "GET",
            next_url,
            headers=_headers(),
            params=current_params,
            timeout=60,
            run_id=run_id,
            agent="sub-agent-1",
        )
        items = resp.json()
        if not isinstance(items, list):
            break
        yield from items

        # Parse Link header for the next page URL
        link_header = resp.headers.get("link", "")
        next_url = _parse_next_link(link_header)
        current_params = None  # params are baked into the next_url


def _parse_next_link(link_header: str) -> str | None:
    """Extract the 'next' URL from a GitHub Link header.

    Example header value:
      <https://api.github.com/...?page=2>; rel="next", <...>; rel="last"
    """
    if not link_header:
        return None
    for part in link_header.split(","):
        part = part.strip()
        if 'rel="next"' in part:
            # Extract the URL between < and >
            start = part.find("<")
            end = part.find(">")
            if start != -1 and end != -1:
                return part[start + 1 : end]
    return None


# ---------------------------------------------------------------------------
# Repo listing
# ---------------------------------------------------------------------------


def _list_repos(
    client: httpx.Client,
    base_url: str,
    account_type: str,
    org: str,
    repo_limit: int,
    *,
    run_id: str | None,
) -> list[str]:
    """Return a list of 'owner/repo' strings for the org/user, up to repo_limit."""
    if account_type == "user":
        url = f"{base_url}/users/{org}/repos"
    else:
        url = f"{base_url}/orgs/{org}/repos"

    repos: list[str] = []
    for repo in _paginate(
        client,
        url,
        params={"per_page": 100, "type": "all", "sort": "updated"},
        run_id=run_id,
    ):
        full_name = repo.get("full_name")
        if full_name:
            repos.append(full_name)
        if len(repos) >= repo_limit:
            break

    return repos


# ---------------------------------------------------------------------------
# Alert fetching
# ---------------------------------------------------------------------------


def _fetch_repo_alerts(
    client: httpx.Client,
    base_url: str,
    repo_full_name: str,
    per_page: int,
    *,
    run_id: str | None,
) -> list[dict]:
    """Fetch all open Dependabot alerts for one repo."""
    url = f"{base_url}/repos/{repo_full_name}/dependabot/alerts"
    alerts: list[dict] = []

    try:
        for alert in _paginate(
            client,
            url,
            params={"state": "open", "per_page": per_page},
            run_id=run_id,
        ):
            if isinstance(alert, dict):
                # Inject repo context so Sub-Agent 1 can build asset_identity
                alert["repo_name"] = repo_full_name
                alerts.append(alert)
    except httpx.HTTPStatusError as exc:
        # 404 = Dependabot not enabled on this repo; 403 = no access.
        # Both are expected for some repos — skip silently.
        if exc.response.status_code in (403, 404):
            return []
        raise

    return alerts


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def fetch(
    registry_entry: dict,
    last_fetched_at: str | None = None,
    *,
    run_id: str | None = None,
) -> list[dict]:
    """Fetch open Dependabot alerts across all repos in the configured org/user.

    Returns a flat list of raw alert dicts, one per alert, each augmented
    with 'repo_name' for asset_identity construction by Sub-Agent 1.
    """
    base_url = (registry_entry.get("endpoint") or _DEFAULT_BASE_URL).rstrip("/")
    metadata = registry_entry.get("metadata") or {}

    account_type = metadata.get("account_type", "org")
    org = (
        metadata.get("org")
        or getattr(settings, "github_org", "")
        or os.environ.get("GITHUB_ORG", "")
    )
    if not org:
        raise ValueError(
            "Dependabot connector: no org configured. "
            "Set GITHUB_ORG in .env or update metadata.org in connection_registry."
        )

    repo_limit = int(metadata.get("repo_limit", _DEFAULT_REPO_LIMIT))
    per_page = min(int(metadata.get("per_page", _DEFAULT_PER_PAGE)), 100)

    cutoff = _parse_iso(last_fetched_at)

    with httpx.Client(timeout=60, headers=_headers()) as client:
        repos = _list_repos(
            client, base_url, account_type, org, repo_limit, run_id=run_id
        )

        all_alerts: list[dict] = []

        for repo_full_name in repos:
            alerts = _fetch_repo_alerts(
                client, base_url, repo_full_name, per_page, run_id=run_id
            )

            for alert in alerts:
                # Watermark: skip alerts we've already processed
                if cutoff is not None:
                    updated_at = _parse_iso(alert.get("updated_at"))
                    if updated_at is not None and updated_at <= cutoff:
                        continue

                all_alerts.append(alert)

    return all_alerts
