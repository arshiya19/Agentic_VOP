"""GitHub Dependabot connector.

Fetches Dependabot vulnerability alerts from the GitHub REST API v3.
Returns one record per open alert, augmented with the repo name so
Sub-Agent 1 can populate asset_identity without re-joining.

Configuration (all under connection_registry):
  endpoint          : Full GitHub repos list URL for the target account, e.g.
                        https://api.github.com/users/{username}/repos   (personal)
                        https://api.github.com/orgs/{orgname}/repos     (organisation)
                      The connector uses this URL as-is to list repos, then
                      derives the API base URL (scheme + host) from it to
                      build per-repo alert URLs.
  auth_ref          : 'env://GITHUB_TOKEN' — Personal Access Token or
                      GitHub App installation token. Requires the
                      'security_events' scope (or 'repo' for private repos).
  metadata:
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
from collections.abc import Iterator
from datetime import datetime
from urllib.parse import urlparse

import httpx

from ...config import settings
from ..http_utils import request_with_retry


_DEFAULT_REPOS_URL = "https://api.github.com/users/{org}/repos"
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
            # GitHub returns a dict on error (e.g. {"message": "..."}).
            # Raise so the caller sees the problem instead of getting 0 results.
            msg = items.get("message", "") if isinstance(items, dict) else str(items)
            raise RuntimeError(f"GitHub API returned non-list response for {next_url}: {msg}")
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


def _is_repos_list_url(url: str) -> bool:
    """Detect whether the URL is a GitHub repos-list endpoint.

    Repos list URLs look like:
      /users/{owner}/repos
      /orgs/{org}/repos

    Single-repo URLs look like:
      /repos/{owner}/{repo}
    """
    path = urlparse(url).path.rstrip("/")
    # /users/{x}/repos or /orgs/{x}/repos
    parts = path.split("/")
    # ['', 'users', '{x}', 'repos'] or ['', 'orgs', '{x}', 'repos']
    if len(parts) == 4 and parts[1] in ("users", "orgs") and parts[3] == "repos":
        return True
    return False


def _extract_repo_full_name(url: str) -> str | None:
    """If the URL points to a single repo, extract 'owner/repo'.

    Handles:
      https://api.github.com/repos/{owner}/{repo}
      https://api.github.com/users/{owner}/repos/{repo}  (common user mistake)
      https://github.com/{owner}/{repo}
    """
    parsed = urlparse(url)
    path = parsed.path.rstrip("/")
    parts = path.split("/")

    # /repos/{owner}/{repo} — GitHub API format
    if len(parts) == 4 and parts[1] == "repos":
        return f"{parts[2]}/{parts[3]}"

    # /users/{owner}/repos/{repo} — user pasted a repo name after the list URL
    if len(parts) == 5 and parts[1] in ("users", "orgs") and parts[3] == "repos":
        return f"{parts[2]}/{parts[4]}"

    # /{owner}/{repo} — github.com web URL format
    if parsed.netloc in ("github.com", "www.github.com") and len(parts) == 3 and parts[1]:
        return f"{parts[1]}/{parts[2]}"

    return None


def _list_repos(
    client: httpx.Client,
    repos_url: str,
    repo_limit: int,
    *,
    run_id: str | None,
) -> list[str]:
    """Return a list of 'owner/repo' strings by calling repos_url directly.

    repos_url is the full endpoint stored in connection_registry, e.g.:
      https://api.github.com/users/{username}/repos
      https://api.github.com/orgs/{orgname}/repos
    """
    repos: list[str] = []
    for repo in _paginate(
        client,
        repos_url,
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
        # 404 = Dependabot not enabled on this repo — skip silently.
        if exc.response.status_code == 404:
            return []
        # 403 = token lacks permissions. Raise so the user knows.
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
    """Fetch open Dependabot alerts for the configured GitHub endpoint.

    The endpoint in connection_registry can be:
      1. A repos list URL (fetches alerts across all repos):
           https://api.github.com/users/{username}/repos
           https://api.github.com/orgs/{orgname}/repos
      2. A single repo URL (fetches alerts for just that repo):
           https://api.github.com/repos/{owner}/{repo}
           https://github.com/{owner}/{repo}

    Whatever the user pastes in the UI is used directly — no path appending
    or hardcoded account names.

    Returns a flat list of raw alert dicts, one per alert, each augmented
    with 'repo_name' for asset_identity construction by Sub-Agent 1.
    """
    endpoint = registry_entry.get("endpoint", "").strip()
    if not endpoint:
        raise ValueError(
            "Dependabot connector: no endpoint configured. "
            "Set the endpoint to a GitHub repos URL, e.g. "
            "https://api.github.com/users/{username}/repos or "
            "https://api.github.com/repos/{owner}/{repo}"
        )

    # Derive the API base URL (scheme + host) for building alert URLs.
    parsed = urlparse(endpoint)
    base_url = f"{parsed.scheme}://{parsed.netloc}"
    # If user pasted a github.com web URL, use the API host for API calls.
    if parsed.netloc in ("github.com", "www.github.com"):
        base_url = "https://api.github.com"

    metadata = registry_entry.get("metadata") or {}
    repo_limit = int(metadata.get("repo_limit", _DEFAULT_REPO_LIMIT))
    per_page = min(int(metadata.get("per_page", _DEFAULT_PER_PAGE)), 100)

    cutoff = _parse_iso(last_fetched_at)

    # Determine whether the endpoint is a repos list or a single repo.
    single_repo = _extract_repo_full_name(endpoint)

    with httpx.Client(timeout=60, headers=_headers()) as client:
        if single_repo:
            # User pasted a single repo URL — scan just that repo.
            repos = [single_repo]
        elif _is_repos_list_url(endpoint):
            # User pasted a repos list URL — enumerate repos from it.
            repos = _list_repos(client, endpoint, repo_limit, run_id=run_id)
        else:
            # Unrecognized URL shape — try using it as a repos list anyway.
            repos = _list_repos(client, endpoint, repo_limit, run_id=run_id)

        all_alerts: list[dict] = []

        for repo_full_name in repos:
            alerts = _fetch_repo_alerts(client, base_url, repo_full_name, per_page, run_id=run_id)

            for alert in alerts:
                # Watermark: skip alerts we've already processed
                if cutoff is not None:
                    updated_at = _parse_iso(alert.get("updated_at"))
                    if updated_at is not None and updated_at <= cutoff:
                        continue

                all_alerts.append(alert)

    return all_alerts
