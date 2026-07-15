"""Quick "is env2 safe to demo?" check.

Usage:
    cd apps/api && uv run python scripts/check_env2_status.py

Prints whether env2 is currently idle (safe to trigger demo) or busy
(someone else's fix_run is in progress) plus the last few fix_runs for
context. Safe to run any time — read-only query, hits the shared Supabase
directly rather than routing through the API.
"""

from __future__ import annotations

from app.config import settings
from supabase import create_client


ACTIVE_STATUSES = ("pending", "provisioning", "executing", "validating")


def main() -> None:
    sb = create_client(
        settings.agentic_vop_supabase_url,
        settings.agentic_vop_supabase_service_key,
    )

    in_flight = (
        sb.schema("demo")
        .table("fix_runs")
        .select("id, status, package_id, started_at, updated_at")
        .in_("status", ACTIVE_STATUSES)
        .order("id", desc=True)
        .execute()
        .data
        or []
    )

    if not in_flight:
        print("✅ env2 IDLE — safe to trigger the demo.")
    else:
        print(f"⏳ env2 BUSY — {len(in_flight)} fix_run(s) currently active:")
        for r in in_flight:
            print(
                f"    fix_run #{r['id']}  status={r['status']:14s}  "
                f"package={r['package_id']}  started={r['started_at'][:19]}  "
                f"last_update={r['updated_at'][:19]}"
            )
        print("\n  → Wait for these to finish, or coordinate with your teammate before retrying.")

    recent = (
        sb.schema("demo")
        .table("fix_runs")
        .select("id, status, package_id, finished_at")
        .order("id", desc=True)
        .limit(5)
        .execute()
        .data
        or []
    )
    print("\nLast 5 fix_runs (any status):")
    for r in recent:
        fin = (r.get("finished_at") or "")[:19] or "(not finished)"
        print(
            f"    fix_run #{r['id']}  status={r['status']:14s}  "
            f"package={r['package_id']}  finished={fin}"
        )


if __name__ == "__main__":
    main()
