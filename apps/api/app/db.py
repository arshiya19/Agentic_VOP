from supabase import Client, create_client

from .config import settings


def supabase_admin() -> Client:
    """Service-role client scoped to the configured schema.

    In production (DB_SCHEMA unset or "public"): targets public.* — no behavioral change.
    In local dev (DB_SCHEMA=dev): targets dev.* — full isolation from prod data.

    The demo pipeline is NOT affected — supabase_admin_demo() remains hardcoded
    to the "demo" schema regardless of this setting.
    """
    client = create_client(
        settings.agentic_vop_supabase_url,
        settings.agentic_vop_supabase_service_key,
    )
    if settings.db_schema != "public":
        return client.schema(settings.db_schema)
    return client


def supabase_admin_demo() -> Client:
    """Service-role client scoped to the `demo` Postgres schema.

    Used by master_demo.py + sub_agent_*_demo.py + planner_demo.py. Every
    sb.table("X") call this client makes hits `demo.X` instead of `public.X`.
    See migration 0046 for the demo schema definition and
    [[agentic-vop-demo-pipeline-architecture]] for why demo runs on a
    dedicated schema instead of a `demo=True` branch in real code.

    Note on shared config tables: demo agents still need to read from
    `public.prompt_db`, `public.schema_mapping`, `public.remediation_patterns`,
    and `public.connection_registry` (config, not per-run state — shared with
    real pipeline). For those, use a separate `supabase_admin()` client in
    parallel — this scoped client only sees `demo.*`.
    """
    return create_client(
        settings.agentic_vop_supabase_url,
        settings.agentic_vop_supabase_service_key,
    ).schema("demo")
