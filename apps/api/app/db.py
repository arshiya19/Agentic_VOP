from supabase import Client, create_client

from .config import settings


def supabase_admin() -> Client:
    """Service-role client for the new project. Bypasses RLS — use for backend writes."""
    return create_client(
        settings.agentic_vop_supabase_url,
        settings.agentic_vop_supabase_service_key,
    )
