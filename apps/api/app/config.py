from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    agentic_vop_supabase_url: str
    agentic_vop_supabase_service_key: str

    openai_api_key: str

    # Optional provider keys — required only when the corresponding model
    # provider is selected in prompt_db.parameters.provider for any agent.
    anthropic_api_key: str = ""
    google_api_key: str = ""

    # Tenable / Nessus (only required if any tool uses connector_type="tenable_api")
    tenable_access_key: str = ""
    tenable_secret_key: str = ""

    # GitHub Dependabot (only required if any tool uses connector_type="dependabot_api")
    # Token needs the 'security_events' scope for public repos, or 'repo' for private repos.
    github_token: str = ""
    github_org: str = (
        ""  # org name or username; can also be set in connection_registry.metadata.org
    )

    # NVD API key (optional; without it, calls are rate-limited to 5 per 30 sec.
    # Get one free from https://nvd.nist.gov/developers/request-an-api-key)
    nvd_api_key: str = ""

    # Parallel LLM workers — Sub-Agent 1 + Sub-Agent 2 run this many threads
    # concurrently. 5 gives ~150K TPM peak — comfortably under OpenAI's default
    # 200K TPM limit for gpt-4o-mini. Bump to 10+ if you have a higher tier.
    llm_parallel_workers: int = 5

    # --- Secrets encryption ---
    # Base64-encoded 32-byte key for AES-256-GCM encryption of sensitive
    # scanner metadata (headers, body, credentials). REQUIRED for production.
    # Generate with: python -c "import secrets,base64; print(base64.b64encode(secrets.token_bytes(32)).decode())"
    secrets_encryption_key: str = ""

    # Which secrets backend to use. Currently only "local" (AES-256-GCM) is
    # supported. Future: "aws_secrets_manager", "hashicorp_vault".
    secrets_backend: str = "local"

    # Comma-separated list of metadata keys treated as sensitive (encrypted at
    # rest, redacted in API responses). Extend for custom credential fields.
    sensitive_metadata_fields: str = "headers,body,credentials"

    # Block saving auth headers against non-HTTPS endpoints. Set to "false"
    # only for local development.
    enforce_https_endpoints: bool = True

    # --- Intelligence Layer (DynamoDB) ---
    # DynamoDB table name for vulnerability intelligence lookups.
    # Pattern: sisyfix-{env}-vulnerability-intelligence
    intelligence_table_name: str = ""

    # AWS region for the intelligence DynamoDB table.
    intelligence_aws_region: str = "us-east-1"

    # Feature flag for gradual rollout of DynamoDB-backed lookups.
    # When False, falls back to direct NVD API calls.
    intelligence_enabled: bool = False

    # Threshold for cache misses before emitting CacheMissesLookupFailed metric.
    max_sync_cache_misses: int = 10


settings = Settings()
