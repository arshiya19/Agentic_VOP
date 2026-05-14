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

    # NVD API key (optional; without it, calls are rate-limited to 5 per 30 sec.
    # Get one free from https://nvd.nist.gov/developers/request-an-api-key)
    nvd_api_key: str = ""

    # Parallel LLM workers — Sub-Agent 1 + Sub-Agent 2 run this many threads
    # concurrently. 5 gives ~150K TPM peak — comfortably under OpenAI's default
    # 200K TPM limit for gpt-4o-mini. Bump to 10+ if you have a higher tier.
    llm_parallel_workers: int = 5


settings = Settings()
