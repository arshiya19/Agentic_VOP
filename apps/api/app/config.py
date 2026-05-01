from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    agentic_vop_supabase_url: str
    agentic_vop_supabase_service_key: str

    anthropic_api_key: str

    # Tenable / Nessus (only required if any tool uses connector_type="tenable_api")
    tenable_access_key: str = ""
    tenable_secret_key: str = ""

    # NVD API key (optional; without it, calls are rate-limited to 5 per 30 sec.
    # Get one free from https://nvd.nist.gov/developers/request-an-api-key)
    nvd_api_key: str = ""


settings = Settings()
