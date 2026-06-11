"""Environment-specific configuration constants for the NVD Sync Lambda."""

import os

# ---------------------------------------------------------------------------
# Runtime environment
# ---------------------------------------------------------------------------
ENVIRONMENT: str = os.environ.get("ENVIRONMENT", "dev")

# ---------------------------------------------------------------------------
# NVD Feed URLs
# ---------------------------------------------------------------------------
NVD_MODIFIED_FEED_URL: str = (
    "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-modified.json.gz"
)
NVD_MODIFIED_META_URL: str = (
    "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-modified.meta"
)
NVD_API_BASE_URL: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_YEARLY_FEED_URL_PATTERN: str = (
    "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{year}.json.gz"
)

# ---------------------------------------------------------------------------
# DynamoDB
# ---------------------------------------------------------------------------
TABLE_NAME_PATTERN: str = "sisyfix-{env}-vulnerability-intelligence"

# ---------------------------------------------------------------------------
# Processing limits
# ---------------------------------------------------------------------------
TIMEOUT_SAFETY_BUFFER_MS: int = 30_000  # 30 seconds
BATCH_SIZE: int = 25
MAX_RETRIES: int = 3
BASE_DELAY_SECONDS: int = 1

# ---------------------------------------------------------------------------
# Lambda resource configuration
# ---------------------------------------------------------------------------
LAMBDA_TIMEOUT_SECONDS: int = 300
LAMBDA_MEMORY_MB_PROD: int = 512
LAMBDA_MEMORY_MB_DEV: int = 256

# ---------------------------------------------------------------------------
# Scheduling
# ---------------------------------------------------------------------------
SCHEDULE_RATE_PROD: str = "rate(2 hours)"
SCHEDULE_RATE_DEV: str = "rate(6 hours)"

# ---------------------------------------------------------------------------
# SSM Parameter Store
# ---------------------------------------------------------------------------
SSM_NVD_API_KEY_PATH: str = "/sisyfix/{env}/nvd-api-key"

# ---------------------------------------------------------------------------
# Gap recovery thresholds
# ---------------------------------------------------------------------------
GAP_THRESHOLD_DAYS: int = 8  # Normal sync vs gap recovery boundary
CRITICAL_GAP_DAYS: int = 120  # Gap recovery vs critical abort boundary

# ---------------------------------------------------------------------------
# Rate limiting (NVD API)
# ---------------------------------------------------------------------------
RATE_LIMIT_REQUESTS: int = 50  # Max requests per rolling window
RATE_LIMIT_WINDOW_SECONDS: int = 30


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------
def get_table_name(env: str) -> str:
    """Return the DynamoDB table name for the given environment."""
    return TABLE_NAME_PATTERN.format(env=env)


def get_ssm_api_key_path(env: str) -> str:
    """Return the SSM parameter path for the NVD API key."""
    return SSM_NVD_API_KEY_PATH.format(env=env)
