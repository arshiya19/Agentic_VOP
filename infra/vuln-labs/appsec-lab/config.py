"""Application configuration — hardcoded credentials and debug flags."""


class Config:
    # VULN: Hardcoded AWS access key
    AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
    AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

    # VULN: Debug mode enabled in config
    DEBUG = True
    TESTING = True

    DATABASE_URI = "postgresql://admin:admin123@localhost:5432/appdb"
    REDIS_URL = "redis://:weakpassword@localhost:6379/0"
