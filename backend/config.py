"""
Backend config (part of Layer 7).

Loads settings from environment variables / .env. Keeping this in one
place means every module reads config the same way instead of scattering
os.getenv() calls throughout the codebase.
"""

import os
from dotenv import load_dotenv

load_dotenv()


class Config:
    APP_NAME = os.getenv("APP_NAME", "ARGUS")
    APP_ENV = os.getenv("APP_ENV", "development")
    DEBUG = os.getenv("DEBUG", "true").lower() == "true"
    DATABASE_URL = os.getenv("DATABASE_URL", "argus.db")
    API_KEY = os.getenv("API_KEY", "dev-api-key")
    THREAT_INTELLIGENCE_API_KEY = os.getenv("THREAT_INTELLIGENCE_API_KEY", "")
    SECRET_KEY = os.getenv("SECRET_KEY", "change_this_in_real_environment")

    @classmethod
    def validate(cls) -> None:
        """Fail fast in production if secrets were left at their defaults."""
        if cls.APP_ENV == "production":
            if cls.SECRET_KEY == "change_this_in_real_environment":
                raise RuntimeError("SECRET_KEY must be set for a production deployment")
            if cls.API_KEY == "dev-api-key":
                raise RuntimeError("API_KEY must be set for a production deployment")


DB_PATH = Config.DATABASE_URL if Config.DATABASE_URL.endswith(".db") else "argus.db"
