import os
from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    # Wazuh API Configuration (Manager API)
    wazuh_api_url: str = os.getenv("WAZUH_API_URL", "https://localhost:55000")
    wazuh_username: str = os.getenv("WAZUH_USERNAME", "wazuh-wui")
    wazuh_password: str = os.getenv("WAZUH_PASSWORD", "MyS3cr37P450r.*-")
    wazuh_verify_ssl: bool = os.getenv("WAZUH_VERIFY_SSL", "false").lower() == "true"
    wazuh_timeout: int = int(os.getenv("WAZUH_TIMEOUT", "30"))

    # JWT Token cache duration (Wazuh tokens expire in 900 seconds by default)
    wazuh_token_cache_duration: int = int(os.getenv("WAZUH_TOKEN_CACHE_DURATION", "800"))  # Refresh before expiry

    # Wazuh Indexer Configuration (OpenSearch)
    wazuh_indexer_url: str = os.getenv("WAZUH_INDEXER_URL", "https://localhost:9200")
    wazuh_indexer_username: str = os.getenv("WAZUH_INDEXER_USERNAME", "admin")
    wazuh_indexer_password: str = os.getenv("WAZUH_INDEXER_PASSWORD", "SecretPassword")
    wazuh_indexer_verify_ssl: bool = os.getenv("WAZUH_INDEXER_VERIFY_SSL", "false").lower() == "true"
    wazuh_indexer_timeout: int = int(os.getenv("WAZUH_INDEXER_TIMEOUT", "30"))
    wazuh_indexer_index_pattern: str = os.getenv("WAZUH_INDEXER_INDEX_PATTERN", "wazuh-alerts-*")

    # Internal Docker lab simulator; never accepts a caller-supplied host.
    attack_simulator_url: str = os.getenv("ATTACK_SIMULATOR_URL", "http://attack-simulator:8090")

    # Application authentication and password recovery.
    admin_email: str = os.getenv("ADMIN_EMAIL", "chemrari.maroua@gmail.com").strip().lower()
    admin_password_hash: str = os.getenv("ADMIN_PASSWORD_HASH", "")
    auth_session_ttl_minutes: int = int(os.getenv("AUTH_SESSION_TTL_MINUTES", "480"))
    auth_cookie_secure: bool = os.getenv("AUTH_COOKIE_SECURE", "false").lower() == "true"
    password_reset_ttl_minutes: int = int(os.getenv("PASSWORD_RESET_TTL_MINUTES", "30"))
    frontend_base_url: str = os.getenv("FRONTEND_BASE_URL", "http://localhost").rstrip("/")

    smtp_host: str = os.getenv("SMTP_HOST", "")
    smtp_port: int = int(os.getenv("SMTP_PORT", "587"))
    smtp_username: str = os.getenv("SMTP_USERNAME", "")
    smtp_password: str = os.getenv("SMTP_PASSWORD", "")
    smtp_from: str = os.getenv("SMTP_FROM", "")
    smtp_use_ssl: bool = os.getenv("SMTP_USE_SSL", "false").lower() == "true"
    smtp_starttls: bool = os.getenv("SMTP_STARTTLS", "true").lower() == "true"
    smtp_timeout_seconds: int = int(os.getenv("SMTP_TIMEOUT_SECONDS", "20"))

    class Config:
        env_file = ".env"
        env_file_encoding = 'utf-8'


# Global settings instance
settings = Settings()