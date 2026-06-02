from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    unifi_host: str
    unifi_api_key: str
    unifi_site: str = "default"
    unifi_verify_ssl: bool = False

    postgres_host: str = "localhost"
    postgres_db: str = "unifi_dashboard"
    postgres_user: str = "dashboard"
    postgres_password: str

    scanner_base_url: str = "http://scanner:8002"
    syslog_port: int = 514
    log_retention_days: int = 30
    poll_interval_seconds: int = Field(default=60, ge=10)
    api_allowed_origins: str = ""

    @property
    def database_url(self) -> str:
        return (
            f"postgresql+asyncpg://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}/{self.postgres_db}"
        )

    @property
    def cors_allowed_origins(self) -> list[str]:
        return [
            origin.strip()
            for origin in self.api_allowed_origins.split(",")
            if origin.strip()
        ]


settings = Settings()
