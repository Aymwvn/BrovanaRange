from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    DATABASE_URL: str
    JWT_SECRET: str
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    REFRESH_TOKEN_EXPIRE_DAYS: int = 14
    EMAIL_TOKEN_EXPIRE_MINUTES: int = 30
    PASSWORD_RESET_EXPIRE_MINUTES: int = 30
    EMAIL_OTP_EXPIRE_MINUTES: int = 10
    REQUIRE_EMAIL_VERIFICATION: bool = False
    REQUIRE_MFA: bool = False
    LAB_TIMEOUT_MINUTES: int = 45
    LAB_CPU_NANOS: int = 500_000_000
    LAB_MEMORY_LIMIT: str = "256m"
    LAB_PIDS_LIMIT: int = 128
    LAB_CONTAINER_RUNTIME: str = "runsc"
    ALLOW_UNSANDBOXED_LABS: bool = False
    DOCKER_LAB_NETWORK_PREFIX: str = "redrange_user"
    CORS_ORIGINS: str = "http://localhost:5173"
    DOCKER_HOST: str = "unix://var/run/docker.sock"
    DEFAULT_ADMIN_USERNAME: str = "admin"
    DEFAULT_ADMIN_EMAIL: str = "admin@redrange.local"
    DEFAULT_ADMIN_PASSWORD: str = "ChangeMeNow_12345!"
    ENVIRONMENT: str = "development"
    PROMETHEUS_METRICS_TOKEN: str = ""

    @property
    def cors_list(self) -> list[str]:
        return [x.strip() for x in self.CORS_ORIGINS.split(",") if x.strip()]

    class Config:
        env_file = ".env"

settings = Settings()
