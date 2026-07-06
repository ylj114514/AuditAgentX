"""全局配置：从环境变量 / .env 加载。"""
from __future__ import annotations

from pathlib import Path
from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


BASE_DIR = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=str(BASE_DIR / ".env"), env_file_encoding="utf-8", extra="ignore"
    )

    # ---- 大模型 ----
    llm_api_key: str = "sk-test"
    llm_base_url: str = "https://api.deepseek.com/v1"
    llm_model: str = "deepseek-chat"
    llm_temperature: float = 0.1
    llm_max_tokens: int = 4096
    llm_timeout: int = 120

    # ---- 数据库 ----
    database_url: str = "sqlite:///./data/auditagentx.db"

    # ---- 目录 ----
    data_dir: str = "./data"
    workspace_dir: str = "./data/projects"

    # ---- 静态扫描工具开关 ----
    enable_semgrep: bool = True
    enable_bandit: bool = True
    enable_gitleaks: bool = True
    enable_trivy: bool = False

    # ---- 沙箱 ----
    enable_sandbox: bool = False
    docker_host: str = "unix:///var/run/docker.sock"
    sandbox_timeout: int = 60

    # ---- 服务 ----
    app_host: str = "0.0.0.0"
    app_port: int = 8000
    log_level: str = "INFO"

    @property
    def data_path(self) -> Path:
        p = (BASE_DIR / self.data_dir).resolve()
        p.mkdir(parents=True, exist_ok=True)
        return p

    @property
    def workspace_path(self) -> Path:
        p = (BASE_DIR / self.workspace_dir).resolve()
        p.mkdir(parents=True, exist_ok=True)
        return p


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
