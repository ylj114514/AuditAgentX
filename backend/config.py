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
    # 调用健壮性：失败重试次数与退避基数（秒）
    llm_max_retries: int = 2
    llm_retry_backoff: float = 1.5

    # ---- 验证并发 ----
    # VerifyAgent 静态复核、利用生成（LLM）与 Harness（函数级）可并行；
    # 按 DeepSeek/API 并发限额调整，1 即退回串行。HTTP 探测因共享靶场固定串行，不在此列。
    verify_workers: int = 4
    max_verify_candidates: int = 50
    dynamic_exploit_workers: int = 4
    dynamic_harness_workers: int = 4
    # 动态验证候选上限：confirmed 全部纳入，剩余预算用于填充 needs_review 中
    # 「动态可验证」的候选，避免超大项目对全部漏洞逐条跑动态验证。
    max_dynamic_candidates: int = 20

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
    # docker_host 留空则用 docker.from_env() 自动适配平台（Windows npipe / Linux socket）
    docker_host: str = ""
    sandbox_timeout: int = 60

    # ---- Fuzzing Harness 动态验证 ----
    harness_timeout: int = 8            # 单次 Harness 执行超时（秒）
    harness_max_retries: int = 2        # DeepAudit 式失败自我修正重试次数
    enable_local_harness: bool = True   # 允许内置模板 Harness 本地回退执行
    # Docker-first 安全策略：LLM 生成的 Harness 必须在 Docker 沙箱执行；
    # Docker 不可用时返回 sandbox_failed 而非本地跑 LLM 代码（模板不受此限）。
    harness_require_docker: bool = True

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
