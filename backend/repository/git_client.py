"""Git 仓库拉取 / 本地目录准备。"""
from __future__ import annotations

import logging
import shutil
from pathlib import Path

from backend.config import settings

logger = logging.getLogger(__name__)


def prepare_workspace(project_id: str, source_type: str, url: str | None,
                      local_path: str | None, branch: str | None) -> Path:
    """将目标项目准备到 workspace，返回本地代码根目录。

    - source_type == "git"：clone 到 workspace/<project_id>
    - source_type == "local"：直接使用 local_path（不复制，只读扫描）
    """
    if source_type == "local":
        if not local_path or not Path(local_path).exists():
            raise ValueError(f"本地路径不存在: {local_path}")
        return Path(local_path).resolve()

    if source_type == "git":
        if not url:
            raise ValueError("git 类型必须提供 url")
        dest = settings.workspace_path / project_id
        if dest.exists():
            shutil.rmtree(dest, ignore_errors=True)
        _git_clone(url, dest, branch)
        return dest

    raise ValueError(f"不支持的 source_type: {source_type}")


def _git_clone(url: str, dest: Path, branch: str | None) -> None:
    try:
        from git import Repo
    except ImportError as e:  # pragma: no cover
        raise RuntimeError("未安装 GitPython，请 pip install GitPython") from e

    kwargs = {"depth": 1}
    if branch:
        kwargs["branch"] = branch
    logger.info("clone %s -> %s (branch=%s)", url, dest, branch)
    Repo.clone_from(url, str(dest), **kwargs)
