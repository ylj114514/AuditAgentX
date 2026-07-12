"""Git 仓库拉取 / 本地目录准备。"""
from __future__ import annotations

import logging
import re
import shutil
import subprocess
from pathlib import Path

from backend.config import settings

logger = logging.getLogger(__name__)
_FULL_COMMIT = re.compile(r"[0-9a-fA-F]{40}")


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
        _remove_workspace(dest)
        _git_clone(url, dest, branch)
        return dest

    raise ValueError(f"不支持的 source_type: {source_type}")


def _git_clone(url: str, dest: Path, branch: str | None) -> None:
    """浅克隆 Git 仓库。

    这里刻意不用 GitPython 的 clone_from：在 Windows + cp936/GBK 终端环境下，
    GitPython 读取 git 子进程输出时可能触发 UnicodeDecodeError，导致 UI 只能看到
    exit code(128) 而看不到真正 stderr。直接用 subprocess 捕获 bytes 后容错解码，
    错误信息更稳定，也更利于前端展示。
    """
    if branch and _FULL_COMMIT.fullmatch(branch):
        dest.parent.mkdir(parents=True, exist_ok=True)
        commands = [
            ["git", "init", str(dest)],
            ["git", "-C", str(dest), "remote", "add", "origin", url],
            ["git", "-C", str(dest), "fetch", "--depth=1", "origin", branch],
            ["git", "-C", str(dest), "checkout", "--detach", "FETCH_HEAD"],
            ["git", "-C", str(dest), "rev-parse", "HEAD"],
        ]
        for command in commands:
            result = _run_git(command)
            if result.returncode != 0:
                _remove_workspace(dest)
                raise RuntimeError(_format_clone_error(result, url, dest, branch=branch))
        observed = _decode_output(result.stdout).strip()
        if observed.lower() != branch.lower():
            _remove_workspace(dest)
            raise RuntimeError(f"固定 commit 校验失败: requested={branch}, observed={observed or 'missing'}")
        return

    args = ["git", "clone", "-v", "--depth=1"]
    if branch:
        args.extend(["--branch", branch])
    args.extend(["--", url, str(dest)])

    logger.info("clone %s -> %s (branch=%s)", url, dest, branch or "default")
    first = _run_git(args)
    if first.returncode == 0:
        return

    if branch:
        logger.warning("clone 指定分支 %s 失败，回退仓库默认分支: %s", branch, url)
        _remove_workspace(dest)
        fallback = _run_git(["git", "clone", "-v", "--depth=1", "--", url, str(dest)])
        if fallback.returncode == 0:
            return
        raise RuntimeError(_format_clone_error(fallback, url, dest, branch=None))

    raise RuntimeError(_format_clone_error(first, url, dest, branch=branch))


def workspace_commit(path: Path) -> str | None:
    result = _run_git(["git", "-C", str(path), "rev-parse", "HEAD"])
    if result.returncode != 0:
        return None
    commit = _decode_output(result.stdout).strip()
    return commit if _FULL_COMMIT.fullmatch(commit) else None


def _run_git(args: list[str]) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        args,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def _remove_workspace(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path, ignore_errors=True)
    if path.exists():
        raise RuntimeError(f"无法清理已有工作目录: {path}")


def _decode_output(data: bytes) -> str:
    if not data:
        return ""
    for encoding in ("utf-8", "gbk"):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="replace")


def _format_clone_error(result: subprocess.CompletedProcess[bytes], url: str,
                        dest: Path, branch: str | None) -> str:
    stdout = _decode_output(result.stdout).strip()
    stderr = _decode_output(result.stderr).strip()
    parts = [
        f"git clone 失败，退出码={result.returncode}",
        f"url={url}",
        f"branch={branch or 'default'}",
        f"dest={dest}",
    ]
    if stderr:
        parts.append(f"stderr={stderr[-2000:]}")
    if stdout:
        parts.append(f"stdout={stdout[-1000:]}")
    return "\n".join(parts)
