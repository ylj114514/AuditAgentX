"""Git 仓库拉取 / 本地目录准备。"""
from __future__ import annotations

import logging
import re
import shutil
import subprocess
import tarfile
import tempfile
from pathlib import Path
from urllib.parse import quote, urlparse
from urllib.request import Request, urlopen

from backend.config import settings

logger = logging.getLogger(__name__)
_FULL_COMMIT = re.compile(r"[0-9a-fA-F]{40}")
_GITHUB_REPOSITORY_PART = re.compile(r"[A-Za-z0-9_.-]+")
_MAX_GITHUB_ARCHIVE_BYTES = 1024 * 1024 * 1024
_MAX_GITHUB_ARCHIVE_EXTRACTED_BYTES = 2 * 1024 * 1024 * 1024


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
                _clone_after_git_failure(result, url, dest, branch)
                return
        observed = _decode_output(result.stdout).strip()
        if observed.lower() != branch.lower():
            _remove_workspace(dest)
            raise RuntimeError(f"固定 commit 校验失败: requested={branch}, observed={observed or 'missing'}")
        return

    # Windows Git can stall or fail with early EOF while negotiating GitHub
    # HTTP/2 transport. Keep this process-local so user/global Git settings
    # remain untouched and every frontend-triggered clone is reproducible.
    args = ["git", "-c", "http.version=HTTP/1.1", "clone", "-v", "--depth=1"]
    if branch:
        args.extend(["--branch", branch])
    args.extend(["--", url, str(dest)])

    logger.info("clone %s -> %s (branch=%s)", url, dest, branch or "default")
    first = _run_git(args)
    if first.returncode == 0:
        return

    _remove_workspace(dest)
    _clone_after_git_failure(first, url, dest, branch)


def _clone_after_git_failure(result: subprocess.CompletedProcess[bytes], url: str,
                             dest: Path, branch: str | None) -> None:
    """Preserve the requested revision when Git transport cannot retrieve GitHub."""
    requested_ref = branch or "HEAD"
    try:
        _clone_github_archive(url, dest, requested_ref)
    except Exception as exc:  # noqa: BLE001  Retain the original Git failure for diagnosis.
        _remove_workspace(dest)
        git_error = _format_clone_error(result, url, dest, branch=branch)
        raise RuntimeError(
            f"{git_error}\nGitHub archive fallback failed for requested ref "
            f"{requested_ref}: {_safe_error_text(exc)}"
        ) from exc
    logger.warning(
        "git transport failed; retrieved GitHub archive at requested ref %s: %s", requested_ref, url,
    )


def _clone_github_archive(url: str, dest: Path, ref: str) -> None:
    """Download and safely unpack GitHub's archive for exactly ``ref``.

    This is intentionally a GitHub-only transport fallback.  It must never turn
    a requested branch/commit into an unrecorded default-branch checkout.
    """
    archive_url = _github_archive_url(url, ref)
    if not archive_url:
        raise ValueError("archive fallback is only available for github.com HTTPS repository URLs")
    dest.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="auditagentx_github_", dir=str(dest.parent)) as temp_dir:
        staging = Path(temp_dir)
        archive_path = staging / "source.tar.gz"
        extracted_root = staging / "extracted"
        _download_github_archive(archive_url, archive_path)
        _extract_github_archive(archive_path, extracted_root)
        roots = [path for path in extracted_root.iterdir() if path.is_dir()]
        if len(roots) != 1:
            raise RuntimeError("GitHub archive must contain exactly one repository root directory")
        shutil.move(str(roots[0]), str(dest))


def _github_archive_url(url: str, ref: str) -> str | None:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or parsed.hostname not in {"github.com", "www.github.com"}:
        return None
    parts = [part for part in parsed.path.split("/") if part]
    if len(parts) != 2:
        return None
    owner, repo = parts
    if repo.endswith(".git"):
        repo = repo[:-4]
    if not (_GITHUB_REPOSITORY_PART.fullmatch(owner) and _GITHUB_REPOSITORY_PART.fullmatch(repo)):
        return None
    return (
        f"https://api.github.com/repos/{quote(owner, safe='')}/{quote(repo, safe='')}"
        f"/tarball/{quote(str(ref), safe='')}"
    )


def _download_github_archive(url: str, destination: Path) -> None:
    timeout = int(getattr(settings, "git_clone_timeout", 600))
    request = Request(url, headers={"Accept": "application/vnd.github+json", "User-Agent": "AuditAgentX"})
    copied = 0
    with urlopen(request, timeout=timeout) as response, destination.open("wb") as output:  # noqa: S310 GitHub URL is constructed above.
        while chunk := response.read(1024 * 1024):
            copied += len(chunk)
            if copied > _MAX_GITHUB_ARCHIVE_BYTES:
                raise RuntimeError(f"archive exceeds {_MAX_GITHUB_ARCHIVE_BYTES} byte download limit")
            output.write(chunk)
    if copied == 0:
        raise RuntimeError("GitHub archive response was empty")


def _extract_github_archive(archive_path: Path, destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    resolved_destination = destination.resolve()
    extracted_bytes = 0
    with tarfile.open(archive_path, mode="r:*") as archive:
        for member in archive.getmembers():
            member_path = Path(member.name)
            if (member_path.is_absolute() or ".." in member_path.parts or member.issym()
                    or member.islnk() or member.isdev() or not (member.isdir() or member.isfile())):
                raise RuntimeError(f"unsafe archive member: {member.name}")
            try:
                (resolved_destination / member_path).resolve().relative_to(resolved_destination)
            except ValueError as exc:
                raise RuntimeError(f"unsafe archive path: {member.name}") from exc
            extracted_bytes += max(0, member.size)
            if extracted_bytes > _MAX_GITHUB_ARCHIVE_EXTRACTED_BYTES:
                raise RuntimeError(f"archive exceeds {_MAX_GITHUB_ARCHIVE_EXTRACTED_BYTES} byte extraction limit")
            archive.extract(member, path=destination, set_attrs=False, numeric_owner=False)


def _safe_error_text(exc: Exception) -> str:
    return " ".join(str(exc or exc.__class__.__name__).split())[:500]


def workspace_commit(path: Path) -> str | None:
    result = _run_git(["git", "-C", str(path), "rev-parse", "HEAD"])
    if result.returncode != 0:
        return None
    commit = _decode_output(result.stdout).strip()
    return commit if _FULL_COMMIT.fullmatch(commit) else None


def _run_git(args: list[str]) -> subprocess.CompletedProcess[bytes]:
    # 超大仓库（如 nextcloud）克隆很慢；无超时会让扫描挂死。加超时后，超时不抛难看的
    # traceback，而是返回一个非 0 结果（含可读原因），由现有 returncode!=0 逻辑统一转成
    # 「克隆失败」错误。已用 --depth=1 浅克隆减少体积。
    timeout = int(getattr(settings, "git_clone_timeout", 600))
    try:
        return subprocess.run(
            args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            check=False, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(
            args, returncode=124, stdout=b"",
            stderr=(f"git 操作超过 {timeout}s 超时（仓库可能过大或网络过慢；"
                    "可调大 git_clone_timeout，或改用本地目录导入）").encode("utf-8"),
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
