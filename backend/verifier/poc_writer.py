"""PoC 文件生成 + 不可变复现元数据（对应作业补项 1 与 3）。

原则：
- **仅在真实动态确认后**（HTTP 真实复现 http_dynamic 或 入口级 target_harness）才生成 PoC 文件，
  绝不为未确认/机理级/自报成功生成"看起来成功"的 PoC。
- PoC 内容全部来自框架侧真实确认记录（路径、方法、参数位置、payload、成功判据、运行命令），
  并附脱敏环境说明（仅本地授权目标）。
- 复现元数据是**不可变证据**：源码 commit、沙箱镜像摘要、执行时间、PoC 文件 hash、
  请求/响应 hash——让报告像可审计的漏洞证据，而不只是 Agent 的自然语言描述。
"""
from __future__ import annotations

import hashlib
import json
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from backend.config import settings

# 敏感 键=值（值取到常见分隔符/行尾，兼容含空格的 "Bearer xxx"）
_SENSITIVE = re.compile(
    r"(password|passwd|secret|secret_key|api[_-]?key|token|authorization|cookie)"
    r"\s*[=:]\s*[^&;,\"'\n]+", re.IGNORECASE)
_BEARER = re.compile(r"[Bb]earer\s+[A-Za-z0-9._\-]+")
_APIKEY = re.compile(r"\bsk-[A-Za-z0-9]{4,}")


def _sanitize(text: Any) -> str:
    s = "" if text is None else str(text)
    s = _SENSITIVE.sub(lambda m: f"{m.group(1)}=<REDACTED>", s)
    s = _BEARER.sub("Bearer <REDACTED>", s)
    s = _APIKEY.sub("<REDACTED>", s)
    return s


def _sha256(data: Any) -> str:
    if isinstance(data, (dict, list)):
        data = json.dumps(data, ensure_ascii=False, sort_keys=True, default=str)
    return hashlib.sha256(str(data).encode("utf-8", "ignore")).hexdigest()


def _git_commit(code_root: Optional[str]) -> Optional[str]:
    if not code_root or not Path(code_root).exists():
        return None
    try:
        out = subprocess.run(["git", "-C", str(code_root), "rev-parse", "HEAD"],
                             capture_output=True, text=True, timeout=8)
        commit = (out.stdout or "").strip()
        return commit or None
    except Exception:  # noqa: BLE001  非 git 仓库/无 git 都不致命
        return None


def _image_digest(image: Optional[str]) -> Optional[str]:
    if not image:
        return None
    try:
        from backend.verifier.app_runner import get_docker_client
        img = get_docker_client().images.get(image)
        digests = getattr(img, "attrs", {}).get("RepoDigests") or []
        return digests[0] if digests else getattr(img, "id", None)
    except Exception:  # noqa: BLE001
        return image  # 至少记下镜像名


def build_reproduction_metadata(finding: dict, evidence: dict, *,
                                code_root: Optional[str] = None,
                                poc_sha256: Optional[str] = None) -> dict:
    """不可变复现元数据（补项 3）。全部为可核验事实，不含 LLM 自述。"""
    ev = evidence or {}
    runtime = ev.get("runtime") or {}
    harness = ev.get("harness") or {}
    ver = ev.get("verification") or {}
    req = runtime.get("request") or {}
    image = (harness.get("execution_backend") == "docker" and
             (settings.harness_sandbox_image or None)) or None
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source_commit": _git_commit(code_root),
        "sandbox_image": settings.harness_sandbox_image or None,
        "sandbox_image_digest": _image_digest(image),
        "dynamic_method": ver.get("dynamic_method"),
        "poc_sha256": poc_sha256,
        "request_hash": _sha256(req) if req else None,
        "response_hash": (_sha256(runtime.get("response_excerpt"))
                          if runtime.get("response_excerpt") else None),
        "runtime_reproduction_status": runtime.get("reproduction_status"),
        "harness_verification_level": harness.get("verification_level"),
    }


def generate_poc_file(finding: dict, evidence: dict, out_dir: Path,
                      *, code_root: Optional[str] = None) -> Optional[dict]:
    """仅对**真实动态确认**的 finding 生成专属 PoC 文件（补项 1）。

    返回 {"path", "sha256", "reproduction_metadata"} 或 None（未达真实动态确认）。
    """
    ev = evidence or {}
    ver = ev.get("verification") or {}
    # 硬门槛：只有框架侧动态确认（HTTP 真实复现 / 入口级 harness）才生成 PoC
    if not ver.get("dynamically_verified"):
        return None
    method = ver.get("dynamic_method") or "dynamic"
    runtime = ev.get("runtime") or {}
    exploit = ev.get("exploit") or {}
    harness = ev.get("harness") or {}
    req = runtime.get("request") or {}

    fid = finding.get("finding_id") or finding.get("id") or "finding"
    vtype = finding.get("type") or "Vulnerability"
    loc = f"{finding.get('file')}:{finding.get('start_line') or finding.get('line')}"
    url = req.get("url") or ""
    http_method = (req.get("method") or exploit.get("http_method") or "GET").upper()
    param = req.get("param") or (exploit.get("_injection_points") or [""])[0]
    payload = _sanitize(runtime.get("matched_payload") or req.get("payload")
                        or (exploit.get("payloads") or [""])[0])
    indicator = runtime.get("matched_indicator") or harness.get("trigger_detail") or ""
    route = harness.get("route") or ""

    # 运行命令：HTTP 用 curl（本地授权目标）；入口级 harness 说明经框架 test-client 复现
    if method == "http_dynamic" and url:
        run_cmd = f"curl -x '' -sS '{_sanitize(url)}'" if http_method == "GET" else \
                  f"curl -x '' -sS -X POST --data '{param}={payload}' '{_sanitize(url)}'"
        repro = "对**本地授权**目标发送上述请求，响应中出现成功判据即复现。"
    else:
        run_cmd = ("# 入口级 Harness 复现：框架在受控 Docker 沙箱内经 test-client 调用真实路由 "
                   f"{route or '(见证据链)'}，用户输入送达危险 sink（{harness.get('sink_name') or ''}）。")
        repro = "由框架固定沙箱镜像内的 test-client 真实调用真实路由 handler 复现，见复现元数据。"

    md = (
        f"# PoC — {vtype}\n\n"
        f"> 仅供**本地授权靶场/沙箱**验证。所有动态操作默认仅限 localhost/127.0.0.1。\n\n"
        f"| 项 | 值 |\n|---|---|\n"
        f"| 漏洞类型 | {vtype} |\n"
        f"| 代码位置 | `{loc}` |\n"
        f"| 确认方式 | {method} |\n"
        f"| 路由/URL | `{_sanitize(url or route) or 'N/A'}` |\n"
        f"| HTTP 方法 | {http_method} |\n"
        f"| 参数位置 | `{param or 'N/A'}` |\n"
        f"| Payload | `{payload or 'N/A'}` |\n"
        f"| 成功判据 | {_sanitize(indicator) or 'N/A'} |\n\n"
        f"## 运行命令\n\n```bash\n{run_cmd}\n```\n\n"
        f"## 复现说明\n\n{repro}\n\n"
        f"## 脱敏环境说明\n\n"
        f"- 目标必须是本地授权靶场；`target_guard` 默认仅放行 localhost/回环。\n"
        f"- HTTP 客户端 `trust_env=False`，忽略系统代理变量。\n"
        f"- 敏感字段（密钥/token/cookie 等）已脱敏。\n"
    )

    poc_sha = _sha256(md)
    meta = build_reproduction_metadata(finding, ev, code_root=code_root, poc_sha256=poc_sha)
    md += f"\n## 不可变复现元数据\n\n```json\n{json.dumps(meta, ensure_ascii=False, indent=2)}\n```\n"
    poc_sha = _sha256(md)  # 含元数据后的最终 hash

    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    fp = out_dir / f"{re.sub(r'[^A-Za-z0-9_.-]', '_', str(fid))}.md"
    fp.write_text(md, encoding="utf-8")
    return {"path": str(fp), "sha256": poc_sha, "reproduction_metadata": meta}
