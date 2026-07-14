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


def runtime_is_executed_not_reproduced(runtime: dict) -> bool:
    """Keep the no-hit runtime fact separate from dynamic confirmation."""
    return bool(
        runtime.get("reproduction_status") == "not_reproduced"
        and not runtime.get("skipped")
    )


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


def canonicalize_confirmed_http_runtime(dynamic: dict | None) -> Optional[dict]:
    """Return the complete writer tuple from one DynamicVerifier confirmation.

    ``ProbeRecord`` deliberately stores the full request parameter map.  Its
    internal injection-point name is not part of that record, so a confirmed
    request with required sibling values needs an unambiguous reconstruction.
    This is fail-closed: the record must be an actual dynamic confirmation and
    exactly one recorded parameter must contain the confirmed payload.
    """
    if not isinstance(dynamic, dict) or not (
        dynamic.get("reproduction_status") == "dynamic_confirmed"
        and dynamic.get("reproducible") is True
    ):
        return None
    record = dynamic.get("confirmed_record")
    baseline = dynamic.get("baseline_record")
    binding = dynamic.get("server_binding")
    if not isinstance(record, dict) or not isinstance(baseline, dict) or not baseline:
        return None
    if not isinstance(binding, dict) or not str(binding.get("kind") or "").strip():
        return None

    params = record.get("params")
    payload = record.get("payload")
    if not isinstance(params, dict) or payload in (None, ""):
        return None
    explicit_param = record.get("param")
    if isinstance(explicit_param, str) and explicit_param in params:
        candidates = [explicit_param] if params[explicit_param] == payload else []
    else:
        candidates = [name for name, value in params.items() if value == payload]
    if len(candidates) != 1:
        return None

    response_status = record.get("status_code")
    if response_status is None:
        response_status = record.get("status")
    headers = record.get("response_headers")
    indicator = dynamic.get("matched_indicator")
    url = record.get("url")
    method = record.get("method")
    if (
        response_status is None
        or not isinstance(headers, dict)
        or not isinstance(indicator, str) or not indicator.strip()
        or not isinstance(url, str) or not url.strip()
        or not isinstance(method, str) or not method.strip()
    ):
        return None
    return {
        "request": {
            "url": url,
            "method": method,
            "param": candidates[0],
            "payload": payload,
            "params": dict(params),
            "transport": record.get("transport"),
        },
        "baseline": dict(baseline),
        "response_status": response_status,
        "response_headers": dict(headers),
        "matched_indicator": indicator,
        "server_binding": dict(binding),
    }


def build_reproduction_metadata(finding: dict, evidence: dict, *,
                                code_root: Optional[str] = None,
                                poc_sha256: Optional[str] = None) -> dict:
    """不可变复现元数据（补项 3）。全部为可核验事实，不含 LLM 自述。"""
    ev = evidence or {}
    runtime = ev.get("runtime") or {}
    harness = ev.get("harness") or {}
    ver = ev.get("verification") or {}
    req = runtime.get("request") or {}
    sandbox = ev.get("sandbox") or runtime.get("sandbox") or {}
    # harness 在 Docker 里跑过就必有一个真实镜像：优先固定沙箱镜像，未配置则记默认基础镜像
    # python:3.11-slim（即 _run_in_docker 的兜底），避免元数据把「跑过的镜像」漏成 None。
    backend_is_docker = harness.get("execution_backend") == "docker"
    image = sandbox.get("image") or (
        (settings.harness_sandbox_image or "python:3.11-slim") if backend_is_docker else None
    )
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source_commit": _git_commit(code_root),
        "sandbox_image": image,
        "sandbox_image_digest": _image_digest(image),
        "dynamic_method": ver.get("dynamic_method"),
        "poc_sha256": poc_sha256,
        "request_hash": _sha256(req) if req else None,
        "response_hash": (_sha256(runtime.get("response_excerpt"))
                          if runtime.get("response_excerpt") else None),
        "runtime_reproduction_status": runtime.get("reproduction_status"),
        "harness_verification_level": harness.get("verification_level"),
        "reproduction_code_sha256": _sha256(
            (ev.get("exploit") or {}).get("exploit_code")
            or (ev.get("harness") or {}).get("harness_code")
            or ""
        ),
        "persistence_status": "persisted",
    }


def generate_poc_file(finding: dict, evidence: dict, out_dir: Path,
                      *, code_root: Optional[str] = None) -> Optional[dict]:
    """仅对**真实动态确认**的 finding 生成专属 PoC 文件（补项 1）。

    返回 {"path", "sha256", "reproduction_metadata"} 或 None（未达真实动态确认）。
    """
    ev = evidence or {}
    ver = ev.get("verification") or {}
    method = ver.get("dynamic_method") or "dynamic"
    executed_without_hit = (
        method == "http_executed_not_reproduced"
        and runtime_is_executed_not_reproduced(ev.get("runtime") or {})
    )
    # A completed no-hit HTTP request can be retained as an explicitly labeled
    # replay artifact.  It is not a dynamic confirmation and must not claim one.
    if not ((ver.get("dynamically_verified") or executed_without_hit)
            and finding.get("status") == "confirmed" and finding.get("verified") is True):
        return None
    runtime = ev.get("runtime") or {}
    exploit = ev.get("exploit") or {}
    harness = ev.get("harness") or {}
    req = runtime.get("request") or {}

    # Candidate, synthetic, failed and blocked results may retain diagnostic
    # metadata, but never receive a formal executable artifact.  HTTP evidence
    # must include a request/baseline/response/binding tuple; target harnesses
    # must retain their framework-derived entrypoint proof.
    if method == "http_dynamic":
        required = (
            runtime.get("reproduction_status") == "dynamic_confirmed",
            all(req.get(key) not in (None, "") for key in ("url", "method", "param", "payload")),
            isinstance(req.get("params"), dict),
            req.get("param") in req.get("params", {}),
            req.get("params", {}).get(req.get("param")) == req.get("payload"),
            isinstance(runtime.get("baseline"), dict) and bool(runtime.get("baseline")),
            runtime.get("response_status") is not None,
            isinstance(runtime.get("response_headers"), dict),
            isinstance(runtime.get("matched_indicator"), str) and bool(runtime.get("matched_indicator").strip()),
            isinstance(runtime.get("server_binding"), dict)
            and bool(str(runtime.get("server_binding", {}).get("kind") or "").strip()),
        )
        if not all(required):
            return None
    elif method == "http_executed_not_reproduced":
        required = (
            runtime.get("reproduction_status") == "not_reproduced",
            not runtime.get("skipped"),
            all(req.get(key) not in (None, "") for key in ("url", "method", "param", "payload")),
            isinstance(req.get("params"), dict),
            req.get("param") in req.get("params", {}),
            req.get("params", {}).get(req.get("param")) == req.get("payload"),
            runtime.get("response_status") is not None,
            isinstance(runtime.get("response_headers"), dict),
            isinstance(runtime.get("server_binding"), dict)
            and bool(str(runtime.get("server_binding", {}).get("kind") or "").strip()),
        )
        if not all(required):
            return None
    elif method == "target_harness":
        if not (harness.get("verdict") == "target_confirmed"
                and harness.get("target_function_called") is True
                and harness.get("entrypoint_reachable") is True
                and harness.get("verification_level") == "entrypoint_reproduced"):
            return None
    else:
        return None

    fid = finding.get("finding_id") or finding.get("id") or "finding"
    vtype = finding.get("type") or "Vulnerability"
    loc = f"{finding.get('file')}:{finding.get('start_line') or finding.get('line')}"
    url = req.get("url") or ""
    http_method = (req.get("method") or exploit.get("http_method") or "GET").upper()
    param = req.get("param") or (exploit.get("_injection_points") or [""])[0]
    if not isinstance(param, str):  # 注入点可能是 dict/对象，PoC 表格需可读字符串
        param = param.get("param") if isinstance(param, dict) else str(param)
    payload = _sanitize(runtime.get("matched_payload") or req.get("payload")
                        or (exploit.get("payloads") or [""])[0])
    indicator = runtime.get("matched_indicator") or harness.get("trigger_detail") or ""
    route = harness.get("route") or ""
    exploit_code = _sanitize(exploit.get("exploit_code") or "")

    # 运行命令：HTTP 用 curl（本地授权目标）；入口级 harness 说明经框架 test-client 复现
    if method == "http_dynamic" and url:
        if runtime.get("setup_records") and exploit_code:
            run_cmd = ("AAX_TARGET_URL='<重新启动后的本地靶场 URL>' "
                       "AAX_SETUP_PASSWORD='<授权测试凭据>' python exploit.py")
            repro = "将下方精确利用代码保存为 `exploit.py`，设置授权测试凭据后运行；代码会先建立会话再重放已确认请求。"
        else:
            run_cmd = f"curl -x '' -sS '{_sanitize(url)}'" if http_method == "GET" else \
                      f"curl -x '' -sS -X {http_method} --data '{param}={payload}' '{_sanitize(url)}'"
            repro = "对**本地授权**目标发送上述请求，响应中出现成功判据即复现。"
    else:
        run_cmd = ("# 入口级 Harness 复现：框架在受控 Docker 沙箱内经 test-client 调用真实路由 "
                   f"{route or '(见证据链)'}，用户输入送达危险 sink（{harness.get('sink_name') or ''}）。")
        repro = "由框架固定沙箱镜像内的 test-client 真实调用真实路由 handler 复现，见复现元数据。"

    outcome_label = (
        "已执行但未命中成功判据（not_reproduced）；不声明漏洞命中"
        if executed_without_hit else "框架侧动态确认"
    )
    evidence_heading = "执行记录（未命中）" if executed_without_hit else "确认证据"
    code_heading = "已执行请求复放代码（未命中）" if executed_without_hit else "精确利用代码"
    md = (
        f"# {'Executed replay (not reproduced)' if executed_without_hit else 'PoC'} — {vtype}\n\n"
        f"> 仅供**本地授权靶场/沙箱**验证。所有动态操作默认仅限 localhost/127.0.0.1。\n\n"
        f"| 项 | 值 |\n|---|---|\n"
        f"| 漏洞类型 | {vtype} |\n"
        f"| 代码位置 | `{loc}` |\n"
        f"| 确认方式 | {method} |\n"
        f"| 路由/URL | `{_sanitize(url or route) or 'N/A'}` |\n"
        f"| HTTP 方法 | {http_method} |\n"
        f"| 参数位置 | `{param or 'N/A'}` |\n"
        f"| Payload | `{payload or 'N/A'}` |\n"
        f"| 观察结果 | {outcome_label} |\n"
        f"| 成功判据 | {_sanitize(indicator) or '未命中'} |\n\n"
        f"## {evidence_heading}\n\n"
        f"- 服务端绑定：`{_sanitize(json.dumps(runtime.get('server_binding') or {}, ensure_ascii=False, sort_keys=True))}`\n"
        f"- 基线响应：`{_sanitize(json.dumps(runtime.get('baseline') or {}, ensure_ascii=False, sort_keys=True))}`\n"
        f"- 攻击响应状态：`{runtime.get('response_status')}`\n"
        f"- 响应头：`{_sanitize(json.dumps(runtime.get('response_headers') or {}, ensure_ascii=False, sort_keys=True))}`\n"
        f"- 完整参数：`{_sanitize(json.dumps(req.get('params') or {}, ensure_ascii=False, sort_keys=True))}`\n\n"
        f"## 运行命令\n\n```bash\n{run_cmd}\n```\n\n"
        f"## 复现说明\n\n{repro}\n\n"
        + (f"## {code_heading}\n\n```python\n{exploit_code}\n```\n\n" if exploit_code else "")
        + (
            "## 脱敏环境说明\n\n"
            "- 目标必须是本地授权靶场；`target_guard` 默认仅放行 localhost/回环。\n"
            "- HTTP 客户端 `trust_env=False`，忽略系统代理变量。\n"
            "- 敏感字段（密钥/token/cookie 等）已脱敏。\n"
        )
    )

    poc_sha = _sha256(md)
    meta = build_reproduction_metadata(finding, ev, code_root=code_root, poc_sha256=poc_sha)
    md += f"\n## 不可变复现元数据\n\n```json\n{json.dumps(meta, ensure_ascii=False, indent=2)}\n```\n"
    poc_sha = _sha256(md)  # 含元数据后的最终 hash

    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    fp = out_dir / f"{re.sub(r'[^A-Za-z0-9_.-]', '_', str(fid))}.md"
    # Hashes are over UTF-8 bytes.  ``write_text`` may translate newlines on
    # Windows after the hash is calculated, producing a different on-disk file.
    fp.write_bytes(md.encode("utf-8"))
    return {"path": str(fp), "sha256": poc_sha, "reproduction_metadata": meta}


def generate_function_forensic_poc(finding: dict, evidence: dict, out_dir: Path,
                                   *, code_root: Optional[str] = None) -> Optional[dict]:
    """Write an attested function-level artifact without claiming endpoint exploitability."""
    ev = evidence or {}
    harness = ev.get("harness") or {}
    attestation = harness.get("nonce_attestation") or {}
    if not (
        harness.get("verdict") == "function_reproduced"
        and harness.get("harness_source") == "scaffold"
        and harness.get("target_function_called") is True
        and harness.get("verification_level") == "target_specific"
        and harness.get("execution_backend") == "docker"
        and attestation.get("marker_observed") is True
        and re.fullmatch(r"[0-9a-f]{64}", str(attestation.get("digest") or ""))
    ):
        return None

    fid = finding.get("finding_id") or finding.get("id") or "finding"
    vtype = finding.get("type") or "Vulnerability"
    location = dict(harness.get("function_location") or {})
    location.setdefault("file", finding.get("file"))
    location.setdefault("start_line", finding.get("start_line") or finding.get("line"))
    location.setdefault("end_line", finding.get("end_line") or location.get("start_line"))
    location.setdefault("function_name", harness.get("function_name"))
    image = harness.get("sandbox_image") or settings.harness_sandbox_image or "python:3.11-slim"
    harness_code = _sanitize(harness.get("harness_code") or "")
    harness_hash = harness.get("harness_code_sha256") or (_sha256(harness_code) if harness_code else None)
    metadata = {
        "artifact_kind": "function_forensic_reproduction",
        "label": "函数级复现(非端到端)",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source_commit": _git_commit(code_root),
        "function_location": location,
        "harness_kind": harness.get("harness_kind"),
        "verification_level": harness.get("verification_level"),
        "sandbox_image": image,
        "sandbox_image_digest": _image_digest(image),
        "nonce_attestation": attestation,
        "function_code_sha256": harness.get("function_code_sha256"),
        "harness_code_sha256": harness_hash,
    }
    md = (
        f"# 函数级复现(非端到端) — {vtype}\n\n"
        "> 此产物只证明攻击输入在隔离切片/Harness 中调用了真实目标函数并到达目标 sink；"
        "不声明 HTTP、CLI、消息队列或其他真实入口可达，也不作为入口级利用 PoC。\n\n"
        "| 项 | 值 |\n|---|---|\n"
        f"| 函数位置 | `{location.get('file')}:{location.get('start_line')}` |\n"
        f"| 函数名称 | `{location.get('function_name') or 'N/A'}` |\n"
        f"| 切片/Harness 类型 | `{harness.get('harness_kind') or 'N/A'}` |\n"
        f"| 沙箱镜像 | `{image}` |\n"
        f"| Sink | `{harness.get('sink_name') or 'N/A'}` |\n"
        f"| 捕获参数 | `{_sanitize(harness.get('captured_argument')) or 'N/A'}` |\n"
        f"| Payload | `{_sanitize(harness.get('payload')) or 'N/A'}` |\n"
        f"| Nonce 摘要 | `{attestation.get('digest')}` |\n\n"
        "## 取证 Harness\n\n"
        + "函数级 Harness 源码不作为可复制制品导出；仅保存 Harness 源码哈希、类型与取证元数据。\n\n"
        + f"## 复现元数据\n\n```json\n{json.dumps(metadata, ensure_ascii=False, indent=2)}\n```\n"
    )
    final_hash = _sha256(md)
    metadata["poc_sha256"] = final_hash
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    safe_id = re.sub(r"[^A-Za-z0-9_.-]", "_", str(fid))
    fp = out_dir / f"{safe_id}.function-forensic.md"
    fp.write_text(md, encoding="utf-8")
    return {"path": str(fp), "sha256": final_hash, "reproduction_metadata": metadata}
