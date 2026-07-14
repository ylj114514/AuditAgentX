"""Local tools used by VerifyAgent.

These helpers make the verifier more than a pure LLM prompt: the agent can read
nearby source code and run deterministic checks before making a final decision.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from backend.verifier.context_classifier import classify_finding_context
from backend.scanners.base import plausible_secret_assignment


RUNTIME_VULN_KEYWORDS = ("sql", "command", "rce", "path", "traversal", "ssrf", "ssti", "upload")
STATIC_ASSET_PARTS = {
    "static", "assets", "asset", "public", "dist", "build", "vendor",
    "node_modules", "third-party", "third_party", "layui", "ueditor", "dplayer",
}
STATIC_ASSET_SUFFIXES = (".min.js", ".bundle.js", ".chunk.js", ".map")


def build_verification_context(
    candidate: dict[str, Any],
    code_root: Path | None,
    *,
    radius: int = 8,
) -> dict[str, Any]:
    context = {
        "mcp_skill_style": True,
        "tool_manifest": [
            {
                "name": "code_context_reader",
                "description": "Read nearby source code around a candidate finding.",
                "input_schema": {"file": "string", "line": "integer", "radius": "integer"},
            },
            {
                "name": "heuristic_static_verifier",
                "description": "Run deterministic source-to-sink and false-positive checks.",
                "input_schema": {"candidate": "object", "code_context": "object"},
            },
            {
                "name": "local_sast_replay",
                "description": "Replay lightweight SAST checks on the local code window.",
                "input_schema": {"snippet": "string", "vulnerability_type": "string"},
            },
        ],
        "tools_used": [],
        "code_context": read_code_context(candidate, code_root, radius=radius),
    }
    context["tools_used"].append({
        "name": "code_context_reader",
        "purpose": "Read source lines around the candidate finding.",
        "success": bool(context["code_context"].get("found")),
    })
    context["context_classification"] = classify_finding_context(
        candidate, context["code_context"].get("snippet"))
    heuristic = run_heuristic_static_verifier(
        candidate, context["code_context"],
        source_route_surfaces=_fresh_source_route_surfaces(candidate, code_root),
    )
    context["heuristic_result"] = heuristic
    context["tools_used"].append({
        "name": "heuristic_static_verifier",
        "purpose": "Check common source-to-sink and false-positive patterns.",
        "success": True,
    })
    sast_replay = run_local_sast_replay(candidate, context["code_context"])
    context["sast_replay"] = sast_replay
    context["tools_used"].append({
        "name": "local_sast_replay",
        "purpose": "Replay lightweight SAST checks on the candidate code window.",
        "success": True,
        "matched_rules": [rule["rule_id"] for rule in sast_replay.get("matched_rules", [])],
    })
    return context


def read_code_context(candidate: dict[str, Any], code_root: Path | None, *, radius: int = 8) -> dict[str, Any]:
    """Public MCP tool implementation for reading nearby source code."""
    return _read_code_context(candidate, code_root, radius=radius)


def run_heuristic_static_verifier(candidate: dict[str, Any], code_context: dict[str, Any], *,
                                  source_route_surfaces: list[dict] | None = None) -> dict[str, Any]:
    """Public MCP tool implementation for source-to-sink and false-positive checks."""
    result = _run_heuristic_verifier(candidate, code_context)
    return _apply_source_route_proof(result, source_route_surfaces)


def run_local_sast_replay(candidate: dict[str, Any], code_context: dict[str, Any]) -> dict[str, Any]:
    """Public MCP tool implementation for deterministic local SAST replay."""
    return _local_sast_replay(candidate, code_context)


def fresh_source_route_surfaces(candidate: dict[str, Any], code_root: Path | None) -> list[dict]:
    """Derive current-code route→sink capabilities for static verification.

    The returned surfaces are private server-minted objects, not persisted route
    claims.  Callers must still validate their capability before treating the
    accompanying proof as attacker-control evidence.
    """
    return _fresh_source_route_surfaces(candidate, code_root)


def _fresh_source_route_surfaces(candidate: dict[str, Any], code_root: Path | None) -> list[dict]:
    if code_root is None:
        return []
    try:
        from backend.dynamic.endpoint_extractor import candidate_attack_surfaces
        from backend.verifier.pipeline import _proven_surfaces_for_finding

        root = Path(code_root).resolve()
        return _proven_surfaces_for_finding(
            candidate, candidate_attack_surfaces(root), root,
        )
    except (OSError, ValueError):
        return []


def _apply_source_route_proof(result: dict[str, Any], surfaces: list[dict] | None) -> dict[str, Any]:
    """Promote an inconclusive parameter origin only with a fresh server proof."""
    from backend.dynamic.source_route_binding import is_server_bound_surface

    proofs = []
    for surface in surfaces or []:
        if not is_server_bound_surface(surface):
            continue
        proof = surface.get("source_route_binding") or {}
        if isinstance(proof, dict) and proof.get("kind") == "source_route_sink":
            proofs.append(dict(proof))
    if not proofs:
        return result

    merged = dict(result)
    merged["source_route_sink_proofs"] = proofs
    merged["source_route_sink_proven"] = True
    merged["checks"] = [
        *(merged.get("checks") or []),
        {
            "name": "server_bound_route_parameter_reaches_sink",
            "passed": True,
            "parameters": sorted({str(proof.get("source_parameter") or "") for proof in proofs}),
        },
    ]
    # A definitive safe pattern remains a false positive.  This proof establishes
    # attacker control, not vulnerability semantics independent of the sink check.
    if merged.get("is_valid") is not None:
        return merged

    parameters = sorted({str(proof.get("source_parameter") or "") for proof in proofs if proof.get("source_parameter")})
    parameter_label = ", ".join(parameters)
    merged.update({
        "is_valid": True,
        "confidence": max(float(merged.get("confidence") or 0.0), 0.8),
        "source": f"OpenAPI/route parameter: {parameter_label}",
        "sink": merged.get("sink") or "candidate sink reached by server-bound route parameter",
        "propagation_path": [
            *(merged.get("propagation_path") or []),
            f"mapped route parameter ({parameter_label})",
            "server-proven route→handler→sink flow",
        ],
        "deterministic_flow": True,
        "evidence_strength": "server_route_sink",
        "verification_level": "local_static_verified",
    })
    return merged


def _read_code_context(candidate: dict[str, Any], code_root: Path | None, *, radius: int) -> dict[str, Any]:
    rel_file = candidate.get("file") or candidate.get("file_path")
    line = _to_int(candidate.get("start_line") or candidate.get("line")) or 1
    fallback = candidate.get("code_snippet") or candidate.get("vulnerable_code") or ""
    if not code_root or not rel_file:
        return {
            "found": False,
            "file": rel_file,
            "line": line,
            "snippet": fallback,
            "reason": "code_root_or_file_missing",
        }

    root = code_root.resolve()
    target = (root / str(rel_file)).resolve()
    try:
        target.relative_to(root)
    except ValueError:
        return {
            "found": False,
            "file": rel_file,
            "line": line,
            "snippet": fallback,
            "reason": "candidate_file_outside_workspace",
        }
    if not target.exists() or not target.is_file():
        return {
            "found": False,
            "file": rel_file,
            "line": line,
            "snippet": fallback,
            "reason": "candidate_file_not_found",
        }

    lines = target.read_text(encoding="utf-8", errors="ignore").splitlines()
    start = max(1, line - radius)
    end = min(len(lines), line + radius)
    numbered = [
        {"line": idx, "code": lines[idx - 1]}
        for idx in range(start, end + 1)
    ]
    return {
        "found": True,
        "file": rel_file,
        "line": line,
        "start_line": start,
        "end_line": end,
        "lines": numbered,
        "snippet": "\n".join(f"{row['line']}: {row['code']}" for row in numbered),
    }


def _run_heuristic_verifier(candidate: dict[str, Any], code_context: dict[str, Any]) -> dict[str, Any]:
    vuln_type = _canonical_vuln_text(candidate)
    context = classify_finding_context(candidate, code_context.get("snippet"))
    if not context.get("allow_confirmed", True) and context.get("risk_modifier") == "false_positive":
        return _with_call_path({
            "is_valid": False,
            "confidence": 0.9,
            "checks": [{"name": "context_false_positive", "passed": True, "context": context.get("context")}],
            "false_positive_reason": context.get("reason"),
            "context": context.get("context"),
            "risk_modifier": context.get("risk_modifier"),
            "allow_confirmed": False,
            "confirmed_blockers": context.get("confirmed_blockers") or [],
            "runtime_verification_status": "not_runtime_verifiable",
            "recommended_poc_strategy": "Do not run dynamic verification unless a browser/HTTP sink is identified.",
        }, candidate, code_context)

    asset_fp = _static_asset_false_positive(candidate, vuln_type)
    if asset_fp:
        return _with_call_path(asset_fp, candidate, code_context)

    iac_result = _verify_iac_misconfiguration(candidate, code_context)
    if iac_result:
        return _with_context(_with_call_path(iac_result, candidate, code_context), context)

    text = "\n".join([
        str(candidate.get("code_snippet") or candidate.get("vulnerable_code") or ""),
        str(code_context.get("snippet") or ""),
    ])
    lowered = text.lower()
    checks: list[dict[str, Any]] = []

    if "sql injection" in vuln_type and "nosql" not in vuln_type:
        return _with_context(_with_call_path(_verify_sql(lowered, checks), candidate, code_context), context)
    if "command" in vuln_type or "rce" in vuln_type:
        return _with_context(_with_call_path(_verify_command(lowered, checks), candidate, code_context), context)
    if "path" in vuln_type or "traversal" in vuln_type:
        return _with_context(_with_call_path(_verify_path_traversal(lowered, checks), candidate, code_context), context)
    if "secret" in vuln_type or "credential" in vuln_type or "key" in vuln_type:
        finding_line = _to_int(candidate.get("start_line") or candidate.get("line"))
        exact_line = next(
            (str(row.get("code") or "") for row in (code_context.get("lines") or [])
             if _to_int(row.get("line")) == finding_line),
            str(candidate.get("code_snippet") or candidate.get("vulnerable_code") or ""),
        )
        return _with_context(
            _with_call_path(_verify_secret(exact_line, checks), candidate, code_context), context
        )
    if "tls verification disabled" in vuln_type or ("tls" in vuln_type and "verification" in vuln_type):
        return _with_context(_with_call_path(_verify_tls_disabled(lowered, checks), candidate, code_context), context)

    # 确定性缺陷（存在即漏洞，无需污点源）——本该高置信确认，绝不塞人工
    if "random" in vuln_type or "prng" in vuln_type or "weakrand" in vuln_type:
        return _with_context(_with_call_path(_verify_weak_random(lowered, checks), candidate, code_context), context)
    if ("crypto" in vuln_type or "cipher" in vuln_type or "ecb" in vuln_type or "cbc" in vuln_type
            or ("hash" in vuln_type and ("weak" in vuln_type or "insecure" in vuln_type or "md5" in vuln_type or "sha1" in vuln_type))):
        return _with_context(_with_call_path(_verify_weak_crypto(lowered, checks), candidate, code_context), context)

    # 注入类：补齐 SQL/命令/路径 之外的常见类型（此前全部落 needs_review）
    _INJ = {
        "xss": (r"innerhtml|document\.write|\.write\s*\(|(?<!//\s)echo\s|render_template_string|response\.(write|getwriter)|out\.print|\|\s*safe\b|<[a-z][a-z0-9]*[\s/>]",
                "HTML/JS 输出 sink", r"escape|htmlspecialchars|bleach|markupsafe|sanitize|\|\s*e\b", "xss"),
        "ssti": (r"render_template_string|template\s*\(|from_string\s*\(|env\.from_string", "模板引擎渲染 sink", r"", "ssti"),
        "deserial": (r"pickle\.loads|cpickle\.loads|yaml\.load\s*\(|marshal\.loads|jsonpickle|__reduce__|unserialize\s*\(", "反序列化 sink", r"safeloader|safe_load|yaml\.safe_load", "deserialization"),
        "pickle": (r"pickle\.loads|cpickle\.loads|marshal\.loads", "反序列化 sink", r"", "deserialization"),
        "ssrf": (r"requests\.(get|post|put|head|delete|request)|urlopen|urllib\.request|httpx\.(get|post|client)|http\.client|\bfetch\s*\(", "出站请求 sink", r"", "ssrf"),
        "code injection": (r"\beval\s*\(|\bexec\s*\(|compile\s*\(|__import__\s*\(", "动态代码执行 sink", r"", "code_injection"),
        "ldap": (r"\.search\s*\(|dircontext|initialdircontext", "LDAP 查询 sink", r"", "ldap"),
        "xpath": (r"xpath|\.evaluate\s*\(|xpathexpression|newxpath", "XPath 表达式 sink", r"", "xpath"),
        "open redirect": (r"redirect\s*\(|sendredirect|header\s*\(\s*['\"]location|location\s*=", "重定向 sink", r"url_has_allowed_host|is_safe_url|allowlist|whitelist", "open_redirect"),
        "xxe": (r"etree|xml\.dom|sax|documentbuilder|parsexml|lxml", "XML 解析 sink", r"resolve_entities\s*=\s*false|no_network|forbid_dtd", "xxe"),
    }
    for key, (sink_rx, label, san_rx, vuln) in _INJ.items():
        if key in vuln_type:
            if vuln == "deserialization":
                return _with_context(_with_call_path(
                    _verify_insecure_deserialization(lowered, checks), candidate, code_context), context)
            return _with_context(_with_call_path(
                _verify_generic_injection(lowered, checks, sink_rx=sink_rx, sink_label=label,
                                          sanitizer_rx=san_rx, vuln=vuln), candidate, code_context), context)

    checks.append({"name": "generic_context_present", "passed": bool(text.strip())})
    return _with_context(_with_call_path({
        "is_valid": None,
        "confidence": 0.55,
        "checks": checks,
        "reason": "No type-specific local verifier matched this finding.",
        "runtime_verification_status": "not_runtime_verifiable",
    }, candidate, code_context), context)


def _local_sast_replay(candidate: dict[str, Any], code_context: dict[str, Any]) -> dict[str, Any]:
    vuln_type = _canonical_vuln_text(candidate)
    text = "\n".join([
        str(candidate.get("code_snippet") or candidate.get("vulnerable_code") or ""),
        str(code_context.get("snippet") or ""),
    ])
    rules = []
    rule_specs = [
        ("sqli-string-concat", "SQL Injection", r"(execute|query|cursor\.execute)\s*\(.*?(\+|f['\"]|format\s*\()"),
        ("command-dynamic-exec", "Command Injection", r"(os\.system|subprocess\.(run|call|popen)|exec|eval)\s*\(.*?(\+|shell\s*=\s*true|f['\"]|format\s*\()"),
        ("path-user-file-read", "Path Traversal", r"(open|readfile|file_get_contents|include|require)\s*\(.*?(request|_GET|_POST|params|args\.get|input)"),
        ("hardcoded-secret-literal", "Hardcoded Secret", r"(password|passwd|secret|api[_-]?key|token|access[_-]?key)\s*[=:]\s*['\"][^'\"]{6,}['\"]"),
    ]
    for rule_id, rule_type, pattern in rule_specs:
        if rule_type.lower() in vuln_type.lower() or not vuln_type:
            if re.search(pattern, text, re.I | re.S):
                rules.append({"rule_id": rule_id, "type": rule_type, "matched": True})
    if "sql" in vuln_type.lower() and not any(rule["type"] == "SQL Injection" for rule in rules):
        built_query_var = re.search(
            r"(?P<var>[a-zA-Z_][\w]*)\s*=\s*[^\n]*(select|insert|update|delete)[^\n]*(\+|f['\"]|format\s*\()",
            text,
            re.I,
        )
        if built_query_var and re.search(rf"\bexecute\s*\(\s*{re.escape(built_query_var.group('var'))}\s*\)", text, re.I):
            rules.append({
                "rule_id": "sqli-built-query-variable",
                "type": "SQL Injection",
                "matched": True,
                "detail": "SQL query is built dynamically and later passed to execute().",
            })
    return {"matched_rules": rules, "snippet_available": bool(text.strip())}


def _canonical_vuln_text(candidate: dict[str, Any]) -> str:
    parts = [
        candidate.get("type"), candidate.get("vulnerability_type"), candidate.get("rule_id"),
        candidate.get("message"), candidate.get("cwe_id"), candidate.get("cwe"),
    ]
    extra = candidate.get("extra") or {}
    parts.extend([extra.get("rule_id"), extra.get("cwe"), extra.get("message")])
    text = " ".join(str(part) for part in parts if part).lower().replace("_", "-")
    aliases = [
        (("cwe-89",), "sql injection"), (("b608",), "sql injection"),
        (("sql", "inject"), "sql injection"), (("raw-query",), "sql injection"),
        (("cwe-78",), "command injection"), (("b602",), "command injection"),
        (("b604",), "command injection"), (("b605",), "command injection"),
        (("shell", "inject"), "command injection"), (("subprocess",), "command injection"),
        (("command", "inject"), "command injection"),
        (("cwe-22",), "path traversal"), (("path", "travers"), "path traversal"),
        (("directory", "travers"), "path traversal"),
        (("cwe-79",), "xss"), (("cross-site", "script"), "xss"), (("xss",), "xss"),
        (("cwe-918",), "ssrf"), (("server-side", "request"), "ssrf"), (("ssrf",), "ssrf"),
        (("cwe-798",), "hardcoded secret"), (("hardcoded", "secret"), "hardcoded secret"),
        (("password",), "hardcoded secret"), (("api-key",), "hardcoded secret"),
        (("b105",), "hardcoded secret"), (("b106",), "hardcoded secret"), (("b107",), "hardcoded secret"),
        (("deserial",), "insecure deserialization"), (("b301",), "insecure deserialization"),
        (("b302",), "insecure deserialization"), (("b506",), "insecure deserialization"),
        (("open", "redirect"), "open redirect"), (("template", "inject"), "ssti"),
        (("weak", "random"), "weak randomness"), (("b311",), "weak randomness"),
        (("blacklist", "pseudo-random"), "weak randomness"), (("weak", "crypto"), "weak cryptography"),
        (("md5",), "weak hash"), (("sha1",), "weak hash"), (("jwt", "none"), "jwt none"),
        (("jwt", "verification", "disabled"), "tls verification disabled"),
        (("jwt", "verify", "false"), "tls verification disabled"),
        (("tls", "verify", "false"), "tls verification disabled"),
        (("certificate", "validation", "disabled"), "tls verification disabled"),
    ]
    for terms, canonical in aliases:
        if all(term in text for term in terms):
            return canonical
    return text


def _with_call_path(result: dict[str, Any], candidate: dict[str, Any],
                    code_context: dict[str, Any]) -> dict[str, Any]:
    result.setdefault("call_path", _build_static_call_path(candidate, code_context, result))
    return result


def _with_context(result: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
    result.setdefault("context", context.get("context"))
    result.setdefault("risk_modifier", context.get("risk_modifier"))
    result.setdefault("allow_confirmed", context.get("allow_confirmed", True))
    result.setdefault("confirmed_blockers", context.get("confirmed_blockers") or [])
    if not context.get("allow_confirmed", True):
        result.setdefault("downgrade_reason", context.get("reason"))
        result["confidence"] = min(float(result.get("confidence") or 0.55), 0.65)
        if context.get("risk_modifier") == "informational":
            result.setdefault("runtime_verification_status", "not_runtime_verifiable")
    return result


def _static_asset_false_positive(candidate: dict[str, Any], vuln_type: str) -> dict[str, Any] | None:
    """Reject server-side runtime findings reported inside static/third-party assets.

    A SQL/command/path traversal finding in a minified frontend asset usually has no
    server-side source-to-sink path and should not be sent to dynamic HTTP probing.
    """
    if not any(keyword in vuln_type for keyword in RUNTIME_VULN_KEYWORDS):
        return None

    file_path = str(candidate.get("file") or candidate.get("file_path") or "").replace("\\", "/").lower()
    if not file_path:
        return None
    parts = {part for part in file_path.split("/") if part}
    is_static_asset = (
        bool(parts & STATIC_ASSET_PARTS)
        or file_path.endswith(STATIC_ASSET_SUFFIXES)
        or "/static_" in file_path
    )
    if not is_static_asset:
        return None

    return {
        "is_valid": False,
        "confidence": 0.9,
        "checks": [
            {"name": "static_or_third_party_asset_detected", "passed": True, "file": file_path},
            {"name": "server_side_runtime_flow_absent", "passed": True},
        ],
        "false_positive_reason": (
            "Candidate is located in a static/third-party/minified frontend asset, "
            "so no server-side runtime source-to-sink path is established."
        ),
        "source": None,
        "sink": None,
        "propagation_path": [],
        "runtime_verification_status": "not_runtime_verifiable",
        "recommended_poc_strategy": "Do not run dynamic HTTP verification unless a backend route reaches this code.",
    }


def _build_static_call_path(candidate: dict[str, Any], code_context: dict[str, Any],
                            verdict: dict[str, Any]) -> list[dict[str, Any]]:
    file_path = candidate.get("file") or candidate.get("file_path") or code_context.get("file")
    finding_line = _to_int(candidate.get("start_line") or candidate.get("line") or code_context.get("line"))
    lines = code_context.get("lines") or []
    snippet = candidate.get("code_snippet") or candidate.get("vulnerable_code") or ""
    hops: list[dict[str, Any]] = []

    source_line = _find_line(lines, ["request", "args.get", "_get", "_post", "params", "input"], fallback=finding_line)
    sink_line = _find_line(lines, ["execute", "query", "os.system", "subprocess", "open(", "readfile", "pickle.loads"], fallback=finding_line)

    if verdict.get("source"):
        hops.append({"stage": "source", "file": file_path, "line": source_line, "detail": verdict["source"]})
    if snippet:
        hops.append({"stage": "candidate", "file": file_path, "line": finding_line, "detail": snippet[:240]})
    if verdict.get("sink"):
        hops.append({"stage": "sink", "file": file_path, "line": sink_line, "detail": verdict["sink"]})
    return hops


def _find_line(lines: list[dict[str, Any]], needles: list[str], fallback: int | None) -> int | None:
    for row in lines:
        code = str(row.get("code") or "").lower()
        if any(needle in code for needle in needles):
            return _to_int(row.get("line")) or fallback
    return fallback


def _verify_sql(text: str, checks: list[dict[str, Any]]) -> dict[str, Any]:
    has_sink = bool(re.search(r"\b(execute|query|cursor\.execute)\s*\(", text))
    concatenates_query = bool(re.search(
        r"(select|insert|update|delete).*?(\+|%\s*[A-Za-z_$][\w$]*|f['\"]|format\s*\()",
        text,
        re.S,
    ))
    parameterized = bool(re.search(r"execute\s*\([^)]*,\s*(\(|\[|\{)", text, re.S))
    user_input = _has_user_source(text)
    source_reaches_sink = _source_reaches_sink(text, r"(?:execute|query|cursor\.execute)\s*\(")
    checks.extend([
        {"name": "sql_sink_present", "passed": has_sink},
        {"name": "query_uses_string_concatenation_or_formatting", "passed": concatenates_query},
        {"name": "parameterized_execute_detected", "passed": parameterized},
        {"name": "attacker_controlled_source_present", "passed": user_input},
        {"name": "attacker_controlled_source_reaches_sink", "passed": source_reaches_sink},
    ])
    if parameterized and not concatenates_query:
        return {
            "is_valid": False,
            "confidence": 0.82,
            "checks": checks,
            "false_positive_reason": "SQL execution appears parameterized; no direct user-controlled string concatenation was detected.",
            "source": "user input parameter",
            "sink": "SQL execution API",
            "propagation_path": [],
            # 参数化查询（占位符 + 参数元组、无字符串拼接）是**确定性**安全判定，不是弱窗口
            # 启发式：即便 LLM 不可用也应直接判 false_positive，不能因 source/sink 存在就
            # 灌进人工复核队列。故打上强否决证据标记。
            "evidence_strength": "parameterized_query",
            "recommended_poc_strategy": "No PoC recommended unless a non-parameterized path is found.",
        }
    if has_sink and concatenates_query and source_reaches_sink:
        return {
            "is_valid": True,
            "confidence": 0.74,
            "checks": checks,
            "source": "request/user-controlled value",
            "sink": "SQL execution API",
            "propagation_path": ["user input", "string-built SQL query", "execute/query sink"],
            "deterministic_flow": True,
            "verification_level": "local_static_verified",
            "evidence_strength": "window_heuristic",
            "recommended_poc_strategy": "Send a boolean or error-based SQL payload to the controlling parameter in a local target.",
        }
    if has_sink and concatenates_query and not source_reaches_sink:
        return _uncertain(checks, "SQL is built dynamically, but the nearby user input was not proven to reach the query sink.")
    return _uncertain(checks, "SQL sink or unsafe query construction was not clearly established.")


def _verify_iac_misconfiguration(candidate: dict[str, Any],
                                 code_context: dict[str, Any]) -> dict[str, Any] | None:
    extra = candidate.get("extra") or {}
    rule_id = str(candidate.get("rule_id") or extra.get("rule_id") or "").upper()
    scanner_class = str(extra.get("scanner_class") or "").lower()
    file_path = str(candidate.get("file") or candidate.get("file_path") or code_context.get("file") or "").lower()
    message = " ".join(str(part or "") for part in (
        candidate.get("type"), candidate.get("message"), rule_id,
    )).lower()
    if scanner_class != "iac" and not rule_id.startswith("DS-") and "dockerfile" not in file_path:
        return None
    snippet = str(code_context.get("snippet") or candidate.get("code_snippet") or "")
    checks: list[dict[str, Any]] = [
        {"name": "iac_scanner_class", "passed": scanner_class == "iac" or rule_id.startswith("DS-")},
        {"name": "dockerfile_context", "passed": "dockerfile" in file_path},
    ]
    if rule_id == "DS-0002" or "should not be 'root'" in message or "non-root user" in message:
        has_non_root_user = bool(re.search(r"^\s*USER\s+(?!root\b|0\b)[^\s#]+", snippet, re.I | re.M))
        checks.append({"name": "non_root_user_directive_present", "passed": has_non_root_user})
        if has_non_root_user:
            return {
                "is_valid": False,
                "confidence": 0.82,
                "checks": checks,
                "false_positive_reason": "Dockerfile contains a non-root USER directive.",
                "source": "Dockerfile",
                "sink": "container runtime user",
                "propagation_path": [],
                "evidence_strength": "iac_safe_configuration",
                "runtime_verification_status": "not_runtime_verifiable",
            }
        return _deterministic_true(
            checks,
            "container runtime user defaults to root",
            0.86,
            "无需 PoC；在 Dockerfile 中增加 USER <non-root-user> 并确保目录权限正确。",
            "Dockerfile 缺少非 root USER 指令",
        )
    if rule_id == "DS-0026" or "healthcheck" in message:
        checks.append({"name": "healthcheck_advisory", "passed": True})
        return {
            "is_valid": None,
            "confidence": 0.55,
            "checks": checks,
            "reason": "Dockerfile HEALTHCHECK is a hardening/operability advisory, not a source-sink vulnerability.",
            "runtime_verification_status": "not_runtime_verifiable",
        }
    if scanner_class == "iac" or rule_id.startswith("DS-"):
        checks.append({"name": "trivy_iac_rule_present", "passed": True})
        return _deterministic_true(
            checks,
            "infrastructure-as-code configuration",
            0.78,
            "无需 PoC；按 Trivy resolution 修复配置并重新扫描。",
            "Trivy IaC 规则命中项目配置文件",
        )
    return None


def _verify_command(text: str, checks: list[dict[str, Any]]) -> dict[str, Any]:
    has_sink = bool(re.search(r"(os\.system|subprocess\.(run|call|popen)|exec|eval)\s*\(", text))
    shell_true = "shell=true" in text
    dynamic_arg = bool(re.search(r"(\+|format\s*\(|f['\"]|\{.*\})", text))
    safe_list = bool(re.search(r"subprocess\.(run|call|popen)\s*\(\s*\[", text)) and not shell_true
    user_input = _has_user_source(text)
    source_reaches_sink = _source_reaches_sink(
        text, r"(?:os\.system|subprocess\.(?:run|call|popen)|exec|eval)\s*\("
    )
    checks.extend([
        {"name": "command_execution_sink_present", "passed": has_sink},
        {"name": "shell_true_detected", "passed": shell_true},
        {"name": "dynamic_argument_detected", "passed": dynamic_arg},
        {"name": "safe_argument_list_detected", "passed": safe_list},
        {"name": "attacker_controlled_source_present", "passed": user_input},
        {"name": "attacker_controlled_source_reaches_sink", "passed": source_reaches_sink},
    ])
    if safe_list and not dynamic_arg:
        return {
            "is_valid": False,
            "confidence": 0.78,
            "checks": checks,
            "false_positive_reason": "Command is invoked with a static argument list and shell=False.",
            "source": "user input parameter",
            "sink": "process execution API",
            "propagation_path": [],
            "recommended_poc_strategy": "No PoC recommended unless user input reaches a shell string.",
        }
    if has_sink and (shell_true or dynamic_arg) and source_reaches_sink:
        return {
            "is_valid": True,
            "confidence": 0.74,
            "checks": checks,
            "source": "request/user-controlled value",
            "sink": "process execution API",
            "propagation_path": ["user input", "command string/argument", "process execution sink"],
            "deterministic_flow": True,
            "verification_level": "local_static_verified",
            "evidence_strength": "window_heuristic",
            "recommended_poc_strategy": "Use a harmless marker command against a local authorized target.",
        }
    if has_sink and (shell_true or dynamic_arg) and not source_reaches_sink:
        return _uncertain(checks, "A dynamic command sink exists, but the nearby user input was not proven to reach it.")
    return _uncertain(checks, "Command sink or user-controlled command construction was not clearly established.")


def _verify_path_traversal(text: str, checks: list[dict[str, Any]]) -> dict[str, Any]:
    has_file_sink = bool(re.search(r"\b(open|readfile|file_get_contents|include|require)\s*\(", text))
    user_input = _has_user_source(text)
    source_reaches_sink = _source_reaches_sink(
        text, r"(?:open|readfile|file_get_contents|include|require)\s*\("
    )
    safe_join = any(token in text for token in ["safe_join", "secure_filename", "basename(", "normpath("])
    checks.extend([
        {"name": "file_read_sink_present", "passed": has_file_sink},
        {"name": "user_input_reference_present", "passed": user_input},
        {"name": "attacker_controlled_source_reaches_sink", "passed": source_reaches_sink},
        {"name": "path_sanitizer_detected", "passed": safe_join},
    ])
    if safe_join and not (has_file_sink and user_input):
        return {
            "is_valid": False,
            "confidence": 0.74,
            "checks": checks,
            "false_positive_reason": "A path sanitizer was detected and no direct unsafe file read path was established.",
            "source": "path parameter",
            "sink": "file read/include API",
            "propagation_path": [],
            "recommended_poc_strategy": "No PoC recommended unless a sanitizer bypass is found.",
        }
    if has_file_sink and source_reaches_sink and not safe_join:
        return {
            "is_valid": True,
            "confidence": 0.82,
            "checks": checks,
            "source": "request path parameter",
            "sink": "file read/include API",
            "propagation_path": ["user input", "path construction", "file read/include sink"],
            "deterministic_flow": True,
            "verification_level": "local_static_verified",
            "recommended_poc_strategy": "Try harmless traversal payloads against a local target and check for expected marker files.",
        }
    return _uncertain(checks, "Path source-to-sink flow was not clearly established.")


def _verify_secret(text: str, checks: list[dict[str, Any]]) -> dict[str, Any]:
    if re.search(r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----|\b(?:gh[pousr]_|sk-|AKIA|ASIA|AIza|xox[baprs]-)", text):
        return {
            "is_valid": True, "confidence": 0.9, "checks": checks,
            "source": "source file credential", "sink": "credential/configuration",
            "propagation_path": ["concrete credential material"],
            "deterministic_flow": True, "evidence_strength": "credential_format",
        }
    plausible, name, value = plausible_secret_assignment(text)
    assignment = name is not None
    checks.extend([
        {"name": "secret_assignment_detected", "passed": assignment},
        {"name": "credential_characteristics_present", "passed": plausible},
    ])
    if assignment and not plausible:
        return {
            "is_valid": False,
            "confidence": 0.7,
            "checks": checks,
            "false_positive_reason": "The assigned literal is a placeholder, public identifier, or low-entropy label rather than a deployable credential.",
            "source": "source file literal",
            "sink": "credential/configuration",
            "propagation_path": [],
            "recommended_poc_strategy": "Do not execute PoC; manually confirm whether the value is real.",
            "evidence_strength": "non_credential_literal",
        }
    if plausible:
        return {
            "is_valid": True,
            "confidence": 0.8,
            "checks": checks,
            "source": "source file literal",
            "sink": "credential/configuration",
            "propagation_path": ["hardcoded literal", "runtime configuration or authentication use"],
            "deterministic_flow": True,
            "evidence_strength": "literal_assignment",
            "recommended_poc_strategy": "No exploit execution; validate usage and rotate the credential if real.",
        }
    return {
        "is_valid": False,
        "confidence": 0.82,
        "checks": checks,
        "false_positive_reason": (
            "The exact source line contains a dynamic/template token reference, not a hardcoded credential literal."
        ),
        "source": None,
        "sink": None,
        "propagation_path": [],
        "evidence_strength": "no_hardcoded_literal",
    }


def _deterministic_true(checks, sink, conf, strategy, path_desc):
    """存在即漏洞的确定性判定（弱加密/弱随机等，无需污点源）。"""
    return {
        "is_valid": True, "confidence": conf, "checks": checks,
        "source": "N/A（确定性缺陷，无需攻击者输入）", "sink": sink,
        "deterministic_flow": True, "evidence_strength": "deterministic_pattern",
        "propagation_path": [path_desc],
        "recommended_poc_strategy": strategy,
    }


def _verify_tls_disabled(text: str, checks: list[dict[str, Any]]) -> dict[str, Any]:
    code = _verification_code_only(text)
    disabled = bool(re.search(
        r"verify\s*=\s*false|cert(?:ificate)?_?verify\s*=\s*false|"
        r"verify_(?:cert|certificate)\s*=\s*false|ssl[_-]?verify\s*=\s*false|"
        r"jwt\.decode\s*\([^\n]*verify\s*=\s*false",
        code,
        re.I,
    ))
    checks.append({"name": "tls_or_token_verification_disabled", "passed": disabled})
    if disabled:
        return _deterministic_true(
            checks,
            "certificate/token verification disabled",
            0.86,
            "无需 PoC；启用证书/签名校验并拒绝 verify=False。",
            "代码显式关闭 TLS 证书或 token 校验",
        )
    return _uncertain(checks, "未在源码窗口中确认 verify=False 或等价的证书/签名校验关闭。")


def _verify_insecure_deserialization(text: str, checks: list[dict[str, Any]]) -> dict[str, Any]:
    code = _verification_code_only(text)
    unsafe_yaml = bool(re.search(r"\byaml\.load\s*\(", code, re.I))
    safe_yaml = bool(re.search(r"yaml\.safe_load\s*\(|loader\s*=\s*yaml\.SafeLoader|SafeLoader", code, re.I))
    unsafe_pickle = bool(re.search(r"\b(?:pickle|cPickle|marshal)\.loads?\s*\(|jsonpickle\.decode\s*\(|\bunserialize\s*\(", code, re.I))
    user_input = _has_user_source(code)
    checks.extend([
        {"name": "unsafe_yaml_load", "passed": unsafe_yaml},
        {"name": "safe_yaml_loader_detected", "passed": safe_yaml},
        {"name": "unsafe_object_deserialization_api", "passed": unsafe_pickle},
        {"name": "attacker_controlled_source_present", "passed": user_input},
    ])
    # 安全加载器优先判 FP（与是否有源无关）。
    if unsafe_yaml and safe_yaml:
        return {
            "is_valid": False,
            "confidence": 0.78,
            "checks": checks,
            "false_positive_reason": "yaml.load 使用了 SafeLoader 或等价安全加载器。",
            "source": None,
            "sink": "YAML loader",
            "propagation_path": [],
            "evidence_strength": "safe_deserialization_loader",
        }
    # 不安全反序列化不是"存在即漏洞"：只有数据来自**攻击者可控源**才可确认；
    # 读本地可信文件（如 pickle.loads(open('cache.bin'))）无法静态断定可利用，
    # 诚实交人工复核，避免过度确认（自我感动）。
    has_unsafe_sink = (unsafe_yaml and not safe_yaml) or unsafe_pickle
    if has_unsafe_sink and user_input:
        sink = "unsafe YAML object deserialization sink" if unsafe_yaml else "unsafe object deserialization sink"
        return {
            "is_valid": True,
            "confidence": 0.82,
            "checks": checks,
            "source": "request/user-controlled value",
            "sink": sink,
            "evidence_strength": "window_heuristic",
            "propagation_path": ["attacker-controlled input", "unsafe deserialization", sink],
            "recommended_poc_strategy": "构造恶意序列化对象（pickle __reduce__ / YAML !!python）在隔离环境验证。",
        }
    if has_unsafe_sink:
        return _uncertain(
            checks,
            "存在不安全反序列化 sink，但当前窗口未确立攻击者可控源"
            "（可能读本地可信数据，或源在跨函数处），不做确定性确认。",
        )
    return _uncertain(checks, "未识别到不安全反序列化 API。")


def _verify_weak_crypto(text: str, checks: list[dict[str, Any]]) -> dict[str, Any]:
    text = _verification_code_only(text)
    weak_hash = re.search(
        r"\b(md5|sha1|sha-1)\b|messagedigest\.getinstance\(\s*['\"](md5|sha-?1)"
        r"|hashlib\.(md5|sha1)\s*\(", text, re.I)
    weak_cipher = re.search(
        r"(?<![\w])des(?![\w])|\brc4\b|\becb\b|"
        r"cipher\.getinstance\(\s*['\"]([^'\"]*des|[^'\"]*rc4|[^'\"]*ecb)", text, re.I)
    security_context = bool(re.search(
        r"password|credential|secret|token|session|auth|signature|signing|encrypt|"
        r"private.?key|api.?key|nonce|salt", text, re.I))
    protocol_signature = bool(re.search(
        r"signature(method|version)?|signstr|strtosign|authorization|wechat|jeepay|"
        r"qiniu|upyun|cdn|hmac-sha1|api protocol", text, re.I,
    ))
    password_storage = bool(re.search(
        r"password(_hash|_verify)?|passwd|user_pwd|stored.?hash|password storage", text, re.I,
    ))
    non_secret_identifier = bool(re.search(
        r"rate[_-]?limit|ai_rate_|visitor(?:id|seed)|search_suggest|sessionid\s*=\s*session_id", text, re.I,
    )) and not bool(re.search(r"login_check|user_check|admin_check|password|user_pwd", text, re.I))
    effective = bool(weak_cipher or (weak_hash and security_context))
    checks += [
        {"name": "weak_hash_primitive", "passed": bool(weak_hash)},
        {"name": "weak_cipher_primitive", "passed": bool(weak_cipher)},
        {"name": "security_sensitive_context", "passed": security_context},
        {"name": "protocol_signature_context", "passed": protocol_signature},
        {"name": "non_secret_identifier_context", "passed": non_secret_identifier},
    ]
    if weak_hash and non_secret_identifier and not weak_cipher:
        return {
            "is_valid": False,
            "confidence": 0.8,
            "checks": checks,
            "false_positive_reason": "MD5 is used as a non-secret correlation/rate-limit identifier, not for passwords, authentication, or signatures.",
            "source": "non-secret request metadata", "sink": "rate-limit/cache identifier",
            "propagation_path": [],
        }
    if weak_hash and protocol_signature and not password_storage and not weak_cipher:
        return {
            "is_valid": False,
            "confidence": 0.8,
            "checks": checks,
            "false_positive_reason": (
                "MD5/SHA-1 is used to implement an external protocol's prescribed signature format, "
                "not as a replaceable password hash or general-purpose security primitive."
            ),
            "source": "protocol-defined fields",
            "sink": "external protocol signature",
            "propagation_path": [],
        }
    if effective:
        result = _deterministic_true(
            checks, "weak/broken cryptographic primitive", 0.85,
            "无需 PoC；改用强算法（SHA-256/AES-GCM，DES→AES，ECB→GCM）。",
            "使用了已被攻破/弱的加密或哈希原语")
        if weak_hash and re.search(
                r"password|user_pwd|stored.?hash|login_check|user_check|admin_check|user_random", text, re.I):
            result["evidence_strength"] = "authentication_hash"
        return result
    if weak_hash:
        return _uncertain(checks, "检测到弱哈希，但未证明其用于密码、签名或令牌等安全场景。")
    return _uncertain(checks, "未明确识别到弱加密原语。")


def _verify_weak_random(text: str, checks: list[dict[str, Any]]) -> dict[str, Any]:
    text = _verification_code_only(text)
    weak = re.search(r"\brandom\.(random|randint|randrange|choice|getrandbits|shuffle|uniform)\s*\("
                     r"|\bmath\.random\s*\(|new\s+random\s*\(|mt_rand\s*\(|\brand\s*\(", text, re.I)
    secure = bool(re.search(r"securerandom|\bsecrets\.|random_bytes|crypto\.randombytes", text, re.I))
    security_context = bool(re.search(
        r"password|credential|secret|token|session|auth|otp|nonce|csrf|reset|salt|key", text, re.I))
    checks += [{"name": "insecure_prng_used", "passed": bool(weak)},
               {"name": "secure_random_detected", "passed": secure},
               {"name": "security_sensitive_context", "passed": security_context}]
    if weak and re.search(r"signature_nonce|signaturenonce|hmac-sha1|signaturemethod", text, re.I) \
            and not re.search(r"password|session.?id|csrf|reset.?token|otp", text, re.I):
        return {
            "is_valid": False, "confidence": 0.8, "checks": checks,
            "false_positive_reason": (
                "The protocol nonce provides request uniqueness for a signed API call; it is not used as a secret or authentication token."
            ),
            "source": "protocol nonce", "sink": "signed API request", "propagation_path": [],
            "evidence_strength": "protocol_nonce",
        }
    if weak and not secure and security_context:
        return _deterministic_true(
            checks, "insecure pseudo-random generator", 0.8,
            "无需 PoC；安全场景改用 secrets / os.urandom / SecureRandom。",
            "在安全相关场景使用了不安全的伪随机数生成器")
    if weak and not security_context:
        return {
            "is_valid": False,
            "confidence": 0.76,
            "checks": checks,
            "false_positive_reason": "弱随机仅用于非安全用途（如临时文件名/展示顺序/去重），未用于 token、密码、会话、OTP、CSRF 或密钥。",
            "source": "non-security random value",
            "sink": "non-security application behavior",
            "propagation_path": [],
            "evidence_strength": "non_security_random_use",
        }
    return _uncertain(checks, "未证明弱随机用于安全敏感值，或已使用安全随机。")


def _verification_code_only(text: str) -> str:
    without_blocks = re.sub(r"/\*.*?\*/", "", str(text or ""), flags=re.S)
    return "\n".join(
        "" if line.lstrip().startswith(("//", "#", "*", "<!--")) else line
        for line in without_blocks.splitlines()
    )


def _verify_generic_injection(text: str, checks: list[dict[str, Any]], *,
                              sink_rx: str, sink_label: str, sanitizer_rx: str,
                              vuln: str) -> dict[str, Any]:
    """通用注入类复核：危险 sink + 攻击者可控源 + 无净化 -> 确认。"""
    has_sink = bool(re.search(sink_rx, text, re.I))
    user_input = _has_user_source(text)
    source_reaches_sink = _source_reaches_sink(text, sink_rx)
    sanitized = bool(sanitizer_rx and re.search(sanitizer_rx, text, re.I))
    checks += [{"name": f"{vuln}_sink_present", "passed": has_sink},
               {"name": "attacker_controlled_source_present", "passed": user_input},
               {"name": "attacker_controlled_source_reaches_sink", "passed": source_reaches_sink},
               {"name": f"{vuln}_sanitizer_detected", "passed": sanitized}]
    if has_sink and sanitized and not user_input:
        return {"is_valid": False, "confidence": 0.72, "checks": checks,
                "false_positive_reason": f"{sink_label} 处检测到净化/编码，且无直接可控输入到达。",
                "sink": sink_label, "propagation_path": []}
    if has_sink and source_reaches_sink and not sanitized:
        return {"is_valid": True, "confidence": 0.74, "checks": checks,
                "source": "request/user-controlled value", "sink": sink_label,
                "deterministic_flow": True,
                "verification_level": "local_static_verified",
                "evidence_strength": "window_heuristic",
                "propagation_path": ["user input", f"unsanitized flow into {sink_label}", sink_label],
                "recommended_poc_strategy": f"对本地授权目标向可控参数发送 {vuln} 载荷并核对成功判据。"}
    if has_sink and not user_input:
        return _uncertain(checks, f"存在 {sink_label} sink，但当前窗口未确立攻击者可控源（可能跨函数）。")
    return _uncertain(checks, f"未清晰确立 {sink_label} 的 source→sink 流。")


def _uncertain(checks: list[dict[str, Any]], reason: str) -> dict[str, Any]:
    return {"is_valid": None, "confidence": 0.55, "checks": checks, "reason": reason}


def _has_user_source(text: str) -> bool:
    return bool(re.search(
        r"(request\.(args|form|values|json|data|files|headers|cookies|get|post|query_params)|"
        r"args\.get\s*\(|req\.(query|body|params|headers|cookies)|\$_(get|post|request|cookie|server)|"
        r"getparameter\s*\(|@requestparam|@pathvariable|@requestbody|argv\[|\binput\s*\(|"
        r"os\.environ|getenv\s*\(|sys\.stdin|scanf\s*\(|fgets\s*\(|(?<![\w.])gets\s*\(|"
        r"params\[|body\.|\.get_json\s*\(|flask\.request|self\.request|request\.POST|request\.GET)",
        text or "", re.I,
    ))


def _source_reaches_sink(text: str, sink_rx: str) -> bool:
    """Require a local variable-level link, not mere source/sink co-occurrence."""
    source_expr = (
        r"request\.(?:args|form|values|json|data|files|headers|cookies|get|post|query_params)"
        r"|args\.get\s*\(|req\.(?:query|body|params|headers|cookies)|\$_(?:get|post|request|cookie|server)"
        r"|getparameter\s*\(|params\[|request\.(?:GET|POST)"
        r"|content\s*\[|data\s*\[|json\s*\["
    )
    # Direct source expression inside the sink argument.
    for line in str(text or "").splitlines():
        if re.search(sink_rx, line, re.I) and re.search(source_expr, line, re.I):
            return True
    # One-window local assignment: the source variable must be referenced again
    # on a sink/construction line. A source elsewhere in the window is not flow.
    assignments = re.finditer(
        rf"(?P<var>[$A-Za-z_][\w$]*)\s*=\s*[^\n;]*(?:{source_expr})", text or "", re.I
    )
    for match in assignments:
        var = re.escape(match.group("var"))
        tail = (text or "")[match.end():]
        sink_match = re.search(sink_rx, tail, re.I)
        if sink_match:
            between = tail[:sink_match.end()]
            if re.search(rf"(?<![\w$]){var}(?![\w$])", between):
                return True
    return False


def _to_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
