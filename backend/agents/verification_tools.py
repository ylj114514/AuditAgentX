"""Local tools used by VerifyAgent.

These helpers make the verifier more than a pure LLM prompt: the agent can read
nearby source code and run deterministic checks before making a final decision.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from backend.verifier.context_classifier import classify_finding_context


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
    heuristic = run_heuristic_static_verifier(candidate, context["code_context"])
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


def run_heuristic_static_verifier(candidate: dict[str, Any], code_context: dict[str, Any]) -> dict[str, Any]:
    """Public MCP tool implementation for source-to-sink and false-positive checks."""
    return _run_heuristic_verifier(candidate, code_context)


def run_local_sast_replay(candidate: dict[str, Any], code_context: dict[str, Any]) -> dict[str, Any]:
    """Public MCP tool implementation for deterministic local SAST replay."""
    return _local_sast_replay(candidate, code_context)


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
    vuln_type = str(candidate.get("type") or candidate.get("vulnerability_type") or "").lower()
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

    text = "\n".join([
        str(candidate.get("code_snippet") or candidate.get("vulnerable_code") or ""),
        str(code_context.get("snippet") or ""),
    ])
    lowered = text.lower()
    checks: list[dict[str, Any]] = []

    if "sql" in vuln_type:
        return _with_context(_with_call_path(_verify_sql(lowered, checks), candidate, code_context), context)
    if "command" in vuln_type or "rce" in vuln_type:
        return _with_context(_with_call_path(_verify_command(lowered, checks), candidate, code_context), context)
    if "path" in vuln_type or "traversal" in vuln_type:
        return _with_context(_with_call_path(_verify_path_traversal(lowered, checks), candidate, code_context), context)
    if "secret" in vuln_type or "credential" in vuln_type or "key" in vuln_type:
        return _with_context(_with_call_path(_verify_secret(text, checks), candidate, code_context), context)

    checks.append({"name": "generic_context_present", "passed": bool(text.strip())})
    return _with_context(_with_call_path({
        "is_valid": None,
        "confidence": 0.55,
        "checks": checks,
        "reason": "No type-specific local verifier matched this finding.",
        "runtime_verification_status": "not_runtime_verifiable",
    }, candidate, code_context), context)


def _local_sast_replay(candidate: dict[str, Any], code_context: dict[str, Any]) -> dict[str, Any]:
    vuln_type = str(candidate.get("type") or candidate.get("vulnerability_type") or "")
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
    concatenates_query = bool(re.search(r"(select|insert|update|delete).*?(\+|f['\"]|format\s*\()", text, re.S))
    parameterized = bool(re.search(r"execute\s*\([^)]*,\s*(\(|\[|\{)", text, re.S))
    user_input = _has_user_source(text)
    checks.extend([
        {"name": "sql_sink_present", "passed": has_sink},
        {"name": "query_uses_string_concatenation_or_formatting", "passed": concatenates_query},
        {"name": "parameterized_execute_detected", "passed": parameterized},
        {"name": "attacker_controlled_source_present", "passed": user_input},
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
            "recommended_poc_strategy": "No PoC recommended unless a non-parameterized path is found.",
        }
    if has_sink and concatenates_query and user_input:
        return {
            "is_valid": True,
            "confidence": 0.74,
            "checks": checks,
            "source": "request/user-controlled value",
            "sink": "SQL execution API",
            "propagation_path": ["user input", "string-built SQL query", "execute/query sink"],
            "evidence_strength": "window_heuristic",
            "recommended_poc_strategy": "Send a boolean or error-based SQL payload to the controlling parameter in a local target.",
        }
    if has_sink and concatenates_query and not user_input:
        return _uncertain(checks, "SQL is built dynamically, but no attacker-controlled source was established.")
    return _uncertain(checks, "SQL sink or unsafe query construction was not clearly established.")


def _verify_command(text: str, checks: list[dict[str, Any]]) -> dict[str, Any]:
    has_sink = bool(re.search(r"(os\.system|subprocess\.(run|call|popen)|exec|eval)\s*\(", text))
    shell_true = "shell=true" in text
    dynamic_arg = bool(re.search(r"(\+|format\s*\(|f['\"]|\{.*\})", text))
    safe_list = bool(re.search(r"subprocess\.(run|call|popen)\s*\(\s*\[", text)) and not shell_true
    user_input = _has_user_source(text)
    checks.extend([
        {"name": "command_execution_sink_present", "passed": has_sink},
        {"name": "shell_true_detected", "passed": shell_true},
        {"name": "dynamic_argument_detected", "passed": dynamic_arg},
        {"name": "safe_argument_list_detected", "passed": safe_list},
        {"name": "attacker_controlled_source_present", "passed": user_input},
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
    if has_sink and (shell_true or dynamic_arg) and user_input:
        return {
            "is_valid": True,
            "confidence": 0.74,
            "checks": checks,
            "source": "request/user-controlled value",
            "sink": "process execution API",
            "propagation_path": ["user input", "command string/argument", "process execution sink"],
            "evidence_strength": "window_heuristic",
            "recommended_poc_strategy": "Use a harmless marker command against a local authorized target.",
        }
    if has_sink and (shell_true or dynamic_arg) and not user_input:
        return _uncertain(checks, "A dynamic command sink exists, but no attacker-controlled source was established.")
    return _uncertain(checks, "Command sink or user-controlled command construction was not clearly established.")


def _verify_path_traversal(text: str, checks: list[dict[str, Any]]) -> dict[str, Any]:
    has_file_sink = bool(re.search(r"\b(open|readfile|file_get_contents|include|require)\s*\(", text))
    user_input = any(token in text for token in ["request", "_get", "_post", "params", "input", "args.get"])
    safe_join = any(token in text for token in ["safe_join", "secure_filename", "basename(", "normpath("])
    checks.extend([
        {"name": "file_read_sink_present", "passed": has_file_sink},
        {"name": "user_input_reference_present", "passed": user_input},
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
    if has_file_sink and user_input and not safe_join:
        return {
            "is_valid": True,
            "confidence": 0.82,
            "checks": checks,
            "source": "request path parameter",
            "sink": "file read/include API",
            "propagation_path": ["user input", "path construction", "file read/include sink"],
            "recommended_poc_strategy": "Try harmless traversal payloads against a local target and check for expected marker files.",
        }
    return _uncertain(checks, "Path source-to-sink flow was not clearly established.")


def _verify_secret(text: str, checks: list[dict[str, Any]]) -> dict[str, Any]:
    secret = bool(re.search(r"(password|passwd|secret|api[_-]?key|token|access[_-]?key)\s*[=:]\s*['\"][^'\"]{6,}['\"]", text, re.I))
    placeholder = bool(re.search(r"(your-|example|dummy|test|placeholder|changeme)", text, re.I))
    checks.extend([
        {"name": "secret_assignment_detected", "passed": secret},
        {"name": "placeholder_detected", "passed": placeholder},
    ])
    if secret and placeholder:
        return {
            "is_valid": False,
            "confidence": 0.7,
            "checks": checks,
            "false_positive_reason": "The detected secret-like value appears to be a placeholder or test value.",
            "source": "source file literal",
            "sink": "credential/configuration",
            "propagation_path": [],
            "recommended_poc_strategy": "Do not execute PoC; manually confirm whether the value is real.",
        }
    if secret:
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
    return _uncertain(checks, "No concrete secret assignment was detected.")


def _uncertain(checks: list[dict[str, Any]], reason: str) -> dict[str, Any]:
    return {"is_valid": None, "confidence": 0.55, "checks": checks, "reason": reason}


def _has_user_source(text: str) -> bool:
    return bool(re.search(
        r"(request\.(args|form|values|json|data|files|headers)|args\.get\s*\(|"
        r"req\.(query|body|params|headers)|\$_(get|post|request|cookie)|"
        r"getparameter\s*\(|@requestparam|@pathvariable|argv\[|\binput\s*\()",
        text or "", re.I,
    ))


def _to_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
