"""AuditAgentX MCP tool server.

The project uses this module as the authoritative MCP tool boundary for
verification. The in-process server is used by tests and the backend runtime;
`backend.mcp.stdio_server` can expose the same tools through the official MCP
SDK when that optional dependency is installed.

工具清单（共 9 个）：
  原有 7 个：
    read_code_context, run_sast_replay, verify_source_sink,
    build_evidence_chain, extract_target_function,
    generate_fuzzing_harness, run_fuzzing_harness
  新增 2 个：
    dynamic_http_verify  — 复用 DynamicVerifier，未配置目标返回 not_executed
    build_final_evidence — 汇总静/动/harness 证据链
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Callable

from backend.agents.verification_tools import (
    read_code_context,
    run_heuristic_static_verifier,
    run_local_sast_replay,
)
from backend.skills.harness_tools import (
    extract_function,
    build_template_harness,
    run_harness,
    _is_builtin_template_harness,
)
from backend.dynamic.symbol_resolver import resolve_symbol
from backend.rag.retriever import SecurityKnowledgeRetriever


class AuditMCPServer:
    """Small MCP-compatible tool registry for verifier tools."""

    server_name = "auditagentx-verification-mcp"

    def __init__(self) -> None:
        self._tools: dict[str, dict[str, Any]] = {
            "retrieve_security_knowledge": {
                "name": "retrieve_security_knowledge",
                "description": "Retrieve CWE/OWASP/verification/remediation knowledge for a candidate finding.",
                "input_schema": {
                    "type": "object",
                    "required": ["candidate"],
                    "properties": {
                        "candidate": {"type": "object"},
                        "query": {"type": ["string", "null"]},
                        "limit": {"type": "integer", "default": 3},
                    },
                },
                "handler": self._retrieve_security_knowledge,
            },
            "retrieve_verification_playbook": {
                "name": "retrieve_verification_playbook",
                "description": "Retrieve verification playbooks and false-positive checks for a candidate finding.",
                "input_schema": {
                    "type": "object",
                    "required": ["candidate"],
                    "properties": {
                        "candidate": {"type": "object"},
                        "limit": {"type": "integer", "default": 2},
                    },
                },
                "handler": self._retrieve_verification_playbook,
            },
            "retrieve_remediation_advice": {
                "name": "retrieve_remediation_advice",
                "description": "Retrieve remediation guidance for a candidate finding.",
                "input_schema": {
                    "type": "object",
                    "required": ["candidate"],
                    "properties": {
                        "candidate": {"type": "object"},
                        "limit": {"type": "integer", "default": 2},
                    },
                },
                "handler": self._retrieve_remediation_advice,
            },
            "read_code_context": {
                "name": "read_code_context",
                "description": "Read nearby source code around a candidate finding.",
                "input_schema": {
                    "type": "object",
                    "required": ["candidate"],
                    "properties": {
                        "candidate": {"type": "object"},
                        "code_root": {"type": ["string", "null"]},
                        "radius": {"type": "integer", "default": 8},
                    },
                },
                "handler": self._read_code_context,
            },
            "run_sast_replay": {
                "name": "run_sast_replay",
                "description": "Replay lightweight SAST checks on the local code window.",
                "input_schema": {
                    "type": "object",
                    "required": ["candidate", "code_context"],
                    "properties": {
                        "candidate": {"type": "object"},
                        "code_context": {"type": "object"},
                    },
                },
                "handler": self._run_sast_replay,
            },
            "verify_source_sink": {
                "name": "verify_source_sink",
                "description": "Run deterministic source-to-sink and false-positive checks.",
                "input_schema": {
                    "type": "object",
                    "required": ["candidate", "code_context"],
                    "properties": {
                        "candidate": {"type": "object"},
                        "code_context": {"type": "object"},
                    },
                },
                "handler": self._verify_source_sink,
            },
            "build_evidence_chain": {
                "name": "build_evidence_chain",
                "description": "Build a structured evidence chain from MCP tool outputs.",
                "input_schema": {
                    "type": "object",
                    "required": ["heuristic_result", "sast_replay", "tool_calls"],
                    "properties": {
                        "heuristic_result": {"type": "object"},
                        "sast_replay": {"type": "object"},
                        "tool_calls": {"type": "array"},
                    },
                },
                "handler": self._build_evidence_chain,
            },
            "extract_target_function": {
                "name": "extract_target_function",
                "description": "Extract the vulnerable function source around a finding for harness building.",
                "input_schema": {
                    "type": "object",
                    "required": ["candidate"],
                    "properties": {
                        "candidate": {"type": "object"},
                        "code_root": {"type": ["string", "null"]},
                    },
                },
                "handler": self._extract_target_function,
            },
            "generate_fuzzing_harness": {
                "name": "generate_fuzzing_harness",
                "description": "Generate a template-based mock fuzzing harness for a vulnerability type (offline fallback).",
                "input_schema": {
                    "type": "object",
                    "required": ["vuln_type"],
                    "properties": {
                        "vuln_type": {"type": "string"},
                        "code_snippet": {"type": ["string", "null"]},
                    },
                },
                "handler": self._generate_fuzzing_harness,
            },
            "run_fuzzing_harness": {
                "name": "run_fuzzing_harness",
                "description": "Execute a fuzzing harness (Python / JavaScript / PHP) in a Docker sandbox (Docker-first for LLM code) and return a structured verdict (target_confirmed / mechanism_confirmed / not_reproduced / inconclusive / sandbox_failed / unsafe_harness_blocked).",
                "input_schema": {
                    "type": "object",
                    "required": ["harness_code"],
                    "properties": {
                        "harness_code": {"type": "string"},
                        "timeout": {"type": ["integer", "null"]},
                        "language": {"type": ["string", "null"],
                                     "description": "python | javascript | php（默认 python）"},
                        "source": {"type": ["string", "null"],
                                   "description": "llm | template（llm 走安全审查 + Docker-first）"},
                        "require_docker": {"type": ["boolean", "null"],
                                           "description": "为 true 时 Docker 不可用返回 sandbox_failed，不本地回退"},
                        "verification_level": {"type": ["string", "null"],
                                               "description": "target_specific | template_mechanism | none（信息性）"},
                    },
                },
                "handler": self._run_fuzzing_harness,
            },
            "run_harness_code": {
                "name": "run_harness_code",
                "description": (
                    "Execute one disposable, network-disabled harness-code sandbox and return "
                    "structured execution evidence. This is the generic sandbox tool; "
                    "run_fuzzing_harness remains its backwards-compatible alias."
                ),
                "input_schema": {
                    "type": "object",
                    "required": ["code"],
                    "properties": {
                        "code": {"type": "string"},
                        "timeout": {"type": ["integer", "null"]},
                        "language": {"type": ["string", "null"]},
                        "source": {"type": ["string", "null"]},
                        "require_docker": {"type": ["boolean", "null"]},
                        "scaffold_token": {"type": ["string", "null"]},
                        "code_root": {"type": ["string", "null"]},
                        "harness_kind": {"type": ["string", "null"]},
                    },
                },
                "handler": self._run_harness_code,
            },
            # ---------------------------------------------------------------- #
            # 新增工具                                                           #
            # ---------------------------------------------------------------- #
            "dynamic_http_verify": {
                "name": "dynamic_http_verify",
                "description": (
                    "Verify a vulnerability dynamically by sending exploit payloads to a running target. "
                    "Reuses backend/verifier/dynamic_verifier.py. "
                    "When base_url is empty/null, returns reproduction_status='not_executed' "
                    "(not 'not_reproduced'). "
                    "not_reproduced is reserved for 'executed but indicator not matched'."
                ),
                "input_schema": {
                    "type": "object",
                    "required": ["finding", "exploit"],
                    "properties": {
                        "finding": {"type": "object"},
                        "exploit": {"type": "object"},
                        "base_url": {"type": ["string", "null"]},
                        "endpoints": {"type": ["array", "null"]},
                        "payloads": {"type": ["array", "null"]},
                        "success_indicators": {"type": ["array", "null"]},
                    },
                },
                "handler": self._dynamic_http_verify,
            },
            "build_final_evidence": {
                "name": "build_final_evidence",
                "description": "Build a comprehensive evidence chain from static verification, exploit, dynamic HTTP, and harness results.",
                "input_schema": {
                    "type": "object",
                    "required": ["verify_result"],
                    "properties": {
                        "verify_result": {"type": "object"},
                        "exploit": {"type": ["object", "null"]},
                        "dynamic": {"type": ["object", "null"]},
                        "harness": {"type": ["object", "null"]},
                        "poc_result": {"type": ["object", "null"]},
                    },
                },
                "handler": self._build_final_evidence,
            },
            "resolve_symbol": {
                "name": "resolve_symbol",
                "description": ("Vulnhuntr-style cross-file symbol resolver: find the definition "
                                "of a function/class/variable by name across the project, so an "
                                "agent can recursively expand the call chain from user input to sink."),
                "input_schema": {
                    "type": "object",
                    "required": ["symbol"],
                    "properties": {
                        "symbol": {"type": "string"},
                        "code_root": {"type": ["string", "null"]},
                        "max_defs": {"type": "integer", "default": 3},
                    },
                },
                "handler": self._resolve_symbol,
            },
        }

    def list_tools(self) -> list[dict[str, Any]]:
        """Return MCP-style tool descriptors without Python callables."""
        return [
            {key: value for key, value in tool.items() if key != "handler"}
            for tool in self._tools.values()
        ]

    def call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """Call one registered tool and return MCP-style structured content."""
        tool = self._tools.get(name)
        if not tool:
            available = ", ".join(sorted(self._tools))
            raise ValueError(f"Unknown MCP tool '{name}'. Available tools: {available}")
        handler: Callable[[dict[str, Any]], dict[str, Any]] = tool["handler"]
        result = handler(arguments)
        return {
            "content": [{"type": "text", "text": f"{name} completed"}],
            "structuredContent": result,
        }

    @staticmethod
    def _retrieve_security_knowledge(arguments: dict[str, Any]) -> dict[str, Any]:
        return SecurityKnowledgeRetriever().retrieve(
            query=arguments.get("query") or "",
            candidate=arguments.get("candidate") or {},
            limit=int(arguments.get("limit") or 3),
        )

    @staticmethod
    def _retrieve_verification_playbook(arguments: dict[str, Any]) -> dict[str, Any]:
        return SecurityKnowledgeRetriever().retrieve_playbook(
            arguments.get("candidate") or {},
            limit=int(arguments.get("limit") or 2),
        )

    @staticmethod
    def _retrieve_remediation_advice(arguments: dict[str, Any]) -> dict[str, Any]:
        return SecurityKnowledgeRetriever().retrieve_remediation(
            arguments.get("candidate") or {},
            limit=int(arguments.get("limit") or 2),
        )

    @staticmethod
    def _read_code_context(arguments: dict[str, Any]) -> dict[str, Any]:
        code_root = arguments.get("code_root")
        return read_code_context(
            arguments.get("candidate") or {},
            Path(code_root) if code_root else None,
            radius=int(arguments.get("radius") or 8),
        )

    @staticmethod
    def _run_sast_replay(arguments: dict[str, Any]) -> dict[str, Any]:
        return run_local_sast_replay(
            arguments.get("candidate") or {},
            arguments.get("code_context") or {},
        )

    @staticmethod
    def _verify_source_sink(arguments: dict[str, Any]) -> dict[str, Any]:
        return run_heuristic_static_verifier(
            arguments.get("candidate") or {},
            arguments.get("code_context") or {},
        )

    @staticmethod
    def _build_evidence_chain(arguments: dict[str, Any]) -> dict[str, Any]:
        heuristic = arguments.get("heuristic_result") or {}
        return {
            "tool_calls": arguments.get("tool_calls") or [],
            "call_path": heuristic.get("call_path") or [],
            "checks": heuristic.get("checks") or [],
            "sast_replay": arguments.get("sast_replay") or {},
        }

    @staticmethod
    def _extract_target_function(arguments: dict[str, Any]) -> dict[str, Any]:
        candidate = arguments.get("candidate") or {}
        code_root = arguments.get("code_root")
        return extract_function(
            Path(code_root) if code_root else None,
            candidate.get("file") or candidate.get("file_path"),
            candidate.get("start_line") or candidate.get("line"),
        )

    @staticmethod
    def _generate_fuzzing_harness(arguments: dict[str, Any]) -> dict[str, Any]:
        harness = build_template_harness(
            arguments.get("vuln_type"), arguments.get("code_snippet"))
        return {"harness_code": harness, "source": "template"}

    @staticmethod
    def _run_fuzzing_harness(arguments: dict[str, Any]) -> dict[str, Any]:
        harness_code = arguments.get("harness_code") or ""
        source = arguments.get("source") or "llm"
        if source == "template" and not _is_builtin_template_harness(harness_code):
            return {
                "executed": False,
                "triggered": False,
                "verdict": "unsafe_harness_blocked",
                "reason": "unsafe_harness_blocked: unrecognized template harness",
                "safety": {
                    "allowed": False,
                    "blocked_reason": "unrecognized template harness",
                    "checks": ["BLOCK: source=template but code is not a built-in template"],
                },
            }
        return run_harness(
            harness_code,
            timeout=arguments.get("timeout"),
            language=arguments.get("language"),
            source=source,
            require_docker=arguments.get("require_docker"),
            scaffold_token=arguments.get("scaffold_token"),
            code_root=arguments.get("code_root"),
            harness_kind=arguments.get("harness_kind"),
        )

    @staticmethod
    def _run_harness_code(arguments: dict[str, Any]) -> dict[str, Any]:
        """通用一次性 Harness 沙箱；保持漏洞专用工具的兼容性。"""
        adapted = dict(arguments)
        adapted["harness_code"] = adapted.pop("code", "")
        return AuditMCPServer._run_fuzzing_harness(adapted)

    @staticmethod
    def _dynamic_http_verify(arguments: dict[str, Any]) -> dict[str, Any]:
        """动态 HTTP 验证工具实现。

        关键语义：
          - base_url 为空/None → reproduction_status = "not_executed"（未尝试执行）
          - 执行了但载荷未命中  → reproduction_status = "not_reproduced"
          - 连接失败           → reproduction_status = "connection_failed"
          - 全 404             → reproduction_status = "endpoint_not_found"
          - 请求超时           → reproduction_status = "request_timeout"
          - 命中成功特征        → reproduction_status = "dynamic_confirmed"

        复用 backend/verifier/dynamic_verifier.py，不重写 HTTP 逻辑。
        """
        # 延迟导入，避免顶层循环依赖
        from backend.verifier.dynamic_verifier import DynamicVerifier

        base_url = arguments.get("base_url") or ""
        exploit = dict(arguments.get("exploit") or {})
        endpoints = arguments.get("endpoints") or None

        # 若调用方传入了 payloads / success_indicators，合并进 exploit
        if arguments.get("payloads"):
            exploit.setdefault("payloads", arguments["payloads"])
        if arguments.get("success_indicators"):
            exploit.setdefault("success_indicators", arguments["success_indicators"])

        # ── 未配置目标：立即返回 not_executed ────────────────────────────
        if not base_url:
            return {
                "reproduction_status": "not_executed",
                "runtime_evidence": {
                    "request": None,
                    "response": None,
                    "matched_indicator": None,
                    "records": [],
                },
                "reason": "base_url 未配置，未尝试执行动态验证",
                "skipped": True,
            }

        from backend.dynamic.target_guard import validate_dynamic_base_url
        try:
            base_url = validate_dynamic_base_url(base_url)
        except ValueError as exc:
            return {
                "reproduction_status": "target_blocked",
                "runtime_evidence": {"request": None, "response": None, "matched_indicator": None, "records": []},
                "reason": str(exc),
                "skipped": True,
            }

        # ── 执行动态验证 ───────────────────────────────────────────────
        dv = DynamicVerifier()
        dr = dv.verify(base_url, exploit, endpoints)

        status = dr.reproduction_status or (
            "dynamic_confirmed" if dr.reproducible else "not_reproduced"
        )

        confirmed = dr.confirmed_record or {}
        return {
            "reproduction_status": status,
            "runtime_evidence": {
                "request": {
                    "url": confirmed.get("url"),
                    "method": confirmed.get("method"),
                    "params": confirmed.get("params"),
                    "payload": confirmed.get("payload"),
                },
                "response": {
                    "status_code": confirmed.get("status_code") or confirmed.get("status"),
                    "excerpt": (confirmed.get("response_excerpt") or "")[:400],
                    "elapsed_ms": confirmed.get("elapsed_ms"),
                },
                "matched_indicator": dr.matched_indicator or None,
                "records": dr.records[:10],
            },
            "reason": dr.reason,
            "error": dr.error,
            "logs": dr.logs[:10],
            "skipped": dr.skipped,
        }

    @staticmethod
    def _build_final_evidence(arguments: dict[str, Any]) -> dict[str, Any]:
        """汇总静/动/harness 证据链为统一结构。

        复用 EvidenceCollector.build()，补充 tool_calls 字段。
        """
        from backend.verifier.evidence_collector import EvidenceCollector

        verify_result = arguments.get("verify_result") or {}
        exploit = arguments.get("exploit") or None
        dynamic = arguments.get("dynamic") or None
        harness = arguments.get("harness") or None
        poc_result = arguments.get("poc_result") or None

        evidence = EvidenceCollector.build(
            verify_result,
            exploit=exploit,
            dynamic=dynamic,
            poc_result=poc_result,
            harness=harness,
        )
        evidence["_from_mcp"] = True
        return evidence

    @staticmethod
    def _resolve_symbol(arguments: dict[str, Any]) -> dict[str, Any]:
        """跨文件符号解析：按名字找函数/类定义源码，供调用链递归补全。"""
        code_root = arguments.get("code_root")
        return resolve_symbol(
            Path(code_root) if code_root else None,
            arguments.get("symbol") or "",
            max_defs=int(arguments.get("max_defs") or 3),
        )
