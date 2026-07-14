"""ACP Agent 流程测试：验证 run_acp() 接口、动态裁决语义、证据链构建、Trace 记录。

全部离线：LLM 调用全部 monkeypatch，HTTP 验证用注入式假探针，无真实端口。
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from backend.acp.factory import make_message
from backend.acp.models import (
    ACPContext, ACPMessageType, ACPState, ACPVerdict,
)
from backend.acp.adapters import raw_finding_to_acp, audit_finding_to_acp
from backend.acp.trace import ACPTracer
from backend.agents.verify_agent import VerifyAgent
from backend.agents.exploit_agent import ExploitAgent
from backend.verifier.evidence_collector import EvidenceCollector
from backend.verifier.dynamic_verifier import DynamicVerifier, ProbeRecord


# ---------------------------------------------------------------------------
# 辅助：构造测试用 ACP finding
# ---------------------------------------------------------------------------

def _sql_injection_finding(tmp_path: Path) -> dict:
    """SQL 注入候选 finding（ACP 统一结构）。"""
    (tmp_path / "app.py").write_text(
        "\n".join([
            "def get_user(uid, cur):",
            "    sql = 'select * from users where id=' + uid",
            "    return cur.execute(sql)",
        ]),
        encoding="utf-8",
    )
    return {
        "finding_id": "f-test-001",
        "type": "SQL Injection",
        "severity": "high",
        "location": {"file": "app.py", "start_line": 2, "end_line": 2},
        "code": {"snippet": "sql = 'select * from users where id=' + uid"},
        "source": {"agent": "audit_agent", "tool": "semgrep", "rule_id": "sqli"},
        "description": "SQL 注入候选",
        "extra": {"confidence": 0.8, "code_root": str(tmp_path)},
    }


# ---------------------------------------------------------------------------
# 1. RawFinding → ACP finding 转换
# ---------------------------------------------------------------------------

class _RF:
    def __init__(self, **kw): self.__dict__.update(kw)


def test_raw_finding_to_acp_finding():
    rf = _RF(type="SQL Injection", file="a.py", line=10, severity="high",
             source="semgrep", code_snippet="...", message="msg", rule_id="r1", extra={})
    result = raw_finding_to_acp(rf)
    assert result["type"] == "SQL Injection"
    assert result["location"]["start_line"] == 10
    assert result["source"]["tool"] == "semgrep"


# ---------------------------------------------------------------------------
# 2. AuditAgent finding → 统一 ACP finding
# ---------------------------------------------------------------------------

def test_audit_finding_to_acp_finding():
    lf = {
        "vulnerability_type": "Command Injection",
        "severity": "critical",
        "file_path": "run.py",
        "start_line": 5,
        "end_line": 5,
        "vulnerable_code": "os.system(cmd)",
        "confidence": 0.9,
    }
    result = audit_finding_to_acp(lf)
    assert result["type"] == "Command Injection"
    assert result["location"]["file"] == "run.py"
    assert result["source"]["agent"] == "audit_agent"


# ---------------------------------------------------------------------------
# 3. VerifyAgent.run_acp() 输出 verify.result
# ---------------------------------------------------------------------------

def test_verify_agent_run_acp_returns_verify_result(monkeypatch, tmp_path: Path):
    """VerifyAgent.run_acp() 必须返回 message_type=verify.result 的 ACPMessage。"""
    monkeypatch.setattr(VerifyAgent, "_call", lambda self, c: {
        "is_valid": True, "confidence": 0.85,
        "source": "uid", "sink": "cursor.execute",
        "call_path": [{"stage": "source", "detail": "uid"}],
    })

    agent = VerifyAgent()
    acp_finding = _sql_injection_finding(tmp_path)
    req = make_message(
        sender="orchestrator",
        receiver="verify_agent",
        message_type=ACPMessageType.VERIFY_REQUEST,
        context=ACPContext(scan_id="s1"),
        payload={"finding": acp_finding},
    )
    reply = agent.run_acp(req)

    # ACPMessageType 是 str enum，.value 取值字符串（兼容 Python 3.9）
    assert reply.header.message_type == ACPMessageType.VERIFY_RESULT
    assert reply.header.sender == "verify_agent"
    assert reply.header.receiver == "orchestrator"
    assert reply.header.in_reply_to == req.header.message_id
    assert "verification" in reply.payload
    vinfo = reply.payload["verification"]
    assert vinfo["static_verdict"] in ("confirmed", "false_positive", "uncertain", "needs_review")
    assert "dynamic_verdict" in vinfo
    assert "final_verdict" in vinfo
    assert vinfo["final_verdict"] in ("statically_verified", "needs_review")
    assert "source" in vinfo
    assert "call_path" in vinfo
    assert reply.status.confidence is not None


def test_verify_agent_run_acp_conflict_is_needs_review(monkeypatch, tmp_path: Path):
    """LLM 确认为漏洞、本地启发式判安全（参数化查询）时：不静默丢成 false_positive，
    而是标为 needs_review 交人工复核（避免真实漏洞被 naive 正则悄悄吞掉）。"""
    (tmp_path / "app.py").write_text(
        "def get_user(uid, cur):\n    return cur.execute('SELECT * FROM users WHERE id=?', (uid,))\n",
        encoding="utf-8",
    )
    # LLM 明确说 is_valid=True，但本地启发式认为参数化查询是安全的 -> 冲突
    monkeypatch.setattr(VerifyAgent, "_call", lambda self, c: {"is_valid": True, "confidence": 0.6})

    agent = VerifyAgent()
    acp_finding = {
        "finding_id": "f-fp",
        "type": "SQL Injection",
        "severity": "high",
        "location": {"file": "app.py", "start_line": 2},
        "code": {"snippet": "cur.execute('SELECT * FROM users WHERE id=?', (uid,))"},
        "source": {"agent": "audit_agent", "tool": "", "rule_id": ""},
        "extra": {"code_root": str(tmp_path)},
    }
    req = make_message(
        sender="orchestrator",
        receiver="verify_agent",
        message_type=ACPMessageType.VERIFY_REQUEST,
        payload={"finding": acp_finding},
    )
    reply = agent.run_acp(req)
    vinfo = reply.payload["verification"]
    # 冲突 -> needs_review（不是 false_positive，也不是无脑 confirmed），并记录分歧原因
    assert vinfo["static_verdict"] == "needs_review"
    assert vinfo["final_verdict"] == "needs_review"
    assert vinfo["false_positive_reason"]


def test_verify_agent_run_acp_false_positive_when_llm_not_confirming(monkeypatch, tmp_path: Path):
    """LLM 未确认（此处报错）+ 本地启发式判安全 -> 仍判 false_positive（启发式否决生效）。"""
    (tmp_path / "app.py").write_text(
        "def get_user(uid, cur):\n    return cur.execute('SELECT * FROM users WHERE id=?', (uid,))\n",
        encoding="utf-8",
    )
    # LLM 调用失败/未确认
    monkeypatch.setattr(VerifyAgent, "_call", lambda self, c: {"_error": "llm unavailable"})

    acp_finding = {
        "finding_id": "f-fp2", "type": "SQL Injection", "severity": "high",
        "location": {"file": "app.py", "start_line": 2},
        "code": {"snippet": "cur.execute('SELECT * FROM users WHERE id=?', (uid,))"},
        "source": {"agent": "audit_agent"}, "extra": {"code_root": str(tmp_path)},
    }
    req = make_message(sender="orchestrator", receiver="verify_agent",
                       message_type=ACPMessageType.VERIFY_REQUEST, payload={"finding": acp_finding})
    vinfo = VerifyAgent().run_acp(req).payload["verification"]
    assert vinfo["static_verdict"] == "false_positive"
    assert vinfo["final_verdict"] == "false_positive"


# ---------------------------------------------------------------------------
# 4. ExploitAgent.run_acp() 输出 exploit.generate.result
# ---------------------------------------------------------------------------

def test_exploit_agent_run_acp_returns_validation_metadata_for_unconfirmed_finding(monkeypatch):
    """未确认 ACP finding 只返回验证元数据，绝不附带可执行 exploit artifact。"""
    # 禁用 LLM，走模板兜底
    monkeypatch.setattr(ExploitAgent, "_call", lambda self, c: {"_error": "llm disabled"})

    agent = ExploitAgent()
    acp_finding = {
        "finding_id": "f-002",
        "type": "SQL Injection",
        "severity": "high",
        "location": {"file": "db.py", "start_line": 10},
        "code": {"snippet": "cursor.execute(q + uid)"},
        "source": {"agent": "audit_agent", "tool": "semgrep", "rule_id": "sqli"},
        "extra": {"confidence": 0.8},
    }
    verification = {
        "source": "uid",
        "sink": "cursor.execute",
        "call_path": [{"stage": "source", "detail": "uid"}, {"stage": "sink", "detail": "cursor.execute"}],
    }
    req = make_message(
        sender="orchestrator",
        receiver="exploit_agent",
        message_type=ACPMessageType.EXPLOIT_GENERATE_REQUEST,
        payload={"finding": acp_finding, "verification": verification},
    )
    reply = agent.run_acp(req)

    assert reply.header.message_type == ACPMessageType.EXPLOIT_GENERATE_RESULT
    assert reply.header.sender == "exploit_agent"
    assert "exploit" in reply.payload
    ep = reply.payload["exploit"]
    assert ep["vuln_type"] or ep["trigger_location"]    # 至少有一个利用字段
    assert isinstance(ep["payloads"], list)
    assert ep["exploit_code"] is None
    assert ep["code_kind"] == "candidate_metadata"
    assert ep["generation_status"] == "validation_pending"
    assert ep["validation_status"] == "validation_pending"
    assert ep["exploit_path"]
    assert ep["success_indicators"]
    assert reply.status.verdict == ACPVerdict.NEEDS_REVIEW
    assert not any(a.artifact_type == "exploit_code" for a in reply.artifacts)


# ---------------------------------------------------------------------------
# 5. EvidenceCollector.build_from_acp() 构建证据链
# ---------------------------------------------------------------------------

def test_evidence_collector_build_from_acp_static_confirmation_keeps_validation_metadata_without_code():
    """静态 confirmed、动态未执行的 ACP 证据仅保留计划元数据，不暴露候选代码。"""
    verify_msg = make_message(
        sender="verify_agent",
        receiver="orchestrator",
        message_type=ACPMessageType.VERIFY_RESULT,
        payload={
            "verification": {
                "static_verdict": "confirmed",
                "dynamic_verdict": "not_executed",
                "final_verdict": "confirmed",
                "source": "uid",
                "sink": "cursor.execute",
                "call_path": [{"stage": "source", "detail": "uid"}, {"stage": "sink", "detail": "cursor.execute"}],
                "evidence_chain": {},
                "mcp_server": "audit-mcp",
                "skill": {"name": "vulnerability_verification", "version": "2.0"},
                "confidence": 0.85,
            }
        },
        tools=[
            {"tool_name": "verify_source_sink", "input": {}, "output": {"valid": True}, "success": True},
            {"tool_name": "retrieve_security_knowledge", "input": {}, "output": {"cwe_id": "CWE-89"}, "success": True},
        ],
        verdict=ACPVerdict.STATICALLY_VERIFIED,
        confidence=0.85,
    )
    exploit_msg = make_message(
        sender="exploit_agent",
        receiver="orchestrator",
        message_type=ACPMessageType.EXPLOIT_GENERATE_RESULT,
        payload={
            "exploit": {
                "vuln_type": "SQL Injection",
                "trigger_location": "db.py:10",
                "exploit_path": "uid -> cursor.execute",
                "payloads": ["1' OR '1'='1"],
                "exploit_code": "import httpx\n# poc",
                "success_indicators": ["SQL syntax"],
            }
        },
        verdict=ACPVerdict.EXPLOIT_GENERATED,
    )

    evidence = EvidenceCollector.build_from_acp([verify_msg, exploit_msg])

    # 静态证据
    assert evidence["source"] == "uid"
    assert evidence["sink"] == "cursor.execute"
    assert evidence["call_path"]
    # 利用证据：输入中即使含有遗留候选代码，也不能在静态阶段透出。
    assert evidence["exploit"]["trigger_location"] == "db.py:10"
    assert evidence["exploit"]["exploit_code"] is None
    assert evidence["exploit"]["code_kind"] == "candidate_metadata"
    assert evidence["exploit"]["generation_status"] == "validation_pending"
    assert evidence["attack_plan"]["plan_status"] == "static_confirmed_pending_runtime"
    assert evidence["attack_plan"]["code"] is None
    assert evidence["attack_plan"]["code_kind"] == "candidate_metadata"
    assert evidence["runtime"]["reproduction_status"] == "not_executed"
    assert evidence["harness"]["verdict"] == "not_executed"
    assert evidence["verification"]["mcp_server"] == "audit-mcp"
    assert evidence["verification"]["skill"]["version"] == "2.0"
    assert evidence["verification"]["dynamic_verdict"] == "not_executed"
    assert evidence["verification"]["final_verdict"] == "confirmed"
    # ACP 专属字段
    assert isinstance(evidence["agent_messages"], list)
    assert len(evidence["agent_messages"]) == 2
    assert isinstance(evidence["tool_calls"], list)
    assert len(evidence["tool_calls"]) == 2


def test_evidence_collector_build_from_acp_http_confirmation_withholds_code_until_persisted():
    """ACP 确认记录可重建候选回放，但未持久化制品前 API 仍不得返回代码。"""
    verify_msg = make_message(
        sender="verify_agent", receiver="orchestrator",
        message_type=ACPMessageType.VERIFY_RESULT,
        payload={"verification": {
            "static_verdict": "confirmed", "dynamic_verdict": "not_executed",
            "final_verdict": "confirmed", "source": "uid", "sink": "cursor.execute",
            "call_path": [{"stage": "source", "detail": "uid"},
                          {"stage": "sink", "detail": "cursor.execute"}],
        }},
    )
    exploit_msg = make_message(
        sender="exploit_agent", receiver="orchestrator",
        message_type=ACPMessageType.EXPLOIT_GENERATE_RESULT,
        payload={"exploit": {
            "vuln_type": "SQL Injection", "trigger_location": "db.py:10",
            "payloads": ["candidate"], "exploit_code": "print('untrusted candidate')",
        }},
    )
    dynamic_msg = make_message(
        sender="dynamic_analysis_agent", receiver="orchestrator",
        message_type=ACPMessageType.DYNAMIC_VERIFY_RESULT,
        payload={
            "runtime": {
                "reproduction_status": "dynamic_confirmed", "reproducible": True,
                "matched_indicator": "SQL syntax",
                "confirmed_record": {
                    "url": "http://127.0.0.1:8080/search?id=confirmed",
                    "method": "POST", "params": {"id": "confirmed"},
                    "payload": "confirmed", "transport": "json",
                },
            },
            "exploit": {"setup_requests": []},
            "verification": {"dynamic_verdict": "dynamic_confirmed", "final_verdict": "dynamic_confirmed"},
        },
        verdict=ACPVerdict.DYNAMIC_CONFIRMED,
    )

    evidence = EvidenceCollector.build_from_acp([verify_msg, exploit_msg, dynamic_msg])

    assert evidence["exploit"]["exploit_code"] is None
    assert evidence["attack_plan"]["code"] is None
    assert "untrusted candidate" not in str(evidence)


def test_evidence_collector_build_from_acp_target_harness_withholds_code_until_persisted():
    """入口级 Harness 也必须等对应制品持久化，不能经 ACP 直接泄露源码。"""
    verify_msg = make_message(
        sender="verify_agent", receiver="orchestrator",
        message_type=ACPMessageType.VERIFY_RESULT,
        payload={"verification": {
            "static_verdict": "confirmed", "final_verdict": "confirmed",
            "source": "command", "sink": "os.system",
            "call_path": [{"stage": "source", "detail": "command"},
                          {"stage": "sink", "detail": "os.system"}],
        }},
    )
    exploit_msg = make_message(
        sender="exploit_agent", receiver="orchestrator",
        message_type=ACPMessageType.EXPLOIT_GENERATE_RESULT,
        payload={"exploit": {"vuln_type": "Command Injection", "exploit_code": "candidate"}},
    )
    harness_code = "# framework-attested target harness\nprint('triggered')"
    harness_msg = make_message(
        sender="dynamic_analysis_agent", receiver="orchestrator",
        message_type=ACPMessageType.HARNESS_VERIFY_RESULT,
        payload={"harness": {
            "verdict": "target_confirmed", "dynamically_triggered": True,
            "function_extracted": True, "target_function_called": True,
            "verification_level": "entrypoint_reproduced", "entrypoint_reachable": True,
            "harness_code": harness_code,
        }},
        verdict=ACPVerdict.HARNESS_CONFIRMED,
    )

    evidence = EvidenceCollector.build_from_acp([verify_msg, exploit_msg, harness_msg])

    assert evidence["verification"]["dynamic_method"] == "target_harness"
    assert evidence["exploit"]["exploit_code"] is None
    assert evidence["attack_plan"]["code"] is None
    assert evidence["harness"]["harness_code"] is None
    assert evidence["harness"]["harness_code_sha256"]


def test_build_from_acp_parses_dynamic_runtime_payload():
    """回归：build_from_acp 要能解析 DynamicAnalysisAgent 发的 payload['runtime']（扁平 dyn_result），
    而不是只认旧的 payload['dynamic']/runtime_evidence 结构。"""
    dyn_msg = make_message(
        sender="dynamic_analysis_agent", receiver="orchestrator",
        message_type=ACPMessageType.DYNAMIC_VERIFY_RESULT,
        payload={
            "finding": {},
            "runtime": {
                "reproduction_status": "dynamic_confirmed",
                "reproducible": True,
                "matched_indicator": "SQL syntax error",
                "confirmed_record": {"url": "http://t/u", "payload": "1' OR '1'='1"},
                "records": [{"url": "http://t/u"}],
                "reason": "",
            },
            "verification": {"dynamic_verdict": "dynamic_confirmed", "final_verdict": "dynamic_confirmed"},
        },
        verdict=ACPVerdict.DYNAMIC_CONFIRMED,
    )
    candidate_msg = make_message(
        sender="exploit_agent", receiver="orchestrator",
        message_type=ACPMessageType.EXPLOIT_GENERATE_RESULT,
        payload={"exploit": {"exploit_code": "print('untrusted candidate')"}},
    )
    evidence = EvidenceCollector.build_from_acp([candidate_msg, dyn_msg])
    rt = evidence["runtime"]
    assert rt["reproduction_status"] == "dynamic_confirmed"
    assert rt["reproducible"] is True
    assert rt["matched_indicator"] == "SQL syntax error"
    # 旧 ACP 记录没有可绑定的请求参数时，仍可解析运行事实，但绝不能生成 PoC。
    assert evidence["exploit"]["exploit_code"] is None
    assert evidence["exploit"]["failure_code"] == "incomplete_confirmed_http_record"
    assert evidence["attack_plan"] is None or evidence["attack_plan"]["code"] is None
    assert "untrusted candidate" not in str(evidence)


# ---------------------------------------------------------------------------
# 6. 未配置 base_url 时 dynamic_verdict = not_executed（不是 not_reproduced）
# ---------------------------------------------------------------------------

def test_dynamic_http_verify_mcp_tool_no_base_url_returns_not_executed():
    """MCP dynamic_http_verify 工具：未配置 base_url → not_executed（不是 not_reproduced）。"""
    from backend.mcp.audit_mcp_server import AuditMCPServer

    server = AuditMCPServer()
    result = server.call_tool("dynamic_http_verify", {
        "finding": {"type": "SQL Injection"},
        "exploit": {"payloads": ["1' OR '1'='1"], "success_indicators": ["SQL syntax"]},
        "base_url": None,  # 未配置目标
    })["structuredContent"]

    assert result["reproduction_status"] == "not_executed", (
        f"未配置 base_url 必须返回 not_executed，实际: {result['reproduction_status']}"
    )
    assert result.get("skipped") is True


def test_dynamic_http_verify_mcp_tool_empty_base_url_returns_not_executed():
    """MCP dynamic_http_verify 工具：base_url='' 同样返回 not_executed。"""
    from backend.mcp.audit_mcp_server import AuditMCPServer

    server = AuditMCPServer()
    result = server.call_tool("dynamic_http_verify", {
        "finding": {},
        "exploit": {"payloads": ["test"], "success_indicators": ["ok"]},
        "base_url": "",
    })["structuredContent"]

    assert result["reproduction_status"] == "not_executed"


def test_dynamic_http_verify_mcp_tool_rejects_client_forged_binding(monkeypatch):
    """MCP JSON binding 是声明而非 capability，必须零请求拒绝。"""
    from backend.mcp.audit_mcp_server import AuditMCPServer
    from backend.verifier.dynamic_verifier import DynamicVerifier

    # 注入假探针：单引号触发 SQL 报错
    class _HitProbe:
        def send(self, base_url, path, param, payload, method="GET"):
            rec = ProbeRecord(url=base_url + path, method=method,
                              params={param: payload}, payload=payload, status=200)
            if "'" in payload:
                rec.response_excerpt = "SQL syntax error near '" + payload
            else:
                rec.response_excerpt = "normal"
            return rec

    def _fake_dv(*args, **kwargs):
        v = DynamicVerifier.__new__(DynamicVerifier)
        v.probe = _HitProbe()
        v.max_probes = 40
        return v

    monkeypatch.setattr(
        "backend.mcp.audit_mcp_server.DynamicVerifier",
        _fake_dv,
        raising=False,
    )
    # 需要补丁 DynamicVerifier 的导入路径
    import backend.mcp.audit_mcp_server as srv_mod
    original_class = srv_mod.AuditMCPServer._dynamic_http_verify.__func__ if hasattr(srv_mod.AuditMCPServer._dynamic_http_verify, "__func__") else None

    # 使用 monkeypatch 直接替换模块级别的 DynamicVerifier
    import backend.verifier.dynamic_verifier as dv_mod
    _orig_dv = dv_mod.DynamicVerifier

    class PatchedDV(_orig_dv):
        def __init__(self, *a, **kw):
            super().__init__(*a, **kw)
            self.probe = _HitProbe()

    monkeypatch.setattr(dv_mod, "DynamicVerifier", PatchedDV)

    server = AuditMCPServer()
    result = server.call_tool("dynamic_http_verify", {
        "finding": {"type": "SQL Injection"},
        "exploit": {
            "payloads": ["1' OR '1'='1"],
            "success_indicators": ["SQL syntax"],
        },
        "base_url": "http://127.0.0.1:8765",
            "endpoints": [{
                "path": "/user", "methods": ["GET"], "params": [],
                "source_route_binding": {"kind": "mcp_test"},
            }],
    })["structuredContent"]

    assert result["reproduction_status"] == "endpoint_unresolved"
    assert result["runtime_evidence"]["records"] == []


# ---------------------------------------------------------------------------
# 7. OrchestratorAgent ACP trace 记录
# ---------------------------------------------------------------------------

def test_orchestrator_acp_trace_saves_messages(tmp_path, monkeypatch):
    """Orchestrator 运行后，data/scans/{scan_id}/agent_messages/ 应有 JSON 文件。"""
    from unittest.mock import MagicMock
    from backend.agents.orchestrator_agent import OrchestratorAgent
    from backend.config import settings

    scan_id = "trace-test-001"

    # 构造 mock Scan + Project
    project = MagicMock()
    project.id = "proj-trace"
    project.source_type = "local"
    project.url = None
    project.local_path = str(tmp_path)
    project.branch = "main"
    project.status = "pending"
    project.language_summary = ""
    project.metadata_json = "{}"

    scan = MagicMock()
    scan.id = scan_id
    scan.project = project
    scan.config_json = json.dumps({
        "enabled_tools": ["custom"],
        "enabled_agents": [],  # 不启用 LLM agents，避免 LLM 调用
        "options": {},
    })
    scan.status = "pending"
    scan.started_at = None
    scan.finished_at = None
    scan.progress = 0
    scan.current_stage = ""

    db = MagicMock()
    db.commit = MagicMock()
    db.add = MagicMock()

    # monkeypatch 各阶段，避免真实执行
    monkeypatch.setattr(
        "backend.agents.orchestrator_agent.prepare_workspace",
        lambda *a, **kw: tmp_path,
    )
    monkeypatch.setattr(
        "backend.agents.orchestrator_agent.RepoParserAgent.run",
        lambda self, code_root: {"languages": ["Python"], "file_count": 1, "frameworks": []},
    )
    monkeypatch.setattr(
        "backend.agents.orchestrator_agent.StaticScanAgent.run",
        lambda self, code_root, tools: [],
    )

    # 确保 data_path 指向 tmp_path
    monkeypatch.setattr(settings, "data_dir", str(tmp_path), raising=False)

    orch = OrchestratorAgent(db=db, scan=scan)
    # 覆盖 tracer 的 base_dir 到 tmp_path
    msg_dir = tmp_path / "scans" / scan_id / "agent_messages"
    orch.tracer.base_dir = msg_dir

    orch.run()

    # 检查 agent_messages 目录下有 JSON 文件
    assert msg_dir.exists(), "agent_messages 目录必须被创建"
    json_files = list(msg_dir.glob("*.json"))
    assert len(json_files) >= 2, f"至少应有 scan.start 和 scan.complete 两条消息，实际: {len(json_files)}"

    # 验证消息结构正确（不依赖文件排序：所有消息都应是合法 ACP 消息）
    all_msgs = [json.loads(fp.read_text(encoding="utf-8")) for fp in json_files]
    for m in all_msgs:
        assert "header" in m
        assert m["header"]["protocol"] == "AuditAgentX-ACP"
    # 编排器至少发出过一条以 orchestrator_agent 为 sender 的消息（如 scan.start）
    senders = {m["header"]["sender"] for m in all_msgs}
    assert "orchestrator_agent" in senders


# ---------------------------------------------------------------------------
# 8. ACPTracer save / load 往返
# ---------------------------------------------------------------------------

def test_acp_tracer_save_and_load(tmp_path):
    """ACPTracer.save() + load_all() 往返必须无损。"""
    tracer = ACPTracer(scan_id="trace-001")
    tracer.base_dir = tmp_path / "agent_messages"

    msg = make_message(
        sender="agent_a",
        receiver="agent_b",
        message_type=ACPMessageType.VERIFY_REQUEST,
        context=ACPContext(scan_id="trace-001"),
        payload={"key": "val"},
        verdict=ACPVerdict.CANDIDATE,
        confidence=0.5,
    )
    tracer.save(msg)

    loaded = tracer.load_all()
    assert len(loaded) == 1
    restored = loaded[0]
    assert restored.header.message_id == msg.header.message_id
    assert restored.header.sender == "agent_a"
    assert restored.payload == {"key": "val"}
    assert restored.status.verdict == ACPVerdict.CANDIDATE


def test_acp_tracer_summary(tmp_path):
    """ACPTracer.summary() 返回消息摘要列表。"""
    tracer = ACPTracer(scan_id="trace-002")
    tracer.base_dir = tmp_path / "agent_messages"

    for mtype in [ACPMessageType.SCAN_START, ACPMessageType.VERIFY_REQUEST]:
        msg = make_message(
            sender="orch", receiver="agent",
            message_type=mtype,
            context=ACPContext(scan_id="trace-002"),
        )
        tracer.save(msg)

    summary = tracer.summary()
    assert len(summary) == 2
    types = {s["message_type"] for s in summary}
    # summary() 里用 str(msg.header.message_type)，Python 3.9 str(StrEnum)='Name.VALUE'
    # 因此用 any() 匹配 value 字符串
    assert any("scan" in t.lower() or "start" in t.lower() for t in types)
    assert any("verify" in t.lower() for t in types)


def test_acp_tracer_load_by_type_accepts_enum_value(tmp_path):
    """动态阶段通过 Enum 序列化后，按协议 value 仍能被可靠筛选。"""
    tracer = ACPTracer(scan_id="trace-progress")
    tracer.base_dir = tmp_path / "agent_messages"
    tracer.save(make_message(
        sender="dynamic_analysis_agent", receiver="orchestrator_agent",
        message_type=ACPMessageType.DYNAMIC_PROGRESS,
        context=ACPContext(scan_id="trace-progress"),
        payload={"progress": {"phase": "http_verification", "completed": 1, "total": 2}},
    ))

    progress = tracer.load_by_type("dynamic.progress")
    assert len(progress) == 1
    assert progress[0].payload["progress"]["phase"] == "http_verification"


# ---------------------------------------------------------------------------
# 9. build_final_evidence MCP 工具
# ---------------------------------------------------------------------------

def test_build_final_evidence_mcp_tool():
    """build_final_evidence MCP 工具必须返回 source/sink/exploit 字段。"""
    from backend.mcp.audit_mcp_server import AuditMCPServer

    server = AuditMCPServer()
    result = server.call_tool("build_final_evidence", {
        "verify_result": {
            "source": "uid",
            "sink": "cursor.execute",
            "propagation_path": "uid -> sql -> cursor.execute",
        },
        "exploit": {
            "trigger_location": "db.py:10",
            "exploit_path": "uid -> cursor.execute",
            "payloads": ["1' OR '1'='1"],
            "exploit_code": "import httpx\n# poc",
        },
    })["structuredContent"]

    assert result["source"] == "uid"
    assert result["sink"] == "cursor.execute"
    assert result["exploit"]["trigger_location"] == "db.py:10"
    assert result.get("_from_mcp") is True


# ---------------------------------------------------------------------------
# 10. MCP 工具清单包含新工具
# ---------------------------------------------------------------------------

def test_mcp_server_exposes_new_tools():
    """MCP server 工具清单必须包含 dynamic_http_verify 和 build_final_evidence。"""
    from backend.mcp.audit_mcp_server import AuditMCPServer

    server = AuditMCPServer()
    tool_names = {t["name"] for t in server.list_tools()}
    assert "dynamic_http_verify" in tool_names
    assert "build_final_evidence" in tool_names
    # 原有工具仍然保留
    assert "read_code_context" in tool_names
    assert "run_sast_replay" in tool_names


# ---------------------------------------------------------------------------
# 11. RepoParserAgent.run_acp() 输出 parse.result
# ---------------------------------------------------------------------------

def test_repo_parser_run_acp_returns_parse_result(tmp_path: Path):
    from backend.agents.repo_parser_agent import RepoParserAgent

    (tmp_path / "app.py").write_text("def f():\n    return 1\n", encoding="utf-8")
    req = make_message(
        sender="orchestrator", receiver="repo_parser_agent",
        message_type=ACPMessageType.PARSE_REQUEST,
        payload={"code_root": str(tmp_path)},
    )
    reply = RepoParserAgent().run_acp(req)
    assert reply.header.message_type == ACPMessageType.PARSE_RESULT
    assert reply.header.sender == "repo_parser_agent"
    assert reply.header.in_reply_to == req.header.message_id
    meta = reply.payload["metadata"]
    assert meta["file_count"] >= 1
    # metadata 是完整结构，不是只有 summary
    for key in ("languages", "frameworks", "dependencies", "entrypoints", "loc"):
        assert key in meta


def test_repo_parser_run_acp_missing_code_root_fails():
    from backend.agents.repo_parser_agent import RepoParserAgent

    req = make_message(
        sender="orchestrator", receiver="repo_parser_agent",
        message_type=ACPMessageType.PARSE_REQUEST, payload={},
    )
    reply = RepoParserAgent().run_acp(req)
    assert reply.status.state == ACPState.FAILED


# ---------------------------------------------------------------------------
# 12. DynamicAnalysisAgent.run_acp() 输出 dynamic.verify.result（裁决同步）
# ---------------------------------------------------------------------------

def test_dynamic_analysis_run_acp_not_executed_is_consistent():
    """全部动态开关关闭：dynamic_verdict=not_executed，且不得与 runtime 冲突。"""
    from backend.agents.dynamic_analysis_agent import DynamicAnalysisAgent

    req = make_message(
        sender="orchestrator", receiver="dynamic_analysis_agent",
        message_type=ACPMessageType.DYNAMIC_VERIFY_REQUEST,
        context=ACPContext(scan_id="s-dyn"),
        payload={
            "finding": {
                "type": "SQL Injection", "severity": "high",
                "location": {"file": "db.py", "start_line": 10},
                "code": {"snippet": "cursor.execute(q + uid)"},
            },
            "verification": {"static_verdict": "confirmed", "source": "uid", "sink": "cursor.execute"},
            "enable_exploit": False, "enable_dynamic": False, "enable_harness": False,
        },
    )
    reply = DynamicAnalysisAgent().run_acp(req)
    assert reply.header.message_type == ACPMessageType.DYNAMIC_VERIFY_RESULT
    vinfo = reply.payload["verification"]
    assert vinfo["dynamic_verdict"] == "not_executed"
    assert vinfo["final_verdict"] == "statically_verified"
    # runtime 为空即未执行——与 dynamic_verdict=not_executed 一致（验收标准四）
    assert not reply.payload["runtime"].get("reproduction_status") \
        or reply.payload["runtime"]["reproduction_status"] == "not_executed"


def test_dynamic_analysis_run_acp_does_not_reopen_false_positive(monkeypatch):
    """静态裁决为误报时，动态阶段不得强改 confirmed 或再次调用利用生成。"""
    from backend.agents.dynamic_analysis_agent import DynamicAnalysisAgent

    monkeypatch.setattr(
        "backend.agents.exploit_agent.ExploitAgent.run",
        lambda *_a, **_k: (_ for _ in ()).throw(AssertionError("false positive must be skipped")),
    )
    req = make_message(
        sender="orchestrator", receiver="dynamic_analysis_agent",
        message_type=ACPMessageType.DYNAMIC_VERIFY_REQUEST,
        context=ACPContext(scan_id="s-dyn-fp"),
        payload={
            "finding": {
                "type": "SQL Injection", "severity": "high",
                "location": {"file": "db.py", "start_line": 10},
                "code": {"snippet": "cursor.execute('SELECT 1')"},
            },
            "verification": {"static_verdict": "false_positive"},
            "enable_exploit": True, "enable_dynamic": False, "enable_harness": False,
        },
    )

    reply = DynamicAnalysisAgent().run_acp(req)

    assert reply.payload["findings"][0]["status"] == "false_positive"
    assert reply.payload["verification"]["final_verdict"] == "false_positive"
    assert reply.payload["exploit"] == {}


# ---------------------------------------------------------------------------
# 13. Orchestrator 主流程确实通过 _dispatch_acp() 调度（消息驱动，非旁路记录）
# ---------------------------------------------------------------------------

def test_orchestrator_main_flow_is_message_driven(tmp_path, monkeypatch):
    """主流程经 _dispatch_acp 调度：trace 中应有成对的 parse/static_scan request+reply 完整消息。"""
    from unittest.mock import MagicMock
    from backend.agents.orchestrator_agent import OrchestratorAgent
    from backend.config import settings

    scan_id = "dispatch-test-001"
    project = MagicMock()
    project.id = "proj-d"
    project.source_type = "local"
    project.url = None
    project.local_path = str(tmp_path)
    project.branch = "main"
    project.status = "pending"
    project.language_summary = ""
    project.metadata_json = "{}"

    scan = MagicMock()
    scan.id = scan_id
    scan.project = project
    scan.config_json = json.dumps({
        "enabled_tools": ["custom"], "enabled_agents": [],
        "options": {"enable_exploit": True},
    })
    scan.status = "pending"
    scan.started_at = None
    scan.finished_at = None
    scan.progress = 0
    scan.current_stage = ""

    db = MagicMock()

    monkeypatch.setattr(
        "backend.agents.orchestrator_agent.prepare_workspace", lambda *a, **kw: tmp_path)
    monkeypatch.setattr(
        "backend.agents.orchestrator_agent.RepoParserAgent.run",
        lambda self, code_root: {"languages": ["Python"], "frameworks": [],
                                 "dependencies": [], "entrypoints": [],
                                 "file_count": 1, "loc": 1, "tree": {}, "_files": []},
    )
    monkeypatch.setattr(
        "backend.agents.orchestrator_agent.StaticScanAgent.run",
        lambda self, code_root, tools: [],
    )
    monkeypatch.setattr(settings, "data_dir", str(tmp_path), raising=False)

    # 记录 _dispatch_acp 被调用的 message_type
    dispatched: list[str] = []
    original = OrchestratorAgent._dispatch_acp

    def _spy(self, request):
        dispatched.append(request.header.message_type.value
                          if hasattr(request.header.message_type, "value")
                          else str(request.header.message_type))
        return original(self, request)

    monkeypatch.setattr(OrchestratorAgent, "_dispatch_acp", _spy)

    orch = OrchestratorAgent(db=db, scan=scan)
    msg_dir = tmp_path / "scans" / scan_id / "agent_messages"
    orch.tracer.base_dir = msg_dir
    orch.run()

    # 主流程确实经 _dispatch_acp 发出了 parse.request 与 static_scan.request
    assert "parse.request" in dispatched
    assert "static_scan.request" in dispatched
    assert "dynamic.verify.request" in dispatched

    # trace 落盘的是完整 request+reply：应同时存在 request 与 result 两侧消息
    all_msgs = [json.loads(fp.read_text(encoding="utf-8")) for fp in msg_dir.glob("*.json")]
    types = [m["header"]["message_type"] for m in all_msgs]
    assert "parse.request" in types and "parse.result" in types
    assert "static_scan.request" in types and "static_scan.result" in types
    assert "dynamic.verify.request" in types and "dynamic.verify.result" in types
    # 完整结构：每条消息都含 header/context/payload/status（非仅 payload_summary）
    for m in all_msgs:
        assert {"header", "context", "payload", "status"} <= set(m.keys())
