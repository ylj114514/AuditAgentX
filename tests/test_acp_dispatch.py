"""ACP 消息驱动通信测试（做实：外部消息 → dispatcher → agent.run_acp → 回复）。"""
from unittest.mock import patch

from fastapi.testclient import TestClient

from backend.main import app
from backend.acp.factory import make_message
from backend.acp.models import ACPContext, ACPMessageType
from backend.acp.dispatcher import ACPDispatcher

client = TestClient(app)


def _verify_request():
    return make_message(
        sender="external_agent", receiver="auditagentx",
        message_type=ACPMessageType.VERIFY_REQUEST,
        payload={"finding": {"type": "SQL Injection",
                             "location": {"file": "app.py", "start_line": 21},
                             "code": {"snippet": "cursor.execute('x'+uid)"}}},
    )


def test_dispatcher_routes_verify_request():
    with patch("backend.agents.verify_agent.VerifyAgent._call", return_value={}):
        reply = ACPDispatcher().dispatch(_verify_request())
    assert reply.header.message_type.value == "verify.result"
    assert reply.header.sender == "verify_agent"


def test_dispatcher_unknown_type_returns_error():
    msg = make_message(sender="x", receiver="y",
                       message_type=ACPMessageType.HEARTBEAT, payload={})
    reply = ACPDispatcher().dispatch(msg)
    assert reply.header.message_type.value == "error"
    assert reply.status.state.value == "failed"


def test_acp_message_types_endpoint():
    r = client.get("/api/acp/message-types")
    assert r.status_code == 200
    body = r.json()
    assert body["protocol"] == "AuditAgentX-ACP"
    assert "verify.request" in body["supported_request_types"]


def test_external_agent_drives_verify_via_http():
    req = _verify_request()
    with patch("backend.agents.verify_agent.VerifyAgent._call", return_value={}):
        r = client.post("/api/acp/message", json=req.to_dict())
    assert r.status_code == 200
    body = r.json()
    assert body["header"]["message_type"] == "verify.result"
    assert body["header"]["in_reply_to"] == req.header.message_id
    assert "verification" in body["payload"]


def test_invalid_message_rejected():
    r = client.post("/api/acp/message", json={"not": "a valid acp message"})
    assert r.status_code == 400


# ---------------------------------------------------------------------------
# 新增 message_type 的分发（parse / static_scan / audit / dynamic.verify）
# ---------------------------------------------------------------------------

def test_message_types_endpoint_lists_new_types():
    """message-types 端点必须声明全部 6 种请求类型。"""
    body = client.get("/api/acp/message-types").json()
    supported = body["supported_request_types"]
    assert supported == ACPDispatcher().supported_request_types()
    for t in ("parse.request", "static_scan.request", "audit.request",
              "verify.request", "exploit.generate.request",
              "dynamic.verify.request"):
        assert t in supported, f"{t} 未在 supported_request_types 中"


def test_dispatcher_routes_parse_request(tmp_path):
    (tmp_path / "app.py").write_text("print('hi')\n", encoding="utf-8")
    req = make_message(
        sender="external", receiver="auditagentx",
        message_type=ACPMessageType.PARSE_REQUEST,
        payload={"code_root": str(tmp_path)},
    )
    reply = ACPDispatcher().dispatch(req)
    assert reply.header.message_type == ACPMessageType.PARSE_RESULT
    assert reply.header.sender == "repo_parser_agent"
    assert "metadata" in reply.payload
    assert "file_count" in reply.payload["metadata"]


def test_dispatcher_routes_static_scan_request(tmp_path):
    (tmp_path / "vuln.py").write_text(
        "import os\ndef h(cmd):\n    os.system('ping ' + cmd)\n", encoding="utf-8")
    req = make_message(
        sender="external", receiver="auditagentx",
        message_type=ACPMessageType.STATIC_SCAN_REQUEST,
        payload={"code_root": str(tmp_path), "enabled_tools": ["custom"]},
    )
    reply = ACPDispatcher().dispatch(req)
    assert reply.header.message_type == ACPMessageType.STATIC_SCAN_RESULT
    assert reply.header.sender == "static_scan_agent"
    assert isinstance(reply.payload.get("findings"), list)
    assert isinstance(reply.payload.get("raw_findings"), list)


def test_dispatcher_routes_audit_request(tmp_path):
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    req = make_message(
        sender="external", receiver="auditagentx",
        message_type=ACPMessageType.AUDIT_REQUEST,
        payload={"metadata": {"languages": ["Python"]},
                 "raw_findings": [], "code_root": str(tmp_path)},
    )
    with patch("backend.agents.audit_agent.AuditAgent._call",
               return_value={"findings": []}):
        reply = ACPDispatcher().dispatch(req)
    assert reply.header.message_type == ACPMessageType.AUDIT_RESULT
    assert reply.header.sender == "audit_agent"
    assert isinstance(reply.payload.get("findings"), list)
    assert isinstance(reply.payload.get("legacy_findings"), list)


def test_dispatcher_routes_dynamic_verify_request(tmp_path):
    """dynamic.verify.request（全部动态开关关闭）→ dynamic.verify.result，dynamic_verdict=not_executed。"""
    req = make_message(
        sender="external", receiver="auditagentx",
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
    reply = ACPDispatcher().dispatch(req)
    assert reply.header.message_type == ACPMessageType.DYNAMIC_VERIFY_RESULT
    assert reply.header.sender == "dynamic_analysis_agent"
    assert isinstance(reply.payload.get("dynamic_summary"), dict)
    vinfo = reply.payload["verification"]
    # 未执行任何动态验证：动态裁决必须为 not_executed，且与 runtime 一致（不能自相矛盾）
    assert vinfo["dynamic_verdict"] == "not_executed"
    assert vinfo["final_verdict"] == "statically_verified"
