"""ACP 消息驱动通信测试（做实：外部消息 → dispatcher → agent.run_acp → 回复）。"""
from unittest.mock import patch

from fastapi.testclient import TestClient

from backend.main import app
from backend.acp.factory import make_message
from backend.acp.models import ACPMessageType
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
