from __future__ import annotations

from backend.agents.verification_tools import run_heuristic_static_verifier
from backend.agents.verify_agent import VerifyAgent
from backend.dynamic.launch_detector import detect_launch
from backend.scanners import registry
from backend.verifier.docker_project_runner import _validate_compose_policy
from backend.verifier.dynamic_verifier import DynamicVerifier, ProbeRecord


class _ConstantProbe:
    def send(self, base_url, path, param, payload, method="GET"):
        return ProbeRecord(
            url=base_url + path, method=method, params={param: payload}, payload=payload,
            status=200, status_code=200, response_excerpt="Welcome admin dashboard", elapsed_ms=20,
        )


class _SlowProbe:
    def send(self, base_url, path, param, payload, method="GET"):
        return ProbeRecord(
            url=base_url + path, method=method, params={param: payload}, payload=payload,
            status=200, status_code=200, response_excerpt="same normal page", elapsed_ms=5000,
        )


def test_normal_baseline_indicator_cannot_self_confirm():
    verifier = DynamicVerifier(max_probes=2)
    verifier.probe = _ConstantProbe()
    result = verifier.verify("http://127.0.0.1:9999", {
        "vuln_type": "SQL Injection",
        "payloads": ["not-an-exploit"],
        "success_indicators": ["admin"],
        "_injection_points": ["q"],
    }, endpoints=["/"])
    assert result.reproducible is False
    assert result.reproduction_status == "not_reproduced"


def test_slow_baseline_cannot_self_confirm_time_injection():
    verifier = DynamicVerifier(max_probes=2)
    verifier.probe = _SlowProbe()
    result = verifier.verify("http://127.0.0.1:9999", {
        "vuln_type": "SQL Injection",
        "payloads": ["1 OR SLEEP(5)"],
        "success_indicators": [],
        "_injection_points": ["id"],
    }, endpoints=["/"])
    assert result.reproducible is False


def test_static_constant_concat_has_no_attacker_source():
    candidate = {
        "type": "SQL Injection", "file": "app.py", "line": 1,
        "code_snippet": 'cursor.execute("SELECT " + "1")',
    }
    result = run_heuristic_static_verifier(candidate, {
        "found": False, "snippet": candidate["code_snippet"],
    })
    assert result["is_valid"] is None
    assert any(check["name"] == "attacker_controlled_source_present" and not check["passed"]
               for check in result["checks"])


def test_mechanism_harness_cannot_become_harness_confirmed():
    candidate = {"type": "Command Injection", "file": "app.py", "line": 1}
    tool_context = {
        "heuristic_result": {"is_valid": True, "confidence": 0.74},
        "sast_replay": {"matched_rules": [{"rule_id": "supporting-only"}]},
        "harness_result": {
            "executed": True, "triggered": True, "dynamically_triggered": False,
            "verdict": "mechanism_confirmed", "verification_level": "template_mechanism",
            "target_function_called": False,
        },
        "tools_used": [],
    }
    result = VerifyAgent._merge_verdict(candidate, tool_context, {
        "is_valid": True, "confidence": 0.9,
    })
    assert result["dynamic_verdict"] == "mechanism_confirmed"
    assert result.get("needs_review") is True


def test_mechanism_harness_through_run_stays_needs_review(monkeypatch):
    """端到端守卫：heuristic 无定论 + LLM 说是漏洞 + 仅机理级 harness triggered
    -> VerifyAgent.run 最终 needs_review（不得静默升 confirmed，不得绕过 LLM-only 守卫）。

    断言在框架合成的最终裁决字段上（is_valid/needs_review/dynamic_verdict），不采信自报字段。
    """
    tool_context = {
        "heuristic_result": {"is_valid": None, "confidence": 0.5},   # 启发式无定论
        "sast_replay": {"matched_rules": []},                        # 无 SAST 命中
        "harness_result": {                                          # 仅机理级（非目标级）
            "executed": True, "triggered": True, "dynamically_triggered": False,
            "verdict": "mechanism_confirmed", "verification_level": "template_mechanism",
            "function_extracted": False, "target_function_called": False,
        },
        "dynamic_result": {},
        "tools_used": [],
    }
    monkeypatch.setattr(VerifyAgent, "_build_mcp_skill_context",
                        staticmethod(lambda *a, **k: tool_context))
    monkeypatch.setattr(VerifyAgent, "_call",
                        lambda self, content: {"is_valid": True, "confidence": 0.9})

    verdict = VerifyAgent().run({"type": "Command Injection", "file": "app.py", "line": 1})

    assert verdict["is_valid"] is True            # LLM 认为是漏洞，但不能据此静默 confirmed
    assert verdict["needs_review"] is True         # 守卫生效：机理级无法绕过人工复核
    assert verdict["dynamic_verdict"] == "mechanism_confirmed"
    assert verdict["confidence"] <= 0.75


def test_native_cli_is_not_reported_as_docker_launch_failure(tmp_path):
    (tmp_path / "configure.ac").write_text("AC_INIT([native], [1.0])", encoding="utf-8")
    (tmp_path / "main.c").write_text("int main(void) { return 0; }", encoding="utf-8")
    plan = detect_launch(tmp_path)
    assert plan["runtime_kind"] == "native_cli"
    assert plan["run_command"] is None


def test_compose_host_mount_is_blocked(tmp_path):
    compose = tmp_path / "docker-compose.yml"
    compose.write_text(
        "services:\n  web:\n    image: nginx\n    privileged: true\n"
        "    volumes:\n      - /:/host\n",
        encoding="utf-8",
    )
    policy = _validate_compose_policy(compose)
    assert policy["allowed"] is False
    assert "privileged" in policy["reason"]
    assert "host volume" in policy["reason"]


def test_compose_relative_bind_mount_is_allowed(tmp_path):
    compose = tmp_path / "docker-compose.yml"
    compose.write_text(
        "services:\n  web:\n    image: nginx\n    volumes:\n      - ./keys:/app/keys:ro\n",
        encoding="utf-8",
    )
    policy = _validate_compose_policy(compose)
    assert policy["allowed"] is True


def test_missing_scanner_is_distinguishable_from_zero_findings(monkeypatch, tmp_path):
    class MissingScanner:
        def available(self):
            return False

    monkeypatch.setitem(registry._SCANNERS, "missing-test", MissingScanner)
    _, statuses = registry.run_scanners_detailed(tmp_path, ["missing-test"])
    status = next(item for item in statuses if item["tool"] == "missing-test")
    assert status["executed"] is False
    assert status["error"] == "not_installed"
