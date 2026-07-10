"""动态验证候选扩大 + 状态升级 + quick 语义修复的回归测试。

覆盖修复点：
  1. needs_review 且「动态可验证」的 finding 会进入动态验证候选（不再只取 confirmed）。
  2. HTTP 可复现 / 目标函数级 Harness 触发 → needs_review 升级为 confirmed + dynamically_verified。
  3. 模板机理级（mechanism_confirmed）不升级 status，confidence 上限 0.75。
  4. 预算上限：confirmed 全量，剩余名额填充 needs_review。
  5. quick 模式（无 verify）status = unverified，而非虚假 confirmed。
"""
from __future__ import annotations

import threading
from pathlib import Path
from types import SimpleNamespace

from backend.acp.models import ACPContext
from backend.agents.dynamic_analysis_agent import DynamicAnalysisAgent
from backend.agents.orchestrator_agent import OrchestratorAgent
from backend.verifier.pipeline import ExploitPipeline


def test_dynamic_selection_respects_context_blocker():
    findings = [{
        "type": "OS Command Injection",
        "file": ".github/workflows/build.yml",
        "start_line": 10,
        "status": "needs_review",
        "severity": "high",
        "dynamic_applicable": False,
    }]
    assert ExploitPipeline._select_candidates(findings, 20) == []


def test_dynamic_budget_caps_confirmed_and_review_together():
    findings = [
        {"type": "SQL Injection", "status": "confirmed", "severity": "high"}
        for _ in range(4)
    ]
    assert len(ExploitPipeline._select_candidates(findings, 2)) == 2

DEMO = Path(__file__).resolve().parent.parent / "examples" / "vulnerable_projects" / "demo_flask_app"


# --------------------------------------------------------------------------- #
# 1. 候选选择：needs_review 动态可验证者纳入，not_applicable/false_positive 排除     #
# --------------------------------------------------------------------------- #
def test_select_candidates_includes_dynamic_applicable_needs_review():
    findings = [
        {"type": "SQL Injection", "status": "confirmed"},
        {"type": "Command Injection", "status": "needs_review"},   # 动态可验证
        {"type": "Hardcoded Secret", "status": "needs_review"},     # not_applicable -> 排除
        {"type": "XSS", "status": "false_positive"},                # 非候选状态 -> 排除
    ]
    picked = ExploitPipeline._select_candidates(findings, max_candidates=20)
    types = [f["type"] for f in picked]
    assert "SQL Injection" in types
    assert "Command Injection" in types          # 核心修复：needs_review 也进入验证
    assert "Hardcoded Secret" not in types       # 静态类无运行时触发点
    assert "XSS" not in types                     # false_positive 不验证


def test_select_candidates_budget_caps_needs_review_but_keeps_confirmed():
    findings = [{"type": "SQL Injection", "status": "confirmed"}]
    findings += [{"type": "Command Injection", "status": "needs_review"} for _ in range(5)]
    picked = ExploitPipeline._select_candidates(findings, max_candidates=3)
    # confirmed 全保留 + 剩余 2 个 needs_review 名额 = 3
    assert len(picked) == 3
    assert picked[0]["status"] == "confirmed"
    assert sum(1 for f in picked if f["status"] == "needs_review") == 2


def test_select_candidates_unlimited_when_budget_non_positive():
    findings = [{"type": "SQL Injection", "status": "confirmed"}]
    findings += [{"type": "Command Injection", "status": "needs_review"} for _ in range(5)]
    picked = ExploitPipeline._select_candidates(findings, max_candidates=0)
    assert len(picked) == 6


# --------------------------------------------------------------------------- #
# 2. 状态升级：HTTP 可复现 / target_harness 触发 → confirmed + dynamically_verified #
# --------------------------------------------------------------------------- #
def _pipeline() -> ExploitPipeline:
    # 不走 __init__（避免初始化 LLM 客户端），_assemble 不依赖实例属性
    return object.__new__(ExploitPipeline)


def test_assemble_http_reproducible_upgrades_needs_review():
    pipe = _pipeline()
    f = {"type": "SQL Injection", "status": "needs_review", "confidence": 0.5}
    dyn_result = {"reproducible": True, "reproduction_status": "dynamic_confirmed", "records": []}
    pipe._assemble(f, {}, dyn_result, None, None)

    assert f["status"] == "confirmed"             # 运行时复现 -> 升级为确认
    assert f["verified"] is True
    assert f["dynamically_verified"] is True
    assert f["dynamic_method"] == "http_dynamic"
    assert f["confidence"] >= 0.98
    ver = f["_evidence"]["verification"]
    assert ver["dynamically_verified"] is True
    assert ver["dynamic_method"] == "http_dynamic"
    assert ver["final_verdict"] == "dynamic_confirmed"


def test_assemble_target_harness_upgrades_needs_review():
    pipe = _pipeline()
    f = {"type": "Command Injection", "status": "needs_review", "confidence": 0.5}
    harness = {"verdict": "target_confirmed", "dynamically_triggered": True,
               "trigger_detail": "os.system 被攻击输入触发",
               "function_extracted": True, "target_function_called": True,
               "verification_level": "entrypoint_reproduced", "entrypoint_reachable": True,
               "harness_source": "scaffold"}
    pipe._assemble(f, {}, None, harness, None)

    assert f["status"] == "confirmed"
    assert f["dynamically_verified"] is True
    assert f["dynamic_method"] == "target_harness"
    assert f["runtime_verification_status"] == "harness_target_confirmed"
    ver = f["_evidence"]["verification"]
    assert ver["dynamically_verified"] is True
    assert ver["dynamic_method"] == "target_harness"


def test_assemble_mechanism_confirmed_keeps_needs_review_and_caps_confidence():
    pipe = _pipeline()
    f = {"type": "Command Injection", "status": "needs_review", "confidence": 0.5}
    harness = {"verdict": "mechanism_confirmed", "dynamically_triggered": False,
               "confidence": 0.9, "function_mechanism_verified": True}
    pipe._assemble(f, {}, None, harness, None)

    assert f["status"] == "needs_review"          # 机理级不升级为确认
    assert f.get("dynamically_verified") is not True
    assert f["function_mechanism_verified"] is True
    assert f["confidence"] <= 0.75                 # 机理级贡献置信度上限 0.75
    ver = f["_evidence"]["verification"]
    assert ver["dynamically_verified"] is False


def test_assemble_mechanism_confirmed_downgrades_weak_confirmed():
    pipe = _pipeline()
    f = {"type": "insecure-use-strtok-fn", "status": "confirmed", "confidence": 0.9, "verified": True}
    harness = {"verdict": "mechanism_confirmed", "dynamically_triggered": False,
               "confidence": 0.95, "function_mechanism_verified": True}
    pipe._assemble(f, {}, None, harness, None)

    assert f["status"] == "needs_review"
    assert f["verified"] is False
    assert f.get("dynamically_verified") is not True
    assert f["confidence"] <= 0.75
    assert any("mechanism" in b.lower() for b in f["confirmed_blockers"])


def test_assemble_unsafe_harness_blocked_clears_dynamic_confirmation():
    pipe = _pipeline()
    f = {"type": "Command Injection", "status": "confirmed", "confidence": 0.96, "verified": True,
         "dynamically_verified": True}
    harness = {"verdict": "unsafe_harness_blocked", "dynamically_triggered": False,
               "reason": "refused to execute dangerous payload"}
    pipe._assemble(f, {}, None, harness, None)

    assert f["status"] == "needs_review"
    assert f["verified"] is False
    assert f["dynamically_verified"] is False
    assert f["runtime_verification_status"] == "unsafe_harness_blocked"


# --------------------------------------------------------------------------- #
# 3. 集成：needs_review 的 finding 现在会真正进入动态验证流水线（此前被跳过）         #
# --------------------------------------------------------------------------- #
def test_needs_review_finding_now_enters_pipeline(monkeypatch):
    # 强制模板 Harness（无 LLM），离线确定性
    monkeypatch.setattr("backend.verifier.harness_verifier.HarnessVerifier._call",
                        lambda self, content: {})
    findings = [{"type": "Command Injection", "file": "app.py", "start_line": 38,
                 "status": "needs_review", "severity": "high",
                 "code_snippet": "os.system(...)"}]
    DynamicAnalysisAgent().run(findings, code_root=DEMO, enable_exploit=False,
                               enable_dynamic=False, enable_harness=True)
    # 修复前：needs_review 不是 confirmed -> _harness 为 None（被跳过）
    # 修复后：needs_review 动态可验证 -> 进入 Harness 验证
    assert findings[0].get("_harness") is not None
    assert findings[0]["_harness"].get("verdict") == "mechanism_confirmed"


# --------------------------------------------------------------------------- #
# 4. quick 模式（无 verify）：status = unverified，而非虚假 confirmed              #
# --------------------------------------------------------------------------- #
def _quick_orchestrator() -> OrchestratorAgent:
    orch = object.__new__(OrchestratorAgent)
    orch.scan = SimpleNamespace(id="scan-quick")
    orch.project = SimpleNamespace(id="project-quick")
    orch.config = {"enabled_tools": [], "enabled_agents": [], "options": {}}
    orch._acp_context = ACPContext(
        scan_id=orch.scan.id, project_id=orch.project.id,
        enabled_tools=[], enabled_agents=[], options={},
    )
    orch._stage = lambda *_a, **_k: None
    return orch


def test_quick_mode_status_is_unverified_not_confirmed():
    orch = _quick_orchestrator()
    candidates = [{
        "type": "XSS", "file": "src/app.py", "line": 1, "severity": "medium",
        "code_snippet": "return request.args['q']", "confidence": 0.5,
        "source": "audit_agent", "status": "candidate",
    }]
    results = orch._verify_and_poc(candidates)
    assert len(results) == 1
    assert results[0]["status"] == "unverified"    # 检出未验证，不是虚假 confirmed
    assert results[0]["verified"] is False
