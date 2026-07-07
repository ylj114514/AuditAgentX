"""漏洞利用 + 动态验证流水线（PDF 模块③ + 动态检测的总装配）。

对一批已确认漏洞：
  1) ExploitAgent 生成利用方案（利用代码 / 触发位置 / 利用路径 / 验证方法）
  2) 若开启动态验证：启动靶场一次，逐条发送载荷、采集运行时证据、判定可复现
  3) EvidenceCollector 汇总证据链，回填到 finding 上
"""
from __future__ import annotations

import logging
from contextlib import contextmanager, nullcontext

from pathlib import Path

from backend.agents.exploit_agent import ExploitAgent
from backend.verifier.dynamic_verifier import DynamicVerifier
from backend.verifier.harness_verifier import HarnessVerifier
from backend.verifier.evidence_collector import EvidenceCollector
from backend.verifier import exploit_templates as tpl
from backend.verifier import app_runner
from backend.dynamic.endpoint_extractor import candidate_endpoints
from backend.dynamic.strategy import HTTP, BOTH, NOT_APPLICABLE, resolve_strategy

logger = logging.getLogger(__name__)

_DYNAMIC_SEVERITIES = {"critical", "high"}
@contextmanager
def _resolve_target(dynamic_target: dict):
    """根据配置解析出目标 base_url（上下文管理器，退出自动清理）。

    dynamic_target 支持三种模式：
      {"mode": "url",   "base_url": "http://...", "endpoints": [...]}   已运行的授权靶场
      {"mode": "local", "command": [...], "cwd": "...", "endpoints": [...]}  本机子进程（隔离环境）
      {"mode": "docker","image": "...", "build_context": "...", "internal_port": 80, "endpoints": [...]}
    """
    mode = (dynamic_target or {}).get("mode")
    endpoints = (dynamic_target or {}).get("endpoints")
    if mode == "url":
        yield dynamic_target.get("base_url"), endpoints
    elif mode == "local":
        with app_runner.LocalAppRunner(
            dynamic_target["command"], dynamic_target.get("cwd", "."),
            env=dynamic_target.get("env"),
        ) as base_url:
            yield base_url, endpoints
    elif mode == "docker":
        with app_runner.DockerAppRunner(
            dynamic_target["image"],
            internal_port=dynamic_target.get("internal_port", 80),
            build_context=dynamic_target.get("build_context"),
        ) as base_url:
            yield base_url, endpoints
    else:
        yield None, endpoints


class ExploitPipeline:
    def __init__(self, scan_id: str | None = None) -> None:
        self.scan_id = scan_id
        self.exploit_agent = ExploitAgent(scan_id=scan_id)
        self.dynamic = DynamicVerifier()
        self.harness = HarnessVerifier(scan_id=scan_id)

    def run(self, findings: list[dict], *, enable_exploit: bool = True,
            enable_dynamic: bool = False, dynamic_target: dict | None = None,
            enable_harness: bool = False, code_root: Path | None = None) -> list[dict]:
        """就地为每条确认漏洞附加利用方案 + 动态验证 + 证据链，返回同一列表。"""
        confirmed = [f for f in findings if f.get("status") == "confirmed"]
        if not confirmed:
            return findings

        # 动态验证目标只启动一次，复用给所有漏洞
        target_ctx = _resolve_target(dynamic_target or {}) if enable_dynamic else nullcontext((None, None))
        with target_ctx as resolved:
            base_url, endpoints = resolved if isinstance(resolved, tuple) else (None, None)
            auto_endpoints = False
            if enable_dynamic and not endpoints and code_root is not None:
                endpoints = candidate_endpoints(code_root)
                auto_endpoints = True
            if enable_dynamic:
                logger.info("动态验证目标: %s", base_url or "（无，跳过）")

            for f in confirmed:
                exploit = self.exploit_agent.run(f) if enable_exploit else {}
                # 把模板注入点补给动态验证器
                template = tpl.match_template(f.get("type"))
                if template:
                    exploit.setdefault("_injection_points", template.injection_points)

                # A) HTTP 动态验证（需运行中的靶场）
                dyn_result = None
                if enable_dynamic:
                    should_run, skip_status, skip_reason = _should_run_dynamic_verify(
                        f, exploit, base_url, endpoints)
                    if should_run:
                        dr = self.dynamic.verify(base_url, exploit, endpoints)
                        dyn_result = dr.__dict__
                        if dr.reproducible:
                            f["confidence"] = max(f.get("confidence", 0.5), 0.98)
                            f["verified"] = True
                            f["dynamically_verified"] = True
                    else:
                        dyn_result = _dynamic_skip_result(skip_status, skip_reason)
                    if dyn_result is not None and auto_endpoints:
                        dyn_result.setdefault("logs", []).append(
                            "未手动提供 endpoint，已使用源码路由自动提取候选入口"
                        )
                        dyn_result["candidate_endpoints"] = endpoints
                    f["runtime_verification_status"] = dyn_result.get("reproduction_status")

                # B) Fuzzing Harness 动态验证（DeepAudit 式，目标无需运行）
                harness_result = None
                if enable_harness and code_root is not None:
                    harness_result = self.harness.run(f, code_root)
                    if harness_result.get("dynamically_triggered"):
                        f["confidence"] = max(f.get("confidence", 0.5), 0.97)
                        f["verified"] = True
                        f["dynamically_verified"] = True
                        f["dynamic_method"] = "fuzzing_harness"

                f["_exploit"] = exploit
                f["_dynamic"] = dyn_result
                f["_harness"] = harness_result
                f["_evidence"] = EvidenceCollector.build(
                    f.get("_verify", {}), exploit=exploit, dynamic=dyn_result,
                    poc_result=f.get("_poc"), harness=harness_result,
                )
        return findings


def _should_run_dynamic_verify(finding: dict, exploit: dict,
                               base_url: str | None,
                               endpoints: list[str] | None) -> tuple[bool, str, str]:
    if not base_url:
        return False, "not_executed", "未配置本地授权靶场 base_url，未执行动态 HTTP 探测"

    strategy = resolve_strategy(finding.get("type"))
    if strategy.get("strategy") == NOT_APPLICABLE:
        return False, "not_runtime_verifiable", strategy.get("reason") or "漏洞类型不适合动态验证"
    if strategy.get("strategy") not in {HTTP, BOTH}:
        return False, "not_runtime_verifiable", strategy.get("reason") or "漏洞类型不适合 HTTP 动态验证"

    severity = str(finding.get("severity") or "low").lower()
    if severity not in _DYNAMIC_SEVERITIES:
        return False, "not_runtime_verifiable", "仅对 High/Critical 高危漏洞执行 HTTP 动态验证"

    if not endpoints:
        return False, "not_runtime_verifiable", "未提供明确 endpoint，避免对无入口漏洞进行猜测式动态验证"

    if not exploit.get("payloads"):
        return False, "not_runtime_verifiable", "ExploitAgent 未生成可执行 payload"

    if not exploit.get("_injection_points"):
        return False, "not_runtime_verifiable", "缺少明确参数注入点，未执行动态 HTTP 探测"

    return True, "", ""


def _dynamic_skip_result(status: str, reason: str) -> dict:
    return {
        "verified": False,
        "reproducible": False,
        "reproduction_status": status,
        "matched_indicator": "",
        "confirmed_record": None,
        "records": [],
        "logs": [reason],
        "skipped": True,
        "reason": reason,
        "error": "",
    }
