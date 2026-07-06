"""漏洞利用 + 动态验证流水线（PDF 模块③ + 动态检测的总装配）。

对一批已确认漏洞：
  1) ExploitAgent 生成利用方案（利用代码 / 触发位置 / 利用路径 / 验证方法）
  2) 若开启动态验证：启动靶场一次，逐条发送载荷、采集运行时证据、判定可复现
  3) EvidenceCollector 汇总证据链，回填到 finding 上
"""
from __future__ import annotations

import logging
from contextlib import contextmanager, nullcontext

from backend.agents.exploit_agent import ExploitAgent
from backend.verifier.dynamic_verifier import DynamicVerifier
from backend.verifier.evidence_collector import EvidenceCollector
from backend.verifier import exploit_templates as tpl
from backend.verifier import app_runner

logger = logging.getLogger(__name__)


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

    def run(self, findings: list[dict], *, enable_exploit: bool = True,
            enable_dynamic: bool = False, dynamic_target: dict | None = None) -> list[dict]:
        """就地为每条确认漏洞附加利用方案与证据链，返回同一列表。"""
        confirmed = [f for f in findings if f.get("status") == "confirmed"]
        if not confirmed:
            return findings

        # 动态验证目标只启动一次，复用给所有漏洞
        target_ctx = _resolve_target(dynamic_target or {}) if enable_dynamic else nullcontext((None, None))
        with target_ctx as resolved:
            base_url, endpoints = resolved if isinstance(resolved, tuple) else (None, None)
            if enable_dynamic:
                logger.info("动态验证目标: %s", base_url or "（无，跳过）")

            for f in confirmed:
                exploit = self.exploit_agent.run(f) if enable_exploit else {}
                # 把模板注入点补给动态验证器
                template = tpl.match_template(f.get("type"))
                if template:
                    exploit.setdefault("_injection_points", template.injection_points)

                dyn_result = None
                if enable_dynamic and base_url and exploit.get("payloads"):
                    dr = self.dynamic.verify(base_url, exploit, endpoints)
                    dyn_result = dr.__dict__
                    # 动态复现成功 -> 提升置信度与状态
                    if dr.reproducible:
                        f["confidence"] = max(f.get("confidence", 0.5), 0.98)
                        f["verified"] = True
                        f["dynamically_verified"] = True

                f["_exploit"] = exploit
                f["_dynamic"] = dyn_result
                f["_evidence"] = EvidenceCollector.build(
                    f.get("_verify", {}), exploit=exploit, dynamic=dyn_result,
                    poc_result=f.get("_poc"),
                )
        return findings
