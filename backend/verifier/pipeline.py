"""漏洞利用 + 动态验证流水线（PDF 模块③ + 动态检测的总装配）。

对一批已确认漏洞：
  1) ExploitAgent 生成利用方案（利用代码 / 触发位置 / 利用路径 / 验证方法）
  2) 若开启动态验证：启动靶场一次，逐条发送载荷、采集运行时证据、判定可复现
  3) EvidenceCollector 汇总证据链，回填到 finding 上
"""
from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager, nullcontext
from typing import Any, Callable

from pathlib import Path

from backend.config import settings
from backend.agents.exploit_agent import ExploitAgent
from backend.verifier.dynamic_verifier import DynamicVerifier
from backend.verifier.harness_verifier import HarnessVerifier
from backend.verifier.evidence_collector import EvidenceCollector
from backend.verifier import exploit_templates as tpl
from backend.verifier import app_runner
from backend.dynamic.endpoint_extractor import candidate_endpoints
from backend.dynamic.strategy import HTTP, BOTH, NOT_APPLICABLE, resolve_strategy, is_dynamic_applicable

logger = logging.getLogger(__name__)


def _parallel_map(items: list, fn: Callable[[Any], Any], workers: int, *,
                  default: Any = None) -> list:
    """按输入顺序并发执行 fn；单个任务失败返回 default，不影响其余任务。

    workers<=1 或 items 很少时退化为串行，避免线程池无谓开销。
    """
    n = len(items)
    if n == 0:
        return []

    def _safe(it):
        try:
            return fn(it)
        except Exception as exc:  # noqa: BLE001
            logger.warning("并行任务失败，使用默认值: %s", exc)
            return default

    workers = max(1, min(int(workers), n))
    if workers == 1:
        return [_safe(it) for it in items]

    results: list = [default] * n
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(_safe, it): idx for idx, it in enumerate(items)}
        for fut in as_completed(futures):
            results[futures[fut]] = fut.result()
    return results

# HTTP 动态验证的严重级门槛：critical/high/medium 均可（low 多为噪声，排除）。
# 注意：此门槛只约束 HTTP 探测；函数级 Harness 不受此限（走 is_dynamic_applicable），
# 因此 Docker/靶场不可用时，medium 的 needs_review 仍可由 Harness 定性。
_DYNAMIC_SEVERITIES = {"critical", "high", "medium"}
@contextmanager
def _resolve_target(dynamic_target: dict, code_root: Path | None = None):
    """根据配置解析目标，统一 yield (base_url, endpoints, sandbox_metadata)。

    dynamic_target 支持四种模式：
      {"mode": "url",   "base_url": "http://...", "endpoints": [...]}   已运行的授权靶场
      {"mode": "local", "command": [...], "cwd": "...", "endpoints": [...]}  本机子进程（隔离环境）
      {"mode": "docker","image": "...", "build_context": "...", "internal_port": 80}  现成镜像
      {"mode": "docker_project", "launch_plan": {...}}  Docker-first：从 code_root 构建并启动项目
    sandbox_metadata：仅 docker_project 模式返回沙箱元信息（含失败状态），其余为 None。
    """
    mode = (dynamic_target or {}).get("mode")
    endpoints = (dynamic_target or {}).get("endpoints")
    if mode == "url":
        yield dynamic_target.get("base_url"), endpoints, None
    elif mode == "local":
        with app_runner.LocalAppRunner(
            dynamic_target["command"], dynamic_target.get("cwd", "."),
            env=dynamic_target.get("env"),
        ) as base_url:
            yield base_url, endpoints, None
    elif mode == "docker":
        with app_runner.DockerAppRunner(
            dynamic_target["image"],
            internal_port=dynamic_target.get("internal_port", 80),
            build_context=dynamic_target.get("build_context"),
        ) as base_url:
            yield base_url, endpoints, None
    elif mode == "docker_project":
        # Docker-first Deep Mode：从 GitHub 项目 code_root 构建并启动容器
        from backend.dynamic.launch_detector import detect_launch
        from backend.verifier.docker_project_runner import DockerProjectRunner
        # 以自动探测为基底，用户显式提供的字段覆盖之（未提供的保留探测结果）——
        # 避免前端只填了 {health_path:"/"} 就把探测到的 run_command/framework 整个抹掉。
        detected = detect_launch(code_root)
        user_plan = dynamic_target.get("launch_plan") or {}
        launch_plan = {**detected, **{k: v for k, v in user_plan.items() if v not in (None, "")}}
        if not endpoints and code_root is not None:
            endpoints = candidate_endpoints(code_root)
        with DockerProjectRunner(code_root, launch_plan,
                                 env=dynamic_target.get("env"),
                                 scan_id=dynamic_target.get("scan_id")) as sandbox:
            yield sandbox.base_url, endpoints, sandbox.metadata
    else:
        yield None, endpoints, None


class ExploitPipeline:
    def __init__(self, scan_id: str | None = None) -> None:
        self.scan_id = scan_id
        self.exploit_agent = ExploitAgent(scan_id=scan_id)
        self.dynamic = DynamicVerifier()
        self.harness = HarnessVerifier(scan_id=scan_id)
        # 并发度：利用生成与 Harness 并行；HTTP 探测因共享靶场固定串行
        self._exploit_workers = int(getattr(settings, "dynamic_exploit_workers", 4))
        self._harness_workers = int(getattr(settings, "dynamic_harness_workers", 4))
        self._max_candidates = int(getattr(settings, "max_dynamic_candidates", 20))

    @staticmethod
    def _select_candidates(findings: list[dict], max_candidates: int) -> list[dict]:
        """挑选动态验证候选：confirmed 全量优先，needs_review 中「动态可验证」的次之。

        逻辑要点（修复 deep≈quick 的核心）：
          - 不再只取 status==confirmed。deep 模式经 VerifyAgent 静态复核后，绝大多数
            finding 被保守降级为 needs_review——它们恰恰是最该用运行时证据来定性的对象。
          - needs_review 仅纳入 is_dynamic_applicable 为真的类型（排除硬编码密钥/弱加密等
            static-only 类型，这些没有运行时触发点，动态验证无意义）。
          - 预算上限：confirmed 全部保留，剩余名额（max_candidates - len(confirmed)）用于
            needs_review，避免超大项目对全部漏洞逐条跑动态验证。max_candidates<=0 表示不限。
        """
        confirmed = [f for f in findings if f.get("status") == "confirmed"]
        needs_review = [
            f for f in findings
            if f.get("status") == "needs_review" and is_dynamic_applicable(f.get("type"))
        ]
        if max_candidates and max_candidates > 0:
            remaining = max(0, max_candidates - len(confirmed))
            return confirmed + needs_review[:remaining]
        return confirmed + needs_review

    def run(self, findings: list[dict], *, enable_exploit: bool = True,
            enable_dynamic: bool = False, dynamic_target: dict | None = None,
            enable_harness: bool = False, code_root: Path | None = None,
            max_candidates: int | None = None) -> list[dict]:
        """就地为候选漏洞附加利用方案 + 动态验证 + 证据链，返回同一列表。

        候选 = confirmed（全量）+ needs_review 中动态可验证者（受预算上限约束）。
        """
        budget = self._max_candidates if max_candidates is None else int(max_candidates)
        candidates = self._select_candidates(findings, budget)
        if not candidates:
            return findings

        # 动态验证目标只启动一次，复用给所有漏洞
        target_ctx = (_resolve_target(dynamic_target or {}, code_root)
                      if enable_dynamic else nullcontext((None, None, None)))
        with target_ctx as resolved:
            # 兼容 2 元组（旧）与 3 元组（含 sandbox metadata）
            if isinstance(resolved, tuple) and len(resolved) == 3:
                base_url, endpoints, sandbox_meta = resolved
            elif isinstance(resolved, tuple):
                base_url, endpoints = resolved
                sandbox_meta = None
            else:
                base_url, endpoints, sandbox_meta = None, None, None
            auto_endpoints = False
            if enable_dynamic and not endpoints and code_root is not None:
                endpoints = candidate_endpoints(code_root)
                auto_endpoints = True
            # 沙箱启动失败时的状态（供 HTTP 验证跳过时使用真实原因）
            sandbox_fail_status = None
            if sandbox_meta and sandbox_meta.get("status") != "started":
                sandbox_fail_status = sandbox_meta.get("status")  # sandbox_start_failed / health_check_failed / dependency_install_failed
            if enable_dynamic:
                logger.info("动态验证目标: %s (sandbox=%s)", base_url or "（无）",
                            sandbox_meta.get("status") if sandbox_meta else "none")

            # ---- 阶段 A：利用生成（并行，纯 LLM、逐条独立、不碰共享靶场）----
            exploits = _parallel_map(
                candidates, lambda f: self._gen_exploit(f, enable_exploit),
                self._exploit_workers, default=None)
            exploits = [e if e else {} for e in exploits]  # 每条独立 dict，避免别名共享

            # ---- 阶段 B：HTTP 动态探测（串行，共享同一靶场，避免有状态载荷互相污染）----
            dyn_results: list = [None] * len(candidates)
            if enable_dynamic:
                for i, f in enumerate(candidates):
                    dyn_results[i] = self._http_verify(
                        f, exploits[i], base_url, endpoints,
                        sandbox_meta, sandbox_fail_status, auto_endpoints)

            # ---- 阶段 C：Fuzzing Harness（并行，函数级独立，每任务独立实例避免共享态竞争）----
            if enable_harness and code_root is not None:
                harness_results = _parallel_map(
                    candidates, lambda f: self._run_harness(f, code_root),
                    self._harness_workers, default=None)
            else:
                harness_results = [None] * len(candidates)

            # ---- 汇总（串行）：裁决 + 证据链回填到每条 finding ----
            for i, f in enumerate(candidates):
                self._assemble(f, exploits[i], dyn_results[i], harness_results[i], sandbox_meta)
        return findings

    # ------------------------------------------------------------------ #
    # 分阶段执行的内部方法（配合并行/串行编排）                            #
    # ------------------------------------------------------------------ #
    def _gen_exploit(self, f: dict, enable_exploit: bool) -> dict:
        """阶段 A：生成利用方案并补齐模板注入点（可并行）。"""
        exploit = self.exploit_agent.run(f) if enable_exploit else {}
        template = tpl.match_template(f.get("type"))
        if template:
            exploit.setdefault("_injection_points", template.injection_points)
        return exploit

    def _http_verify(self, f: dict, exploit: dict, base_url, endpoints,
                     sandbox_meta, sandbox_fail_status, auto_endpoints) -> dict:
        """阶段 B：对共享靶场做 HTTP 动态探测（必须串行）。仅返回 dyn_result，不改 finding。"""
        should_run, skip_status, skip_reason = _should_run_dynamic_verify(
            f, exploit, base_url, endpoints)
        # 沙箱启动失败：适合 HTTP 验证的漏洞用真实沙箱失败状态，而非泛化 not_executed
        if sandbox_fail_status and skip_status == "not_executed" and not base_url:
            strat = resolve_strategy(f.get("type"))
            if strat.get("strategy") in {HTTP, BOTH}:
                skip_status = sandbox_fail_status
                sb_reason = (sandbox_meta or {}).get("reason") or ""
                skip_reason = (
                    f"Docker 沙箱未就绪（{sandbox_fail_status}）：{sb_reason}"
                    if sb_reason else
                    f"Docker 沙箱未就绪（{sandbox_fail_status}），未执行 HTTP 动态验证"
                )
        if should_run:
            dyn_result = self.dynamic.verify(base_url, exploit, endpoints).__dict__
        else:
            dyn_result = _dynamic_skip_result(skip_status, skip_reason)
        if auto_endpoints:
            dyn_result.setdefault("logs", []).append(
                "未手动提供 endpoint，已使用源码路由自动提取候选入口")
            dyn_result["candidate_endpoints"] = endpoints
        if sandbox_meta:
            dyn_result["sandbox"] = sandbox_meta
        return dyn_result

    def _run_harness(self, f: dict, code_root: Path) -> dict | None:
        """阶段 C：函数级 Harness 验证（可并行）。用独立实例避免 HarnessVerifier 内部共享态竞争。"""
        return HarnessVerifier(scan_id=self.scan_id).run(f, code_root)

    def _assemble(self, f: dict, exploit: dict, dyn_result, harness_result, sandbox_meta) -> None:
        """汇总阶段：把 HTTP / Harness 结果落到 finding，套用裁决与回退，构建证据链。"""
        # HTTP 复现裁决：可复现 -> 升级为 confirmed（needs_review 借运行时证据定性）
        if dyn_result is not None:
            if dyn_result.get("reproducible"):
                f["confidence"] = max(f.get("confidence", 0.5), 0.98)
                f["verified"] = True
                f["dynamically_verified"] = True
                f["dynamic_method"] = "http_dynamic"
                f["status"] = "confirmed"  # 运行时可复现 -> 确认
            f["runtime_verification_status"] = dyn_result.get("reproduction_status")

        # Harness 裁决：严格区分「真实目标函数确认」与「模板机理确认」
        hv = (harness_result or {}).get("verdict")
        if hv == "target_confirmed":
            # 真实目标函数 + 危险 sink 被攻击输入触发 -> 视为动态确认
            f["confidence"] = max(f.get("confidence", 0.5), 0.97)
            f["verified"] = True
            f["dynamically_verified"] = True
            f["dynamic_method"] = "target_harness"
            f["status"] = "confirmed"  # 目标函数级 Harness 触发 -> 确认
            f["runtime_verification_status"] = "harness_target_confirmed"
            if dyn_result is not None and not dyn_result.get("reproducible"):
                dyn_result["harness_confirmed"] = True
                dyn_result["reason"] = ((dyn_result.get("reason") or "")
                                        + "（HTTP 未复现，但目标函数级 Harness 已触发该漏洞）")
                dyn_result.setdefault("logs", []).append(
                    "回退：目标函数级 Harness 已复现漏洞，见 harness 证据")
        elif hv == "mechanism_confirmed":
            # 模板 Harness 只证明「漏洞类型机理」，不等价真实可利用 -> 不标记完全动态确认，
            # 也不升级 status（维持 needs_review/原状）。机理级贡献的置信度上限 0.75。
            f["function_mechanism_verified"] = True
            mech_conf = min(float(harness_result.get("confidence") or 0.75), 0.75)
            f["confidence"] = max(f.get("confidence", 0.5), mech_conf)
            f["runtime_verification_status"] = "harness_mechanism_confirmed"
            if dyn_result is not None and not dyn_result.get("reproducible"):
                dyn_result.setdefault("logs", []).append(
                    "模板 Harness 只证明漏洞机理，仍需 source-to-sink 或 HTTP 复现确认")
                if not dyn_result.get("reason"):
                    dyn_result["reason"] = "模板 Harness 只证明漏洞机理，仍需 HTTP/真实函数复现确认"

        f["_exploit"] = exploit
        f["_dynamic"] = dyn_result
        f["_harness"] = harness_result
        f["_sandbox"] = sandbox_meta
        f["_evidence"] = EvidenceCollector.build(
            f.get("_verify", {}), exploit=exploit, dynamic=dyn_result,
            poc_result=f.get("_poc"), harness=harness_result,
            sandbox=sandbox_meta,
        )


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
        return False, "not_runtime_verifiable", "仅对 Medium/High/Critical 漏洞执行 HTTP 动态验证（Low 级排除）"

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
