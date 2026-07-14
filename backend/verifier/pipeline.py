"""漏洞利用 + 动态验证流水线（PDF 模块③ + 动态检测的总装配）。

对一批已确认漏洞：
  1) ExploitAgent 生成利用方案（利用代码 / 触发位置 / 利用路径 / 验证方法）
  2) 若开启动态验证：启动靶场一次，逐条发送载荷、采集运行时证据、判定可复现
  3) EvidenceCollector 汇总证据链，回填到 finding 上
"""
from __future__ import annotations

import ast
import logging
import copy
import re
import threading
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager
from typing import Any, Callable

from pathlib import Path

from backend.config import settings
from backend.agents.exploit_agent import (
    ExploitAgent,
    build_authorization_workflow_poc,
    build_confirmed_http_poc,
    build_deterministic_bound_exploit,
    build_executed_not_reproduced_http_replay,
)
from backend.verifier.dynamic_verifier import DynamicVerifier
from backend.verifier.harness_verifier import HarnessVerifier
from backend.verifier.evidence_collector import (
    EvidenceCollector, apply_product_evidence_policy, is_executed_not_reproduced_runtime,
)
from backend.verifier.poc_writer import canonicalize_confirmed_http_runtime
from backend.verifier import exploit_templates as tpl
from backend.verifier import app_runner
from backend.dynamic.endpoint_extractor import candidate_attack_surfaces, candidate_endpoints
from backend.dynamic.authorization_planner import (
    plan_authorization_workflow,
    plan_disposable_initializer,
)
from backend.dynamic.strategy import HARNESS, HTTP, BOTH, NOT_APPLICABLE, resolve_strategy
from backend.dynamic.target_guard import validate_dynamic_base_url
from backend.dynamic.source_route_binding import bind_server_surface, is_server_bound_surface
from backend.dynamic.open_redirect import build_open_redirect_plan, is_open_redirect_type
from backend.verifier.context_classifier import apply_context_to_finding, classify_finding_context
from backend.runtime.scan_execution import SandboxCommandCancelled, is_cancelled

logger = logging.getLogger(__name__)


def _emit_progress(callback, phase: str, *, completed: int = 0, total: int = 0,
                   detail: str = "", **extra) -> None:
    """发布动态 campaign 的可观测进度；回调失败绝不能中断漏洞验证。"""
    if callback is None:
        return
    payload = {"phase": phase, "completed": completed, "total": total,
               "detail": detail, **extra}
    try:
        callback(payload)
    except Exception as exc:  # noqa: BLE001
        logger.debug("动态进度回调失败（忽略）: %s", exc)


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
        except SandboxCommandCancelled:
            raise
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
# 注意：此门槛只约束 HTTP 探测；它不能在候选阶段过滤 needs_review，
# 因此 Docker/靶场不可用时，medium 的 needs_review 仍可由 Harness 定性。
_DYNAMIC_SEVERITIES = {"critical", "high", "medium"}


def _should_run_docker_fallback(finding: dict, harness_result: dict | None) -> bool:
    """Decide whether optional Docker/HTTP evidence is still useful.

    This function deliberately runs *after* the PoC Sandbox Harness.  A target
    confirmation is already sufficient evidence; starting an application then is
    wasted work and would invert the requested evidence hierarchy.  Findings such
    as DOM-only React sinks explicitly opt out because text HTTP reflection is not
    a valid JavaScript-execution oracle.
    """
    if (harness_result or {}).get("verdict") == "target_confirmed":
        return False
    return bool(resolve_strategy(finding.get("type")).get("docker_fallback"))


def _is_disposable_sandbox(metadata: dict | None) -> bool:
    """Whether the runtime is an AuditAgentX-owned, teardown-on-exit target.

    DockerProjectRunner changes its public mode to ``docker_compose`` when a
    repository Compose file is used.  Treating only ``docker_project`` as
    disposable silently disabled safe initializers such as VAmPI's /createdb
    after the container had already been isolated for this scan.
    """
    return bool(
        metadata
        and metadata.get("status") == "started"
        and metadata.get("mode") in {"docker", "docker_project", "docker_compose"}
    )


@contextmanager
def _resolve_target(dynamic_target: dict, code_root: Path | None = None):
    """根据配置解析目标，统一 yield (base_url, endpoints, sandbox_metadata, runtime_log_supplier)。

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
        yield validate_dynamic_base_url(dynamic_target.get("base_url")), endpoints, None, None
    elif mode == "local":
        if not settings.enable_local_dynamic_runner:
            raise RuntimeError("local dynamic runner is disabled; use docker_project or explicitly enable it")
        with app_runner.LocalAppRunner(
            dynamic_target["command"], dynamic_target.get("cwd", "."),
            env=dynamic_target.get("env"),
        ) as base_url:
            yield base_url, endpoints, None, None
    elif mode == "docker":
        try:
            with app_runner.DockerAppRunner(
                dynamic_target["image"],
                internal_port=dynamic_target.get("internal_port", 80),
                build_context=dynamic_target.get("build_context"),
            ) as base_url:
                yield base_url, endpoints, {
                    "status": "started",
                    "mode": "docker",
                    "image": dynamic_target["image"],
                    "internal_port": dynamic_target.get("internal_port", 80),
                    "health_check": "ready",
                }, None
        except app_runner.DockerTargetStartError as exc:
            # 普通 docker 模式也必须像 docker_project 一样失败闭合：容器未健康时
            # 不得把随机端口继续交给 DynamicVerifier，再伪装成 payload_not_matched。
            yield None, endpoints, dict(exc.metadata), None
    elif mode == "docker_project":
        # Docker-first Deep Mode：从 GitHub 项目 code_root 构建并启动容器
        from backend.dynamic.launch_detector import detect_launch
        from backend.dynamic.docker_bootstrap import ensure_docker_running
        from backend.verifier.docker_project_runner import DockerProjectRunner
        engine_state = None
        if dynamic_target.get("auto_start_docker"):
            # 后端启动时已有异步预热；扫描开始时再同步确认一次，避免用户刚打开
            # Docker Desktop 就立即发起 Deep 扫描时发生竞态。
            engine_state = ensure_docker_running()
        # 以自动探测为基底，用户显式提供的字段覆盖之（未提供的保留探测结果）——
        # 避免前端只填了 {health_path:"/"} 就把探测到的 run_command/framework 整个抹掉。
        detected = detect_launch(code_root)
        user_plan = dynamic_target.get("launch_plan") or {}
        launch_plan = {**detected, **{k: v for k, v in user_plan.items() if v not in (None, "")}}
        if not endpoints and code_root is not None:
            endpoints = candidate_attack_surfaces(code_root)
        with DockerProjectRunner(code_root, launch_plan,
                                 env=dynamic_target.get("env"),
                                 scan_id=dynamic_target.get("scan_id"),
                                 trust_project_container_config=bool(
                                     dynamic_target.get("trust_project_container_config", False)
                                 )) as sandbox:
            sandbox.metadata["docker_autostart_requested"] = bool(
                dynamic_target.get("auto_start_docker")
            )
            sandbox.metadata["docker_engine"] = engine_state or {"status": "not_requested"}
            if (sandbox.metadata.get("status") == "launch_not_detected"
                    and (engine_state or {}).get("status") in {"already_running", "started"}):
                sandbox.metadata["reason"] += (
                    " Docker 引擎已经就绪；未创建容器的原因是被测项目缺少可识别的 Web "
                    "启动命令，而不是 Docker Desktop 故障。"
                )
            yield sandbox.base_url, endpoints, sandbox.metadata, sandbox.runtime_logs
    else:
        yield None, endpoints, None, None


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
        """挑选实际运行时验证候选：优先消解 needs_review，再处理已确认项。

        逻辑要点（修复 deep≈quick 的核心）：
          - 不再只取 status==confirmed。deep 模式经 VerifyAgent 静态复核后，绝大多数
            finding 被保守降级为 needs_review——它们恰恰是最该用运行时证据来定性的对象。
          - 上下文允许的 needs_review 都会保留在 finding 输出中；但静态/不适用类型只记录
            策略原因，不能消耗真正会运行 Harness/HTTP 的候选预算。
          - 预算上限是用户显式的资源约束。模棱两可的 needs_review 优先获得运行时
            证据；未入队项会保留 budget skipped 记录。max_candidates<=0 表示不限。
        """
        for finding in findings:
            if "dynamic_applicable" not in finding:
                apply_context_to_finding(finding)

        def executable(finding: dict) -> bool:
            return (
                resolve_strategy(finding.get("type")).get("strategy") in {HARNESS, HTTP, BOTH}
                and not _static_counterevidence_reason(finding)
            )

        confirmed = [
            f for f in findings
            if f.get("status") == "confirmed"
            and f.get("dynamic_applicable") is not False
            and executable(f)
        ]
        needs_review = [
            f for f in findings
            if f.get("status") == "needs_review"
            and f.get("dynamic_applicable") is not False
            and executable(f)
        ]
        # Deep 的首要目的，是用运行时证据消解静态阶段无法定性的 finding；预算不足时，
        # 不应让既有 confirmed 挤掉 needs_review。
        selected = needs_review + confirmed
        if max_candidates and max_candidates > 0:
            return selected[:max_candidates]
        return selected

    @staticmethod
    def _record_dynamic_policy_skips(findings: list[dict]) -> None:
        """Document static policy exclusions without fabricating a runtime attempt."""
        for finding in findings:
            if finding.get("status") not in {"confirmed", "needs_review"}:
                continue
            counterevidence = _static_counterevidence_reason(finding)
            if counterevidence:
                verify = finding.setdefault("_verify", {})
                verify.update({
                    "dynamic_policy_skipped": True,
                    "dynamic_policy_reason": counterevidence,
                    "runtime_verification_status": "not_runtime_verifiable",
                })
                finding["_dynamic"] = _dynamic_skip_result("not_runtime_verifiable", counterevidence)
                finding["_harness"] = {
                    "verdict": "not_applicable", "dynamically_triggered": False,
                    "reason": counterevidence,
                }
                finding["_sandbox"] = {"status": "not_requested", "mode": "static_review", "reason": counterevidence}
                continue
            strategy = resolve_strategy(finding.get("type"))
            if strategy.get("strategy") != NOT_APPLICABLE:
                continue
            reason = strategy.get("reason") or "漏洞类型不适合运行时验证"
            verify = finding.setdefault("_verify", {})
            verify.update({
                "dynamic_policy_skipped": True,
                "dynamic_policy_reason": reason,
                "runtime_verification_status": "not_runtime_verifiable",
            })
            finding["_dynamic"] = _dynamic_skip_result("not_runtime_verifiable", reason)
            finding["_harness"] = {
                "verdict": "not_applicable",
                "dynamically_triggered": False,
                "reason": reason,
            }
            finding["_sandbox"] = {
                "status": "not_requested",
                "mode": "static_review",
                "reason": reason,
            }

    @staticmethod
    def _record_dynamic_budget_skips(findings: list[dict], candidates: list[dict], budget: int) -> None:
        """Persist an honest budget reason without pretending a dynamic run occurred."""
        if budget <= 0:
            return
        selected_ids = {id(finding) for finding in candidates}
        for finding in findings:
            if finding.get("status") not in {"confirmed", "needs_review"}:
                continue
            if finding.get("dynamic_applicable") is False or id(finding) in selected_ids:
                continue
            if resolve_strategy(finding.get("type")).get("strategy") not in {HARNESS, HTTP, BOTH}:
                continue
            verify = finding.setdefault("_verify", {})
            verify.update({
                "dynamic_budget_skipped": True,
                "dynamic_budget_reason": (
                    f"未进入本次动态验证：超过 max_dynamic_candidates={budget} 的显式预算。"
                ),
            })

    def run(self, findings: list[dict], *, enable_exploit: bool = True,
            enable_dynamic: bool = False, dynamic_target: dict | None = None,
            enable_harness: bool = False, code_root: Path | None = None,
            max_candidates: int | None = None, on_progress=None) -> list[dict]:
        """就地为候选漏洞附加利用方案 + 动态验证 + 证据链，返回同一列表。

        候选 = 上下文允许的 confirmed + needs_review（受预算上限约束）。
        """
        self._code_root = str(code_root) if code_root else None
        budget = self._max_candidates if max_candidates is None else int(max_candidates)
        self._record_dynamic_policy_skips(findings)
        candidates = self._select_candidates(findings, budget)
        self._record_dynamic_budget_skips(findings, candidates, budget)
        _emit_progress(on_progress, "candidate_selection", completed=len(candidates), total=len(candidates),
                       detail=f"已选择 {len(candidates)} 个运行时验证候选", budget=budget)
        if not candidates:
            _emit_progress(on_progress, "completed", completed=0, total=0,
                           detail="没有适合动态验证的候选")
            return findings

        target_config = dynamic_target or {}
        # Dynamic-target/ACP endpoint JSON is an untrusted path suggestion, not a
        # source→route capability.  Re-extract the project routes in this server
        # process and use that inventory for both planning and HTTP dispatch.
        # Missing source is deliberately fail-closed: no route proof, no request.
        exploit_endpoints = candidate_attack_surfaces(code_root) if code_root is not None else []
        auth_endpoints = _auth_bootstrap_inventory(exploit_endpoints)
        # Stateful authorization workflows are never permitted for a caller's
        # URL/local target.  Docker modes are created and torn down by this
        # pipeline; the HTTP lane still verifies the sandbox actually started
        # before adding its DB initializer.
        disposable_target = target_config.get("mode") in {
            "docker", "docker_project", "docker_compose",
        }

        def _exploit_lane() -> list[dict]:
            self._raise_if_cancelled("exploit_generation")
            _emit_progress(on_progress, "exploit_generation", completed=0, total=len(candidates),
                           detail="正在生成利用计划")
            progress_lock = threading.Lock()
            completed = [0]

            def _one(finding):
                self._raise_if_cancelled("exploit_generation")
                try:
                    result = self._gen_exploit(
                        finding, enable_exploit, endpoints=exploit_endpoints,
                        disposable_target=disposable_target, code_root=code_root,
                    )
                except SandboxCommandCancelled:
                    raise
                except Exception as exc:  # noqa: BLE001 - isolate one generation failure
                    logger.warning("利用计划生成异常（已隔离）: %s", type(exc).__name__)
                    # Docker / Harness now run in parallel with this lane.  A failed
                    # LLM request must not erase the deterministic payload/template
                    # needed to retain an honest HTTP-sandbox failure or run a local
                    # verification after the target becomes ready.
                    result = self._gen_exploit(
                        finding, False, endpoints=exploit_endpoints,
                        disposable_target=disposable_target, code_root=code_root,
                    )
                with progress_lock:
                    completed[0] += 1
                    _emit_progress(
                        on_progress, "exploit_generation", completed=completed[0],
                        total=len(candidates), detail="利用计划生成完成",
                        finding_type=finding.get("type"),
                    )
                return result

            results = _parallel_map(candidates, _one, self._exploit_workers, default=None)
            return [dict(result) if isinstance(result, dict) else {} for result in results]

        def _harness_lane() -> list:
            self._raise_if_cancelled("harness_verification")
            if not (enable_harness and code_root is not None):
                return [None] * len(candidates)
            _emit_progress(on_progress, "harness_verification", completed=0, total=len(candidates),
                           detail="正在运行受控目标函数 Harness")
            progress_lock = threading.Lock()
            completed = [0]
            # This is the sole Deep-pipeline opt-in.  Direct HarnessVerifier,
            # MCP and API calls keep the safe false default; a Deep scan has
            # already selected an isolated Docker target and enabled HTTP
            # dynamic verification.
            allow_unsafe_harness_in_docker = bool(
                enable_dynamic
                and isinstance(dynamic_target, dict)
                and dynamic_target.get("mode") in {"docker", "docker_project", "docker_compose"}
            )

            def _one(finding):
                self._raise_if_cancelled("harness_verification")
                try:
                    if allow_unsafe_harness_in_docker:
                        result = self._run_harness(
                            finding, code_root, allow_unsafe_harness_in_docker=True,
                        )
                    else:
                        result = self._run_harness(finding, code_root)
                except SandboxCommandCancelled:
                    raise
                except Exception as exc:  # noqa: BLE001 - one finding must not stop the lane
                    logger.warning("Harness 验证异常（已隔离）: %s", type(exc).__name__)
                    result = _harness_error_result(exc)
                with progress_lock:
                    completed[0] += 1
                    _emit_progress(
                        on_progress, "harness_verification", completed=completed[0],
                        total=len(candidates), detail=(result or {}).get("reason") or "Harness 完成",
                        finding_type=finding.get("type"), verdict=(result or {}).get("verdict"),
                    )
                return result

            return _parallel_map(candidates, _one, self._harness_workers, default=None)

        def _http_lane(exploits: list[dict]) -> dict:
            self._raise_if_cancelled("target_preparation")
            if not enable_dynamic:
                return {"dynamic": [None] * len(candidates), "sandbox": None,
                        "base_url": None}
            _emit_progress(on_progress, "http_verification", completed=0, total=len(candidates),
                           detail="正在准备本地项目靶场并执行 HTTP 验证")
            try:
                # The context is created, entered, exited, and cleaned up in this lane's
                # thread. Never pass an entered generator context manager across threads.
                with _resolve_target(target_config, code_root) as resolved:
                    base_url, _requested_endpoints, sandbox_meta, runtime_log_supplier = _unpack_target(resolved)
                    # Never permit target_config endpoints to become a binding.
                    # ``exploit_endpoints`` was freshly extracted above from the
                    # project source and is the only inventory eligible for scoping.
                    endpoints = exploit_endpoints
                    auto_endpoints = bool(endpoints)
                    sandbox_fail_status = (
                        sandbox_meta.get("status")
                        if sandbox_meta and sandbox_meta.get("status") != "started" else None
                    )
                    logger.info("动态验证目标: %s (sandbox=%s)", base_url or "（无）",
                                sandbox_meta.get("status") if sandbox_meta else "none")
                    _emit_progress(
                        on_progress, "environment_ready", completed=1, total=1,
                        detail=(sandbox_meta or {}).get("reason")
                        or ("动态靶场就绪" if base_url else "动态靶场不可用，将保留 Harness 回退"),
                        target_status=(sandbox_meta or {}).get("status")
                        or ("started" if base_url else "not_available"), base_url=base_url or "",
                    )
                    dynamic_results = [None] * len(candidates)
                    for index, finding in enumerate(candidates):
                        self._raise_if_cancelled("http_verification")
                        close = getattr(getattr(self.dynamic, "probe", None), "close", None)
                        try:
                            if callable(close):
                                close()
                            bound_endpoints = _proven_surfaces_for_finding(
                                finding, endpoints, code_root,
                            )
                            dynamic_results[index] = self._http_verify(
                                finding, exploits[index], base_url, bound_endpoints, sandbox_meta,
                                sandbox_fail_status, auto_endpoints, runtime_log_supplier, auth_endpoints,
                                full_endpoint_inventory=endpoints,
                            )
                        except SandboxCommandCancelled:
                            raise
                        except Exception as exc:  # noqa: BLE001 - isolate each request campaign
                            logger.warning("HTTP 验证异常（已隔离）: %s", type(exc).__name__)
                            dynamic_results[index] = _http_error_result(exc, sandbox_meta)
                        finally:
                            if callable(close):
                                try:
                                    close()
                                except Exception as exc:  # noqa: BLE001
                                    logger.debug("HTTP probe cleanup failed: %s", type(exc).__name__)
                        _emit_progress(
                            on_progress, "http_verification", completed=index + 1,
                            total=len(candidates),
                            detail=(dynamic_results[index] or {}).get("reason") or "HTTP 验证完成",
                            finding_type=finding.get("type"),
                            reproduction_status=(dynamic_results[index] or {}).get("reproduction_status"),
                        )
                    return {"dynamic": dynamic_results, "sandbox": sandbox_meta,
                            "base_url": base_url}
            except SandboxCommandCancelled:
                raise
            except Exception as exc:  # noqa: BLE001 - target setup/cleanup becomes evidence
                logger.warning("动态靶场准备异常（已结构化）: %s", type(exc).__name__)
                sandbox_meta = _target_error_result(exc)
                reason = sandbox_meta["reason"]
                dynamic_results = []
                for index, finding in enumerate(candidates):
                    self._raise_if_cancelled("target_preparation")
                    result = _dynamic_skip_result("sandbox_start_failed", reason)
                    result["sandbox"] = sandbox_meta
                    dynamic_results.append(result)
                    _emit_progress(
                        on_progress, "http_verification", completed=index + 1,
                        total=len(candidates), detail=reason,
                        finding_type=finding.get("type"),
                        reproduction_status="sandbox_start_failed",
                    )
                return {"dynamic": dynamic_results, "sandbox": sandbox_meta,
                        "base_url": None}

        # Harness/PoC Sandbox is the primary verification path.  Docker is only
        # considered after its verdict is known, so a confirmed sandbox result never
        # waits for, triggers, or is overwritten by project startup.
        with ThreadPoolExecutor(max_workers=2, thread_name_prefix="dynamic-primary") as lanes:
            exploit_future = lanes.submit(_exploit_lane)
            harness_future = lanes.submit(_harness_lane)
            exploits = exploit_future.result()
            harness_results = harness_future.result()

        docker_fallback_enabled = bool(target_config.get("enable_docker_fallback", True))
        docker_fallback_needed = bool(enable_dynamic) and docker_fallback_enabled and any(
            _should_run_docker_fallback(finding, harness_results[index])
            for index, finding in enumerate(candidates)
        )
        if docker_fallback_needed:
            http_state = _http_lane(exploits)
        else:
            reason = ("Docker fallback was disabled by scan configuration"
                      if not docker_fallback_enabled else
                      "PoC Sandbox 已给出主验证结论或该 finding 无 Docker HTTP 增强路径")
            http_state = {
                "dynamic": [_dynamic_skip_result("not_executed", reason) for _ in candidates],
                "sandbox": {"status": "not_requested", "reason": reason, "mode": "docker_optional"},
                "base_url": None,
            }

        dyn_results = http_state["dynamic"]
        sandbox_meta = http_state["sandbox"]
        base_url = http_state["base_url"]
        self._raise_if_cancelled("evidence_assembly")
        _emit_progress(on_progress, "evidence_assembly", completed=0, total=len(candidates),
                       detail="正在汇总运行时证据")
        for i, f in enumerate(candidates):
            self._raise_if_cancelled("evidence_assembly")
            # Preserve every completed lane output even if EvidenceCollector or artifact
            # persistence unexpectedly fails for this one finding.
            f["_exploit"] = _redact_exploit_for_storage(exploits[i])
            f["_dynamic"] = dyn_results[i]
            f["_harness"] = harness_results[i]
            f["_sandbox"] = sandbox_meta
            try:
                self._assemble(f, exploits[i], dyn_results[i], harness_results[i], sandbox_meta)
                detail = "证据链已写入"
            except SandboxCommandCancelled:
                raise
            except Exception as exc:  # noqa: BLE001 - isolate evidence assembly per finding
                logger.warning("单条 finding 证据装配异常（已隔离）: %s", type(exc).__name__)
                f["_evidence_assembly_error"] = _safe_stage_error("Evidence assembly", exc)
                detail = f["_evidence_assembly_error"]
            _emit_progress(on_progress, "evidence_assembly", completed=i + 1, total=len(candidates),
                           detail=detail, finding_type=f.get("type"))
        _emit_progress(
            on_progress, "completed", completed=len(candidates), total=len(candidates),
            detail="动态验证 campaign 完成",
            target_status=(sandbox_meta or {}).get("status")
            or ("started" if base_url else "not_available"),
        )
        return findings

    def _raise_if_cancelled(self, phase: str) -> None:
        scan_id = getattr(self, "scan_id", None)
        if scan_id and is_cancelled(scan_id):
            raise SandboxCommandCancelled("scan cancellation requested", phase=phase)

    # ------------------------------------------------------------------ #
    # 分阶段执行的内部方法（配合并行/串行编排）                            #
    # ------------------------------------------------------------------ #
    def _gen_exploit(self, f: dict, enable_exploit: bool, *, endpoints=None,
                       disposable_target: bool = False,
                       code_root: Path | None = None) -> dict:
        """阶段 A：生成利用方案并补齐模板注入点（可并行）。"""
        template = tpl.match_template(f.get("type"))
        # This is deliberately before authorization planning.  A BOLA workflow
        # may only be planned from server-bound structured surfaces, never from
        # the complete extracted endpoint inventory.  The source-less in-process
        # planner path mints metadata-only scope through _surfaces_for_finding;
        # it cannot dispatch HTTP.  The production HTTP path has code_root and
        # therefore still requires the stricter source→route→parameter proof.
        scoped_endpoints = (
            _proven_surfaces_for_finding(f, endpoints, code_root)
            if code_root is not None else
            _surfaces_for_finding(f, endpoints)
        )
        deterministic = build_deterministic_bound_exploit(f, scoped_endpoints)
        if deterministic is not None:
            return deterministic
        workflow = plan_authorization_workflow(
            f, scoped_endpoints,
            disposable=disposable_target, seed=getattr(self, "scan_id", None) or "adhoc",
            # The runtime may be an external/failed target despite its requested
            # mode.  The generic initializer is attached only after the pipeline
            # has verified ownership of the started Docker sandbox.
            include_initializer=False,
        )
        # 手动复核/ACP 链路可能已经生成了利用方案。动态阶段必须复用该制品，
        # 否则不仅会重复消耗一次 LLM/API，还可能用第二次生成的载荷覆盖已审计内容。
        existing = f.get("_exploit")
        if isinstance(existing, dict) and existing:
            exploit = dict(existing)
        elif workflow:
            # 业务逻辑漏洞优先使用 OpenAPI 约束的确定性工作流，避免为每条 BOLA
            # 调用 LLM，也避免模型猜测凭据/路由后自行宣判成功。
            exploit = ExploitAgent._fallback(f, template)
        else:
            exploit = (self.exploit_agent.run(f) if enable_exploit
                       else ExploitAgent._fallback(f, template))
        # LLM/既有制品可能只给出 payload。用确定性模板补齐利用代码、触发位置和验证方法，
        # 这样低 API/离线模式仍满足“自动形成漏洞利用代码”，同时不覆盖目标特定字段。
        fallback = ExploitAgent._fallback(f, template)
        for key, value in fallback.items():
            if value not in (None, "", [], {}):
                exploit.setdefault(key, value)
        strategy = resolve_strategy(f.get("type"))
        if template:
            # DeepAudit 的专用 PoC 模板思路可以借鉴，但 LLM 失败/离线时也必须给出
            # 可执行、可审计的确定性载荷；否则所谓 Deep 模式实际上不会发出任何验证请求。
            exploit.setdefault("vuln_type", f.get("type"))
            exploit.setdefault("payloads", list(template.payloads))
            exploit.setdefault("success_indicators", list(template.success_indicators))
            exploit.setdefault("_injection_points", template.injection_points)
        if strategy.get("param_hint"):
            exploit.setdefault("_injection_points", strategy.get("param_hint"))
        if strategy.get("http_method"):
            exploit.setdefault("http_method", strategy.get("http_method"))
        if workflow:
            exploit["vuln_type"] = f.get("type") or "BOLA"
            exploit["authorization_workflow"] = workflow
            # A planned authorization workflow remains a hypothesis until the
            # framework has supplied a real confirmed_record.  Do not construct
            # a runnable state-machine script merely because planning succeeded.
            exploit["exploit_code"] = None
            exploit["code_kind"] = "candidate_metadata"
            exploit["generation_status"] = "validation_pending"
            exploit["validation_status"] = "validation_pending"
            exploit["verification_method"] = (
                "在一次性本地沙箱中执行 owner control 与跨身份双次读取；"
                "仅由 DynamicVerifier 的 owner/secret 不变量裁决")
            exploit["attack_vector"] = "OpenAPI 约束的多身份对象级授权工作流"
            exploit["payloads"] = []
        return exploit

    def _http_verify(self, f: dict, exploit: dict, base_url, endpoints,
                       sandbox_meta, sandbox_fail_status, auto_endpoints,
                       runtime_log_supplier=None, auth_endpoints: list[dict] | None = None,
                       full_endpoint_inventory: list[dict] | None = None) -> dict:
        """阶段 B：对共享靶场做 HTTP 动态探测（必须串行）。仅返回 dyn_result，不改 finding。"""
        # Binding happens only in the server-side source extraction lane above.
        # Do not re-bind raw structured JSON here: ACP/MCP/client payloads may
        # contain forged ``source_route_binding``/``call_path`` descriptions.
        scoped_endpoints = [
            surface for surface in (endpoints or [])
            if _is_proven_bound_surface(surface)
        ]
        # The finding-scoped surfaces intentionally exclude unrelated routes, but
        # a safe DB bootstrap such as VAmPI's source-extracted /createdb is not
        # sink-bound.  Attach it only now: this is the first point where the
        # pipeline knows both the real base URL and that it owns a started Docker
        # sandbox.  URL/local/external targets therefore receive no initializer.
        initializer_surfaces = _attach_disposable_initializer(
            exploit, full_endpoint_inventory, sandbox_meta, base_url,
        )
        verification_endpoints = [*scoped_endpoints, *initializer_surfaces]
        # Open Redirect has a complete, source-bound HTTP oracle.  Unlike generic
        # payload generation it must not depend on the LLM returning a payload.
        # Planning is delayed until a local sandbox base_url exists, so no plan is
        # generated for an external target or an unbound/ambiguous route.
        if is_open_redirect_type(f.get("type")) and base_url:
            plan, plan_status, plan_reason = build_open_redirect_plan(
                f, base_url, scoped_endpoints,
            )
            if plan_status != "ready":
                dyn_result = _dynamic_skip_result(plan_status, plan_reason)
                if sandbox_meta:
                    dyn_result["sandbox"] = sandbox_meta
                return dyn_result
            exploit.update({
                "vuln_type": f.get("type") or "Open Redirect",
                "payloads": [plan["payload"]],
                "success_indicators": [],
                "_injection_points": [plan["param"]],
                "http_method": plan["method"],
                "open_redirect_plan": plan,
            })
        should_run, skip_status, skip_reason = _should_run_dynamic_verify(
            f, exploit, base_url, verification_endpoints)
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
        if exploit.get("deterministic_local_only") and not _is_started_local_sandbox(sandbox_meta, base_url):
            # Preserve a real DockerProjectRunner failure rather than replacing
            # it with a generic local-only skip.  Conversely, a source-unbound
            # plan remains endpoint_unresolved: neither case sends a request.
            if should_run:
                skip_status = "not_executed"
                skip_reason = "确定性利用计划仅允许已启动的本地 Docker sandbox；未发送 HTTP 请求"
            dyn_result = _dynamic_skip_result(skip_status, skip_reason)
            if sandbox_meta:
                dyn_result["sandbox"] = sandbox_meta
            return dyn_result
        if should_run:
            dyn_result = self.dynamic.verify(
                base_url, exploit, verification_endpoints,
                runtime_log_supplier=runtime_log_supplier,
                auth_endpoints=auth_endpoints,
            ).__dict__
            # The shared project target has no generic DB snapshot/reset contract.
            # Do not grant a high-confidence endpoint verdict after a stateful probe
            # unless the caller explicitly supplied per-finding isolation.
            disposable_auth_in_owned_sandbox = bool(
                dyn_result.get("disposable_auth_bootstrap") and _is_disposable_sandbox(sandbox_meta)
            )
            if (dyn_result.get("state_contamination_possible")
                    and not bool((sandbox_meta or {}).get("per_finding_isolation"))
                    and not disposable_auth_in_owned_sandbox):
                dyn_result["state_contamination_possible"] = True
                if dyn_result.get("reproducible"):
                    dyn_result["reproducible"] = False
                    dyn_result["verified"] = False
                    dyn_result["reproduction_status"] = "inconclusive"
                    dyn_result["reason"] = "state_contamination_possible"
                    dyn_result["blocker_reason"] = "state_contamination_possible"
                    dyn_result.setdefault("logs", []).append(
                        "请求可能改变共享靶场状态，未提供每 finding 重置/快照；禁止升级动态确认")
        else:
            dyn_result = _dynamic_skip_result(skip_status, skip_reason)
        if auto_endpoints:
            dyn_result.setdefault("logs", []).append(
                "未手动提供 endpoint，已使用源码路由自动提取候选入口")
            dyn_result["candidate_endpoints"] = [
                item.get("path") if isinstance(item, dict) else item for item in (scoped_endpoints or [])
            ]
            if scoped_endpoints is not endpoints and len(scoped_endpoints or []) < len(endpoints or []):
                dyn_result.setdefault("logs", []).append(
                    "已按 finding 文件位置绑定到最近的源码路由，跳过同文件无关入口")
        if sandbox_meta:
            dyn_result["sandbox"] = sandbox_meta
        return dyn_result

    def _run_harness(self, f: dict, code_root: Path, *,
                     allow_unsafe_harness_in_docker: bool = False) -> dict | None:
        """阶段 C：函数级 Harness 验证（可并行）。用独立实例避免 HarnessVerifier 内部共享态竞争。"""
        return HarnessVerifier(scan_id=self.scan_id).run(
            f, code_root,
            allow_unsafe_harness_in_docker=allow_unsafe_harness_in_docker,
        )

    def _assemble(self, f: dict, exploit: dict, dyn_result, harness_result, sandbox_meta) -> None:
        """汇总阶段：把 HTTP / Harness 结果落到 finding，套用裁决与回退，构建证据链。"""
        initial_verify = dict(f.get("_verify") or {})
        initial_static_verdict = str(
            initial_verify.get("static_verdict") or initial_verify.get("final_verdict") or ""
        ).lower()
        static_confirmed = (
            initial_static_verdict in {"confirmed", "confirmed_static", "statically_verified"}
            or (
                f.get("status") == "confirmed" and f.get("verified") is True
                and initial_static_verdict not in {"false_positive", "out_of_scope"}
            )
        )
        executed_http_not_reproduced = is_executed_not_reproduced_runtime(dyn_result)
        context = classify_finding_context(f)
        apply_context_to_finding(f, context)
        allow_confirmed = bool(context.get("allow_confirmed", True))
        independently_confirmed = bool(
            allow_confirmed and f.get("status") == "confirmed" and f.get("verified") is True
        )
        # HTTP 复现裁决：可复现 -> 升级为 confirmed（needs_review 借运行时证据定性）
        if dyn_result is not None:
            if dyn_result.get("reproducible"):
                if allow_confirmed:
                    f["confidence"] = max(f.get("confidence", 0.5), 0.98)
                    f["verified"] = True
                    f["dynamically_verified"] = True
                    f["dynamic_method"] = "http_dynamic"
                    f["status"] = "confirmed"  # 运行时可复现 -> 确认
                else:
                    dyn_result["blocked_reproducible"] = True
                    dyn_result["reproducible"] = False
                    dyn_result["reproduction_status"] = "dynamic_confirmed_blocked_by_context"
                    f["status"] = "needs_review"
                    f["verified"] = False
                    f["dynamically_verified"] = False
                    f["runtime_verification_status"] = "dynamic_confirmed_blocked_by_context"
                    dyn_result.setdefault("logs", []).append(
                        "动态复现被上下文降级阻断，不能自动升级 confirmed")
            f["runtime_verification_status"] = dyn_result.get("reproduction_status")
            if dyn_result.get("reproducible") and not allow_confirmed:
                f["runtime_verification_status"] = "dynamic_confirmed_blocked_by_context"
            elif executed_http_not_reproduced:
                # Preserve the completed no-hit runtime fact while confirming the
                # finding for product/UI policy.  This is never dynamic_confirmed.
                f["status"] = "confirmed"
                f["verified"] = True
                f["dynamically_verified"] = False
                f["dynamic_method"] = "http_executed_not_reproduced"
                dyn_result.setdefault("logs", []).append(
                    "动态 HTTP 验证已执行但未命中成功判据（not_reproduced）；保留该运行时事实"
                )

        # Harness 裁决：严格区分「真实目标函数确认」与「模板机理确认」
        hv = (harness_result or {}).get("verdict")
        # HTTP endpoint 复现是最强的运行时证据：同入口基线、攻击请求与专用 oracle
        # 已齐全。后续 Harness 仅能补充证据，绝不能以函数级/模板级上限覆盖它。
        http_confirmed = bool(dyn_result and dyn_result.get("reproducible"))
        if hv == "target_confirmed":
            blockers = _harness_target_blockers(harness_result)
            if allow_confirmed and not blockers:
                # 真实目标函数 + 危险 sink 被攻击输入触发 -> 视为动态确认
                f["confidence"] = max(f.get("confidence", 0.5), 0.97)
                f["verified"] = True
                f["dynamically_verified"] = True
                if not http_confirmed:
                    f["dynamic_method"] = "target_harness"
                f["status"] = "confirmed"  # 目标函数级 Harness 触发 -> 确认
                if not http_confirmed:
                    f["runtime_verification_status"] = "harness_target_confirmed"
                if dyn_result is not None and not dyn_result.get("reproducible"):
                    dyn_result["harness_confirmed"] = True
                    dyn_result["reason"] = ((dyn_result.get("reason") or "")
                                            + "（HTTP 未复现，但目标函数级 Harness 已触发该漏洞）")
                    dyn_result.setdefault("logs", []).append(
                        "回退：目标函数级 Harness 已复现漏洞，见 harness 证据")
            else:
                harness_result["blocked_verdict"] = "target_confirmed"
                harness_result["verdict"] = "target_blocked"
                harness_result["dynamically_triggered"] = False
                harness_result["confirmed_blockers"] = blockers or f.get("confirmed_blockers") or []
                # Harness 证据不足只能否定该 Harness 的确认资格，不能推翻已经由
                # 独立 HTTP baseline/attack 对照得到的真实 endpoint 复现结论。
                if not (dyn_result and dyn_result.get("reproducible")) and not independently_confirmed:
                    f["status"] = "needs_review"
                    f["verified"] = False
                    f["dynamically_verified"] = False
                    f["runtime_verification_status"] = "harness_target_blocked"
                    f["confirmed_blockers"] = _dedupe(
                        list(f.get("confirmed_blockers") or []) + blockers)
                    f["downgrade_reason"] = f.get("downgrade_reason") or "; ".join(blockers)
                elif not (dyn_result and dyn_result.get("reproducible")) and not executed_http_not_reproduced:
                    f["runtime_verification_status"] = "harness_target_blocked"
        elif hv == "function_reproduced":
            # 自包含切片只证明真实项目函数单元可触发，不证明生产入口可达。
            f["function_mechanism_verified"] = True
            f["function_unit_reproduced"] = True
            if not http_confirmed and not executed_http_not_reproduced:
                f["runtime_verification_status"] = "function_reproduced"
            if not http_confirmed and not executed_http_not_reproduced:
                f["status"] = "needs_review"
                f["verified"] = False
                f["dynamically_verified"] = False
                f["dynamic_method"] = "function_harness"
                if dyn_result is not None:
                    dyn_result.setdefault("logs", []).append(
                        "函数级切片已复现（非端到端）；入口未确认，保持 needs_review")
        elif hv == "mechanism_confirmed":
            # 模板 Harness 只证明「漏洞类型机理」，不等价真实可利用 -> 不标记完全动态确认，
            # 也不升级 status（维持 needs_review/原状）。机理级贡献的置信度上限 0.75。
            f["function_mechanism_verified"] = True
            mech_conf = min(float(harness_result.get("confidence") or 0.75), 0.75)
            if not http_confirmed and not independently_confirmed:
                f["confidence"] = min(max(f.get("confidence", 0.5), mech_conf), 0.75)
            if not (dyn_result and dyn_result.get("reproducible")) and not independently_confirmed:
                f["dynamically_verified"] = False
            if not (dyn_result and dyn_result.get("reproducible")) and not executed_http_not_reproduced:
                f["runtime_verification_status"] = "harness_mechanism_confirmed"
            if (dyn_result is not None and not dyn_result.get("reproducible")
                    and not executed_http_not_reproduced):
                dyn_result.setdefault("logs", []).append(
                    "模板 Harness 只证明漏洞机理，仍需 source-to-sink 或 HTTP 复现确认")
                if not dyn_result.get("reason"):
                    dyn_result["reason"] = "模板 Harness 只证明漏洞机理，仍需 HTTP/真实函数复现确认"
        elif hv == "synthetic_demo_only":
            # LLM 玩具程序：只执行了它自己重写的“相似漏洞”，未触及项目真实目标代码。
            # 必须明确标注、绝不晋级、不计入真实动态复现；也不据此下调有独立静态证据的候选。
            f["synthetic_demo_only"] = True
            if harness_result is not None:
                harness_result["counts_as_real_reproduction"] = False
            if not (dyn_result and dyn_result.get("reproducible")) and not executed_http_not_reproduced:
                f["runtime_verification_status"] = "harness_synthetic_demo_only"
                if not independently_confirmed:
                    f["dynamically_verified"] = False
        elif hv in {"unsafe_harness_blocked", "sandbox_failed", "not_reproduced"}:
            if not (dyn_result and dyn_result.get("reproducible")) and not executed_http_not_reproduced:
                f["runtime_verification_status"] = hv

        # Canonicalize before constructing replay code.  A claimed runtime success
        # without the complete, unambiguous executed request remains diagnostic
        # evidence only and must not release a PoC.
        dyn_result = _canonicalize_confirmed_http_result(dyn_result)
        canonical_http = canonicalize_confirmed_http_runtime(dyn_result)
        # HTTP 确认后，用实际命中的 method/path/transport/param/payload 重建精确利用代码，
        # 取代通用模板端点，确保报告里的代码可复现且与证据记录一一对应。
        if canonical_http is not None:
            if (dyn_result.get("oracle") == "cross_identity_owner_secret_replay"
                    and exploit.get("authorization_workflow")):
                exploit["exploit_code"] = build_authorization_workflow_poc(
                    exploit["authorization_workflow"], dyn_result.get("matched_indicator") or "")
                exploit["verification_method"] = (
                    "重放 owner control 与跨身份双次读取，并校验 owner/secret 不变量")
            else:
                exploit["exploit_code"] = build_confirmed_http_poc(
                    dyn_result["confirmed_record"], dyn_result.get("matched_indicator") or "",
                    _recorded_poc_setup_steps(dyn_result) or exploit.get("setup_requests") or [],
                )
                exploit["verification_method"] = "重放框架侧 confirmed_record，并匹配动态成功判据"
            exploit.setdefault(
                "trigger_location",
                f"{f.get('file')}:{f.get('start_line') or f.get('line')}",
            )
        elif executed_http_not_reproduced:
            records = (dyn_result or {}).get("records") or []
            record = next(
                (item for item in records if isinstance(item, dict) and item.get("role") == "attack"),
                records[0] if records and isinstance(records[0], dict) else None,
            )
            if record:
                try:
                    exploit["exploit_code"] = build_executed_not_reproduced_http_replay(
                        record, _recorded_poc_setup_steps(dyn_result),
                    )
                    exploit["code_kind"] = "executed_http_replay_not_reproduced"
                    exploit["generation_status"] = "generated"
                    exploit["validation_status"] = "executed_not_reproduced"
                    exploit["verification_method"] = (
                        "重放实际执行但未命中成功判据的动态请求；不声明漏洞命中"
                    )
                except ValueError:
                    dyn_result.setdefault("logs", []).append(
                        "已执行但未复现的请求记录不完整，未生成复放代码"
                    )
        elif hv == "target_confirmed" and (harness_result or {}).get("harness_code"):
            exploit["exploit_code"] = harness_result["harness_code"]
            exploit["code_kind"] = "target_harness_reproduction"
            exploit["generation_status"] = "generated"
            exploit["validation_status"] = "validated"
            exploit["verification_method"] = "在受控 Harness 中经真实入口调用目标代码并观察框架证明的 sink 触发"
        f["_exploit"] = _redact_exploit_for_storage(exploit)
        f["_dynamic"] = dyn_result
        f["_harness"] = harness_result
        f["_sandbox"] = sandbox_meta
        f.setdefault("_verify", {})
        if static_confirmed:
            f["_verify"]["static_verdict"] = (
                initial_static_verdict if initial_static_verdict in {"confirmed", "confirmed_static", "statically_verified"}
                else "confirmed"
            )
        dynamic_verdict = (
            "harness_confirmed" if (harness_result or {}).get("verdict") == "target_confirmed"
            else (dyn_result or {}).get("reproduction_status") or "not_executed"
        )
        if dynamic_verdict in {"dynamic_confirmed", "harness_confirmed"}:
            final_verdict = dynamic_verdict
        elif f.get("status") in {"false_positive", "out_of_scope", "informational"}:
            final_verdict = f.get("status")
        elif executed_http_not_reproduced:
            final_verdict = "confirmed"
        elif f.get("status") == "confirmed":
            final_verdict = "statically_verified"
        else:
            final_verdict = "needs_review"
        f["_verify"].update({
            # Batch ACP requests pass legacy findings straight through this pipeline.
            # Keep the canonical verification envelope synchronized here, before
            # EvidenceCollector snapshots it, instead of only fixing the single-item
            # DynamicAnalysisAgent path after evidence has already been built.
            "dynamic_verdict": dynamic_verdict,
            "final_verdict": final_verdict,
            "context": f.get("context"),
            "risk_modifier": f.get("risk_modifier"),
            "downgrade_reason": f.get("downgrade_reason"),
            "confirmed_blockers": f.get("confirmed_blockers") or [],
            "dynamic_applicable": f.get("dynamic_applicable"),
        })
        if harness_result:
            harness_result.setdefault("harness_kind", harness_result.get("harness_source"))
            harness_result.setdefault("confirmed_blockers", f.get("confirmed_blockers") or [])
        f["_evidence"] = EvidenceCollector.build(
            f.get("_verify", {}), exploit=exploit, dynamic=dyn_result,
            poc_result=f.get("_poc"), harness=harness_result,
            sandbox=sandbox_meta,
        )

        # 仅在真实动态确认或已执行但未命中的 HTTP 请求后生成专属 replay 文件，
        # 并把不可变复现元数据（源码 commit / 镜像摘要 / 时间 / PoC hash / 请求响应 hash）
        # 写入证据链——让报告成为可审计证据，而非 Agent 自然语言描述。
        primary_artifact = f["_evidence"]["artifacts"]["validated_poc"]
        if (f["_evidence"].get("verification") or {}).get("dynamic_method") in {
            "http_dynamic", "http_executed_not_reproduced", "target_harness",
        }:
            try:
                from backend.verifier.poc_writer import generate_poc_file
                out_dir = settings.data_path / "scans" / (getattr(self, "scan_id", None) or "adhoc") / "pocs"
                writer_evidence = _writer_evidence(f["_evidence"], exploit, harness_result)
                poc = generate_poc_file(f, writer_evidence, out_dir,
                                        code_root=getattr(self, "_code_root", None))
                if poc:
                    f["_evidence"]["poc_file"] = {"path": poc["path"], "sha256": poc["sha256"]}
                    f["_evidence"]["reproduction_metadata"] = poc["reproduction_metadata"]
                    f["_poc_file"] = poc["path"]
                    primary_artifact.update({
                        "generation_status": "generated",
                        "validation_status": (
                            "executed_not_reproduced"
                            if (f["_evidence"].get("verification") or {}).get("dynamic_method")
                            == "http_executed_not_reproduced" else "validated"
                        ),
                        "persistence_status": "persisted",
                        "name": Path(poc["path"]).name,
                        "sha256": poc["sha256"],
                        "failure_code": None,
                    })
                    _restore_persisted_primary_code(f["_evidence"], exploit, harness_result)
                else:
                    primary_artifact.update({
                        "generation_status": "not_generated",
                        "persistence_status": "persistence_failed",
                        "failure_code": "required_artifact_not_generated",
                        "error_summary": "Required validated artifact was not generated.",
                    })
            except Exception as exc:  # noqa: BLE001  PoC 生成失败不影响确认结论
                logger.warning("PoC 文件生成失败（不影响确认）: %s", exc)
                primary_artifact.update({
                    "persistence_status": "persistence_failed",
                    "failure_code": "artifact_persistence_failed",
                    "error_summary": _safe_artifact_error(exc),
                })

        if (harness_result or {}).get("verdict") == "function_reproduced":
            forensic_artifact = f["_evidence"]["artifacts"]["function_forensic"]
            try:
                from backend.verifier.poc_writer import generate_function_forensic_poc
                out_dir = settings.data_path / "scans" / (getattr(self, "scan_id", None) or "adhoc") / "pocs"
                forensic = generate_function_forensic_poc(
                    f, _writer_evidence(f["_evidence"], exploit, harness_result), out_dir,
                    code_root=getattr(self, "_code_root", None),
                )
                if forensic:
                    f["_evidence"]["forensic_poc_file"] = {
                        "path": forensic["path"], "sha256": forensic["sha256"],
                        "label": "函数级复现(非端到端)",
                    }
                    f["_evidence"]["function_reproduction_metadata"] = forensic["reproduction_metadata"]
                    f["_function_forensic_poc_file"] = forensic["path"]
                    forensic_artifact.update({
                        "generation_status": "generated",
                        "validation_status": "validated",
                        "persistence_status": "persisted",
                        "name": Path(forensic["path"]).name,
                        "sha256": forensic["sha256"],
                        "failure_code": None,
                    })
                else:
                    forensic_artifact.update({
                        "generation_status": "not_generated",
                        "persistence_status": "persistence_failed",
                        "failure_code": "required_artifact_not_generated",
                        "error_summary": "Required forensic artifact was not generated.",
                    })
            except Exception as exc:  # noqa: BLE001
                logger.warning("函数级取证 PoC 生成失败（不影响确认结论）: %s", exc)
                forensic_artifact.update({
                    "persistence_status": "persistence_failed",
                    "failure_code": "artifact_persistence_failed",
                    "error_summary": _safe_artifact_error(exc),
                })

        # Artifact persistence is part of completeness for runtime-confirmed levels.
        f["_evidence"] = apply_product_evidence_policy(
            f["_evidence"], status=f.get("status"), verified=f.get("verified"),
            file=f.get("file"), line=f.get("start_line") or f.get("line"),
        )
        _enforce_pipeline_poc_release(f["_evidence"])


def _safe_artifact_error(exc: Exception) -> str:
    """Return an operator-useful error class without leaking local paths."""
    return f"Artifact persistence failed ({type(exc).__name__})."


def _canonicalize_confirmed_http_result(dyn_result: dict | None) -> dict | None:
    """Add the exact DynamicVerifier request tuple before evidence is snapshotted.

    The public ``ProbeRecord`` preserves all request values but not its selected
    injection parameter.  Only the writer's strict canonicalizer may recover it;
    ambiguous, partial, static, harness, or unresolved results are returned
    untouched and will remain ineligible for executable PoC persistence.
    """
    canonical = canonicalize_confirmed_http_runtime(dyn_result)
    if canonical is None:
        return dyn_result
    normalized = dict(dyn_result)
    record = dict(normalized.get("confirmed_record") or {})
    record.update(canonical["request"])
    record["status_code"] = canonical["response_status"]
    record["response_headers"] = canonical["response_headers"]
    normalized.update({
        "confirmed_record": record,
        "baseline_record": canonical["baseline"],
        "matched_indicator": canonical["matched_indicator"],
        "server_binding": canonical["server_binding"],
    })
    return normalized


def _recorded_poc_setup_steps(dynamic: dict | None) -> list[dict]:
    """Build a replayable form-auth prelude from sanitized runtime setup evidence.

    Only the verifier-created ``auth_bootstrap`` envelope is accepted.  Route,
    method, transport, and field names therefore originate in the actual local
    campaign; disposable values are regenerated as harmless placeholders rather
    than copied into a stored PoC.
    """
    if not isinstance(dynamic, dict):
        return []
    steps: list[dict] = []
    for record in dynamic.get("setup_records") or []:
        if not isinstance(record, dict):
            continue
        envelope = record.get("auth_bootstrap")
        if not isinstance(envelope, dict) or envelope.get("stage") not in {"form_fetch", "form_submit"}:
            continue
        parsed = urlparse(str(record.get("url") or ""))
        path = parsed.path
        method = str(record.get("method") or "").upper()
        if not path.startswith("/") or path.startswith("//") or method not in {"GET", "POST"}:
            return []
        field_names = envelope.get("field_names") or []
        if not isinstance(field_names, list) or any(not isinstance(name, str) or not name for name in field_names):
            return []
        values = {
            name: _poc_disposable_form_value(name)
            for name in field_names
        }
        step = {
            "path": path,
            "method": method,
            "transport": "query" if method == "GET" else "form",
            "values": values,
        }
        csrf_field = envelope.get("dynamic_csrf_field")
        if csrf_field:
            # The dynamic verifier accepts only the exact _csrf hidden field.
            # Keep the field name, never its one-time value, so generated replay
            # code fetches a fresh token immediately before the form submission.
            if method != "POST" or csrf_field != "_csrf":
                return []
            step["dynamic_csrf_field"] = csrf_field
        steps.append(step)
    return steps


def _poc_disposable_form_value(field_name: str) -> str:
    """Safe, non-secret placeholder values for a fresh local-sandbox registration."""
    field = str(field_name).lower()
    if "email" in field:
        return "aax_replay@example.invalid"
    if "password" in field or field in {"pass", "passwd", "verify"}:
        return "CHANGE_ME"
    if field in {"firstname", "first_name", "given_name"}:
        return "Audit"
    if field in {"lastname", "last_name", "family_name"}:
        return "Agent"
    return "aax_replay_user"


def _writer_evidence(evidence: dict, exploit: dict, harness: dict | None) -> dict:
    """Create an in-memory-only writer view without weakening public evidence policy."""
    writer = copy.deepcopy(evidence)
    code = exploit.get("exploit_code") if isinstance(exploit, dict) else None
    if code:
        writer.setdefault("exploit", {})["exploit_code"] = code
        writer.setdefault("attack_plan", {})["code"] = code
    harness_code = (harness or {}).get("harness_code")
    if harness_code:
        writer.setdefault("harness", {})["harness_code"] = harness_code
    return writer


def _restore_persisted_primary_code(evidence: dict, exploit: dict,
                                    harness: dict | None) -> None:
    """Restore confirmed or honestly executed replay code after persistence."""
    code = exploit.get("exploit_code") if isinstance(exploit, dict) else None
    if not code:
        return
    evidence_exploit = evidence.setdefault("exploit", {})
    evidence_exploit["exploit_code"] = code
    evidence_exploit["code_kind"] = exploit.get("code_kind") or "validated_http_replay"
    evidence_exploit["generation_status"] = "generated"
    executed_without_hit = (
        (evidence.get("verification") or {}).get("dynamic_method")
        == "http_executed_not_reproduced"
    )
    evidence_exploit["validation_status"] = (
        "executed_not_reproduced" if executed_without_hit else "validated"
    )
    plan = evidence.get("attack_plan")
    if isinstance(plan, dict):
        plan["code"] = code
        artifact = (evidence.get("artifacts") or {}).get("validated_poc") or {}
        plan["persistence_status"] = artifact.get("persistence_status")
        plan["artifact_sha256"] = artifact.get("sha256")
        plan["code_kind"] = exploit.get("code_kind") or "validated_http_replay"
        plan["generation_status"] = "generated"
        plan["validation_status"] = (
            "executed_not_reproduced" if executed_without_hit else "validated"
        )
    if (harness or {}).get("verdict") == "target_confirmed":
        evidence.setdefault("harness", {})["harness_code"] = (harness or {}).get("harness_code")


def _enforce_pipeline_poc_release(evidence: dict) -> None:
    """Defence in depth: UI-facing pipeline output has no unpersisted PoC code."""
    verification = evidence.get("verification") or {}
    artifact = (evidence.get("artifacts") or {}).get("validated_poc") or {}
    runtime_authorized = (
        verification.get("dynamically_verified")
        and verification.get("dynamic_method") in {"http_dynamic", "target_harness"}
    ) or (
        verification.get("dynamic_method") == "http_executed_not_reproduced"
        and is_executed_not_reproduced_runtime(evidence.get("runtime") or {})
    )
    authorized = bool(
        runtime_authorized
        and artifact.get("persistence_status") == "persisted"
        and isinstance(artifact.get("sha256"), str)
        and artifact["sha256"].strip()
    )
    if authorized:
        return
    for section in ("exploit", "attack_plan", "harness", "poc_result"):
        if section in evidence:
            evidence[section] = _redact_poc_code(evidence[section])


def _redact_poc_code(value):
    if isinstance(value, dict):
        return {
            key: (None if str(key).lower() in {"code", "exploit_code", "harness_code"}
                  else _redact_poc_code(item))
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact_poc_code(item) for item in value]
    return value


def _safe_stage_error(stage: str, exc: BaseException) -> str:
    """Describe an internal failure without persisting exception text or local paths."""
    return f"{stage} failed ({type(exc).__name__})."


def _http_error_result(exc: BaseException, sandbox_meta: dict | None) -> dict:
    result = _dynamic_skip_result(
        "execution_error", _safe_stage_error("HTTP verification", exc),
    )
    result["skipped"] = False
    if sandbox_meta:
        result["sandbox"] = sandbox_meta
    return result


def _harness_error_result(exc: BaseException) -> dict:
    return {
        "verdict": "execution_error",
        "dynamically_triggered": False,
        "reason": _safe_stage_error("Harness verification", exc),
    }


def _target_error_result(exc: BaseException) -> dict:
    return {
        "status": "sandbox_start_failed",
        "failure_code": "sandbox_start_failed",
        "reason": _safe_stage_error("Dynamic target preparation", exc),
    }


def _unpack_target(resolved) -> tuple:
    """Normalize legacy target context tuples without moving the context across threads."""
    if isinstance(resolved, tuple) and len(resolved) == 4:
        return resolved
    if isinstance(resolved, tuple) and len(resolved) == 3:
        return (*resolved, None)
    if isinstance(resolved, tuple) and len(resolved) >= 2:
        return resolved[0], resolved[1], None, None
    return None, None, None, None


def _should_run_dynamic_verify(finding: dict, exploit: dict,
                               base_url: str | None,
                               endpoints: list[dict] | None) -> tuple[bool, str, str]:
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

    if not endpoints or not all(_is_proven_bound_surface(surface) for surface in endpoints):
        return False, "endpoint_unresolved", "未解析到 source→route/endpoint 绑定；未执行猜测式 HTTP 探测"

    if exploit.get("authorization_workflow"):
        return True, "", ""

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


def _is_started_local_sandbox(sandbox_meta: dict | None, base_url: str | None) -> bool:
    """Deterministic injection plans may target only this scan's loopback sandbox."""
    if not isinstance(sandbox_meta, dict) or sandbox_meta.get("status") != "started":
        return False
    host = (urlparse(str(base_url or "")).hostname or "").strip("[]").lower()
    return host in {"127.0.0.1", "::1", "localhost"}


def _attach_disposable_initializer(exploit: dict, full_endpoint_inventory: list[dict] | None,
                                   sandbox_meta: dict | None, base_url: str | None) -> list[dict]:
    """Attach one source-extracted DB reset only to this scan's Docker sandbox.

    The full source inventory is deliberately separate from the finding-bound
    surfaces: an initializer prepares the target but cannot prove a sink flow.
    It receives a narrow server capability solely when this pipeline owns a
    started loopback Docker target.  Nothing is attached for URL, local-process,
    failed, or externally addressed targets.
    """
    if not (_is_disposable_sandbox(sandbox_meta) and _is_started_local_sandbox(sandbox_meta, base_url)):
        return []
    initializer = plan_disposable_initializer(full_endpoint_inventory)
    if not initializer:
        return []

    source = next((
        item for item in (full_endpoint_inventory or [])
        if isinstance(item, dict)
        and plan_disposable_initializer([item]) == initializer
    ), None)
    if source is None:  # Defensive: planner and capability must describe one route.
        return []
    capability = bind_server_surface(dict(source), {
        "kind": "disposable_initializer",
        "route_file": source.get("file"),
        "route_line": source.get("line"),
        "operation_id": source.get("operation_id"),
    })
    if not is_server_bound_surface(capability):
        return []

    if isinstance(exploit.get("authorization_workflow"), dict):
        workflow = exploit["authorization_workflow"]
        steps = workflow.get("steps")
        if not isinstance(steps, list) or any(
            isinstance(step, dict) and step.get("role") == "initialize" for step in steps
        ):
            return []
        workflow["steps"] = [dict(initializer), *steps]
    else:
        existing = exploit.get("setup_requests") or []
        if not isinstance(existing, list):
            return []
        exploit["setup_requests"] = [dict(initializer), *existing]
    return [capability]


def _auth_bootstrap_inventory(endpoints: list[dict] | None) -> list[dict]:
    """Mint an auth-only capability from freshly extracted server route metadata.

    This inventory is passed separately from the finding-bound target surface, so
    it cannot broaden candidate probing.  The form helper still requires exactly
    one GET+POST registration path and one GET+POST login path.
    """
    from backend.dynamic.form_auth import is_auth_bootstrap_surface

    inventory = []
    for surface in endpoints or []:
        if not is_auth_bootstrap_surface(surface):
            continue
        item = dict(surface)
        inventory.append(bind_server_surface(item, {
            "kind": "auth_bootstrap_inventory",
            "route_file": item.get("file"),
            "route_line": item.get("line"),
        }))
    return inventory


def _proven_surfaces_for_finding(finding: dict, endpoints, code_root: Path | None) -> list[dict]:
    """Mint HTTP capability only for a source-file-proven route→source→sink flow.

    A route adjacent to a sink is not evidence that its request data reaches the
    sink.  The conservative proof accepts either a direct handler request read
    or a statically resolved local Python call chain that preserves a declared
    request parameter.  Unsupported flows stay unresolved rather than becoming
    speculative HTTP probes.
    """
    if code_root is None:
        return []
    root = Path(code_root).resolve()
    bound = _surfaces_for_finding(finding, endpoints)
    # A model/service-layer sink has no same-file decorator.  Every extracted
    # route is considered only for the static intermodule proof below; a route
    # that cannot prove parameter flow is never minted or requested.
    proof_candidates = bound or [item for item in endpoints if isinstance(item, dict)]
    proven: list[dict] = []
    python_index: dict | None = None
    for surface in proof_candidates:
        proof = _source_route_sink_proof(finding, surface, root)
        if proof is None:
            python_index = python_index or _python_function_index(root)
            proof = _intermodule_source_route_sink_proof(finding, surface, python_index)
        if proof is None:
            continue
        item = dict(surface)
        item["source_route_binding"] = proof
        proven.append(bind_server_surface(item, proof))
    return proven


def _source_route_sink_proof(finding: dict, surface: dict, root: Path) -> dict | None:
    """Return server-derived proof for a direct handler input→sink association."""
    raw_file = str(surface.get("file") or "").replace("\\", "/").lstrip("./")
    try:
        route_line = int(surface.get("line") or 0)
        sink_line = int(finding.get("start_line") or finding.get("line") or 0)
    except (TypeError, ValueError):
        return None
    if not raw_file or route_line <= 0 or sink_line < route_line:
        return None
    path = (root / raw_file).resolve()
    try:
        path.relative_to(root)
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except (OSError, ValueError):
        return None
    if sink_line > len(lines):
        return None
    route_end = len(lines) + 1
    for candidate in (surface.get("_all_route_lines") or []):
        try:
            candidate_line = int(candidate)
        except (TypeError, ValueError):
            continue
        if route_line < candidate_line < route_end:
            route_end = candidate_line
    # Endpoint extraction reports independent route entries.  Recover the next
    # decorator/route declaration from the actual source so a source read from
    # a later handler cannot be used to justify this sink.
    route_declaration = re.compile(
        r"^\s*(?:@(?:\w+\.)?(?:route|get|post|put|delete|patch)|"
        r"(?:app|router|server|api)\.(?:get|post|put|delete|patch|all)\s*\()",
        re.I,
    )
    for index in range(route_line, min(route_end - 1, len(lines))):
        if route_declaration.search(lines[index]):
            route_end = index + 1
            break
    if sink_line >= route_end:
        return None
    source_region = "\n".join(lines[route_line - 1:sink_line])
    sink_text = lines[sink_line - 1]
    for parameter in surface.get("params") or []:
        if not isinstance(parameter, dict):
            continue
        name = str(parameter.get("name") or "").strip()
        if not name:
            continue
        input_pattern = _request_parameter_pattern(name)
        if not input_pattern:
            continue
        if input_pattern.search(sink_text):
            return _binding_proof(finding, surface, route_line, sink_line, name, "direct_request_expression")
        for match in re.finditer(
                rf"\b([A-Za-z_$][\w$]*)\s*=\s*[^\n]*{input_pattern.pattern}",
                source_region, re.I):
            variable = match.group(1)
            if re.search(rf"\b{re.escape(variable)}\b", sink_text):
                return _binding_proof(finding, surface, route_line, sink_line, name, "one_hop_local_assignment")
    return None


def _intermodule_source_route_sink_proof(finding: dict, surface: dict, index: dict) -> dict | None:
    """Prove a route request value reaches a sink through local Python calls.

    This deliberately analyzes only parseable files under the scanned root,
    literal local imports, named request reads, and positional/named Python call
    arguments.  It never consumes model-produced call paths, nor does it infer a
    route from a sink function name.  Unsupported flows remain unresolved.
    """
    try:
        sink_file = _relative_python_path(finding.get("file"))
        route_file = _relative_python_path(surface.get("file"))
        sink_line = int(finding.get("start_line") or finding.get("line") or 0)
        route_line = int(surface.get("line") or 0)
    except (TypeError, ValueError):
        return None
    if not sink_file or not route_file or sink_line <= 0 or route_line <= 0 or sink_file == route_file:
        return None
    route = _route_handler(index, route_file, route_line)
    sink = _function_at_line(index, sink_file, sink_line)
    if route is None or sink is None:
        return None
    source_parameters = {
        str(parameter.get("name"))
        for parameter in surface.get("params") or []
        if isinstance(parameter, dict) and parameter.get("name")
    }
    for parameter in sorted(source_parameters):
        depth = _trace_python_parameter_flow(
            index, route, {parameter}, sink, sink_line, parameter, visited=set(), depth=0,
        )
        if depth is not None:
            proof = _binding_proof(
                finding, surface, route_line, sink_line, parameter, "intermodule_parameter_flow",
            )
            proof["call_depth"] = depth
            return proof
    return None


def _relative_python_path(value: object) -> str:
    return str(value or "").replace("\\", "/").lstrip("./")


def _python_function_index(root: Path) -> dict:
    """Index only local Python modules and their literal import aliases."""
    modules: dict[str, str] = {}
    trees: dict[str, ast.Module] = {}
    for path in root.rglob("*.py"):
        if len(trees) >= 4000:
            break
        if any(part in {".git", ".venv", "venv", "__pycache__", "node_modules"} for part in path.parts):
            continue
        try:
            rel = path.resolve().relative_to(root).as_posix()
            trees[rel] = ast.parse(path.read_text(encoding="utf-8", errors="ignore"))
            modules[_python_module_name(rel)] = rel
        except (OSError, ValueError, SyntaxError):
            continue
    functions: dict[tuple[str, str], dict] = {}
    for rel, tree in trees.items():
        imports = _local_python_imports(tree, rel, modules)
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                functions[(rel, node.name)] = _indexed_python_function(node, rel, imports)
            elif isinstance(node, ast.ClassDef):
                # Class attributes are resolvable only when Python can dispatch
                # them without an instance.  This covers service/model helpers
                # such as ``User.get_user(value)`` while refusing speculative
                # instance-method flows such as ``service.get_user(value)``.
                for method in node.body:
                    if (isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef))
                            and _is_class_dispatchable_method(method)):
                        name = f"{node.name}.{method.name}"
                        functions[(rel, name)] = _indexed_python_function(
                            method, rel, imports, name=name,
                        )
    return {"functions": functions}


def _indexed_python_function(node: ast.FunctionDef | ast.AsyncFunctionDef, rel: str,
                             imports: dict[str, tuple[str, str]], *, name: str | None = None) -> dict:
    return {
        "file": rel,
        "name": name or node.name,
        "node": node,
        "imports": imports,
        "params": [argument.arg for argument in (*node.args.posonlyargs, *node.args.args)],
        "start": min([node.lineno, *[decorator.lineno for decorator in node.decorator_list]]),
        "end": getattr(node, "end_lineno", node.lineno),
    }


def _is_class_dispatchable_method(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """Whether ``Class.method(...)`` is provably valid without an instance."""
    return any(
        isinstance(decorator, ast.Name) and decorator.id in {"staticmethod", "classmethod"}
        for decorator in node.decorator_list
    )


def _python_module_name(rel: str) -> str:
    module = rel[:-3].replace("/", ".")
    return module.rsplit(".__init__", 1)[0] if module.endswith(".__init__") else module


def _local_python_imports(tree: ast.Module, rel: str, modules: dict[str, str]) -> dict[str, tuple[str, str]]:
    imports: dict[str, tuple[str, str]] = {}
    package = _python_module_name(rel).split(".")[:-1]
    for node in tree.body:
        if not isinstance(node, ast.ImportFrom):
            continue
        base = node.module.split(".") if node.module else []
        if node.level:
            base = package[:max(0, len(package) - node.level + 1)] + base
        target_file = modules.get(".".join(base))
        if not target_file:
            continue
        for alias in node.names:
            imports[alias.asname or alias.name] = (target_file, alias.name)
    return imports


def _route_handler(index: dict, route_file: str, route_line: int) -> dict | None:
    for function in index["functions"].values():
        if function["file"] == route_file and function["start"] == route_line:
            return function
    return None


def _function_at_line(index: dict, file_path: str, line: int) -> dict | None:
    matches = [function for function in index["functions"].values()
               if function["file"] == file_path and function["start"] <= line <= function["end"]]
    return min(matches, key=lambda function: function["end"] - function["start"]) if matches else None


def _trace_python_parameter_flow(index: dict, function: dict, tainted: set[str], sink: dict,
                                 sink_line: int, source_parameter: str, *, visited: set, depth: int) -> int | None:
    if depth > 6:
        return None
    key = (function["file"], function["name"], tuple(sorted(tainted)))
    if key in visited:
        return None
    visited = {*visited, key}
    node = function["node"]
    if function is sink and _sink_line_uses_taint(
            node, sink_line, _propagate_local_taint(node, tainted, source_parameter, sink_line)):
        return depth
    for call in sorted(_function_calls(node), key=lambda item: item.lineno):
        target = _local_call_target(index, function, call)
        if target is None:
            continue
        tainted_at_call = _propagate_local_taint(node, tainted, source_parameter, call.lineno)
        target_taint = _tainted_call_parameters(call, target, tainted_at_call, source_parameter)
        if not target_taint:
            continue
        result = _trace_python_parameter_flow(
            index, target, target_taint, sink, sink_line, source_parameter,
            visited=visited, depth=depth + 1,
        )
        if result is not None:
            return result
    return None


def _function_calls(node: ast.AST) -> list[ast.Call]:
    calls: list[ast.Call] = []

    class _Calls(ast.NodeVisitor):
        def visit_FunctionDef(self, child):
            if child is node:
                self.generic_visit(child)

        visit_AsyncFunctionDef = visit_FunctionDef

        def visit_Lambda(self, child):
            return None

        def visit_Call(self, child):
            calls.append(child)
            self.generic_visit(child)

    _Calls().visit(node)
    return calls


def _local_call_target(index: dict, function: dict, call: ast.Call) -> dict | None:
    if isinstance(call.func, ast.Name):
        name = call.func.id
        target_key = function["imports"].get(name, (function["file"], name))
    elif (isinstance(call.func, ast.Attribute)
          and isinstance(call.func.value, ast.Name)):
        class_name = call.func.value.id
        target_file, declared_class = function["imports"].get(
            class_name, (function["file"], class_name),
        )
        target_key = (target_file, f"{declared_class}.{call.func.attr}")
    else:
        return None
    return index["functions"].get(target_key)


def _propagate_local_taint(node: ast.AST, tainted: set[str], source_parameter: str,
                           before_or_at: int) -> set[str]:
    tainted = set(tainted)
    json_aliases: set[str] = set()
    assignments: list[ast.Assign | ast.AnnAssign] = []

    class _Assignments(ast.NodeVisitor):
        def visit_FunctionDef(self, child):
            if child is node:
                self.generic_visit(child)

        visit_AsyncFunctionDef = visit_FunctionDef

        def visit_Lambda(self, child):
            return None

        def visit_Assign(self, child):
            assignments.append(child)
            self.generic_visit(child)

        def visit_AnnAssign(self, child):
            assignments.append(child)
            self.generic_visit(child)

    _Assignments().visit(node)
    for child in sorted(assignments, key=lambda item: item.lineno):
        if child.lineno > before_or_at:
            break
        targets = [target.id for target in (child.targets if isinstance(child, ast.Assign) else [child.target])
                   if isinstance(target, ast.Name)]
        if not targets:
            continue
        if _is_request_json(child.value):
            json_aliases.update(targets)
        if (_expression_reads_request_parameter(child.value, source_parameter, json_aliases)
                or _expression_uses_taint(child.value, tainted)):
            tainted.update(targets)
    return tainted


def _is_request_json(value: ast.AST) -> bool:
    return bool(isinstance(value, ast.Call) and isinstance(value.func, ast.Attribute)
                and isinstance(value.func.value, ast.Name) and value.func.value.id == "request"
                and value.func.attr == "get_json") or bool(
                    isinstance(value, ast.Attribute) and isinstance(value.value, ast.Name)
                    and value.value.id == "request" and value.attr == "json")


def _expression_reads_request_parameter(value: ast.AST, name: str, json_aliases: set[str]) -> bool:
    escaped = re.escape(name)
    try:
        text = ast.unparse(value)
    except Exception:  # noqa: BLE001 - parseable AST nodes should unparse, otherwise fail closed
        return False
    request_read = re.compile(
        rf"request\.(?:args|form|values|json)\s*(?:\.get\(|\[)\s*['\"]{escaped}['\"]|"
        rf"request\.get_json\(\)\.get\(\s*['\"]{escaped}['\"]|"
        rf"request\.get_json\(\)\s*\[\s*['\"]{escaped}['\"]",
    )
    if request_read.search(text):
        return True
    return any(re.search(rf"\b{re.escape(alias)}\s*(?:\.get\(|\[)\s*['\"]{escaped}['\"]", text)
               for alias in json_aliases)


def _expression_uses_taint(value: ast.AST, tainted: set[str]) -> bool:
    return any(isinstance(child, ast.Name) and child.id in tainted for child in ast.walk(value))


def _tainted_call_parameters(call: ast.Call, target: dict, tainted: set[str],
                             source_parameter: str) -> set[str]:
    output: set[str] = set()
    for position, argument in enumerate(call.args):
        if position < len(target["params"]) and (
                _expression_uses_taint(argument, tainted)
                or _expression_reads_request_parameter(argument, source_parameter, set())):
            output.add(target["params"][position])
    for keyword in call.keywords:
        if keyword.arg in target["params"] and (
                _expression_uses_taint(keyword.value, tainted)
                or _expression_reads_request_parameter(keyword.value, source_parameter, set())):
            output.add(keyword.arg)
    return output


def _sink_line_uses_taint(node: ast.AST, sink_line: int, tainted: set[str]) -> bool:
    return any(
        isinstance(child, ast.Name) and child.id in tainted
        and getattr(child, "lineno", 0) <= sink_line <= getattr(child, "end_lineno", child.lineno)
        for child in ast.walk(node)
    )


def _request_parameter_pattern(name: str) -> re.Pattern | None:
    """Match a named server request read; never infer a parameter by convention."""
    escaped = re.escape(name)
    return re.compile(
        rf"(?:request\.(?:args|form|values|json)\.get\(\s*['\"]{escaped}['\"]|"
        rf"request\.get_json\(\)\.get\(\s*['\"]{escaped}['\"]|"
        rf"request\.(?:args|form|values|json)\s*\[\s*['\"]{escaped}['\"]\s*\]|"
        rf"req\.(?:query|body|params)\.{escaped}\b|"
        rf"req\.(?:query|body|params)\s*\[\s*['\"]{escaped}['\"]\s*\]|"
        rf"\$_(?:GET|POST|REQUEST)\s*\[\s*['\"]{escaped}['\"]\s*\])",
        re.I,
    )


def _binding_proof(finding: dict, surface: dict, route_line: int, sink_line: int,
                   parameter: str, proof_kind: str) -> dict:
    return {
        "kind": "source_route_sink",
        "proof_kind": proof_kind,
        "finding_file": finding.get("file"),
        "finding_line": sink_line,
        "route_file": surface.get("file"),
        "route_line": route_line,
        "source_parameter": parameter,
    }


def _surfaces_for_finding(finding: dict, endpoints):
    """Bind only the finding's server-recorded source location to current routes."""
    if not isinstance(endpoints, list) or not endpoints or not all(
        isinstance(item, dict) for item in endpoints
    ):
        # Legacy list[str] configurations carry no source→route proof.  They
        # must never reach DynamicVerifier as a convenient HTTP spray list.
        return []
    # ``_verify`` is persisted/transported JSON and may include model-generated
    # call paths, source labels, or route claims.  It is diagnostic evidence only:
    # never use it to move a finding to another file or parameter.  The static
    # finding location and freshly extracted current-code routes are the complete
    # authority for this binding.
    file_path = str(finding.get("file") or "").replace("\\", "/").lstrip("./")
    try:
        finding_line = int(finding.get("start_line") or finding.get("line") or 0)
    except (TypeError, ValueError):
        finding_line = 0
    if file_path and finding_line > 0:
        same_file = [
            item for item in endpoints
            if str(item.get("file") or "").replace("\\", "/").lstrip("./") == file_path
            and int(item.get("line") or 0) > 0
            and int(item.get("line") or 0) <= finding_line
        ]
        if same_file:
            nearest_line = max(int(item.get("line") or 0) for item in same_file)
            return _bound_surfaces_for_finding(
                [item for item in same_file if int(item.get("line") or 0) == nearest_line],
                endpoints, finding, "nearest_source_route",
            )
    # No source-to-route/parameter association is evidence of an unresolved
    # entrypoint, never permission to probe every discovered application route.
    return []


def _bound_surfaces_for_finding(surfaces: list[dict], all_endpoints: list[dict], finding: dict,
                                kind: str) -> list[dict]:
    """Bind a direct route, plus an explicit server-derived BOLA workflow scope."""
    if _is_bola_finding(finding):
        # A BOLA proof needs authenticated setup/create/read operations.  Once a
        # direct source route anchors the finding, the server binds this extracted
        # API inventory as one auditable workflow scope before the planner sees it.
        return _bind_surfaces_to_finding(all_endpoints, finding, "authorization_workflow_scope")
    return _bind_surfaces_to_finding(surfaces, finding, kind)


def _is_bola_finding(finding: dict) -> bool:
    value = str(finding.get("type") or "").lower()
    return any(token in value for token in ("bola", "idor", "object level authorization"))


def _bind_surfaces_to_finding(surfaces: list[dict], finding: dict, kind: str) -> list[dict]:
    """Attach auditable source→route binding to extracted structured surfaces."""
    bound = []
    for surface in surfaces:
        if not isinstance(surface, dict) or not str(surface.get("path") or "").startswith("/"):
            continue
        item = dict(surface)
        binding = {
            "kind": kind,
            "finding_file": finding.get("file"),
            "finding_line": finding.get("start_line") or finding.get("line"),
            "route_file": item.get("file"),
            "route_line": item.get("line"),
        }
        bound.append(bind_server_surface(item, binding))
    return bound


def _is_proven_bound_surface(surface: object) -> bool:
    return bool(
        is_server_bound_surface(surface)
        and str(surface.get("path") or "").startswith("/")
    )


_COUNTEREVIDENCE_BLOCKER_CODES = {
    "source_not_user_controlled", "template_source_not_user_controlled",
    "no_path_sink", "path_sink_absent", "no_sink", "sink_unreachable",
}


def _static_counterevidence_reason(finding: dict) -> str | None:
    """Return only explicit structured Verify evidence; never infer from prose."""
    verify = finding.get("_verify") or {}
    reason = verify.get("false_positive_reason")
    if isinstance(reason, str) and reason.strip():
        return "Verify evidence contains an explicit false_positive_reason; candidate execution is suppressed"
    for blocker in verify.get("confirmed_blockers") or finding.get("confirmed_blockers") or []:
        code = blocker.get("code") if isinstance(blocker, dict) else None
        if str(code or "").strip().lower() in _COUNTEREVIDENCE_BLOCKER_CODES:
            return f"Verify evidence blocker {code} suppresses candidate execution"
    return None


def _harness_target_blockers(harness: dict | None) -> list[str]:
    h = harness or {}
    blockers: list[str] = []
    if not h.get("function_extracted"):
        blockers.append("function_extracted=false: target project function was not extracted")
    if not h.get("target_function_called"):
        blockers.append("target_function_called=false: harness did not prove real target invocation")
    if h.get("verification_level") != "entrypoint_reproduced":
        blockers.append("verification_level is not entrypoint_reproduced")
    if not h.get("entrypoint_reachable"):
        blockers.append("entrypoint_reachable=false: no real entrypoint-to-function flow was proven")
    if h.get("harness_source") == "template":
        blockers.append("template harness is mechanism-only")
    return blockers


def _dedupe(items: list[Any]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        text = str(item)
        if text and text not in seen:
            seen.add(text)
            out.append(text)
    return out


def _redact_exploit_for_storage(exploit: dict) -> dict:
    """持久化前移除认证前置步骤中的凭据；运行阶段仍使用内存中的原值。"""
    stored = copy.deepcopy(exploit)
    # detail_json is not the canonical persisted artifact.  Keeping code here
    # leaks hypotheses before artifact persistence and creates a second source
    # of executable content.  The Evidence policy may expose the canonical
    # persisted artifact only after its hash is present.
    stored["exploit_code"] = None
    sensitive = re.compile(r"password|passwd|secret|token|api[_-]?key|authorization|cookie", re.I)
    for step in stored.get("setup_requests") or []:
        if not isinstance(step, dict):
            continue
        for field in ("values", "json", "data", "params"):
            values = step.get(field)
            if not isinstance(values, dict):
                continue
            for key in list(values):
                if sensitive.search(str(key)):
                    values[key] = "<redacted>"
    workflow = stored.get("authorization_workflow")
    for step in (workflow.get("steps") if isinstance(workflow, dict) else []) or []:
        if not isinstance(step, dict):
            continue
        for field in ("values", "headers"):
            values = step.get(field)
            if not isinstance(values, dict):
                continue
            for key in list(values):
                if sensitive.search(str(key)):
                    values[key] = "<redacted>"
    headers = stored.get("request_headers")
    if isinstance(headers, dict):
        for key in list(headers):
            if sensitive.search(str(key)):
                headers[key] = "<redacted>"
    return _redact_nested_sensitive(stored, sensitive)


def _redact_nested_sensitive(value, sensitive: re.Pattern):
    """Apply the same secret rule to workflow oracle/headers and future nested fields."""
    if isinstance(value, dict):
        return {
            key: ("<redacted>" if sensitive.search(str(key)) and item not in (None, "")
                  else _redact_nested_sensitive(item, sensitive))
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact_nested_sensitive(item, sensitive) for item in value]
    if isinstance(value, tuple):
        return tuple(_redact_nested_sensitive(item, sensitive) for item in value)
    return value
