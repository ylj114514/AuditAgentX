"""动态验证器（PDF 选题一：动态检测 / 漏洞验证）。

对一个**正在运行的目标应用**（沙箱内或授权靶场）发送攻击载荷，
采集 request / response / log 证据，并根据成功特征判定漏洞是否**可复现**。

设计为 provider 无关：只需要一个可访问的 base_url。
- Docker 沙箱起服务  -> DockerAppRunner / DockerProjectRunner
- 本地授权靶场       -> LocalAppRunner（仅限隔离实验环境）
"""
from __future__ import annotations

import json
import logging
import random
import re
import time
from collections import Counter
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, quote, urlencode, urlparse, urlunparse

logger = logging.getLogger(__name__)

# HTTP 状态 -> 机器可读 blocker 原因。这些状态表示请求在进入目标业务逻辑之前就被拦截
# （鉴权/授权/方法/媒体类型/必填校验/限流/网关），属于 blocked，绝不能当成 not_reproduced。
_BLOCKED_STATUS_REASONS = {
    400: "request_invalid",
    401: "authentication_failed",
    403: "authorization_blocked",
    404: "endpoint_unreachable",
    405: "method_not_allowed",
    406: "not_acceptable",
    415: "unsupported_media_type",
    422: "request_invalid",
    429: "rate_limited",
    501: "not_implemented",
    502: "gateway_error",
    503: "target_unhealthy",
    504: "gateway_timeout",
}


def _status_reason(status: "int | None") -> str:
    """状态码 -> blocker 原因；2xx/3xx 与 500（handler 已执行、error-based 可利用）
    返回空串（非 blocker）。"""
    if status is None:
        return ""
    return _BLOCKED_STATUS_REASONS.get(int(status), "")


def _reached_business_logic(status) -> bool:
    """请求是否已进入目标业务逻辑：2xx/3xx=handler 正常执行；500=handler 执行中抛错
    （error-based 注入的关键信号）。其余状态多为业务逻辑之前的前置拦截。"""
    if status is None:
        return False
    status = int(status)
    return status < 400 or status == 500

# 从代码/路由里猜测的常见端点（无显式 endpoints 时的兜底）
_HEURISTIC_PATHS = ["/", "/user", "/search", "/ping", "/load", "/api", "/download", "/view"]
# 同一候选连续两次无法建立连接或请求超时，继续把 120 个载荷都打到已失效
# 的靶场没有新增证据价值，反而会让动态阶段长时间看似卡住。
_MAX_CONSECUTIVE_TRANSPORT_FAILURES = 2


@dataclass
class ProbeRecord:
    url: str
    method: str
    params: dict
    payload: str
    transport: str = "query"
    role: str = "attack"  # baseline | attack | confirmation
    status: int | None = None
    status_code: int | None = None
    response_excerpt: str = ""
    response_headers: dict = field(default_factory=dict)
    redirect_location: str = ""
    setup_response_body: str = ""  # bounded in-memory form parsing only; never public evidence
    elapsed_ms: int = 0
    runtime_log_excerpt: str = ""
    request_header_names: list = field(default_factory=list)
    error: str = ""
    reason: str = ""


@dataclass
class DynamicResult:
    verified: bool = False
    reproducible: bool = False
    reproduction_status: str = "not_executed"
    matched_indicator: str = ""
    confirmed_record: dict | None = None
    baseline_record: dict | None = None
    baseline_records: list = field(default_factory=list)
    records: list = field(default_factory=list)   # list[ProbeRecord as dict]
    logs: list = field(default_factory=list)
    skipped: bool = False
    reason: str = ""
    error: str = ""
    verification_level: str = "not_executed"
    oracle: str = ""
    surfaces: list = field(default_factory=list)
    setup_records: list = field(default_factory=list)
    confirmation_records: list = field(default_factory=list)
    blocker_reason: str = ""
    application_reached: bool = False
    state_contamination_possible: bool = False
    disposable_auth_bootstrap: bool = False
    server_binding: dict = field(default_factory=dict)


class HttpProbe:
    """底层 HTTP 探测：发请求并完整记录，供证据链使用。"""

    def __init__(self, timeout: int = 10) -> None:
        self.timeout = timeout
        self._client = None

    def _session(self):
        """One client per verifier campaign so login cookies and CSRF state survive."""
        if self._client is None:
            import httpx
            self._client = httpx.Client(
                timeout=self.timeout, follow_redirects=False, trust_env=False,
            )
        return self._client

    def close(self) -> None:
        if self._client is not None:
            self._client.close()
            self._client = None

    def send(self, base_url: str, path: str, param: str, payload: str,
             method: str = "GET", transport: str = "query", role: str = "attack",
             headers: dict | None = None, sibling_values: dict | None = None) -> ProbeRecord:
        values = dict(sibling_values or {})
        values[param] = payload
        return self.send_values(
            base_url, path, values, method=method, transport=transport,
            role=role, headers=headers, payload=payload,
        )

    def send_values(self, base_url: str, path: str, values: dict, *,
                    method: str = "POST", transport: str = "json",
                    role: str = "setup", headers: dict | None = None,
                    payload: str = "") -> ProbeRecord:
        """发送多字段请求，供登录/会话初始化等有状态验证前置步骤使用。"""
        import httpx
        from backend.dynamic.target_guard import validate_dynamic_base_url

        safe_base = validate_dynamic_base_url(base_url)
        if not str(path or "").startswith("/") or str(path).startswith("//"):
            raise ValueError("dynamic endpoint must be a project-relative path starting with one slash")
        method = _http_method(method)
        transport = _transport_for(method, transport)
        values = dict(values or {})
        request_path = path
        if transport == "path":
            for name, value in values.items():
                request_path = _replace_path_parameter(request_path, str(name), str(value))
        url = safe_base.rstrip("/") + request_path
        rec = ProbeRecord(
            url=url, method=method, params=values,
            payload=payload or str(next(iter(values.values()), "")),
            transport=transport, role=role,
            request_header_names=sorted(str(key) for key in (headers or {})),
        )
        t0 = time.time()
        try:
            # 禁止自动跟随重定向：否则本地靶场可用 30x 把探测器带到外部地址，
            # 绕过 local-only 目标保护；开放重定向也必须通过 Location 头判定。
            client = self._session()
            if transport == "path":
                resp = client.request(method, url, headers=headers)
            elif transport == "query":
                resp = client.request(method, url, params=values, headers=headers)
            elif transport == "json":
                resp = client.request(method, url, json=values, headers=headers)
            elif transport == "multipart":
                files = {str(k): ("aax.txt", str(v).encode("utf-8"), "text/plain")
                         for k, v in values.items()}
                resp = client.request(method, url, files=files, headers=headers)
            elif transport == "header":
                merged_headers = {**(headers or {}), **{str(k): str(v) for k, v in values.items()}}
                resp = client.request(method, url, headers=merged_headers)
            elif transport == "cookie":
                resp = client.request(method, url, headers=headers,
                                      cookies={str(k): str(v) for k, v in values.items()})
            else:
                resp = client.request(method, url, data=values, headers=headers)
            rec.url = str(resp.request.url)
            rec.status = resp.status_code
            rec.status_code = resp.status_code
            rec.response_excerpt = resp.text[:800]
            if role == "setup":
                rec.setup_response_body = resp.text[:65536]
            rec.response_headers = {str(k).lower(): str(v)[:500] for k, v in resp.headers.items()}
            rec.redirect_location = str(resp.headers.get("location") or "")[:500]
            rec.reason = _status_reason(resp.status_code)
        except httpx.ConnectError as e:
            rec.error = str(e)
            rec.reason = "connection_failed"
        except httpx.TimeoutException as e:
            rec.error = str(e)
            rec.reason = "request_timeout"
        except httpx.RequestError as e:
            rec.error = str(e)
            rec.reason = "request_error"
        except Exception as e:  # noqa: BLE001
            rec.error = str(e)
            rec.reason = "request_error"
        rec.elapsed_ms = int((time.time() - t0) * 1000)
        return rec


class DynamicVerifier:
    """对运行中的目标执行动态利用并判定可复现。"""

    def __init__(self, timeout: int = 10, max_probes: int = 120) -> None:
        self.probe = HttpProbe(timeout=timeout)
        self.max_probes = max_probes

    def verify(self, base_url: str, exploit: dict,
               endpoints: list[dict] | None = None, *, runtime_log_supplier=None,
               auth_endpoints: list[dict] | None = None) -> DynamicResult:
        """
        base_url  : 运行中的目标（如 http://127.0.0.1:8080）
        exploit   : ExploitAgent 产出，含 payloads / success_indicators / injection_points
        endpoints : 显式端点路径；缺省用启发式路径
        """
        result = DynamicResult()
        # Setup/login and mutating endpoints can change shared target state. The
        # pipeline may provide a disposable target, but this verifier never silently
        # assumes reset/snapshot semantics it cannot prove.
        result.state_contamination_possible = bool(exploit.get("setup_requests"))
        if not base_url:
            result.skipped = True
            result.reproduction_status = "not_executed"
            result.reason = "无可用目标 base_url（未启用沙箱/靶场）"
            return result

        # This verifier is intentionally stricter than the general target guard:
        # confirmed-PoC evidence is local-only even if an unrelated deployment
        # setting permits external diagnostic targets.  Check before the probe so
        # fake clients and future transports cannot bypass the zero-request rule.
        from backend.dynamic.target_guard import is_loopback_base_url
        if not is_loopback_base_url(base_url):
            result.skipped = True
            result.reproduction_status = "not_applicable"
            result.reason = "confirmed PoC HTTP verification requires a loopback base_url; no request sent"
            return result

        # This is the final HTTP boundary.  Callers must pass a structured
        # surface carrying a source→route proof, or the route service's explicit
        # manual-override marker. Raw strings and client-supplied binding claims
        # are not evidence of a finding-specific entrypoint.
        if not _has_proven_bound_surfaces(endpoints):
            result.skipped = True
            result.reproduction_status = "endpoint_unresolved"
            result.reason = "未提供证明 source→route 绑定的结构化 endpoint surface；未发送 HTTP 探测请求"
            return result

        if _is_open_redirect_type(exploit.get("vuln_type") or exploit.get("type")):
            return self._verify_open_redirect(
                base_url, exploit, endpoints or [], result, auth_endpoints=auth_endpoints)

        # BOLA/IDOR 不是“把一个 payload 塞进一个参数”就能证明的漏洞。它至少需要
        # 两个不同身份、一个明确归属的对象、owner control 和跨身份重复读取。
        # 工作流是受约束的数据结构，不执行 LLM 生成的脚本，也不允许绝对 URL。
        if exploit.get("authorization_workflow"):
            return self._verify_authorization_workflow(base_url, exploit, endpoints or [], result)

        payloads = exploit.get("payloads") or []
        indicators = [i for i in (exploit.get("success_indicators") or []) if i]
        source_parameter, source_parameter_error = _proven_source_parameter(endpoints)
        if source_parameter_error:
            result.skipped = True
            result.reproduction_status = "endpoint_unresolved"
            result.reason = source_parameter_error
            return result
        # A fresh server-side route→sink proof is stronger than a generic exploit
        # template's field hint.  This lets handler arguments such as
        # ``get_user(username)`` stay executable when their OpenAPI path parameter
        # was statically proven to reach the sink, without deriving a name from the
        # handler or guessing one from a route.
        params = ([source_parameter] if source_parameter else
                  [str(value) for value in (exploit.get("_injection_points") or []) if str(value)])
        preferred_method = _http_method(exploit.get("http_method") or exploit.get("method"))
        if not source_parameter and not _has_explicit_bound_parameter(endpoints, exploit):
            result.skipped = True
            result.reproduction_status = "endpoint_unresolved"
            result.reason = "未提供与 source-bound endpoint 匹配的明确参数；未发送 HTTP 探测请求"
            return result
        if not params:
            params = _bound_parameter_names(endpoints)
        if not payloads:
            result.skipped = True
            result.reproduction_status = "not_runtime_verifiable"
            result.reason = "该漏洞无动态载荷（可能为静态类，如硬编码密钥）"
            return result
        raw_surfaces = _surface_specs(endpoints, preferred_method)
        surfaces = _normalize_surfaces(raw_surfaces, params, preferred_method)
        result.surfaces = surfaces[:80]
        if not surfaces:
            result.skipped = True
            result.reproduction_status = "not_runtime_verifiable"
            result.reason = "没有安全的项目相对 endpoint；拒绝绝对 URL/协议相对路径"
            return result

        request_headers: dict[str, str] = {
            str(key): str(value) for key, value in (exploit.get("request_headers") or {}).items()
        }
        if not self._run_setup_requests(base_url, exploit, result, request_headers):
            result.skipped = True
            result.reproduction_status = "setup_failed"
            result.verification_level = "setup_failed"
            return self._finalize(result)

        # 每个“端点 + 方法 + 参数位置”都有独立良性基线。不能用 / 的响应给 /api/search 作对照。
        baseline_cache: dict[tuple[str, str, str, str], ProbeRecord] = {}
        result.logs.append(f"目标={base_url} 攻击面={len(surfaces)} 载荷数={len(payloads)}")

        # 迭代顺序保持 payload -> surface：优先以首个 payload 横扫真实源码/运行时入口，
        # 避免把预算耗在单一路径的一串猜测参数上。
        probes = 0
        stopped = False
        auth_bootstrap_attempted = False
        consecutive_transport_failures = 0
        for payload in payloads:
            if stopped:
                break
            for surface in surfaces:
                if probes >= self.max_probes:
                    result.logs.append("达到最大探测次数上限，停止")
                    stopped = True
                    break
                path = surface["path"]
                method = surface["method"]
                param = surface["param"]
                transport = surface["transport"]
                sibling_values = surface.get("sibling_values") or {}
                if method in {"POST", "PUT", "PATCH", "DELETE"}:
                    result.state_contamination_possible = True
                key = (path, method, param, transport)
                baseline = baseline_cache.get(key)
                if baseline is None:
                    baseline = self._send(
                        base_url, path, param, _control_value(param), method, transport,
                        "baseline", request_headers, sibling_values,
                    )
                    baseline_cache[key] = baseline
                    result.baseline_records.append(_public_record(baseline))
                    # A bound candidate may legitimately sit behind a local form-login
                    # wall.  Bootstrap is intentionally available only after seeing
                    # that redirect, never by guessing an auth route up front.
                    if not auth_bootstrap_attempted and _is_local_auth_redirect(base_url, baseline):
                        auth_bootstrap_attempted = True
                        bootstrap = _bootstrap_local_form_auth(
                            base_url, auth_endpoints if auth_endpoints is not None else (endpoints or []), self.probe)
                        _append_sanitized_auth_setup_records(result, bootstrap)
                        if not bootstrap.authenticated:
                            result.reason = "authentication_required"
                            result.blocker_reason = "authentication_required"
                            result.reproduction_status = "authentication_required"
                            result.verification_level = "endpoint_blocked"
                            result.logs.append("本地表单认证前置条件未满足；未猜测字段、CSRF 或外部 action")
                            return self._finalize(result)
                        result.state_contamination_possible = True
                        result.disposable_auth_bootstrap = True
                        # Cookies live in HttpProbe's one campaign client.  Rebuild the
                        # candidate-specific baseline after login before any attack.
                        baseline = self._send(
                            base_url, path, param, _control_value(param), method, transport,
                            "baseline", request_headers, sibling_values,
                        )
                        baseline_cache[key] = baseline
                        result.baseline_records.append(_public_record(baseline))
                        if _is_local_auth_redirect(base_url, baseline) or (baseline.status_code or baseline.status) in {401, 403}:
                            result.reason = "authentication_required"
                            result.blocker_reason = "authentication_required"
                            result.reproduction_status = "authentication_required"
                            result.verification_level = "endpoint_blocked"
                            result.logs.append("本地认证提交后目标入口仍要求认证；未确认漏洞")
                            return self._finalize(result)
                probes += 1
                log_before = _safe_logs(runtime_log_supplier)
                rec = self._send(
                    base_url, path, param, payload, method, transport, "attack", request_headers,
                    sibling_values,
                )
                if runtime_log_supplier is not None:
                    rec.runtime_log_excerpt = _log_delta(log_before, _safe_logs(runtime_log_supplier))
                if not rec.status_code and rec.status is not None:
                    rec.status_code = rec.status
                result.records.append(_public_record(rec))
                if rec.error:
                    result.logs.append(
                        f"请求失败: {rec.url} reason={rec.reason or 'request_error'} error={rec.error}"
                    )
                    if rec.reason in {"connection_failed", "request_timeout"}:
                        consecutive_transport_failures += 1
                        if consecutive_transport_failures >= _MAX_CONSECUTIVE_TRANSPORT_FAILURES:
                            result.logs.append(
                                "目标连续连接失败或超时；提前停止该候选的重复 HTTP 探测"
                            )
                            stopped = True
                            break
                    else:
                        consecutive_transport_failures = 0
                    continue
                consecutive_transport_failures = 0
                hit = self._judge(
                    rec, indicators, baseline,
                    vuln_type=str(exploit.get("vuln_type") or ""),
                )
                if hit:
                    # A response from an auth gateway, router, content-type validator
                    # or proxy is not evidence that the finding's business data flow ran.
                    # Indicators in those pages/logs are untrusted diagnostics only.
                    if not _reached_business_logic(rec.status_code or rec.status):
                        result.logs.append(
                            f"忽略未进入业务逻辑的响应中的判据: status={rec.status_code or rec.status} indicator={hit!r}"
                        )
                        continue
                    # 时间型确认要求第二组独立的 control/attack 采样，避免慢页面自证。
                    if hit.startswith("time-based") and not self._confirm_time_based(
                        base_url, path, param, payload, method, transport, baseline,
                        request_headers, sibling_values, result,
                    ):
                        result.logs.append("时间型差异未在第二次独立采样中复现，保持未确认")
                        continue
                    result.verified = True
                    result.reproducible = True
                    result.reproduction_status = "dynamic_confirmed"
                    result.verification_level = "endpoint_reproduced"
                    result.oracle = _oracle_name(exploit.get("vuln_type"), hit)
                    result.matched_indicator = hit
                    result.confirmed_record = _public_record(rec)
                    result.baseline_record = _public_record(baseline)
                    result.server_binding = dict(surface.get("source_route_binding") or {})
                    result.logs.append(
                        f"命中: {method} {path} ({transport}:{param}) payload={payload!r} -> 判据 {hit!r}"
                    )
                    return self._finalize(result)
                boolean_confirmation = self._confirm_boolean_sql(
                    base_url, path, param, payload, method, transport, baseline, rec,
                    request_headers, str(exploit.get("vuln_type") or ""), sibling_values,
                )
                if boolean_confirmation:
                    false_record, repeated_true, boolean_indicator = boolean_confirmation
                    result.records.extend([_public_record(false_record), _public_record(repeated_true)])
                    result.confirmation_records = [
                        _public_record(false_record), _public_record(repeated_true)]
                    result.verified = True
                    result.reproducible = True
                    result.reproduction_status = "dynamic_confirmed"
                    result.verification_level = "endpoint_reproduced"
                    result.oracle = "paired_boolean_differential"
                    result.matched_indicator = boolean_indicator
                    result.confirmed_record = _public_record(rec)
                    result.baseline_record = _public_record(baseline)
                    result.server_binding = dict(surface.get("source_route_binding") or {})
                    result.logs.append(
                        f"布尔差分复现: {method} {path} ({transport}:{param}) "
                        f"true/false 对照稳定 -> {boolean_indicator}"
                    )
                    return self._finalize(result)
                if rec.status == 404:
                    result.logs.append(f"端点不存在: {rec.url}")
                elif rec.status in {405, 415, 422}:
                    result.logs.append(f"目标反馈 {rec.status}：已保留该响应，将继续尝试源码/运行时发现的其它传输方式")
        # 循环正常结束或因预算上限停止：统一给出明确失败原因（修复旧实现命中上限时
        # 直接 return 导致 reproduction_status 停留在 not_executed 的不诚实状态）。
        self._set_failure_reason(result)
        return self._finalize(result)

    # ---------- 内部 ----------
    def _verify_open_redirect(self, base_url: str, exploit: dict,
                              endpoints: list[dict], result: DynamicResult, *,
                              auth_endpoints: list[dict] | None = None) -> DynamicResult:
        """Confirm only a local 3xx response whose Location preserves our exact canary."""
        from backend.dynamic.open_redirect import validate_open_redirect_plan

        plan, status, reason = validate_open_redirect_plan(
            exploit.get("vuln_type") or exploit.get("type"), base_url, endpoints,
            exploit.get("open_redirect_plan"),
        )
        if status != "ready":
            result.skipped = True
            result.reproduction_status = status
            result.reason = reason
            return self._finalize(result)

        result.surfaces = _public_bound_surfaces(endpoints)
        baseline = self._send(
            base_url, plan["path"], plan["param"], "/aax-redirect-baseline", plan["method"],
            plan["transport"], "baseline",
        )
        result.baseline_records.append(_public_record(baseline))
        if _is_local_auth_redirect(base_url, baseline):
            bootstrap = _bootstrap_local_form_auth(
                base_url, auth_endpoints if auth_endpoints is not None else endpoints, self.probe)
            _append_sanitized_auth_setup_records(result, bootstrap)
            if not bootstrap.authenticated:
                result.reason = "authentication_required"
                result.blocker_reason = "authentication_required"
                result.reproduction_status = "authentication_required"
                result.verification_level = "endpoint_blocked"
                result.logs.append("Open Redirect 基线要求本地表单认证；认证前置条件未满足")
                return self._finalize(result)
            result.state_contamination_possible = True
            result.disposable_auth_bootstrap = True
            # The same campaign client owns the freshly established cookies.  The
            # original anonymous baseline remains evidence; exact-location judging
            # uses this authenticated retry and its subsequent attack replay.
            baseline = self._send(
                base_url, plan["path"], plan["param"], "/aax-redirect-baseline", plan["method"],
                plan["transport"], "baseline",
            )
            result.baseline_records.append(_public_record(baseline))
            if _is_local_auth_redirect(base_url, baseline) or (baseline.status_code or baseline.status) in {401, 403}:
                result.reason = "authentication_required"
                result.blocker_reason = "authentication_required"
                result.reproduction_status = "authentication_required"
                result.verification_level = "endpoint_blocked"
                result.logs.append("Open Redirect 本地认证提交后入口仍要求认证；未确认漏洞")
                return self._finalize(result)
        rec = self._send(
            base_url, plan["path"], plan["param"], plan["payload"], plan["method"],
            plan["transport"], "attack",
        )
        if not rec.status_code and rec.status is not None:
            rec.status_code = rec.status
        result.records.append(_public_record(rec))
        if rec.error:
            self._set_failure_reason(result)
            return self._finalize(result)

        status_code = int(rec.status_code or rec.status or 0)
        if 300 <= status_code < 400 and rec.redirect_location == plan["payload"]:
            if baseline.redirect_location == plan["payload"]:
                result.reproduction_status = "not_reproduced"
                result.reason = "redirect_location_matches_baseline"
                return self._finalize(result)
            result.verified = True
            result.reproducible = True
            result.reproduction_status = "dynamic_confirmed"
            result.verification_level = "endpoint_reproduced"
            result.application_reached = True
            result.oracle = "exact_redirect_location"
            result.matched_indicator = "3xx Location exactly preserves redirect canary"
            result.confirmed_record = _public_record(rec)
            result.baseline_record = _public_record(baseline)
            result.server_binding = dict(next(iter(endpoints), {}).get("source_route_binding") or {})
            result.logs.append(
                f"Open Redirect confirmed: {plan['method']} {plan['path']} preserves exact Location canary"
            )
            return self._finalize(result)

        result.application_reached = _reached_business_logic(status_code)
        result.reproduction_status = "not_reproduced"
        result.verification_level = "endpoint_not_reproduced"
        result.reason = "redirect_location_not_preserved"
        result.logs.append("Open Redirect oracle not met: expected 3xx with exact Location canary")
        return self._finalize(result)

    def _send(self, base_url: str, path: str, param: str, payload: str,
              method: str, transport: str, role: str,
              headers: dict | None = None,
              sibling_values: dict | None = None) -> ProbeRecord:
        """兼容旧测试替身，同时给真实探针传入请求编码和请求角色。"""
        try:
            return self.probe.send(base_url, path, param, payload, method=method,
                                   transport=transport, role=role, headers=headers,
                                   sibling_values=sibling_values)
        except TypeError as exc:
            if "sibling_values" in str(exc):
                try:
                    return self.probe.send(
                        base_url, path, param, payload, method=method,
                        transport=transport, role=role, headers=headers,
                    )
                except TypeError as legacy_exc:
                    exc = legacy_exc
            if "headers" in str(exc):
                try:
                    return self.probe.send(
                        base_url, path, param, payload, method=method,
                        transport=transport, role=role,
                    )
                except TypeError as legacy_exc:
                    exc = legacy_exc
            # 更旧的测试替身只接受 method；仅在签名不兼容时回退，避免吞掉真实错误。
            if "transport" not in str(exc) and "role" not in str(exc):
                raise
            record = self.probe.send(base_url, path, param, payload, method=method)
            record.transport = transport
            record.role = role
            return record

    def _run_setup_requests(self, base_url: str, exploit: dict, result: DynamicResult,
                            request_headers: dict[str, str]) -> bool:
        steps = exploit.get("setup_requests") or []
        for index, step in enumerate(steps):
            if not isinstance(step, dict):
                result.reason = f"setup_invalid: step {index + 1} is not an object"
                return False
            path = str(step.get("path") or "")
            method = _http_method(step.get("method") or "POST")
            transport = str(step.get("transport") or "json").lower()
            values = step.get("values") or step.get("json") or step.get("data") or step.get("params") or {}
            if not path.startswith("/") or path.startswith("//") or not isinstance(values, dict):
                result.reason = f"setup_invalid: step {index + 1} requires relative path and object values"
                return False
            try:
                rec = self.probe.send_values(
                    base_url, path, values, method=method, transport=transport,
                    role="setup", headers=request_headers,
                )
            except Exception as exc:  # noqa: BLE001
                result.reason = f"setup_failed: {type(exc).__name__}: {str(exc)[:160]}"
                return False
            result.setup_records.append(_public_record(rec))
            if rec.error or rec.status_code is None or rec.status_code >= 400:
                status = rec.status_code
                if status == 401:
                    result.reason = "authentication_failed"
                elif status == 403:
                    result.reason = "authorization_blocked"
                elif status in {404, 405, 415, 422}:
                    result.reason = _status_reason(status)
                else:
                    result.reason = (
                        f"setup_failed: {method} {path} returned "
                        f"{status if status is not None else rec.reason or 'request_error'}"
                    )
                result.blocker_reason = result.reason
                return False
            captures = step.get("capture_response_headers") or {}
            for response_name, request_name in captures.items():
                value = rec.response_headers.get(str(response_name).lower())
                if not value:
                    result.reason = f"setup_failed: response header {response_name!r} missing"
                    return False
                request_headers[str(request_name)] = value
            body = _response_json(rec)
            for response_name, request_name in (step.get("capture_response_json") or {}).items():
                value = _json_field(body, str(response_name)) if body is not None else None
                if value in (None, ""):
                    result.reason = f"setup_failed: response JSON field {response_name!r} missing"
                    result.blocker_reason = result.reason
                    return False
                request_headers[str(request_name)] = str(value)
            # Common declarative shorthand: turn a body token into a Bearer header.
            bearer_field = step.get("capture_bearer_json")
            if bearer_field:
                value = _json_field(body, str(bearer_field)) if body is not None else None
                if value in (None, ""):
                    result.reason = f"setup_failed: bearer JSON field {bearer_field!r} missing"
                    result.blocker_reason = result.reason
                    return False
                request_headers["Authorization"] = f"Bearer {value}"
        if steps:
            result.logs.append(f"已执行 {len(steps)} 个会话/认证前置步骤，并捕获后续请求所需响应头")
        return True

    def _verify_authorization_workflow(self, base_url: str, exploit: dict,
                                       endpoints: list[dict], result: DynamicResult) -> DynamicResult:
        """执行受约束的 BOLA/IDOR 多请求状态机并以跨身份稳定泄露作裁决。"""
        workflow = exploit.get("authorization_workflow") or {}
        steps = workflow.get("steps") if isinstance(workflow, dict) else None
        oracle = workflow.get("oracle") if isinstance(workflow, dict) else None
        vuln_type = str(exploit.get("vuln_type") or "").lower()
        if not isinstance(steps, list) or not isinstance(oracle, dict) or not steps:
            result.skipped = True
            result.reason = "authorization_workflow_invalid: steps and oracle are required"
            result.reproduction_status = "not_runtime_verifiable"
            return self._finalize(result)
        if not any(token in vuln_type for token in ("idor", "bola", "object level authorization")):
            result.skipped = True
            result.reason = "authorization_workflow_invalid: vulnerability type is not BOLA/IDOR"
            result.reproduction_status = "not_runtime_verifiable"
            return self._finalize(result)
        if len(steps) > 12:
            result.skipped = True
            result.reason = "authorization_workflow_invalid: maximum 12 steps"
            result.reproduction_status = "not_runtime_verifiable"
            return self._finalize(result)
        if not _workflow_uses_only_bound_surfaces(steps, endpoints):
            result.skipped = True
            result.reason = "authorization_workflow_unbound_endpoint: workflow step is outside server-bound surfaces"
            result.reproduction_status = "endpoint_unresolved"
            return self._finalize(result)

        variables: dict[str, str] = {}
        owner_control: ProbeRecord | None = None
        attack: ProbeRecord | None = None
        rendered_attack: dict | None = None
        result.logs.append(f"执行受约束授权工作流: {len(steps)} steps")
        result.surfaces = _public_bound_surfaces(endpoints)
        for index, step in enumerate(steps):
            if not isinstance(step, dict):
                return self._workflow_failure(result, f"step {index + 1} is not an object")
            try:
                path = _render_workflow_value(str(step.get("path") or ""), variables)
                method = _http_method(step.get("method") or "GET")
                transport = _transport_for(method, step.get("transport"))
                values = _render_workflow_value(step.get("values") or {}, variables)
                headers = _render_workflow_value(step.get("headers") or {}, variables)
            except (KeyError, TypeError, ValueError) as exc:
                return self._workflow_failure(result, f"step {index + 1} render failed: {exc}")
            if (not path.startswith("/") or path.startswith("//")
                    or not isinstance(values, dict) or not isinstance(headers, dict)):
                return self._workflow_failure(
                    result, f"step {index + 1} requires relative path and object values/headers")
            if not _workflow_request_uses_only_bound_surface(path, method, endpoints):
                result.skipped = True
                result.reproduction_status = "endpoint_unresolved"
                result.reason = (
                    "authorization_workflow_unbound_endpoint: rendered workflow step "
                    "is outside server-bound surfaces"
                )
                return self._finalize(result)
            role = str(step.get("role") or "setup")
            try:
                rec = self.probe.send_values(
                    base_url, path, values, method=method, transport=transport,
                    role=role, headers={str(k): str(v) for k, v in headers.items()},
                )
            except Exception as exc:  # noqa: BLE001
                return self._workflow_failure(
                    result, f"step {index + 1} request failed: {type(exc).__name__}: {str(exc)[:120]}")
            public = _public_record(rec)
            if role in {"owner_control", "authorization_attack"}:
                result.records.append(public)
            else:
                result.setup_records.append(public)
            allowed = step.get("expected_status") or list(range(200, 300))
            if isinstance(allowed, int):
                allowed = [allowed]
            if rec.error or rec.status_code not in allowed:
                return self._workflow_failure(
                    result, f"step {index + 1} {method} {path} returned "
                    f"{rec.status_code if rec.status_code is not None else rec.reason or 'request_error'}")
            body = _response_json(rec)
            for field_name, variable_name in (step.get("capture_json") or {}).items():
                value = _json_field(body, str(field_name))
                if value in (None, ""):
                    return self._workflow_failure(
                        result, f"step {index + 1} response field {field_name!r} missing")
                variables[str(variable_name)] = str(value)
            for variable_name, field_names in (step.get("capture_json_candidates") or {}).items():
                candidates = field_names if isinstance(field_names, list) else [field_names]
                captured = next((
                    _json_field(body, str(field_name)) for field_name in candidates
                    if _json_field(body, str(field_name)) not in (None, "")
                ), None)
                if captured in (None, ""):
                    return self._workflow_failure(
                        result,
                        f"step {index + 1} none of response fields {candidates!r} were present",
                    )
                variables[str(variable_name)] = str(captured)
            if role == "owner_control":
                owner_control = rec
            elif role == "authorization_attack":
                attack = rec
                rendered_attack = {
                    "path": path, "method": method, "transport": transport,
                    "values": values, "headers": headers,
                }

        if owner_control is None or attack is None or rendered_attack is None:
            return self._workflow_failure(
                result, "workflow requires owner_control and authorization_attack roles")

        confirmation = self.probe.send_values(
            base_url, rendered_attack["path"], rendered_attack["values"],
            method=rendered_attack["method"], transport=rendered_attack["transport"],
            role="confirmation", headers=rendered_attack["headers"],
        )
        result.confirmation_records.append(_public_record(confirmation))
        if confirmation.error or confirmation.status_code != attack.status_code:
            return self._workflow_failure(result, "cross-identity request was not stable on replay")

        owner_identity = str(oracle.get("owner_identity") or "")
        attacker_identity = str(oracle.get("attacker_identity") or "")
        owner_field = str(oracle.get("owner_json_field") or "owner")
        secret_field = str(oracle.get("secret_json_field") or "secret")
        secret_value = str(oracle.get("secret_value") or "")
        control_json = _response_json(owner_control)
        attack_json = _response_json(attack)
        confirmation_json = _response_json(confirmation)
        invariant = bool(
            owner_identity and attacker_identity and owner_identity != attacker_identity
            and secret_value
            and _json_field(control_json, owner_field) == owner_identity
            and _json_field(control_json, secret_field) == secret_value
            and _json_field(attack_json, owner_field) == owner_identity
            and _json_field(attack_json, secret_field) == secret_value
            and _json_field(confirmation_json, owner_field) == owner_identity
            and _json_field(confirmation_json, secret_field) == secret_value
            and 200 <= int(attack.status_code or 0) < 300
            and attack.response_excerpt == confirmation.response_excerpt
        )
        if not invariant:
            return self._workflow_failure(
                result, "cross-identity owner/secret invariant was not satisfied")

        result.verified = True
        result.reproducible = True
        result.reproduction_status = "dynamic_confirmed"
        result.verification_level = "endpoint_reproduced"
        result.oracle = "cross_identity_owner_secret_replay"
        result.matched_indicator = (
            f"BOLA(owner={owner_identity},attacker={attacker_identity},stable_replays=2)")
        result.baseline_record = _public_record(owner_control)
        result.confirmed_record = _public_record(attack)
        result.logs.append("跨身份读取连续两次返回 owner control 中的同一私有 sentinel，确认 BOLA/IDOR")
        return self._finalize(result)

    @staticmethod
    def _workflow_failure(result: DynamicResult, reason: str) -> DynamicResult:
        result.reason = f"authorization_workflow_not_confirmed: {reason}"
        result.reproduction_status = "not_reproduced"
        result.verification_level = "workflow_not_confirmed"
        result.logs.append(reason)
        return DynamicVerifier._finalize(result)

    def _confirm_time_based(self, base_url: str, path: str, param: str, payload: str,
                             method: str, transport: str, first_baseline: ProbeRecord,
                             headers: dict | None = None, sibling_values: dict | None = None,
                             result: DynamicResult | None = None) -> bool:
        # Two independently ordered pairs counter warm-up/cache drift. Persist every
        # sample so a time verdict can be audited rather than asserted by one delta.
        samples: list[ProbeRecord] = []
        for _ in range(2):
            sequence = [("baseline", _control_value(param)), ("confirmation", payload)]
            random.SystemRandom().shuffle(sequence)
            pair: dict[str, ProbeRecord] = {}
            for role, value in sequence:
                record = self._send(base_url, path, param, value, method, transport, role,
                                    headers, sibling_values)
                pair[role] = record
                samples.append(record)
            control, attack = pair["baseline"], pair["confirmation"]
            if control.error or attack.error:
                if result is not None:
                    result.confirmation_records.extend(_public_record(item) for item in samples)
                return False
            delta = attack.elapsed_ms - control.elapsed_ms
            if not (not first_baseline.error and attack.elapsed_ms >= 4500 and delta >= 3000
                    and attack.elapsed_ms >= max(4500, control.elapsed_ms * 2)):
                if result is not None:
                    result.confirmation_records.extend(_public_record(item) for item in samples)
                return False
        if result is not None:
            result.confirmation_records.extend(_public_record(item) for item in samples)
        return True

    def _confirm_boolean_sql(self, base_url: str, path: str, param: str, payload: str,
                              method: str, transport: str, baseline: ProbeRecord,
                              first_true: ProbeRecord, headers: dict | None,
                              vuln_type: str, sibling_values: dict | None = None):
        """用 baseline/true/false/true 四点对照确认常见布尔 SQL 注入。"""
        if "sql" not in vuln_type.lower() or baseline.error or first_true.error:
            return None
        false_payload = _false_sql_payload(payload)
        if not false_payload:
            return None
        false_record = self._send(
            base_url, path, param, false_payload, method, transport, "boolean_false", headers, sibling_values)
        repeated_true = self._send(
            base_url, path, param, payload, method, transport, "confirmation", headers, sibling_values)
        records = (baseline, first_true, false_record, repeated_true)
        if any(record.error or record.status_code is None for record in records):
            return None
        if len({record.status_code for record in records}) != 1:
            return None
        baseline_body = (baseline.response_excerpt or "").strip()
        true_body = (first_true.response_excerpt or "").strip()
        false_body = (false_record.response_excerpt or "").strip()
        repeated_body = (repeated_true.response_excerpt or "").strip()
        # false 必须回到良性基线，两次 true 必须稳定一致；再要求足够大的内容差异，
        # 避免时间戳、CSRF token 或普通个性化页面造成的单次长度抖动。
        if false_body != baseline_body or repeated_body != true_body or true_body == false_body:
            return None
        delta = abs(len(true_body) - len(false_body))
        if delta < 20:
            return None
        indicator = f"boolean-differential(true={len(true_body)},false={len(false_body)},delta={delta})"
        return false_record, repeated_true, indicator

    def _judge(self, rec: ProbeRecord, indicators: list[str], baseline: ProbeRecord,
                *, vuln_type: str = "") -> str:
        """返回命中的特征串；未命中返回空串。"""
        if not _reached_business_logic(rec.status_code or rec.status):
            return ""
        body = rec.response_excerpt or ""
        runtime_log = rec.runtime_log_excerpt or ""
        base_body = baseline.response_excerpt or ""

        # XSS 的字符串反射（包括 HTML 转义后的反射）不等于 JavaScript 执行。
        # 在接入浏览器 canary 前，HTTP 文本探针不得自动确认 XSS。
        if "xss" in vuln_type.lower() or "cross-site scripting" in vuln_type.lower():
            return ""

        # 1) 成功特征必须是攻击响应相对良性基线新增的高质量特征。
        for ind in indicators:
            if not _credible_indicator(ind):
                continue
            # The deterministic command probe is deliberately limited to a
            # harmless local output marker.  Its marker necessarily appears in
            # the payload, so the generic reflection rule would make this
            # oracle unreachable.  Baseline absence is mandatory here.
            if ("command" in vuln_type.lower()
                    and "aax_local_cmd_marker" in ind.lower()
                    and _matches(ind, body) and not _matches(ind, base_body)):
                return ind
            # 反射防御（防"自我感动"）：若该 indicator 在**发出的 payload 本身**就能匹配，
            # 那它出现在响应/日志里可能只是应用回显了输入（reflection），而非漏洞真正
            # 执行/求值。模板 indicator 都要求真执行（如 {{7*191}}->1337、id->uid=，
            # payload 里没有该串），不受影响；仅挡住 LLM 生成的"payload 子串即判据"这类
            # 反射可解释的弱判据，避免纯回显被误判 dynamic_confirmed。
            if _matches(ind, rec.payload):
                continue
            if _matches(ind, body) and not _matches(ind, base_body):
                return ind
            # Docker 应用通常在生产配置下把异常隐藏为 500 页面；只接受“请求后新增”的
            # 服务端日志特征，且仍要求有该条 HTTP attack record 和同入口 baseline。
            if _matches(ind, runtime_log):
                return f"runtime-log:{ind}"
        # 2) 时间盲注：响应明显变慢
        baseline_ms = int(baseline.elapsed_ms or 0)
        delay_delta = rec.elapsed_ms - baseline_ms
        if (not baseline.error and rec.elapsed_ms >= 4500
                and delay_delta >= 3000
                and rec.elapsed_ms >= max(4500, baseline_ms * 2)
                and ("sleep" in rec.payload.lower() or "waitfor" in rec.payload.lower())):
            return f"time-based(delta={delay_delta}ms,baseline={baseline_ms}ms)"

        # 不再用单次响应长度差直接确认布尔盲注。真实确认需要成对 true/false
        # control payload、多次采样和稳定性检验；当前缺少这些证据时保持未复现。
        return ""

    @staticmethod
    def _set_failure_reason(result: DynamicResult) -> None:
        """给未命中的动态验证结果设置明确、可展示的失败原因。"""
        if not result.records:
            result.reason = "no_probe_executed"
            result.logs.append("未执行任何动态探测")
            return

        reasons = [r.get("reason") for r in result.records if r.get("reason")]
        statuses = [r.get("status_code", r.get("status")) for r in result.records]

        if reasons and all(reason == "connection_failed" for reason in reasons):
            result.reason = "connection_failed"
            result.error = result.records[0].get("error", "")
            result.logs.append("目标连接失败，无法建立 HTTP 连接")
            return
        if reasons and all(reason == "request_timeout" for reason in reasons):
            result.reason = "request_timeout"
            result.error = result.records[0].get("error", "")
            result.logs.append("请求超时，目标未在限制时间内响应")
            return
        # all([]) 为 True；普通 request_error 的 status 全是 None 时，旧逻辑会被
        # 误报为 endpoint_not_found。只有每条攻击请求都明确返回 404 才能这样归类。
        if statuses and all(status == 404 for status in statuses):
            # 保留历史 reason 名，但归入 blocked：404 说明请求根本没进入目标业务逻辑。
            result.reason = "endpoint_not_found"
            result.blocker_reason = "endpoint_unreachable"
            result.logs.append("所有探测端点均返回 404，未找到可验证入口（blocked）")
            return

        # 每条探测都只有传输层错误、拿不到任何响应：无法判定，inconclusive（非未复现、非 blocked）。
        if statuses and all(s is None for s in statuses) and any(r.get("error") for r in result.records):
            result.reason = "request_error"
            result.logs.append("所有探测均为传输层错误、未取得任何响应，无法判定（inconclusive）")
            return

        # 只统计攻击/确认请求（baseline 已单列），判断是否有任何一次真正进入业务逻辑。
        attack_statuses = [
            r.get("status_code", r.get("status")) for r in result.records
            if r.get("role", "attack") in ("attack", "confirmation")
        ] or statuses
        result.application_reached = any(_reached_business_logic(s) for s in attack_statuses)

        if not result.application_reached:
            # 每次探测都在进入业务逻辑前被拦截（鉴权/方法/媒体类型/必填校验/网关）。
            # 这是 blocked：把它写成 not_reproduced 等于把环境失败谎报成“漏洞不存在”。
            blockers = [_status_reason(s) for s in attack_statuses if _status_reason(s)]
            dominant = (Counter(blockers).most_common(1)[0][0]
                        if blockers else "request_blocked_before_business_logic")
            result.reason = dominant
            result.blocker_reason = dominant
            result.logs.append(
                f"所有探测均在进入业务逻辑前被拦截（{dominant}），判定 blocked，不作未复现结论")
            return

        # 请求确已进入业务逻辑、输入也进入相关数据流，但成功 oracle 未成立 -> 才是真正的未复现。
        result.reason = "payload_not_matched"
        result.logs.append("请求已进入业务逻辑但所有载荷均未命中成功特征，判定不可复现")

    @staticmethod
    def _finalize(result: DynamicResult) -> DynamicResult:
        # 复现成立即意味着攻击输入确已到达并触发目标业务逻辑（sink），application_reached
        # 必为真——否则证据链会自相矛盾（confirmed 却声称没进业务逻辑）。
        if result.reproducible:
            result.application_reached = True
        if not result.reproduction_status or result.reproduction_status == "not_executed":
            if result.reproducible:
                result.reproduction_status = "dynamic_confirmed"
            elif result.blocker_reason:
                # 进入业务逻辑前被拦截：blocked（不是 not_reproduced，也不是漏洞不存在）。
                result.reproduction_status = "blocked"
            elif result.reason == "payload_not_matched":
                # 唯一允许 not_reproduced 的路径：请求确已进入业务逻辑但 oracle 未成立。
                result.reproduction_status = "not_reproduced"
            elif result.reason in {"connection_failed", "request_timeout", "no_probe_executed"}:
                result.reproduction_status = result.reason
            else:
                result.reproduction_status = "inconclusive"
        if not result.verification_level or result.verification_level == "not_executed":
            result.verification_level = {
                "dynamic_confirmed": "endpoint_reproduced",
                "not_reproduced": "endpoint_not_reproduced",
                "blocked": "endpoint_blocked",
                "inconclusive": "endpoint_inconclusive",
                "connection_failed": "transport_failed",
                "request_timeout": "transport_failed",
                "no_probe_executed": "no_probe_executed",
            }.get(result.reproduction_status, result.reproduction_status or "not_executed")
        # 只保留前若干条记录，避免证据体积过大
        result.records = result.records[:30]
        result.baseline_records = result.baseline_records[:30]
        result.setup_records = result.setup_records[:10]
        result.confirmation_records = result.confirmation_records[:6]
        # Logs are evidence too. Never leave setup credentials or a sensitive injected
        # value in an otherwise-redacted DynamicResult waiting for a later collector.
        result.logs = [_redact_response_excerpt(str(item)) for item in result.logs[:80]]
        return result


def _http_method(value: str | None) -> str:
    method = str(value or "GET").upper()
    return method if method in {"GET", "POST", "PUT", "PATCH", "DELETE"} else "GET"


def _is_open_redirect_type(vuln_type: object) -> bool:
    from backend.dynamic.open_redirect import is_open_redirect_type

    return is_open_redirect_type(vuln_type)


def _is_local_auth_redirect(base_url: str, record: ProbeRecord) -> bool:
    from backend.dynamic.form_auth import is_local_auth_redirect

    return is_local_auth_redirect(base_url, record)


def _bootstrap_local_form_auth(base_url: str, endpoints: list[dict], probe):
    from backend.dynamic.form_auth import bootstrap_disposable_form_auth

    try:
        return bootstrap_disposable_form_auth(base_url, endpoints, probe)
    except Exception:  # noqa: BLE001 - an unexpected parser/client error must fail closed
        from backend.dynamic.form_auth import AuthBootstrapResult

        return AuthBootstrapResult(reason="authentication_required")


def _append_sanitized_auth_setup_records(result: DynamicResult, bootstrap) -> None:
    """Persist auth setup shape, never disposable credentials or form response bodies."""
    for item in getattr(bootstrap, "records", []) or []:
        record = getattr(item, "record", None)
        if record is None:
            continue
        public = _public_record(record)
        # Unlike declarative setup, the values were generated solely for this
        # campaign.  Retain only field names so the persisted evidence cannot be
        # reused as credentials while the PoC builder can replay the observed flow.
        public["params"] = {str(key): "<redacted>" for key in (record.params or {})}
        public["payload"] = "<redacted>"
        public["response_excerpt"] = "<redacted form response>"
        public["auth_bootstrap"] = {
            "kind": str(getattr(item, "kind", "form_auth")),
            "stage": str(getattr(item, "stage", "setup")),
            "field_names": list(getattr(item, "field_names", []) or []),
            "dynamic_csrf_field": str(getattr(item, "csrf_field", "") or ""),
        }
        result.setup_records.append(public)


def _transport_for(method: str, transport: str | None) -> str:
    value = str(transport or "").lower()
    if value in {"path", "header", "cookie"}:
        return value
    if method == "GET" and value not in {"header", "cookie"}:
        return "query"
    return value if value in {"query", "form", "json", "multipart"} else "form"


def _normalize_surfaces(raw_endpoints, hints: list[str], preferred_method: str) -> list[dict]:
    """将旧 paths 和新结构化 attack surface 统一为可执行 case。

    路由声明的方法优先于漏洞模板建议；源码/运行时提取到的参数优先于模板参数。
    对未知 POST 参数同时尝试 form 与 JSON，借由 415/422 的真实响应继续推进，而不是猜测成功。
    """
    cases: list[dict] = []
    seen: set[tuple[str, str, str, str]] = set()
    for endpoint in raw_endpoints or []:
        if isinstance(endpoint, str):
            surface = {"path": endpoint, "methods": [preferred_method], "params": [], "source": "legacy"}
        elif isinstance(endpoint, dict):
            surface = endpoint
        else:
            continue
        path = str(surface.get("path") or "")
        if not path.startswith("/") or path.startswith("//"):
            continue
        methods = [_http_method(method) for method in (surface.get("methods") or [preferred_method])]
        if preferred_method in methods:
            methods = [preferred_method] + [method for method in methods if method != preferred_method]
        all_params = [p for p in (surface.get("params") or []) if isinstance(p, dict) and p.get("name")]
        params = all_params
        # Auth inventory can accompany the candidate inventory.  Its route fields
        # are not candidate injection points and must never become an HTTP spray.
        if hints:
            params = [p for p in all_params if str(p.get("name")) in hints]
            if not params:
                continue
        if not params:
            fallback_location = "query" if (methods[0] if methods else preferred_method) == "GET" else "unknown"
            params = [{"name": name, "location": fallback_location} for name in hints[:6]]
        for method in methods:
            for parameter in params:
                name = str(parameter.get("name") or "")
                if not name:
                    continue
                location = str(parameter.get("location") or "unknown").lower()
                case_path = str(surface.get("raw_path") or path) if location == "path" else path
                if location == "path":
                    transports = ["path"]
                elif method == "GET":
                    transports = ["query"]
                elif location == "json":
                    transports = ["json"]
                elif location in {"form", "body"}:
                    transports = ["form"]
                elif location in {"multipart", "header", "cookie"}:
                    transports = [location]
                elif location == "query":
                    transports = ["query"]
                else:
                    transports = ["form", "json"]
                for transport in transports:
                    key = (case_path, method, name, transport)
                    if key not in seen:
                        seen.add(key)
                        # Only required siblings in the same encoding belong in this
                        # request payload. Optional fields and path/query/header/cookie
                        # fields must not be silently injected into a JSON/form body.
                        sibling_values = {
                            str(other.get("name")): _minimum_value(other)
                            for other in all_params
                            if other.get("name") != name
                            and bool(other.get("required"))
                            and _parameter_transport(other, method) == transport
                        }
                        cases.append({"path": case_path, "method": method, "param": name,
                                      "transport": transport, "source": surface.get("source", "unknown"),
                                      "source_route_binding": dict(surface.get("source_route_binding") or {}),
                                      "sibling_values": sibling_values})
    return cases[:160]


def _minimum_value(parameter: dict):
    """Build a non-secret minimal valid value for required sibling fields."""
    if parameter.get("default") not in (None, ""):
        return parameter["default"]
    enum = parameter.get("enum") or []
    if enum:
        return enum[0]
    kind = str(parameter.get("type") or "string").lower()
    if kind in {"integer", "number"}:
        return 1
    if kind == "boolean":
        return False
    if kind == "array":
        return []
    if kind == "object":
        return {}
    name = str(parameter.get("name") or "value").lower()
    if "email" in name:
        return "aax@example.invalid"
    if name.endswith("id") or name == "id":
        return "1"
    return "AUDITAGENTX_VALID"


def _parameter_transport(parameter: dict, method: str) -> str:
    location = str(parameter.get("location") or "unknown").lower()
    if location in {"path", "header", "cookie", "multipart"}:
        return location
    if location == "json":
        return "json"
    if location in {"form", "body"}:
        return "form"
    if location == "query" or method == "GET":
        return "query"
    return "form"


def _surface_specs(raw_endpoints, preferred_method: str) -> list[dict]:
    """Normalize already-authorized structured surfaces for probing."""
    specs: list[dict] = []
    for endpoint in raw_endpoints or []:
        if isinstance(endpoint, str):
            specs.append({"path": endpoint, "methods": [preferred_method], "params": [], "source": "legacy"})
        elif isinstance(endpoint, dict):
            specs.append(dict(endpoint))
    return specs


def _has_proven_bound_surfaces(endpoints) -> bool:
    from backend.dynamic.source_route_binding import is_server_bound_surface

    if not isinstance(endpoints, list) or not endpoints:
        return False
    for endpoint in endpoints:
        if not is_server_bound_surface(endpoint) or not str(endpoint.get("path") or "").startswith("/"):
            return False
    return True


def _has_explicit_bound_parameter(endpoints, exploit: dict) -> bool:
    """Require one server-extracted, plan-matched request parameter before I/O."""
    names = [str(value) for value in (exploit.get("_injection_points") or []) if str(value)]
    bound_surface = exploit.get("bound_surface") or {}
    if isinstance(bound_surface, dict) and bound_surface.get("param"):
        names = [str(bound_surface["param"])]
    if not names:
        names = _bound_parameter_names(endpoints)
    if len(names) != 1:
        return False
    name = names[0]
    matches = []
    for surface in endpoints or []:
        for parameter in surface.get("params") or []:
            if isinstance(parameter, dict) and str(parameter.get("name") or "") == name:
                matches.append((str(surface.get("path") or ""), name))
    return len(matches) == 1


def _proven_source_parameter(endpoints) -> tuple[str | None, str]:
    """Return one parameter explicitly proven by fresh route→sink analysis.

    ``source_parameter`` is minted only by the server-side static proof, never by
    persisted finding metadata.  A malformed proof, a parameter absent from its
    bound surface, or competing proven parameters refuses HTTP execution rather
    than falling back to a template hint.
    """
    parameters: set[str] = set()
    saw_source_route_sink_proof = False
    for surface in endpoints or []:
        if not isinstance(surface, dict):
            continue
        binding = surface.get("source_route_binding") or {}
        if not isinstance(binding, dict) or binding.get("kind") != "source_route_sink":
            continue
        saw_source_route_sink_proof = True
        parameter = str(binding.get("source_parameter") or "").strip()
        names = {
            str(item.get("name") or "").strip()
            for item in (surface.get("params") or [])
            if isinstance(item, dict)
        }
        if not parameter or parameter not in names:
            return None, "source-bound route proof lacks a matching declared parameter; no HTTP request sent"
        parameters.add(parameter)
    if not saw_source_route_sink_proof:
        return None, ""
    if len(parameters) != 1:
        return None, "source-bound route proofs disagree on the injection parameter; no HTTP request sent"
    return next(iter(parameters)), ""


def _bound_parameter_names(endpoints) -> list[str]:
    """Return one unambiguous server-extracted parameter name, never a guess."""
    names = {
        str(parameter.get("name"))
        for surface in endpoints or []
        for parameter in (surface.get("params") or [])
        if isinstance(parameter, dict) and str(parameter.get("name") or "")
    }
    return sorted(names)


def _public_bound_surfaces(endpoints: list[dict]) -> list[dict]:
    """Keep proof metadata auditable without exporting the in-process capability."""
    return [
        {key: value for key, value in surface.items() if not str(key).startswith("_")}
        for surface in endpoints[:20] if isinstance(surface, dict)
    ]


def _workflow_uses_only_bound_surfaces(steps: list, endpoints: list[dict]) -> bool:
    """Every BOLA workflow request must match one server-bound route/method."""
    for step in steps:
        if not isinstance(step, dict):
            return False
        path = str(step.get("path") or "")
        method = _http_method(step.get("method") or "GET")
        if not _workflow_request_uses_only_bound_surface(path, method, endpoints):
            return False
    return True


def _workflow_request_uses_only_bound_surface(path: str, method: str,
                                               endpoints: list[dict]) -> bool:
    return any(
        method in {_http_method(value) for value in (surface.get("methods") or [])}
        and _path_matches_bound_template(path, str(surface.get("raw_path") or surface.get("path") or ""))
        for surface in endpoints if isinstance(surface, dict)
    )


def _path_matches_bound_template(path: str, template: str) -> bool:
    if not path.startswith("/") or not template.startswith("/"):
        return False
    pattern = re.sub(r"\{[^{}]+\}", r"[^/]+", re.escape(template).replace("\\{", "{").replace("\\}", "}"))
    return bool(re.fullmatch(pattern, path))


def _replace_path_parameter(path: str, name: str, value: str) -> str:
    encoded = quote(value, safe="")
    patterns = (
        rf"\{{{re.escape(name)}\}}",
        rf":{re.escape(name)}(?=/|$)",
        rf"<(?:(?:string|int|path|uuid):)?{re.escape(name)}>",
    )
    result = path
    for pattern in patterns:
        result, count = re.subn(pattern, encoded, result, count=1)
        if count:
            return result
    raise ValueError(f"path parameter {name!r} not found in endpoint template")


_WORKFLOW_VARIABLE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")
_SENSITIVE_FIELD = re.compile(
    r"password|passwd|secret|token|api[_-]?key|authorization|cookie", re.I)


def _render_workflow_value(value, variables: dict[str, str]):
    """只做显式变量替换；不求值表达式，不执行模板代码。"""
    if isinstance(value, str):
        def replace(match: re.Match) -> str:
            name = match.group(1)
            if name not in variables:
                raise KeyError(f"workflow variable {name!r} is not captured")
            return variables[name]
        return _WORKFLOW_VARIABLE.sub(replace, value)
    if isinstance(value, dict):
        return {str(key): _render_workflow_value(item, variables) for key, item in value.items()}
    if isinstance(value, list):
        return [_render_workflow_value(item, variables) for item in value]
    if value is None or isinstance(value, (int, float, bool)):
        return value
    raise TypeError(f"unsupported workflow value type: {type(value).__name__}")


def _response_json(record: ProbeRecord):
    try:
        return json.loads(record.response_excerpt or "")
    except (TypeError, ValueError):
        return None


def _json_field(value, dotted_path: str):
    current = value
    for part in dotted_path.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def _public_record(record: ProbeRecord) -> dict:
    """证据记录保留结构与状态，但不得把凭据、会话令牌或私有 sentinel 落盘。"""
    data = dict(record.__dict__)
    data.pop("setup_response_body", None)
    data["params"] = {
        str(key): ("<redacted>" if _SENSITIVE_FIELD.search(str(key)) else value)
        for key, value in (record.params or {}).items()
    }
    data["response_headers"] = {
        str(key): ("<redacted>" if _SENSITIVE_FIELD.search(str(key)) else value)
        for key, value in (record.response_headers or {}).items()
    }
    sensitive_payload = any(
        _SENSITIVE_FIELD.search(str(key)) and str(value) == str(record.payload)
        for key, value in (record.params or {}).items()
    )
    data["url"] = _redact_url(record.url or "")
    data["redirect_location"] = _redact_url(record.redirect_location or "")
    data["payload"] = "<redacted>" if sensitive_payload else _redact_response_excerpt(record.payload or "")
    data["response_excerpt"] = _redact_response_excerpt(record.response_excerpt or "")
    data["runtime_log_excerpt"] = _redact_response_excerpt(record.runtime_log_excerpt or "")
    return data


def _redact_url(value: str) -> str:
    """Redact sensitive query values while retaining a useful, correlateable URL shape."""
    try:
        parsed = urlparse(str(value))
        if not parsed.query:
            return str(value)
        query = [
            (key, "<redacted>" if _SENSITIVE_FIELD.search(key) else item)
            for key, item in parse_qsl(parsed.query, keep_blank_values=True)
        ]
        return urlunparse(parsed._replace(query=urlencode(query)))
    except (TypeError, ValueError):
        return _redact_response_excerpt(str(value or ""))


def _redact_response_excerpt(text: str) -> str:
    """优先按 JSON 结构脱敏，失败时再处理常见键值和 Bearer 文本。"""
    try:
        parsed = json.loads(text)
    except (TypeError, ValueError):
        parsed = None
    if parsed is not None:
        return json.dumps(_redact_public_value(parsed), ensure_ascii=False, sort_keys=True)
    # Redact bearer material first; otherwise the generic ``Authorization:`` rule
    # only consumes the word "Bearer" and leaves the actual token behind.
    value = re.sub(
        r"(?i)bearer\s+[A-Za-z0-9._~+\-/=]{6,}", "Bearer <redacted>", str(text),
    )
    value = re.sub(
        r"(?i)(password|passwd|secret|token|api[_-]?key|authorization|cookie)"
        r"\s*[:=]\s*([^\s,;]+)",
        lambda match: f"{match.group(1)}=<redacted>", value,
    )
    return value


def _redact_public_value(value):
    if isinstance(value, dict):
        return {
            str(key): (
                "<redacted>" if _SENSITIVE_FIELD.search(str(key)) and item not in (None, "")
                else _redact_public_value(item)
            )
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact_public_value(item) for item in value]
    return value


def _needs_live_discovery(surfaces: list[dict]) -> bool:
    """源码/OpenAPI 已给出结构化入口时不再混入主页链接，避免探针预算被无关路由耗尽。"""
    if not surfaces:
        return True
    grounded = {
        str(item.get("source") or "")
        for item in surfaces
        if isinstance(item, dict) and item.get("path")
    }
    return not grounded or grounded <= {"heuristic", "legacy", "unknown"}


def _false_sql_payload(payload: str) -> str | None:
    """只转换明确的常见恒真表达式；不对任意 SQL 文本猜测 false control。"""
    value = str(payload or "")
    for true_expr, false_expr in (("'1'='1", "'1'='2"), ('"1"="1', '"1"="2')):
        if true_expr in value:
            return value.replace(true_expr, false_expr, 1)
    replacements = ((r"\b1\s*=\s*1\b", "1=2"),)
    for pattern, replacement in replacements:
        changed, count = re.subn(pattern, replacement, value, count=1, flags=re.I)
        if count and changed != value:
            return changed
    return None


def _control_value(param: str) -> str:
    return "1" if str(param).lower().endswith(("id", "_id", "count", "page")) else "AUDITAGENTX_CONTROL"


def _oracle_name(vuln_type: str | None, indicator: str) -> str:
    lower = str(vuln_type or "").lower()
    if indicator.startswith("time-based"):
        return "paired_time_differential"
    if "sql" in lower:
        return "new_database_error_indicator"
    if "command" in lower:
        return "command_output_marker"
    if "traversal" in lower or "lfi" in lower:
        return "sensitive_file_content_marker"
    if "ssti" in lower or "template" in lower:
        return "template_evaluation_marker"
    return "new_response_indicator"


def _safe_logs(supplier) -> str:
    if supplier is None:
        return ""
    try:
        return str(supplier() or "")[-6000:]
    except Exception:  # noqa: BLE001
        return ""


def _log_delta(before: str, after: str) -> str:
    """保留攻击请求之后新增的容器日志，避免早先异常成为本次攻击的伪证据。"""
    if not after:
        return ""
    if before and after.startswith(before):
        return after[len(before):][-1200:]
    # Docker tail 截断或日志轮转时无法证明哪些内容由本次请求新增。返回旧日志尾部会让
    # 历史异常命中 success_indicator，形成“自己骗自己”的动态确认，因此宁可放弃该证据。
    return ""


_GENERIC_INDICATORS = {
    "ok", "success", "error", "admin", "html", "true", "false", "server", "warning",
}


def _credible_indicator(value: str) -> bool:
    indicator = str(value or "").strip()
    if len(indicator) < 4 or indicator.lower() in _GENERIC_INDICATORS:
        return False
    if indicator in {".*", ".+", "^.*$", "\\w+", "\\d+"}:
        return False
    return True


def _matches(indicator: str, text: str) -> bool:
    try:
        return bool(re.search(indicator, text or "", re.IGNORECASE))
    except re.error:
        return indicator.lower() in (text or "").lower()
