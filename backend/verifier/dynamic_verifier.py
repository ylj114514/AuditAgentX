"""动态验证器（PDF 选题一：动态检测 / 漏洞验证）。

对一个**正在运行的目标应用**（沙箱内或授权靶场）发送攻击载荷，
采集 request / response / log 证据，并根据成功特征判定漏洞是否**可复现**。

设计为 provider 无关：只需要一个可访问的 base_url。
- Docker 沙箱起服务  -> SandboxAppRunner（sandbox_manager.py）
- 本地授权靶场       -> LocalAppRunner（仅限隔离实验环境）
"""
from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass, field
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

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
    elapsed_ms: int = 0
    runtime_log_excerpt: str = ""
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


class HttpProbe:
    """底层 HTTP 探测：发请求并完整记录，供证据链使用。"""

    def __init__(self, timeout: int = 10) -> None:
        self.timeout = timeout

    def send(self, base_url: str, path: str, param: str, payload: str,
             method: str = "GET", transport: str = "query", role: str = "attack") -> ProbeRecord:
        import httpx
        from backend.dynamic.target_guard import validate_dynamic_base_url

        safe_base = validate_dynamic_base_url(base_url)
        if not str(path or "").startswith("/") or str(path).startswith("//"):
            raise ValueError("dynamic endpoint must be a project-relative path starting with one slash")
        url = safe_base.rstrip("/") + path
        method = _http_method(method)
        transport = _transport_for(method, transport)
        rec = ProbeRecord(url=url, method=method, params={param: payload}, payload=payload,
                          transport=transport, role=role)
        t0 = time.time()
        try:
            # 禁止自动跟随重定向：否则本地靶场可用 30x 把探测器带到外部地址，
            # 绕过 local-only 目标保护；开放重定向也必须通过 Location 头判定。
            with httpx.Client(timeout=self.timeout, follow_redirects=False, trust_env=False) as client:
                if transport == "query":
                    resp = client.request(method, url, params={param: payload})
                elif transport == "json":
                    resp = client.request(method, url, json={param: payload})
                else:
                    resp = client.request(method, url, data={param: payload})
            rec.url = str(resp.request.url)
            rec.status = resp.status_code
            rec.status_code = resp.status_code
            rec.response_excerpt = resp.text[:800]
            rec.response_headers = {str(k).lower(): str(v)[:500] for k, v in resp.headers.items()}
            rec.redirect_location = str(resp.headers.get("location") or "")[:500]
            if resp.status_code == 404:
                rec.reason = "endpoint_not_found"
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
               endpoints: list[str] | None = None, *, runtime_log_supplier=None) -> DynamicResult:
        """
        base_url  : 运行中的目标（如 http://127.0.0.1:8080）
        exploit   : ExploitAgent 产出，含 payloads / success_indicators / injection_points
        endpoints : 显式端点路径；缺省用启发式路径
        """
        result = DynamicResult()
        if not base_url:
            result.skipped = True
            result.reproduction_status = "not_executed"
            result.reason = "无可用目标 base_url（未启用沙箱/靶场）"
            return result

        payloads = exploit.get("payloads") or []
        indicators = [i for i in (exploit.get("success_indicators") or []) if i]
        params = exploit.get("_injection_points") or ["id", "q", "input", "file", "host"]
        preferred_method = _http_method(exploit.get("http_method") or exploit.get("method"))
        if not payloads:
            result.skipped = True
            result.reproduction_status = "not_runtime_verifiable"
            result.reason = "该漏洞无动态载荷（可能为静态类，如硬编码密钥）"
            return result
        raw_surfaces = _surface_specs(endpoints or _HEURISTIC_PATHS, preferred_method)
        # 实际 HTTP probe 时，补充运行中目标暴露的 OpenAPI/HTML 表单；测试替身不触网。
        if isinstance(self.probe, HttpProbe):
            try:
                from backend.dynamic.endpoint_extractor import discover_live_surfaces, merge_attack_surfaces
                raw_surfaces = merge_attack_surfaces(raw_surfaces, discover_live_surfaces(base_url))
            except Exception as exc:  # noqa: BLE001 - discovery failure cannot invalidate source-grounded probes
                result.logs.append(f"运行时攻击面发现跳过: {type(exc).__name__}: {str(exc)[:160]}")
        surfaces = _normalize_surfaces(raw_surfaces, params, preferred_method)
        result.surfaces = surfaces[:80]
        if not surfaces:
            result.skipped = True
            result.reproduction_status = "not_runtime_verifiable"
            result.reason = "没有安全的项目相对 endpoint；拒绝绝对 URL/协议相对路径"
            return result

        # 每个“端点 + 方法 + 参数位置”都有独立良性基线。不能用 / 的响应给 /api/search 作对照。
        baseline_cache: dict[tuple[str, str, str, str], ProbeRecord] = {}
        result.logs.append(f"目标={base_url} 攻击面={len(surfaces)} 载荷数={len(payloads)}")

        # 迭代顺序保持 payload -> surface：优先以首个 payload 横扫真实源码/运行时入口，
        # 避免把预算耗在单一路径的一串猜测参数上。
        probes = 0
        stopped = False
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
                key = (path, method, param, transport)
                baseline = baseline_cache.get(key)
                if baseline is None:
                    baseline = self._send(base_url, path, param, _control_value(param), method, transport, "baseline")
                    baseline_cache[key] = baseline
                    result.baseline_records.append(baseline.__dict__)
                probes += 1
                log_before = _safe_logs(runtime_log_supplier)
                rec = self._send(base_url, path, param, payload, method, transport, "attack")
                if runtime_log_supplier is not None:
                    rec.runtime_log_excerpt = _log_delta(log_before, _safe_logs(runtime_log_supplier))
                if not rec.status_code and rec.status is not None:
                    rec.status_code = rec.status
                result.records.append(rec.__dict__)
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
                    # 时间型确认要求第二组独立的 control/attack 采样，避免慢页面自证。
                    if hit.startswith("time-based") and not self._confirm_time_based(
                        base_url, path, param, payload, method, transport, baseline
                    ):
                        result.logs.append("时间型差异未在第二次独立采样中复现，保持未确认")
                        continue
                    result.verified = True
                    result.reproducible = True
                    result.reproduction_status = "dynamic_confirmed"
                    result.verification_level = "endpoint_reproduced"
                    result.oracle = _oracle_name(exploit.get("vuln_type"), hit)
                    result.matched_indicator = hit
                    result.confirmed_record = rec.__dict__
                    result.baseline_record = baseline.__dict__
                    result.logs.append(
                        f"命中: {method} {path} ({transport}:{param}) payload={payload!r} -> 判据 {hit!r}"
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
    def _send(self, base_url: str, path: str, param: str, payload: str,
              method: str, transport: str, role: str) -> ProbeRecord:
        """兼容旧测试替身，同时给真实探针传入请求编码和请求角色。"""
        try:
            return self.probe.send(base_url, path, param, payload, method=method,
                                   transport=transport, role=role)
        except TypeError as exc:
            # 旧版测试替身只接受 method；仅在参数签名不兼容时回退，避免吞掉真实错误。
            if "transport" not in str(exc) and "role" not in str(exc):
                raise
            record = self.probe.send(base_url, path, param, payload, method=method)
            record.transport = transport
            record.role = role
            return record

    def _confirm_time_based(self, base_url: str, path: str, param: str, payload: str,
                            method: str, transport: str, first_baseline: ProbeRecord) -> bool:
        control = self._send(base_url, path, param, _control_value(param), method, transport, "baseline")
        attack = self._send(base_url, path, param, payload, method, transport, "confirmation")
        if control.error or attack.error:
            return False
        delta = attack.elapsed_ms - control.elapsed_ms
        # 第一组基线也必须正常，防止慢页面/慢机器制造假差异。
        return bool(
            not first_baseline.error
            and attack.elapsed_ms >= 4500
            and delta >= 3000
            and attack.elapsed_ms >= max(4500, control.elapsed_ms * 2)
        )

    def _judge(self, rec: ProbeRecord, indicators: list[str], baseline: ProbeRecord,
                *, vuln_type: str = "") -> str:
        """返回命中的特征串；未命中返回空串。"""
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
            result.reason = "endpoint_not_found"
            result.logs.append("所有探测端点均返回 404，未找到可验证入口")
            return

        result.reason = "payload_not_matched"
        result.logs.append("所有载荷均未命中成功特征，判定不可复现")

    @staticmethod
    def _finalize(result: DynamicResult) -> DynamicResult:
        if not result.reproduction_status or result.reproduction_status == "not_executed":
            if result.reproducible:
                result.reproduction_status = "dynamic_confirmed"
            elif result.reason == "payload_not_matched":
                result.reproduction_status = "not_reproduced"
            elif result.reason in {"connection_failed", "request_timeout", "endpoint_not_found", "no_probe_executed"}:
                result.reproduction_status = result.reason
        # 只保留前若干条记录，避免证据体积过大
        result.records = result.records[:30]
        result.baseline_records = result.baseline_records[:30]
        return result


def _http_method(value: str | None) -> str:
    method = str(value or "GET").upper()
    return method if method in {"GET", "POST", "PUT", "PATCH", "DELETE"} else "GET"


def _transport_for(method: str, transport: str | None) -> str:
    value = str(transport or "").lower()
    if method == "GET":
        return "query"
    return value if value in {"query", "form", "json"} else "form"


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
        params = [p for p in (surface.get("params") or []) if isinstance(p, dict) and p.get("name")]
        if not params:
            fallback_location = "query" if (methods[0] if methods else preferred_method) == "GET" else "unknown"
            params = [{"name": name, "location": fallback_location} for name in hints[:6]]
        for method in methods:
            for parameter in params:
                name = str(parameter.get("name") or "")
                if not name:
                    continue
                location = str(parameter.get("location") or "unknown").lower()
                if method == "GET":
                    transports = ["query"]
                elif location == "json":
                    transports = ["json"]
                elif location in {"form", "body"}:
                    transports = ["form"]
                elif location == "query":
                    transports = ["query"]
                else:
                    transports = ["form", "json"]
                for transport in transports:
                    key = (path, method, name, transport)
                    if key not in seen:
                        seen.add(key)
                        cases.append({"path": path, "method": method, "param": name,
                                      "transport": transport, "source": surface.get("source", "unknown")})
    return cases[:160]


def _surface_specs(raw_endpoints, preferred_method: str) -> list[dict]:
    """把兼容旧 API 的字符串路径转换为结构化 surface，供静态/运行时结果合并。"""
    specs: list[dict] = []
    for endpoint in raw_endpoints or []:
        if isinstance(endpoint, str):
            specs.append({"path": endpoint, "methods": [preferred_method], "params": [], "source": "legacy"})
        elif isinstance(endpoint, dict):
            specs.append(dict(endpoint))
    return specs


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
