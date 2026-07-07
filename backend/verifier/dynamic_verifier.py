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


@dataclass
class ProbeRecord:
    url: str
    method: str
    params: dict
    payload: str
    status: int | None = None
    status_code: int | None = None
    response_excerpt: str = ""
    elapsed_ms: int = 0
    error: str = ""
    reason: str = ""


@dataclass
class DynamicResult:
    verified: bool = False
    reproducible: bool = False
    reproduction_status: str = "not_executed"
    matched_indicator: str = ""
    confirmed_record: dict | None = None
    records: list = field(default_factory=list)   # list[ProbeRecord as dict]
    logs: list = field(default_factory=list)
    skipped: bool = False
    reason: str = ""
    error: str = ""


class HttpProbe:
    """底层 HTTP 探测：发请求并完整记录，供证据链使用。"""

    def __init__(self, timeout: int = 10) -> None:
        self.timeout = timeout

    def send(self, base_url: str, path: str, param: str, payload: str,
             method: str = "GET") -> ProbeRecord:
        import httpx

        url = base_url.rstrip("/") + path
        rec = ProbeRecord(url=url, method=method, params={param: payload}, payload=payload)
        t0 = time.time()
        try:
            with httpx.Client(timeout=self.timeout, follow_redirects=True, trust_env=False) as client:
                if method == "GET":
                    resp = client.get(url, params={param: payload})
                else:
                    resp = client.post(url, data={param: payload})
            rec.status = resp.status_code
            rec.status_code = resp.status_code
            rec.response_excerpt = resp.text[:800]
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

    def __init__(self, timeout: int = 10, max_probes: int = 40) -> None:
        self.probe = HttpProbe(timeout=timeout)
        self.max_probes = max_probes

    def verify(self, base_url: str, exploit: dict,
               endpoints: list[str] | None = None) -> DynamicResult:
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
        paths = endpoints or _HEURISTIC_PATHS
        if not payloads:
            result.skipped = True
            result.reproduction_status = "not_runtime_verifiable"
            result.reason = "该漏洞无动态载荷（可能为静态类，如硬编码密钥）"
            return result

        # 基线：用良性值请求，用于差异对比
        baseline = self._baseline(base_url, paths, params[0])
        result.logs.append(f"目标={base_url} 端点数={len(paths)} 载荷数={len(payloads)}")

        probes = 0
        for path in paths:
            for param in params:
                for payload in payloads:
                    if probes >= self.max_probes:
                        result.logs.append("达到最大探测次数上限，停止")
                        return self._finalize(result)
                    probes += 1
                    rec = self.probe.send(base_url, path, param, payload)
                    if not rec.status_code and rec.status is not None:
                        rec.status_code = rec.status
                    result.records.append(rec.__dict__)
                    if rec.error:
                        result.logs.append(
                            f"请求失败: {rec.url} reason={rec.reason or 'request_error'} error={rec.error}"
                        )
                        continue
                    if rec.status == 404:
                        result.logs.append(f"端点不存在: {rec.url}")
                        continue
                    hit = self._judge(rec, indicators, baseline)
                    if hit:
                        result.verified = True
                        result.reproducible = True
                        result.reproduction_status = "dynamic_confirmed"
                        result.matched_indicator = hit
                        result.confirmed_record = rec.__dict__
                        result.logs.append(
                            f"命中: {path}?{param}={payload!r} -> 特征 {hit!r}"
                        )
                        return self._finalize(result)
        self._set_failure_reason(result)
        return self._finalize(result)

    # ---------- 内部 ----------
    def _baseline(self, base_url: str, paths: list[str], param: str) -> dict:
        """采集良性请求基线（长度/状态），用于盲注差异判断。"""
        base = {}
        for path in paths[:3]:
            rec = self.probe.send(base_url, path, param, "1")
            base[path] = {"status": rec.status, "len": len(rec.response_excerpt)}
        return base

    def _judge(self, rec: ProbeRecord, indicators: list[str], baseline: dict) -> str:
        """返回命中的特征串；未命中返回空串。"""
        body = rec.response_excerpt or ""
        # 1) 成功特征正则匹配（回显/报错/敏感数据）
        for ind in indicators:
            try:
                if re.search(ind, body, re.IGNORECASE):
                    return ind
            except re.error:
                if ind.lower() in body.lower():
                    return ind
        # 2) 时间盲注：响应明显变慢
        if rec.elapsed_ms >= 4500 and ("sleep" in rec.payload.lower()
                                       or "waitfor" in rec.payload.lower()):
            return f"time-based(delay={rec.elapsed_ms}ms)"
        # 3) 布尔差异：响应长度相对基线显著变化
        path = urlparse(rec.url).path or "/"
        base = baseline.get(path)
        if base and rec.status == 200 and base["len"] > 0:
            ratio = abs(len(body) - base["len"]) / max(base["len"], 1)
            if ratio > 0.5 and ("or '1'='1" in rec.payload.lower() or "or 1=1" in rec.payload.lower()):
                return f"boolean-diff(ratio={ratio:.2f})"
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
        if statuses and all(status == 404 for status in statuses if status is not None):
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
        return result
