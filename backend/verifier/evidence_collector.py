"""证据链采集：把 source→sink→exploit→dynamic runtime 汇总为可追溯结构。

对应 md「证据链可追溯」创新点 & PDF「给出触发文件位置、利用路径、验证方法」。
"""
from __future__ import annotations

import re


def _build_call_path(verify_result: dict, exploit: dict) -> list[dict]:
    """把 source→传播→sink 整理为逐跳「调用路径」（结构化，便于证据链展示）。

    兼容 propagation_path 为字符串（-> / → / => 分隔）或列表；
    静态信息缺失时用 exploit 的触发位置与利用路径兜底。
    """
    hops: list[dict] = []
    source = verify_result.get("source")
    sink = verify_result.get("sink")
    prop = verify_result.get("propagation_path")
    structured = verify_result.get("call_path")

    if isinstance(structured, list) and structured:
        return structured

    if source:
        hops.append({"stage": "source", "detail": str(source)})

    if isinstance(prop, str) and prop.strip():
        for part in re.split(r"->|→|=>", prop):
            step = part.strip()
            if step and step != str(source) and step != str(sink):
                hops.append({"stage": "propagation", "detail": step})
    elif isinstance(prop, (list, tuple)):
        for step in prop:
            hops.append({"stage": "propagation",
                         "detail": step if isinstance(step, str) else str(step)})

    if sink:
        hops.append({"stage": "sink", "detail": str(sink)})

    # 缺少静态数据流时，用利用证据兜底，保证「调用路径」始终有内容
    if not hops and exploit:
        if exploit.get("trigger_location"):
            hops.append({"stage": "trigger", "detail": str(exploit["trigger_location"])})
        if exploit.get("exploit_path"):
            hops.append({"stage": "exploit_path", "detail": str(exploit["exploit_path"])})
    return hops


class EvidenceCollector:
    @staticmethod
    def build(verify_result: dict, exploit: dict | None = None,
              dynamic: dict | None = None, poc_result: dict | None = None) -> dict:
        """组装写入 evidence 表的证据结构（md 7.9 证据链格式 + 动态利用证据）。"""
        exploit = exploit or {}
        dynamic = dynamic or {}
        logs = ["候选漏洞由 AuditAgent 产生", "VerifyAgent 独立复核通过"]

        if exploit:
            logs.append(f"ExploitAgent 生成利用方案: {exploit.get('vuln_type', '')}")
        if dynamic:
            if dynamic.get("skipped"):
                logs.append(f"动态验证跳过: {dynamic.get('reason', '')}")
            elif dynamic.get("reproducible"):
                logs.append(f"动态验证成功，命中特征: {dynamic.get('matched_indicator', '')}")
            else:
                logs.append("动态验证执行，但未复现")
            logs.extend(dynamic.get("logs", [])[:5])

        confirmed = dynamic.get("confirmed_record") or {}
        call_path = _build_call_path(verify_result, exploit)

        return {
            # 静态数据流证据
            "source": verify_result.get("source"),
            "sink": verify_result.get("sink"),
            "data_flow": verify_result.get("propagation_path"),
            # 结构化调用路径：source -> 传播 -> sink，逐跳可追溯
            "call_path": call_path,
            # 利用证据（PDF 模块③要求）
            "exploit": {
                "trigger_location": exploit.get("trigger_location"),
                "exploit_path": exploit.get("exploit_path"),
                "attack_vector": exploit.get("attack_vector"),
                "payloads": exploit.get("payloads"),
                "exploit_code": exploit.get("exploit_code"),
                "verification_method": exploit.get("verification_method"),
                "impact": exploit.get("impact"),
            },
            # 动态运行时证据
            "runtime": {
                "reproducible": dynamic.get("reproducible", False),
                "verified": dynamic.get("verified", False),
                "reason": dynamic.get("reason", ""),
                "error": dynamic.get("error", ""),
                "matched_indicator": dynamic.get("matched_indicator"),
                "request": {
                    "url": confirmed.get("url"),
                    "method": confirmed.get("method"),
                    "params": confirmed.get("params"),
                    "payload": confirmed.get("payload"),
                },
                "response_status": confirmed.get("status_code") or confirmed.get("status"),
                "response_excerpt": (confirmed.get("response_excerpt") or "")[:400],
                "elapsed_ms": confirmed.get("elapsed_ms"),
                "records": dynamic.get("records", [])[:10],
            },
            "poc_result": {
                "poc": (poc_result or {}).get("poc"),
                "executed": (poc_result or {}).get("poc_executed", False),
                "sandbox": (poc_result or {}).get("sandbox_result") or {},
            },
            "logs": logs,
        }
