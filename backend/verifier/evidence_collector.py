"""证据链采集：把 source→sink→exploit→dynamic runtime 汇总为可追溯结构。

对应 md「证据链可追溯」创新点 & PDF「给出触发文件位置、利用路径、验证方法」。
"""
from __future__ import annotations


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

        return {
            # 静态数据流证据
            "source": verify_result.get("source"),
            "sink": verify_result.get("sink"),
            "data_flow": verify_result.get("propagation_path"),
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
                "matched_indicator": dynamic.get("matched_indicator"),
                "request": {
                    "url": confirmed.get("url"),
                    "params": confirmed.get("params"),
                    "payload": confirmed.get("payload"),
                },
                "response_status": confirmed.get("status"),
                "response_excerpt": (confirmed.get("response_excerpt") or "")[:400],
            },
            "poc_result": {
                "poc": (poc_result or {}).get("poc"),
                "executed": (poc_result or {}).get("poc_executed", False),
                "sandbox": (poc_result or {}).get("sandbox_result") or {},
            },
            "logs": logs,
        }
