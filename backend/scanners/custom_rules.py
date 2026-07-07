"""自定义污点分析扫描器（离线兜底，升级自单行正则）。

升级点（借鉴 Semgrep taint mode）：
  旧版：单行匹配危险函数 -> 误报高（不管数据是否用户可控）。
  新版：source→sink 可达性分析 ——
    - 注入类 sink（SQL/命令/路径/SSRF/SSTI/XSS）：在「函数体窗口」内追踪是否有用户可控 source
      流向该 sink，且中途无 sanitizer，才判定为漏洞；据此给出置信度与污点路径。
    - 非注入类（硬编码密钥/不安全反序列化/弱加密）：本身即问题，直接命中。

输出的 RawFinding.extra 携带污点证据：source_line / sanitized / confidence / taint_flow。
外部工具（Semgrep 等）缺失时，本扫描器保证离线也能给出「带数据流依据」的结果。
"""
from __future__ import annotations

from pathlib import Path

from backend.scanners.base import BaseScanner, RawFinding
from backend.repository.language_detector import scan_files
from backend.scanners import taint_rules as tr

# 在 sink 上下多少行的窗口内寻找 source（近似函数体作用域）
_WINDOW = 15


class CustomRuleScanner(BaseScanner):
    name = "custom"

    def available(self) -> bool:
        return True  # 纯 Python，永远可用

    def run(self, target: Path) -> list[RawFinding]:
        findings: list[RawFinding] = []
        for f in scan_files(target):
            try:
                lines = f.read_text(encoding="utf-8", errors="ignore").splitlines()
            except OSError:
                continue
            rel = (f.relative_to(target).as_posix()
                   if target in f.parents or target == f.parent else f.name)
            findings.extend(self._scan_file(rel, lines))
        return findings

    def _scan_file(self, rel: str, lines: list[str]) -> list[RawFinding]:
        out: list[RawFinding] = []
        for idx, line in enumerate(lines, start=1):
            for vuln_type, base_sev, sink_re, require_source in tr.TAINT_SINKS:
                if not sink_re.search(line):
                    continue
                finding = self._evaluate(rel, lines, idx, line, vuln_type,
                                         base_sev, require_source)
                if finding:
                    out.append(finding)
        return out

    def _evaluate(self, rel, lines, idx, line, vuln_type, base_sev, require_source):
        """对一个 sink 命中做污点评估，返回 RawFinding 或 None（判为噪音时）。"""
        # 硬编码密钥：占位值直接跳过（降误报）
        if vuln_type == "Hardcoded Secret" and tr.PLACEHOLDER.search(line):
            return None

        # 非注入类：本身即问题，直接命中，置信度中等
        if not require_source:
            return self._make(rel, idx, line, vuln_type, base_sev,
                              confidence=0.6, source_line=None, sanitized=False,
                              note="sink 本身即风险（非注入类）")

        # 注入类：sink 行必须有动态构造痕迹（拼接/格式化），否则是静态字面量调用，非污点注入
        if not tr.has_injection_marker(line):
            return None

        # 在窗口内找 source + sanitizer
        start = max(0, idx - 1 - _WINDOW)
        end = min(len(lines), idx + _WINDOW)
        window_text = "\n".join(lines[start:end])
        line_has_src = tr.has_source(line)
        window_has_src = tr.has_source(window_text)
        sanitized = tr.has_sanitizer(window_text)

        if not window_has_src:
            # 没有任何用户可控 source -> 大概率误报，降级为 low/信息，低置信
            return self._make(rel, idx, line, vuln_type, "low",
                              confidence=0.25, source_line=None, sanitized=sanitized,
                              note="命中危险 sink 但窗口内未见用户可控输入，疑似噪音")

        # 找到 source 所在行号
        source_line = None
        for off in range(start, end):
            if tr.has_source(lines[off]):
                source_line = off + 1
                break

        if sanitized:
            # source 存在但检出净化器 -> 中低危、中置信
            return self._make(rel, idx, line, vuln_type, "medium",
                              confidence=0.5, source_line=source_line, sanitized=True,
                              note="source→sink 可达但检出疑似净化，需人工确认")

        # source 可达 sink 且无净化 -> 维持基础严重级，高置信
        confidence = 0.85 if line_has_src else 0.75
        return self._make(rel, idx, line, vuln_type, base_sev,
                          confidence=confidence, source_line=source_line,
                          sanitized=False, note="user input (source) → dangerous sink，无有效净化")

    @staticmethod
    def _make(rel, idx, line, vuln_type, sev, *, confidence, source_line,
              sanitized, note) -> RawFinding:
        taint_flow = []
        if source_line is not None:
            taint_flow.append({"stage": "source", "file": rel, "line": source_line})
        taint_flow.append({"stage": "sink", "file": rel, "line": idx})
        return RawFinding(
            type=vuln_type, file=rel, line=idx, severity=sev, source="custom-taint",
            code_snippet=line.strip()[:200],
            message=f"污点分析: {vuln_type} —— {note}",
            rule_id=f"taint-{vuln_type.lower().replace(' ', '-')}",
            extra={
                "confidence": confidence,
                "source_line": source_line,
                "sanitized": sanitized,
                "taint_flow": taint_flow,
                "analysis": "taint",
            },
        )
