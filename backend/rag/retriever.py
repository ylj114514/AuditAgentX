"""Deterministic offline retriever for security knowledge records."""
from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

from backend.rag.models import SecurityKnowledgeItem


SOURCES_DIR = Path(__file__).resolve().parent / "sources"
TOKEN_RE = re.compile(r"[a-zA-Z0-9_.$:-]+")


class SecurityKnowledgeRetriever:
    """Small keyword/metadata retriever for vulnerability verification.

    Phase 1 intentionally avoids embedding dependencies. The retriever favors
    exact vulnerability/CWE matches, then source/sink overlap and full-text
    token overlap. This keeps results predictable and easy to test.
    """

    def __init__(self, items: list[SecurityKnowledgeItem] | None = None) -> None:
        self.items = items or load_default_items()

    def retrieve(self, query: str = "", candidate: dict[str, Any] | None = None,
                 *, source_type: str | None = None, limit: int = 3) -> dict[str, Any]:
        candidate = candidate or {}
        query_text = _build_query(query, candidate)
        query_tokens = _tokens(query_text)
        scored: list[tuple[float, SecurityKnowledgeItem]] = []
        for item in self.items:
            # Learned feedback enriches a canonical security record below; it
            # is not authoritative enough to become the primary result.  In
            # particular, feedback records may intentionally omit CWE/OWASP
            # metadata and must not displace an offline CWE entry because of
            # incidental source-file token overlap.
            if source_type is None and item.source_type == "learned_feedback":
                continue
            if source_type and item.source_type != source_type:
                continue
            if source_type and not _candidate_matches_item(candidate, item):
                continue
            score = self._score(item, query_text, query_tokens, candidate)
            if score > 0:
                scored.append((score, item))

        scored.sort(key=lambda pair: pair[0], reverse=True)
        results = [item.to_dict(score=score) for score, item in scored[:max(limit, 1)]]
        result = {
            "query": query_text,
            "results": results,
            "top_result": results[0] if results else None,
            "summary": _summarize(results),
        }
        self._merge_learned_feedback(candidate, result)
        return result

    def _merge_learned_feedback(self, candidate: dict[str, Any], result: dict[str, Any]) -> None:
        """把匹配同类型的「学到的反馈知识」（误报信号 / 验证要点）合并进 top_result。

        自进化知识可能排名不到 top，但其 false_positive_signals / verification_checks
        必须始终参与后续复核——这才是"越用越准"的落点。
        """
        top = result.get("top_result")
        vuln_type = str(candidate.get("type") or candidate.get("vulnerability_type") or "").strip().lower()
        if top is None or not vuln_type:
            return
        for item in self.items:
            if item.source_type != "learned_feedback":
                continue
            if not any(vuln_type == t.lower() or vuln_type in t.lower() or t.lower() in vuln_type
                       for t in item.vuln_types):
                continue
            for k in ("false_positive_signals", "verification_checks"):
                merged = list(top.get(k) or [])
                for v in getattr(item, k, []) or []:
                    if v not in merged:
                        merged.append(v)
                top[k] = merged
            top["learned_feedback_applied"] = True

    def retrieve_playbook(self, candidate: dict[str, Any], *, limit: int = 2) -> dict[str, Any]:
        return self.retrieve(candidate=candidate, source_type="verification_playbook", limit=limit)

    def retrieve_remediation(self, candidate: dict[str, Any], *, limit: int = 2) -> dict[str, Any]:
        return self.retrieve(candidate=candidate, source_type="remediation_guide", limit=limit)

    @staticmethod
    def _score(item: SecurityKnowledgeItem, query_text: str, query_tokens: set[str],
               candidate: dict[str, Any]) -> float:
        haystack = " ".join([
            item.id, item.title, item.summary, item.cwe_id or "",
            " ".join(item.vuln_types), " ".join(item.aliases),
            " ".join(item.sources), " ".join(item.sinks),
            " ".join(item.sanitizers), " ".join(item.tags),
        ]).lower()
        item_tokens = _tokens(haystack)
        score = len(query_tokens & item_tokens) * 0.8

        vuln_type = str(candidate.get("type") or candidate.get("vulnerability_type") or "").lower()
        cwe = str(candidate.get("cwe_id") or candidate.get("cwe") or "").lower()
        if cwe and cwe == (item.cwe_id or "").lower():
            score += 20
        if vuln_type:
            names = [item.title, *item.vuln_types, *item.aliases]
            if any(vuln_type == name.lower() for name in names):
                score += 16
            elif any(vuln_type in name.lower() or name.lower() in vuln_type for name in names):
                score += 10

        source_sink_text = " ".join([
            str(candidate.get("source") or ""),
            str(candidate.get("sink") or ""),
            str(candidate.get("code_snippet") or candidate.get("vulnerable_code") or ""),
        ]).lower()
        for source in item.sources:
            if source.lower() in source_sink_text:
                score += 2.5
        for sink in item.sinks:
            if sink.lower() in source_sink_text:
                score += 3.5

        context_text = " ".join([
            str(candidate.get("language") or ""),
            " ".join(candidate.get("languages") or []),
            str(candidate.get("framework") or ""),
            " ".join(candidate.get("frameworks") or []),
        ]).lower()
        for language in item.languages:
            if language.lower() in context_text:
                score += 1.5
        for framework in item.frameworks:
            if framework.lower() in context_text:
                score += 2.0
        return score


def feedback_dir() -> Path:
    """运行时"学习到的反馈知识"目录（不进仓库、gitignore）。"""
    from backend.config import settings
    d = settings.data_path / "rag_feedback"
    d.mkdir(parents=True, exist_ok=True)
    return d


@lru_cache(maxsize=1)
def load_default_items() -> list[SecurityKnowledgeItem]:
    items: list[SecurityKnowledgeItem] = []
    dirs = [SOURCES_DIR]
    try:
        dirs.append(feedback_dir())   # 额外加载"自进化"学到的可信反馈知识
    except Exception:  # noqa: BLE001  无 data 目录不致命
        pass
    for base in dirs:
        for path in sorted(base.glob("*.json")):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except Exception:  # noqa: BLE001  单个损坏文件不影响整体
                continue
            records = data.get("items", data if isinstance(data, list) else [])
            items.extend(SecurityKnowledgeItem.from_dict(record) for record in records)
    return items


def _build_query(query: str, candidate: dict[str, Any]) -> str:
    parts = [query]
    for key in ("type", "vulnerability_type", "cwe_id", "cwe", "rule_id", "source", "sink",
                "code_snippet", "vulnerable_code", "file", "file_path"):
        value = candidate.get(key)
        if value:
            parts.append(str(value))
    return " ".join(part for part in parts if part).strip()


def _tokens(text: str) -> set[str]:
    return {match.group(0).lower() for match in TOKEN_RE.finditer(text or "") if len(match.group(0)) > 1}


def _candidate_matches_item(candidate: dict[str, Any], item: SecurityKnowledgeItem) -> bool:
    """Require typed lookups to match the candidate type/CWE, not just generic tokens.

    Without this guard, queries such as "code injection" or "file upload" can
    match unrelated playbooks that merely share broad words like "injection" or
    filesystem sinks. Untyped queries still fall back to keyword scoring.
    """
    vuln_type = str(candidate.get("type") or candidate.get("vulnerability_type") or "").strip().lower()
    cwe = str(candidate.get("cwe_id") or candidate.get("cwe") or "").strip().lower()
    if not vuln_type and not cwe:
        return True
    if cwe and cwe == (item.cwe_id or "").lower():
        return True
    if not vuln_type:
        return False
    names = [item.title, *item.vuln_types, *item.aliases]
    return any(vuln_type == name.lower() for name in names)


def _summarize(results: list[dict[str, Any]]) -> dict[str, Any]:
    if not results:
        return {"cwe_id": None, "owasp": [], "verification_checks": [], "remediation": []}
    top = results[0]
    return {
        "cwe_id": top.get("cwe_id"),
        "owasp": top.get("owasp") or [],
        "dynamic_strategy": top.get("dynamic_strategy"),
        "verification_checks": top.get("verification_checks") or [],
        "false_positive_signals": top.get("false_positive_signals") or [],
        "remediation": top.get("remediation") or [],
        "references": top.get("references") or [],
    }
