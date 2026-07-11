"""RAG 自进化：把**可信标签**的漏洞反馈归纳进知识库，让后续复核越用越准（Q2）。

⚠️ 生死攸关的铁律（防止"自我感动"循环自欺）：
    只录入**可信来源**的标签，绝不录入 Agent 自己没独立验证的判断（needs_review / LLM 自述）。
    否则"Agent 自己说对 → 存进 KB → 下次更自信说对"会把知识库越喂越脏。

可信来源（RELIABLE_LABEL_SOURCES）：
    - human                : 人工在前端标注（黄金 ground truth）
    - dynamic_confirmed    : 框架侧动态确认（nonce / HTTP 真实复现），有独立证据
    自动 VerifyAgent 结论不是独立真值，不能反向训练自身。误报只接受人工标注；
    真实漏洞可接受运行时独立复现。

学到的知识写入 data/rag_feedback/learned_feedback.json（gitignore，不污染 curated 知识），
retriever.load_default_items 会自动加载它并用于后续检索。
"""
from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone
from typing import Any, Optional

logger = logging.getLogger(__name__)

RELIABLE_LABEL_SOURCES = {"human", "dynamic_confirmed"}
_LEARNED_FILE = "learned_feedback.json"


def _key(vuln_type: str, label: str) -> str:
    return hashlib.sha1(f"{label}|{vuln_type}".lower().encode()).hexdigest()[:16]


def _text(v: Any) -> str:
    return "" if v is None else str(v)


def _load_learned(path) -> dict:
    if path.exists():
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            return {it["id"]: it for it in data.get("items", []) if it.get("id")}
        except Exception:  # noqa: BLE001
            return {}
    return {}


def is_reliable(label_source: str) -> bool:
    return label_source in RELIABLE_LABEL_SOURCES


def ingest_feedback(finding: dict, label: str, label_source: str) -> bool:
    """把一条**可信标签**反馈归纳进学习知识库。

    label ∈ {"true_positive", "false_positive"}；label_source 必须在 RELIABLE_LABEL_SOURCES 内。
    返回是否成功录入（不可信来源 / 缺信息 -> False，不录）。
    """
    if label not in ("true_positive", "false_positive"):
        return False
    if not is_reliable(label_source):
        logger.info("拒绝录入不可信标签来源 '%s'（防自我感动）: %s", label_source, finding.get("type"))
        return False

    vuln_type = _text(finding.get("type") or finding.get("vulnerability_type")).strip()
    if not vuln_type:
        return False
    ev = finding.get("evidence") or finding.get("_evidence") or {}
    ver = ev.get("verification") or {}
    source = _text(ev.get("source") or finding.get("source_symbol"))
    sink = _text(ev.get("sink"))
    cwe = _text(finding.get("cwe_id") or (ev.get("knowledge") or {}).get("cwe_id"))
    ctx = _text(finding.get("context") or ver.get("context"))
    fp_reason = _text(finding.get("false_positive_reason") or ver.get("false_positive_reason")
                      or finding.get("downgrade_reason"))
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    from backend.rag.retriever import feedback_dir, load_default_items
    path = feedback_dir() / _LEARNED_FILE
    learned = _load_learned(path)
    item_id = f"learned-{_key(vuln_type, label)}"
    item = learned.get(item_id) or {
        "id": item_id, "source_type": "learned_feedback",
        "title": f"实战{'真实确认' if label == 'true_positive' else '已知误报'}模式：{vuln_type}",
        "summary": "", "cwe_id": cwe or None, "vuln_types": [vuln_type],
        "sources": [], "sinks": [], "verification_checks": [],
        "false_positive_signals": [], "tags": ["learned", label], "references": [],
    }

    def _add(lst_key: str, value: str):
        v = value.strip()
        if v and v not in item.setdefault(lst_key, []):
            item[lst_key].append(v)

    if source:
        _add("sources", source)
    if sink:
        _add("sinks", sink)
    _add("tags", f"src:{label_source}")
    if label == "true_positive":
        detail = f"[{stamp}] 经{label_source}确认的真实漏洞：{vuln_type}"
        if source or sink:
            detail += f"（source={source or 'N/A'} → sink={sink or 'N/A'}）"
        _add("verification_checks", detail)
    else:
        detail = f"[{stamp}] 经{label_source}判定的误报：{vuln_type}"
        if fp_reason:
            detail += f"，原因：{fp_reason[:160]}"
        if ctx:
            detail += f"（上下文={ctx}）"
        _add("false_positive_signals", detail)

    learned[item_id] = item
    path.write_text(json.dumps({"items": list(learned.values())}, ensure_ascii=False, indent=2),
                    encoding="utf-8")
    load_default_items.cache_clear()   # 让检索立即用上新学到的知识
    logger.info("已录入 %s 反馈到 RAG 知识库: %s (来源=%s)", label, vuln_type, label_source)
    return True


def learn_from_scan(findings: list[dict]) -> dict:
    """扫描结束后自动从**可信**结果自进化：
      - dynamically_verified=True -> true_positive（来源 dynamic_confirmed）
    Agent 自己的 false_positive / needs_review / unverified 一律不录，避免
    “自己判定 -> 写入知识库 -> 下次用自己的结论增强置信度”的反馈回路。
    """
    tp = fp = 0
    for f in findings or []:
        ev = f.get("evidence") or f.get("_evidence") or {}
        ver = ev.get("verification") or {}
        if f.get("dynamically_verified") or ver.get("dynamically_verified"):
            tp += 1 if ingest_feedback(f, "true_positive", "dynamic_confirmed") else 0
    if tp or fp:
        logger.info("扫描自进化：录入真实确认 %d 条 / 误报 %d 条", tp, fp)
    return {"true_positive_ingested": tp, "false_positive_ingested": fp}
