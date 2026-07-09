# -*- coding: utf-8 -*-
"""OWASP BenchmarkJava 真实评测（per-category recall / precision / FPR / score）。

用真实的 OWASP BenchmarkJava（2740 个有 ground-truth 标签的 Java Web 测试用例）量化
AuditAgentX 静态检测栈在各漏洞类别上的召回/精度，形成「改一版规则→立刻测」的闭环。

评分口径（对齐 OWASP Benchmark 官方方法）：
  - 每个测试文件只针对其【指定类别】评估（CSV 的 category 列）。
  - TP：real=true 且扫描器在该文件报出匹配类别；FN：real=true 但未报。
  - FP：real=false（安全用例）但扫描器报出该类别；TN：real=false 且未报。
  - 每类别 TPR=TP/(TP+FN)，FPR=FP/(FP+TN)，Youden Score = TPR - FPR。
    （Benchmark 用 TPR-FPR 惩罚"见 sink 就报"的高误报工具。）

数据位置（gitignore，不随仓库分发；缺失则优雅跳过）：
  data/projects/BenchmarkJava/expectedresults-1.2.csv
  data/projects/BenchmarkJava/src/main/java/org/owasp/benchmark/testcode/*.java

用法：
    python scripts/run_owasp_benchmark.py                 # 仅内置 custom 扫描器（快）
    python scripts/run_owasp_benchmark.py --semgrep       # 额外叠加 semgrep（慢）
    python scripts/run_owasp_benchmark.py --min-confidence 0.5
"""
from __future__ import annotations

import argparse
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.scanners.custom_rules import CustomRuleScanner  # noqa: E402
from backend.scanners.semgrep_runner import SemgrepScanner  # noqa: E402

_ROOT = Path(__file__).resolve().parent.parent
BENCH_DIR = _ROOT / "data" / "projects" / "BenchmarkJava"
CSV_PATH = BENCH_DIR / "expectedresults-1.2.csv"
TESTCODE_DIR = BENCH_DIR / "src" / "main" / "java" / "org" / "owasp" / "benchmark" / "testcode"
# 扫描根：取 src/main，使 resources/benchmark.properties（弱算法配置）与 testcode 同在扫描范围，
# 从而跨文件解析 getProperty("hashAlg1")->MD5 这类间接弱哈希（真实全项目扫描本就如此）。
SCAN_ROOT = BENCH_DIR / "src" / "main"

# 扫描器 finding.type -> OWASP Benchmark 类别
_TYPE_TO_CATEGORY = {
    "sql injection": "sqli",
    "command injection": "cmdi",
    "path traversal": "pathtraver",
    "xss": "xss",
    "weak cryptography": "crypto",
    "weak hash": "hash",
    "weak randomness": "weakrand",
    "trust boundary violation": "trustbound",
    "ldap injection": "ldapi",
    "xpath injection": "xpathi",
    "insecure cookie": "securecookie",
}

# 所有 Benchmark 类别（用于报告排序与「未覆盖」提示）
_ALL_CATEGORIES = [
    "sqli", "cmdi", "pathtraver", "xss", "crypto", "hash",
    "weakrand", "trustbound", "ldapi", "xpathi", "securecookie",
]


def _norm_category(finding_type: str) -> str | None:
    return _TYPE_TO_CATEGORY.get((finding_type or "").strip().lower())


def load_ground_truth() -> list[tuple[str, str, bool]]:
    """读取 CSV -> [(test_name, category, is_real_vuln)]。"""
    rows: list[tuple[str, str, bool]] = []
    for line in CSV_PATH.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = [p.strip() for p in line.split(",")]
        if len(parts) < 3:
            continue
        name, category, real = parts[0], parts[1], parts[2].lower() == "true"
        rows.append((name, category, real))
    return rows


def scan_testcode(min_confidence: float, use_semgrep: bool) -> dict[str, set[str]]:
    """扫描 testcode 目录，返回 {测试文件名(不含扩展名): {检出的 Benchmark 类别}}。"""
    detected: dict[str, set[str]] = defaultdict(set)

    def _collect(scanner, *, honor_confidence: bool) -> None:
        for f in scanner.run(SCAN_ROOT):
            if honor_confidence:
                conf = (getattr(f, "extra", {}) or {}).get("confidence")
                if conf is not None and conf < min_confidence:
                    continue
            cat = _norm_category(f.type)
            if not cat:
                continue
            stem = Path(str(f.file)).stem  # BenchmarkTest00001.java -> BenchmarkTest00001
            detected[stem].add(cat)

    print(f"扫描 {SCAN_ROOT} ...")
    _collect(CustomRuleScanner(), honor_confidence=True)
    if use_semgrep:
        sg = SemgrepScanner()
        if sg.available():
            print("叠加 semgrep（可能较慢）...")
            _collect(sg, honor_confidence=False)  # semgrep 无置信度字段
        else:
            print("（semgrep 不可用，跳过）")
    return detected


def score(rows, detected) -> dict:
    """按 OWASP 口径逐类别统计 TP/FP/FN/TN + TPR/FPR/score。"""
    per_cat = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0, "tn": 0})
    for name, category, is_real in rows:
        hit = category in detected.get(name, set())
        c = per_cat[category]
        if is_real and hit:
            c["tp"] += 1
        elif is_real and not hit:
            c["fn"] += 1
        elif not is_real and hit:
            c["fp"] += 1
        else:
            c["tn"] += 1
    return dict(per_cat)


def _rates(c: dict) -> tuple[float, float, float, float]:
    tp, fp, fn, tn = c["tp"], c["fp"], c["fn"], c["tn"]
    tpr = tp / (tp + fn) if (tp + fn) else 0.0            # recall
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 1.0
    return tpr, fpr, precision, tpr - fpr


def print_report(per_cat: dict) -> None:
    print("\n" + "=" * 78)
    print("OWASP BenchmarkJava 评测结果（每类别）")
    print("=" * 78)
    hdr = f"{'category':13}{'TP':>5}{'FN':>5}{'FP':>5}{'TN':>5}{'Recall':>9}{'FPR':>8}{'Prec':>8}{'Score':>8}"
    print(hdr)
    print("-" * 78)
    tot = {"tp": 0, "fp": 0, "fn": 0, "tn": 0}
    for cat in _ALL_CATEGORIES:
        if cat not in per_cat:
            continue
        c = per_cat[cat]
        for k in tot:
            tot[k] += c[k]
        tpr, fpr, prec, sc = _rates(c)
        print(f"{cat:13}{c['tp']:>5}{c['fn']:>5}{c['fp']:>5}{c['tn']:>5}"
              f"{tpr:>9.2%}{fpr:>8.2%}{prec:>8.2%}{sc:>+8.2f}")
    print("-" * 78)
    tpr, fpr, prec, sc = _rates(tot)
    print(f"{'TOTAL':13}{tot['tp']:>5}{tot['fn']:>5}{tot['fp']:>5}{tot['tn']:>5}"
          f"{tpr:>9.2%}{fpr:>8.2%}{prec:>8.2%}{sc:>+8.2f}")
    print("=" * 78)
    print("说明：Score=Recall-FPR（OWASP Youden 指数）。Recall 是本次改进的主要目标；"
          "\n对抗性安全用例（bar=三元?常量:param 打断污点）会抬高 FPR，属已知固有上限。")


def main() -> int:
    ap = argparse.ArgumentParser(description="OWASP BenchmarkJava 真实评测")
    ap.add_argument("--semgrep", action="store_true", help="叠加 semgrep（慢）")
    ap.add_argument("--min-confidence", type=float, default=0.5,
                    help="custom 扫描器置信度阈值（默认 0.5）")
    args = ap.parse_args()

    if not CSV_PATH.exists() or not SCAN_ROOT.exists():
        print(f"未找到 OWASP BenchmarkJava 数据：\n  {CSV_PATH}\n  {SCAN_ROOT}\n"
              "该数据集在 data/（已 gitignore），请先放置后再评测。")
        return 0

    rows = load_ground_truth()
    print(f"ground truth 用例数：{len(rows)}")
    detected = scan_testcode(args.min_confidence, args.semgrep)
    per_cat = score(rows, detected)
    print_report(per_cat)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
