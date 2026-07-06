"""批量扫描脚本 —— 对应 md 文档阶段 9「测试 20 个开源项目」。

用法：
    python scripts/batch_scan.py                # 使用内置 20 项目清单
    python scripts/batch_scan.py projects.json  # 使用自定义清单

策略（md 建议）：
    5 个项目做完整动态验证（enable_poc），15 个做静态扫描 + 报告统计。

注意：真实 clone 需网络与 git；离线可将 source_type 改为 local 指向本地副本。
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.database import init_db, SessionLocal  # noqa: E402
from backend.core import ids  # noqa: E402
from backend.models import Project, Scan, Finding  # noqa: E402
from backend.agents.orchestrator_agent import OrchestratorAgent  # noqa: E402

# md 文档阶段 9 推荐的 20 个测试项目
DEFAULT_TARGETS = [
    {"name": "DVWA", "url": "https://github.com/digininja/DVWA"},
    {"name": "WebGoat", "url": "https://github.com/WebGoat/WebGoat"},
    {"name": "Juice-Shop", "url": "https://github.com/juice-shop/juice-shop"},
    {"name": "NodeGoat", "url": "https://github.com/OWASP/NodeGoat"},
    {"name": "Damn-Vulnerable-DeFi", "url": "https://github.com/theredguild/damn-vulnerable-defi"},
    {"name": "vulnerable-flask-app", "url": "https://github.com/we45/Vulnerable-Flask-App"},
    {"name": "django.nV", "url": "https://github.com/nVisium/django.nV"},
    {"name": "maccms-v10", "url": "https://github.com/magicblack/maccms10"},
    {"name": "openvpn", "url": "https://github.com/OpenVPN/openvpn"},
    {"name": "Mutillidae", "url": "https://github.com/webpwnized/mutillidae"},
    # ... 其余 10 个可按需补充，或改为本地副本
]


def load_targets() -> list[dict]:
    if len(sys.argv) > 1:
        return json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    return DEFAULT_TARGETS


def main() -> None:
    init_db()
    targets = load_targets()
    db = SessionLocal()
    summary_rows = []

    for idx, t in enumerate(targets):
        # 前 5 个完整验证，其余仅静态
        full = idx < 5
        pid = ids.project_id()
        proj = Project(
            id=pid, name=t["name"],
            source_type=t.get("source_type", "git"),
            url=t.get("url"), local_path=t.get("local_path"),
            branch=t.get("branch", "main"), status="created",
        )
        db.add(proj)
        db.commit()

        sid = ids.scan_id()
        scan = Scan(
            id=sid, project_id=pid,
            scan_type="full" if full else "static", status="queued",
            config_json=json.dumps({
                "enabled_tools": ["semgrep", "gitleaks", "custom"],
                "enabled_agents": ["audit", "verify", "poc"] if full else ["audit", "verify"],
                "options": {"enable_poc": full, "enable_sandbox": False},
            }),
        )
        db.add(scan)
        db.commit()

        print(f"[{idx + 1}/{len(targets)}] 扫描 {t['name']} ({'完整' if full else '静态'}) ...")
        t0 = time.time()
        try:
            OrchestratorAgent(db, scan).run()
        except Exception as e:  # noqa: BLE001
            print(f"  失败: {e}")
        db.refresh(scan)
        n = db.query(Finding).filter(Finding.scan_id == sid).count()
        summary_rows.append({
            "name": t["name"], "scan_id": sid, "status": scan.status,
            "findings": n, "seconds": round(time.time() - t0, 1),
        })
        print(f"  状态={scan.status} 漏洞={n} 耗时={round(time.time() - t0, 1)}s")

    # 输出统计表
    out = Path("data/reports/batch_summary.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(summary_rows, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\n汇总已写入 {out}")
    db.close()


if __name__ == "__main__":
    main()
