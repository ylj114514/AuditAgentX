# AuditAgentX · 开源项目智能安全审计与验证系统

> LLM-Agent Based Open Source Security Audit and Verification Platform
>
> 2026 年春季学期《网络空间安全综合实验》—— 选题一
> 实验时间：2026-07-06 ~ 2026-07-17

本系统不是单纯调用大模型检查代码，而是采用：

```
静态工具扫描 + LLM 多智能体语义审计 + 独立验证智能体 + PoC 沙箱验证 + 结构化报告生成
```

形成**可审计、可验证、可复现**的安全缺陷审计系统。

---

## ✨ 核心特性

- **多源审计融合**：Semgrep / Bandit / Gitleaks / Trivy / 自定义正则规则 + LLM 语义审计
- **多智能体协作**：RepoParser → StaticScan → Audit → Verify →（PoC/Sandbox）→ Report
- **双智能体交叉验证**：AuditAgent 发现，VerifyAgent 独立复核，显著降低误报
- **可追溯证据链**：source → 传播路径 → sink → PoC → 运行时证据
- **可复现**：每次 prompt / 模型输出 / 参数自动落盘（`data/scans/<id>/agent_traces/`）
- **沙箱验证**：PoC 仅在断网的一次性 Docker 容器中运行，绝不攻击真实系统
- **多格式报告**：HTML / Markdown / PDF / JSON

---

## 📁 目录结构

```
AuditAgentX/
├── backend/          FastAPI 后端
│   ├── api/          REST 接口（对应规划文档第 7 节）
│   ├── agents/       7 个智能体 + 编排器
│   ├── scanners/     静态扫描工具封装 + 自定义规则 + 注册表
│   ├── repository/   clone / 语言识别 / 依赖 / 目录树
│   ├── verifier/     沙箱 / PoC 运行 / 证据采集 / 结果裁决
│   ├── report/       报告模板与导出
│   ├── models/       SQLAlchemy ORM（5 张表）
│   ├── prompts/      4 个智能体提示词
│   └── core/         LLM 客户端 / ID 生成
├── frontend/         Vue3 + Element Plus 前端骨架
├── scripts/          batch_scan.py 批量扫描 20 项目
├── rules/            自定义扫描规则
├── tests/            pytest 用例
├── docs/             架构 / API / 流程 / 竞品 / 实验报告
└── examples/         演示靶场与样例
```

---

## 🚀 快速开始

### 1. 安装依赖

```bash
cd AuditAgentX
pip install -r requirements.txt
# 可选：静态扫描工具 CLI
pip install semgrep bandit
# gitleaks / trivy 按需从官方安装
```

### 2. 配置

```bash
cp .env.example .env
# 编辑 .env，填入 LLM_API_KEY / LLM_BASE_URL / LLM_MODEL
```

> 不配置 LLM 也能运行：仅用静态扫描 + 自定义规则跑通链路（见下方离线演示）。

### 3. 启动后端

```bash
uvicorn backend.main:app --reload --port 8000
# 打开 http://localhost:8000/docs 查看交互式 API 文档
```

### 4. 启动前端（可选）

```bash
cd frontend
npm install
npm run dev          # http://localhost:5173
```

### 5. 离线端到端演示（无需 LLM / 外部工具）

```bash
python - <<'PY'
import json
from backend.database import init_db, SessionLocal
from backend.core import ids
from backend.models import Project, Scan, Finding
from backend.agents.orchestrator_agent import OrchestratorAgent
init_db(); db = SessionLocal()
p = Project(id=ids.project_id(), name="demo", source_type="local",
            local_path="examples/vulnerable_projects/demo_flask_app", status="created")
db.add(p); db.commit()
s = Scan(id=ids.scan_id(), project_id=p.id, scan_type="static", status="queued",
         config_json=json.dumps({"enabled_tools":["custom"],"enabled_agents":[],"options":{}}))
db.add(s); db.commit()
OrchestratorAgent(db, s).run()
for f in db.query(Finding).filter(Finding.scan_id==s.id):
    print(f.severity, f.type, f"{f.file_path}:{f.start_line}")
PY
```

### 6. 批量测试 20 个开源项目

```bash
python scripts/batch_scan.py          # 内置清单，前 5 完整验证 + 其余静态
# 结果统计写入 data/reports/batch_summary.json
```

---

## 🧪 测试

```bash
pytest tests/ -q
```

---

## ⚠️ 合规声明

PoC 自动利用**仅限本地授权靶场或授权项目**，禁止攻击真实第三方系统。
沙箱默认关闭，开启后在断网、限内存的一次性容器中运行。

---

## 📚 文档

- 系统架构：[docs/architecture.md](docs/architecture.md)
- API 文档：[docs/api.md](docs/api.md)
- 开发流程与进度：[docs/workflow.md](docs/workflow.md)
- 竞品对比：[docs/comparison.md](docs/comparison.md)
- 实验报告模板：[docs/experiment_report.md](docs/experiment_report.md)
