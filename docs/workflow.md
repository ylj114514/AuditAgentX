# 开发流程与进度对照（对应 md 规划文档第 10 节 & 课程时间表）

课程实验时间：**2026-07-06 ~ 2026-07-17**，7 月 17 日答辩。

| 阶段 | 建议时间 | 任务 | 产出 | 当前脚手架状态 |
|---|---|---|---|---|
| 1 需求分析与竞品调研 | 第 1 天 | 读题、调研 DeepAudit/AgentStalker 等 | `docs/comparison.md` | 待补充 |
| 2 系统架构设计 | 第 1-2 天 | 模块/多智能体/DB/API/前端原型 | `docs/architecture.md` `docs/api.md` | ✅ 已完成 |
| 3 后端基础框架 | 第 2-4 天 | FastAPI、DB 模型、任务调度、clone | `backend/main.py` `models/` `api/` | ✅ 已完成 |
| 4 仓库解析模块 | 第 3-5 天 | 语言/目录树/依赖/入口 | `backend/repository/` | ✅ 已完成 |
| 5 静态扫描集成 | 第 4-6 天 | Semgrep/Bandit/Gitleaks/Trivy + 统一格式 | `backend/scanners/` | ✅ 已完成（工具需自行安装 CLI） |
| 6 多智能体模块 | 第 5-8 天 | Orchestrator/Audit/Verify/Poc/Report | `backend/agents/` `prompts/` | ✅ 已完成（需配置 LLM key） |
| 7 漏洞验证与证据链 | 第 7-10 天 | Docker 沙箱、PoC 运行、证据采集 | `backend/verifier/` | ✅ 框架完成（沙箱默认关闭） |
| 8 前端页面 | 第 8-11 天 | 7 个页面 | `frontend/src/` | ✅ 骨架完成 |
| 9 测试 20 个开源项目 | 第 10-13 天 | 5 完整 + 15 静态 | `scripts/batch_scan.py` | ✅ 脚本完成，待跑数据 |
| 10 报告/PPT/视频 | 第 13-15 天 | Word 报告、PPT、演示视频 | `docs/experiment_report.md` | 模板待补充 |

## 下一步建议（MVP 优先）

1. 复制 `.env.example` 为 `.env`，填入 DeepSeek/Qwen 等 LLM key。
2. 安装静态工具 CLI：`pip install semgrep bandit`，Gitleaks/Trivy 按需装。
3. 本地起服务：`uvicorn backend.main:app --reload`，访问 `/docs` 手工验证链路。
4. 用 `examples/vulnerable_projects/demo_flask_app` 跑通全链路（离线也可）。
5. 逐步接入真实开源项目，运行 `scripts/batch_scan.py` 产出 20 项目统计表。
