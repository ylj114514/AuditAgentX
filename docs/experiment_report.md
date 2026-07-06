# 《网络空间安全综合实验》实验报告（模板）

> 选题一：基于大模型智能体的开源项目安全缺陷自动审计和验证系统
> 项目名：AuditAgentX　小组：____　组长：____

按 md 规划文档第 13 节结构组织，以下为骨架，团队按实际填充。

## 1. 摘要

## 2. 目录

## 3. 小组成员分工与工作量占比

| 姓名 | 学号 | 角色 | 主要任务 | 工作量占比 |
|---|---|---|---|---|
| | | 组长/架构 | 总体设计、进度、答辩 | % |
| | | 后端 | FastAPI/DB/调度 | % |
| | | 智能体 | Prompt/Agent/LLM | % |
| | | 工具集成 | Semgrep/Gitleaks/PoC | % |
| | | 前端 | Dashboard/报告展示 | % |
| | | 测试与报告 | 20 项目测试、报告、PPT | % |

## 4. 课题背景与意义

（直接使用 md 第 1.2 实验背景：误报率高、缺乏证据链、结果不可复现等五大问题。）

## 5. 国内外相关系统调研

见 `docs/comparison.md`：DeepAudit / AgentStalker / OpenSecurity / ESAA-Security / Sandyaa。

## 6. 系统需求分析

## 7. 系统总体架构

见 `docs/architecture.md`。

## 8. 核心模块设计

- 8.1 仓库解析模块（`backend/repository/`）
- 8.2 静态扫描模块（`backend/scanners/`）
- 8.3 多智能体审计模块（`backend/agents/`）
- 8.4 漏洞验证模块（`backend/verifier/`）
- 8.5 报告生成模块（`backend/report/`）

## 9. 数据库与接口设计

见 `docs/api.md` 与 md 第 8 节数据库表设计（projects/scans/findings/evidence/reports）。

## 10. 关键技术实现

- LLM 统一调用与 JSON 容错解析（`backend/core/llm_client.py`）
- 双智能体交叉验证降低误报
- 证据链采集与可复现 trace 落盘

## 11. 实验环境

- OS / Python 版本 / 依赖版本
- LLM 模型（DeepSeek/Qwen/...）与参数
- 静态工具版本（Semgrep/Bandit/Gitleaks/Trivy）

## 12. 实验过程

## 13. 20 个开源项目测试结果

由 `scripts/batch_scan.py` 生成 `data/reports/batch_summary.json`，整理为下表：

| 序号 | 项目 | 语言 | 漏洞数 | Critical/High/Medium/Low | 是否动态验证 | 耗时 |
|---|---|---|---|---|---|---|

## 14. 典型漏洞案例分析

（挑 2-3 个高危漏洞，展示 source→sink→数据流→PoC→证据链全过程。）

## 15. 系统对比与创新点

见 `docs/comparison.md` 与 md 第 12 节五大创新点。

## 16. 问题与不足

## 17. 总结

## 18. 参考文献

## 19. 附录（关键代码、Prompt、扫描配置）
