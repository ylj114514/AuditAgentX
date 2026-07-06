# AuditAgentX 系统架构

## 1. 总体数据流

```
用户输入 GitHub/GitLab URL 或本地目录
        │
        ▼
[RepoParserAgent] 仓库解析：语言 / 框架 / 依赖 / 目录树 / 入口点
        │
        ▼
[StaticScanAgent] 静态工具扫描：Semgrep / Bandit / Gitleaks / Trivy / 自定义规则
        │
        ▼
[AuditAgent] LLM 语义审计：结合扫描结果与代码片段，发现工具漏报
        │
        ▼
[VerifyAgent] 独立交叉验证：判定真伪、降低误报
        │
        ▼
[ExploitAgent] 漏洞自动利用：生成利用代码 / 触发位置 / 利用路径 / 验证方法
        │
        ▼
[DynamicVerifier + Sandbox] 动态验证：发送载荷 → 采集运行时证据 → 判定可复现
        │
        ▼
[结果裁决] 去重 / 风险评级 / 误报过滤（verifier/exploit_validator.py）
        │
        ▼
[ReportAgent + report_builder] 生成 HTML / Markdown / PDF / JSON 报告
```

以上由 `OrchestratorAgent`（总控调度）串联，运行在 FastAPI 后台任务中，
通过更新 `scans / findings / evidence` 三张表实时反映进度。

## 2. 分层设计

| 层 | 目录 | 职责 |
|---|---|---|
| API 层 | `backend/api/` | FastAPI 路由，对应 md 第 7 节接口 |
| 智能体层 | `backend/agents/` | 7 个智能体 + 编排器 |
| 扫描层 | `backend/scanners/` | 外部工具封装 + 自定义规则 + 注册表 |
| 仓库层 | `backend/repository/` | clone / 语言识别 / 依赖 / 目录树 |
| 验证层 | `backend/verifier/` | 沙箱 / PoC / **漏洞利用 / 动态验证** / 证据采集 / 裁决（详见 `docs/dynamic_exploitation.md`） |
| 报告层 | `backend/report/` | 模板渲染 + 导出 |
| 模型层 | `backend/models/` | SQLAlchemy ORM（5 张表） |
| 核心 | `backend/core/` | LLM 客户端 / ID 生成 |

## 3. 核心卖点（对应 md 第 12 节创新点）

1. **多源审计融合**：SAST 工具 + 自定义规则 + LLM 语义 + 动态 PoC。
2. **双智能体交叉验证**：AuditAgent 发现，VerifyAgent 独立复核，降低误报。
3. **证据链可追溯**：source → propagation path → sink → PoC → runtime evidence。
4. **结果可复现**：`agents/base_agent.py` 落盘每次 prompt / 模型输出 / 参数。
5. **沙箱验证**：PoC 仅在断网的一次性 Docker 容器中运行，绝不攻击真实系统。
