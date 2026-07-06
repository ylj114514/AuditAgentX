# 功能实现映射

本文档用于说明课程选题一四个核心功能在 AuditAgentX 中的对应文件结构。

## 1. 代码仓库解析模块

要求：支持 GitHub/GitLab URL 或本地目录，识别语言，提取项目结构、依赖和元信息。

对应文件：

```text
backend/api/routes_projects.py          # 创建项目、解析项目、获取目录树接口
backend/repository/git_client.py        # Git URL clone 与本地目录工作区准备
backend/repository/language_detector.py # 编程语言和代码行数识别
backend/repository/dependency_parser.py # 依赖文件与框架识别
backend/repository/file_tree_builder.py # 文件结构和入口点提取
backend/agents/repo_parser_agent.py     # 仓库解析智能体封装
```

主要接口：

```text
POST /api/projects
POST /api/projects/{project_id}/parse
GET  /api/projects/{project_id}/tree
```

## 2. 智能体审计模块

要求：构建多个协作智能体，扫描智能体识别 SQL 注入、命令注入、路径遍历、硬编码密钥等风险，验证智能体独立复核并过滤误报，具备工具调用能力。

对应文件：

```text
backend/agents/orchestrator_agent.py    # 总控编排 RepoParser -> StaticScan -> Audit -> Verify -> Exploit -> Report
backend/agents/static_scan_agent.py     # 扫描智能体，调用 scanners 工具注册表
backend/agents/audit_agent.py           # LLM 语义审计智能体
backend/agents/verify_agent.py          # MCP+Skill 独立验证智能体，复核并过滤误报
backend/mcp/audit_mcp_server.py         # 验证工具 MCP Server：源码上下文、SAST replay、source/sink 复核、证据链
backend/mcp/audit_mcp_client.py         # MCP Client：按 Skill 工作流调度 MCP tools
backend/mcp/stdio_server.py             # 可选标准 stdio MCP 入口，安装官方 mcp SDK 后可运行
backend/skills/vulnerability_verification/SKILL.md # 漏洞复核 Skill，声明工具和执行流程
backend/skills/loader.py                # Skill 加载器
backend/scanners/registry.py            # 工具调用注册表
backend/scanners/semgrep_runner.py      # Semgrep SAST 调用
backend/scanners/bandit_runner.py       # Bandit 调用
backend/scanners/gitleaks_runner.py     # Gitleaks 调用
backend/scanners/trivy_runner.py        # Trivy 调用
backend/scanners/custom_rules.py        # 内置规则，覆盖 SQL 注入、命令注入、路径遍历、硬编码密钥等
backend/prompts/audit_agent_prompt.md   # 审计智能体提示词
backend/prompts/verify_agent_prompt.md  # 验证智能体提示词
```

## 3. 漏洞自动利用模块

要求：对验证存在的漏洞生成利用代码，输出包含文件位置、调用路径、验证结果的证据链。

对应文件：

```text
backend/agents/exploit_agent.py             # 漏洞利用智能体，LLM + 模板兜底
backend/verifier/exploit_templates.py       # 常见漏洞安全载荷模板
backend/verifier/dynamic_verifier.py        # 本地授权靶场动态验证与运行时证据采集
backend/verifier/pipeline.py                # ExploitAgent + DynamicVerifier 流水线
backend/verifier/evidence_collector.py      # source -> sink -> exploit -> runtime 证据链组装
backend/api/routes_findings.py              # 单条漏洞按需验证和证据链查询接口
examples/vulnerable_projects/               # 本地安全演示靶场
```

主要接口：

```text
POST /api/findings/{finding_id}/verify
GET  /api/findings/{finding_id}/evidence
```

## 4. 报告生成模块

要求：自动生成结构化报告，包含漏洞列表、严重等级、证据链、修复建议。

对应文件：

```text
backend/api/routes_reports.py          # 报告生成和下载接口
backend/report/report_builder.py       # Markdown / HTML / JSON / PDF 渲染
backend/report/markdown_template.md    # Markdown 报告模板，包含证据链展示
backend/report/html_template.html      # HTML 报告模板，包含证据链展示
backend/agents/report_agent.py         # LLM 报告摘要智能体
backend/prompts/report_agent_prompt.md # 报告智能体提示词
```

主要接口：

```text
POST /api/reports
GET  /api/reports/{report_id}/download
```
