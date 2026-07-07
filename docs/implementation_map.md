# 功能实现映射

本文档用于说明课程选题一四个核心功能在 AuditAgentX 中的对应文件结构。

## 0. AuditAgentX-ACP 统一 Agent 通信协议（v2.0 新增）

按北邮 ACP（Agent Communication Protocol）通信协议字段思想，统一项目内所有 Agent 间的字段接口。

```text
backend/acp/models.py       # ACPMessage 数据模型：header/context/payload/tools/artifacts/status
backend/acp/factory.py      # 便捷消息构造器：make_message() / make_reply()，自动填充 ID 和时间戳
backend/acp/adapters.py     # legacy dict ↔ ACPMessage 互转，RawFinding / AuditFinding → 统一 ACPFinding
backend/acp/trace.py        # ACPTracer：消息落盘到 data/scans/{scan_id}/agent_messages/，可回放
backend/acp/README.md       # 协议规范、字段说明、verdict 语义（重点区分 not_executed vs not_reproduced）
```

关键设计：
- ACPMessage 四主节：header（路由元信息）/ context（任务元信息）/ payload（业务数据）/ status（执行结果）
- ACPVerdict 严格区分：`not_executed`（未曾尝试，如未配置 base_url）vs `not_reproduced`（执行了但未命中）
- 统一 finding 字段：`{finding_id, type, severity, location{file,start_line,end_line}, code{snippet}, source{agent,tool,rule_id}, description, extra{}}`
- ACP 接口：`VerifyAgent.run_acp()` / `ExploitAgent.run_acp()` / `ReportAgent.run_acp()`（保留原 `run()` 向后兼容）
- `EvidenceCollector.build_from_acp(messages)`：从 ACP 消息列表重建证据链

**模型落地（v2.1）**：`ACPVerification` / `ACPExploit` 不再是"定义了没人用"——
`VerifyAgent.run_acp` / `ExploitAgent.run_acp` 现在用这两个 Pydantic 模型**实例化**再 `model_dump()`，
获得字段校验与统一默认值；测试断言输出可被 `model_validate()` 反校验通过。

**Agent × Skill × MCP 统一（v2.1）**：每个该走 Skill 的 Agent 都加载了对应 Skill——
VerifyAgent→vulnerability-verification、HarnessVerifier→dynamic-exploitation（消灭孤儿 Skill，
且经 MCP 调 extract_target_function / run_fuzzing_harness）、StaticScanAgent→static-scanning、
ExploitAgent→exploit-generation。VerifyAgent 动态工具由 `run_acp` 从 ACP `context.options` 激活。

```text
tests/test_acp_models.py         # ACPMessage 结构完整性测试
tests/test_acp_adapters.py       # finding 字段转换测试
tests/test_acp_agent_flow.py     # Agent ACP 接口 + 动态裁决语义 + Trace 记录
tests/test_acp_model_grounding.py # ACPVerification/ACPExploit 落地 + Agent×Skill×MCP 统一（5 项）
```

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
                                        # v2.0 新增：每阶段生成 ACPMessage 并由 ACPTracer 持久化
backend/agents/static_scan_agent.py     # 扫描智能体，调用 scanners 工具注册表
backend/agents/audit_agent.py           # LLM 语义审计智能体
backend/agents/verify_agent.py          # MCP+Skill 独立验证智能体，复核并过滤误报
                                        # v2.0 新增：run_acp() ACP 协议接口
backend/agents/exploit_agent.py         # 漏洞利用智能体（v2.0 新增：run_acp()）
backend/agents/report_agent.py          # 报告智能体（v2.0 新增：run_acp()）
backend/mcp/audit_mcp_server.py         # 验证工具 MCP Server（v2.0：9 个工具）
                                        #   原有 7 个 + 新增 dynamic_http_verify / build_final_evidence
backend/mcp/audit_mcp_client.py         # MCP Client：按 Skill v2.0 工作流调度工具
                                        #   新增 enable_dynamic / enable_harness 参数
backend/mcp/stdio_server.py             # stdio MCP 入口（v2.0 新增 2 个工具的暴露）
backend/skills/vulnerability_verification/SKILL.md # 漏洞复核 Skill v2.0
                                        #   新增工具：dynamic_http_verify / extract_target_function
                                        #   generate_fuzzing_harness / run_fuzzing_harness
                                        #   工作流明确区分 not_executed vs not_reproduced 语义
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
                                            # v2.0 新增：run_acp() 输出 exploit.generate.result
backend/verifier/exploit_templates.py       # 常见漏洞安全载荷模板
backend/verifier/dynamic_verifier.py        # 本地授权靶场动态验证与运行时证据采集
                                            # MCP dynamic_http_verify 工具复用此模块
backend/verifier/pipeline.py                # ExploitAgent + DynamicVerifier 流水线
backend/verifier/evidence_collector.py      # source -> sink -> exploit -> runtime 证据链组装
                                            # v2.0 新增：build_from_acp() 从 ACP 消息重建证据链
backend/api/routes_findings.py              # 单条漏洞按需验证和证据链查询接口
examples/vulnerable_projects/               # 本地安全演示靶场
```

动态验证裁决语义（v2.0 严格区分）：
- `not_executed`：未曾尝试执行动态验证（base_url 未配置）
- `not_reproduced`：执行了但所有载荷均未命中成功特征
- `dynamic_confirmed`：执行成功且命中特征

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
