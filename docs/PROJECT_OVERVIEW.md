# AuditAgentX 项目真实说明文档

本文档是 AuditAgentX 当前集中式项目说明文档，按照当前仓库真实代码、目录和功能整理。它替代 `docs/` 目录下原先分散的架构、API、动态验证、Benchmark、环境、对比和实验报告草稿文档。

## 1. 项目定位

AuditAgentX 是一个面向课程实验、安全研究原型和本地授权靶场的代码安全审计平台。它把传统静态扫描工具、自定义轻量污点分析、LLM 多智能体审计、独立复核、RAG 安全知识库、动态 HTTP 验证、Fuzzing Harness 验证、证据链和报告生成串成一条可复现审计流程。

当前项目是 MVP/实验原型，不是生产级漏洞扫描服务。能力可准确概括为「**静态发现 + 静态复核 + 动态验证 + 有限的运行时异常发现**」：它**不是**能自动完整启动任意开源项目的系统，**也不是**面向公网目标的通用 DAST。所有动态验证、PoC、Harness 和沙箱能力都只应在本地靶场、Docker 沙箱或明确授权目标中使用。

## 2. 真实能力和边界

### 已实现能力

- 支持本地目录和 Git 仓库项目录入。
- 解析语言、依赖、目录树、框架和启动方式。
- 集成 Semgrep、Bandit、Gitleaks、Trivy，并始终追加 custom 扫描器兜底。
- 自定义扫描包含顺序/变量敏感轻量污点、Python AST 跨函数污点、Java `javalang` 顺序敏感函数级污点。
- 多 Agent 闭环：RepoParser、StaticScan、Audit、Verify、Exploit、DynamicAnalysis、Summary。报告生成与 RAG 修复建议已并入 SummaryAgent，历史上的独立 `report_agent` / `poc_agent` 已删除。
- ACP 统一 Agent 通信协议和 trace 文件。
- MCP 本地工具边界，给 VerifyAgent / DynamicAnalysisAgent 使用。
- RAG 知识库：CWE、OWASP、验证 playbook、误报信号、修复建议。
- HTTP 动态验证：对已运行授权目标发送 payload 并保存请求/响应证据；`httpx` 用 `trust_env=False` 绕开系统代理，目标经 `target_guard` 校验默认仅回环地址。
- 整项目 Docker 路径（**增强能力**）：尝试用 docker/compose 构建或启动被测项目容器，再对映射端口做 HTTP 动态验证；真实第三方项目「自动跑起来」是已知难题，起不来时回退到 Harness。
- 函数级真实源码 Harness（**主要回退路径**）：只读挂载项目源码、`import` 真实模块调用真实目标函数，用框架随机 nonce 独立判定调用与 sink 到达，区分 `target_confirmed` 与模板机理级 `mechanism_confirmed`；脚本自报字段一律不采信。
- 证据链：source、sink、call_path、payload、runtime、sandbox、harness、tool_calls、knowledge。
- Vue 前端：项目创建、扫描工作台、漏洞详情、动态验证、Agent 通信流、报告和统计。
- OWASP BenchmarkJava 分类评测脚本。

### 必须如实说明的限制

- `examples/vulnerable_projects/safe_sqli_target` 是安全 SQLi 模拟靶场，不执行真实 SQL。
- 模板 Harness 只证明漏洞机理，不能当作真实项目可利用复现。
- 只有 `target_confirmed` 才表示真实目标函数被调用，且攻击 payload 到达被 mock 的危险 sink。
- 单漏洞详情页的按需验证接口主要执行 ExploitAgent + HTTP DynamicVerifier，不额外生成新的 Harness 证据。
- OWASP BenchmarkJava 早期初步评测中，SQLi、命令注入、路径遍历等注入类已有一定能力，粗略召回约 39%；当前代码已加入 Java 函数级污点和弱算法/弱随机增强，最新结果应以 `scripts/run_owasp_benchmark.py` 在本地 BenchmarkJava 数据集上的实际输出为准。

## 3. 总体工作流

```text
项目创建
  -> RepoParserAgent 解析仓库
  -> StaticScanAgent 调用扫描器
  -> AuditAgent 做 LLM 语义审计
  -> VerifyAgent 独立复核和误报过滤
  -> ExploitAgent 生成本地授权 PoC / payload
  -> DynamicAnalysisAgent 调度 HTTP / Harness 动态验证
  -> EvidenceCollector 汇总证据链
  -> SummaryAgent 生成摘要和报告（含 RAG 修复建议，原 ReportAgent 职责已并入）
  -> 前端展示漏洞、证据、报告、统计、ACP 消息流
```

动态验证的网络关系需要理解清楚：

- HTTP 验证走 `httpx(trust_env=False)`，主动忽略 `HTTP_PROXY`/`HTTPS_PROXY` 等系统代理变量；`target_guard` 默认只放行 `localhost`/`127.0.0.1`/`::1`，需显式 `allow_external_dynamic_targets=True` 才能打其它目标。
- **Docker 容器里的 `127.0.0.1` 不是宿主机的 `127.0.0.1`**：容器内回环指向容器自身。宿主访问容器服务靠端口映射（如 `127.0.0.1:8080:8080`）打到宿主回环；容器互访靠 Compose 服务名和自定义网络，而非 `localhost`。
- Harness 沙箱 run 时叠加 `network=none`、`read_only`、`cap_drop=ALL`、`no-new-privileges`、pids/mem/cpu/timeout 限制，只读挂载 `/target` 源码，不挂 docker socket、不继承宿主代理。固定沙箱镜像由 `docker/harness/Dockerfile` 构建，经 `harness_sandbox_image` 配置启用。

## 4. 快速运行

### 后端

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn backend.main:app --reload --host 127.0.0.1 --port 8000
```

### 前端

```powershell
cd frontend
npm install
npm run dev
```

### 测试

```powershell
pytest
cd frontend
npm run build
```

### 安全 SQLi 模拟靶场

```powershell
docker compose up safe-sqli-target --build
```

默认靶场地址：`http://127.0.0.1:8080`。

## 5. 根目录文件

**文件夹总结：** 根目录承担项目入口、依赖声明、本地编排、Git/CI 配置和顶层文档职责。这里的文件不直接实现审计逻辑，但决定项目如何安装、启动、忽略本地敏感数据并在 GitHub 上执行自动化检查。

| 路径 | 功能 |
|---|---|
| `.env.example` | 环境变量示例，用于配置数据库、LLM、扫描工具、沙箱和并发参数。真实 `.env` 不应提交。 |
| `.github/workflows/ci.yml` | GitHub Actions CI 配置，用于自动化测试和质量检查。 |
| `.gitignore` | 忽略虚拟环境、依赖目录、构建产物、数据库、日志、缓存和密钥文件。 |
| `README.md` | 项目入口说明，是本文档的压缩总结版。 |
| `requirements.txt` | 后端依赖，包括 FastAPI、SQLAlchemy、Docker SDK、OpenAI 兼容 SDK、javalang、pytest 等。 |
| `docker-compose.yml` | 平台编排文件：`backend` + `frontend` 两个服务，data/reports 走目录挂载，默认不挂 docker socket；安全 SQLi 靶场、docker socket、PostgreSQL 为可选/注释/独立 profile。 |
| `.dockerignore` | 构建镜像时排除 reports/、data/scans/、临时 harness、docker 日志、`.pytest_cache`、`.env`、token、代理配置等，避免把运行数据和密钥打进镜像。 |
| `docker/harness/Dockerfile` | 固定预构建 Harness 沙箱镜像（预装常见 Python 框架），供函数级真实源码验证 `import` 项目真实模块；经 `harness_sandbox_image` 启用。 |

## 6. 后端目录 `backend/`

**文件夹总结：** `backend/` 是 AuditAgentX 的核心服务端，包含 FastAPI API、数据库模型、多智能体、扫描器、RAG、ACP、MCP、动态验证、Harness、报告生成和统计模块。所有项目扫描、漏洞验证、证据链构建和报告导出都由该目录下的代码完成。

| 文件 | 功能 |
|---|---|
| `backend/Dockerfile` | 后端容器镜像，安装常用静态扫描工具并启动 Uvicorn。 |
| `backend/__init__.py` | 后端 Python 包初始化。 |
| `backend/main.py` | FastAPI 应用入口，挂载所有 API 路由和健康检查。 |
| `backend/config.py` | 全局配置，读取环境变量控制数据库、LLM、沙箱、扫描器、Harness 和并发。 |
| `backend/database.py` | SQLAlchemy engine、Session 和数据库初始化。 |
| `backend/schemas.py` | Pydantic API 请求/响应模型。 |

### `backend/api/`

**文件夹总结：** `backend/api/` 是前端和外部调用方进入系统的 HTTP 边界。它不直接实现扫描算法，而是把项目、扫描、漏洞、报告、统计和 ACP 调试请求转换为数据库操作或 Agent/Verifier 调用。

| 文件 | 功能 |
|---|---|
| `__init__.py` | API 包初始化。 |
| `routes_projects.py` | 项目创建、列表、详情接口。 |
| `routes_scans.py` | 创建扫描、查询扫描状态、扫描结果、ACP 消息摘要；根据 quick/standard/deep 模式组装配置。 |
| `routes_findings.py` | 漏洞详情、单漏洞按需 HTTP 动态验证、证据链查询。 |
| `routes_reports.py` | 报告生成、报告数据组装和导出。 |
| `routes_analytics.py` | 漏洞统计、严重级分布、趋势和对标数据。 |
| `routes_agents.py` | 返回 Agent 名称和角色，供前端展示。 |
| `routes_acp.py` | ACP 调试接口，把消息路由到 Agent 的 `run_acp()`。 |

### `backend/models/`

**文件夹总结：** `backend/models/` 定义持久化数据结构，是项目运行状态、扫描记录、漏洞、证据和报告之间的关系模型。API、Orchestrator、ReportBuilder 和前端展示都依赖这些表。

| 文件 | 功能 |
|---|---|
| `__init__.py` | 聚合导出数据库模型。 |
| `project.py` | Project 表，保存项目来源、本地路径、Git URL 和状态。 |
| `scan.py` | Scan 表，保存扫描类型、配置、状态、时间和统计。 |
| `finding.py` | Finding 表，保存漏洞类型、严重级、文件位置、代码片段、置信度和状态。 |
| `evidence.py` | Evidence 表，保存 source/sink/data_flow、PoC、runtime、harness、日志等证据。 |
| `report.py` | Report 表，保存报告格式、路径、状态和关联扫描。 |

### `backend/core/`

**文件夹总结：** `backend/core/` 放置跨模块通用基础能力，包括统一 ID 生成和 LLM 客户端。它是 Agent 调用模型和数据库对象命名的一层公共基础设施。

| 文件 | 功能 |
|---|---|
| `__init__.py` | core 包初始化。 |
| `ids.py` | 统一生成 project、scan、finding、evidence、report 等 ID。 |
| `llm_client.py` | OpenAI 兼容 LLM 客户端，负责调用、重试、JSON 解析和错误兜底。 |

### `backend/repository/`

**文件夹总结：** `backend/repository/` 负责把用户输入的 Git 仓库或本地目录变成可分析的项目上下文，包括语言、依赖、文件树和代码文件集合。RepoParserAgent 主要调用这里的能力。

| 文件 | 功能 |
|---|---|
| `__init__.py` | repository 包初始化。 |
| `git_client.py` | Git clone / checkout 封装。 |
| `language_detector.py` | 遍历源码并识别语言、文件数量、代码行数。 |
| `file_tree_builder.py` | 构建项目文件树摘要。 |
| `dependency_parser.py` | 解析 requirements、package.json、pom.xml 等依赖文件。 |

### `backend/scanners/`

**文件夹总结：** `backend/scanners/` 是静态扫描层。它把外部 SAST 工具和自研污点规则统一成 RawFinding，并通过 registry 并行调度。该目录直接决定候选漏洞的覆盖面、召回率和初始误报水平。

| 文件 | 功能 |
|---|---|
| `README.md` | 扫描器模块说明，保留为源码目录开发上下文。 |
| `__init__.py` | scanners 包初始化。 |
| `base.py` | BaseScanner 和 RawFinding 统一输出结构。 |
| `registry.py` | 并行调度 Semgrep、Bandit、Gitleaks、Trivy、custom，保证 custom 始终执行并合并跨工具重复命中。 |
| `semgrep_runner.py` | 调用 Semgrep 并转换结果。 |
| `bandit_runner.py` | 调用 Bandit 扫描 Python 安全问题。 |
| `gitleaks_runner.py` | 调用 Gitleaks 检测密钥泄露。 |
| `trivy_runner.py` | 调用 Trivy 扫描依赖 CVE、secret 和 IaC/容器配置，并保证 secret 字段不进入结果。 |
| `custom_rules.py` | 自定义扫描器，做顺序/变量敏感污点、确定性配置规则、弱算法 properties 解析，并调用 Python/Java AST 分析。 |
| `taint_rules.py` | source、sink、sanitizer、注入标记、硬编码密钥、弱加密、弱随机等模式库。 |
| `interproc_taint.py` | Python AST 1-hop 跨函数污点分析。 |
| `java_taint.py` | Java `javalang` 方法内多跳污点分析，覆盖 SQLi、CMDi、路径遍历、XSS、Trust Boundary、LDAP、XPath。 |

### `backend/agents/`

**文件夹总结：** `backend/agents/` 是多智能体审计闭环。每个 Agent 负责一个审计阶段：解析、扫描、语义审计、验证、利用生成、动态分析、摘要和报告；OrchestratorAgent 负责把这些阶段串起来并落库。

| 文件 | 功能 |
|---|---|
| `README.md` | Agent 模块说明，保留为源码目录开发上下文。 |
| `__init__.py` | agents 包初始化。 |
| `base_agent.py` | Agent 基类，负责加载 prompt、调用 LLM、解析 JSON 和失败兜底。 |
| `repo_parser_agent.py` | 解析仓库语言、依赖、目录、框架和入口。 |
| `static_scan_agent.py` | 调用扫描器注册表并规范化候选漏洞。 |
| `audit_agent.py` | LLM 语义审计，补充传统工具可能漏报的风险。 |
| `verify_agent.py` | 独立复核候选漏洞，结合 MCP、RAG 和本地工具过滤误报。 |
| `verification_tools.py` | VerifyAgent 的本地工具：读上下文、SAST replay、source-sink 检查、placeholder secret 检查等。 |
| `exploit_agent.py` | 为已确认漏洞生成授权 PoC、payload、利用路径和验证方法；LLM 不可用时模板兜底。 |
| `dynamic_analysis_agent.py` | 动态分析调度，识别启动方式、提取 endpoints、选择 HTTP/Harness 策略。 |
| `summary_agent.py` | 生成项目风险摘要、关键风险和修复计划，并经 RAG 检索标准修复建议。 |
| `orchestrator_agent.py` | 总控调度，串联解析、扫描、审计、验证、利用、动态分析、证据链和报告落库。 |

### `backend/prompts/`

**文件夹总结：** `backend/prompts/` 存放 LLM Agent 的提示词，是模型行为约束层。它规定 Agent 输出格式、安全边界、验证逻辑和报告风格，避免模型自由发挥导致结构不稳定。

| 文件 | 功能 |
|---|---|
| `audit_agent_prompt.md` | AuditAgent 语义审计提示词。 |
| `verify_agent_prompt.md` | VerifyAgent 独立复核提示词。 |
| `exploit_agent_prompt.md` | ExploitAgent 本地授权利用生成提示词。 |
| `harness_agent_prompt.md` | Harness 生成提示词，要求 mock 危险 sink 并输出结构化结果。 |
| `summary_agent_prompt.md` | SummaryAgent 摘要提示词。 |

### `backend/acp/`

**文件夹总结：** `backend/acp/` 实现 AuditAgentX-ACP 统一 Agent 通信协议。它把不同 Agent 的输入输出标准化为 ACPMessage，使 trace、证据重建、前端通信流展示和未来跨进程 Agent 调度成为可能。

| 文件 | 功能 |
|---|---|
| `README.md` | ACP 协议说明，保留为协议开发上下文。 |
| `__init__.py` | acp 包初始化。 |
| `models.py` | ACPMessage、Header、Context、Status、Artifact、Finding、Verification、Exploit 等模型。 |
| `factory.py` | ACP 请求和回复构造工具。 |
| `dispatcher.py` | ACPDispatcher，把消息分发给对应 Agent。 |
| `adapters.py` | ACP finding 和 legacy dict 之间互转。 |
| `trace.py` | ACP trace 持久化和读取。 |

### `backend/mcp/`

**文件夹总结：** `backend/mcp/` 是本地工具调用边界。VerifyAgent 和动态验证流程通过这里调用读取代码、RAG 检索、source-sink 验证、动态 HTTP 验证和 Harness 执行等确定性工具。

| 文件 | 功能 |
|---|---|
| `README.md` | MCP 工具说明，保留为工具边界上下文。 |
| `__init__.py` | mcp 包初始化。 |
| `audit_mcp_server.py` | in-process MCP 工具注册表，提供 RAG、读代码、SAST replay、source-sink 验证、动态验证、Harness 和证据构建。 |
| `audit_mcp_client.py` | MCP 客户端封装。 |
| `stdio_server.py` | stdio MCP 服务入口。 |

### `backend/rag/`

**文件夹总结：** `backend/rag/` 是安全知识增强层。它提供 CWE/OWASP 分类、验证步骤、误报信号和修复建议，帮助 VerifyAgent 和报告从“发现问题”升级到“解释为什么成立、如何确认、如何修复”。

| 文件 | 功能 |
|---|---|
| `README.md` | RAG 模块说明，保留为知识库维护上下文。 |
| `__init__.py` | rag 包初始化。 |
| `models.py` | RAG 知识条目和检索结果模型。 |
| `retriever.py` | SecurityKnowledgeRetriever，检索 CWE、验证 playbook 和修复建议，并做候选匹配过滤。 |
| `sources/cwe_core.json` | 核心 CWE/OWASP 知识。 |
| `sources/verification_playbooks.json` | 验证步骤、动态策略和误报信号。 |
| `sources/remediation_guides.json` | 修复建议知识库。 |

### `backend/dynamic/`

**文件夹总结：** `backend/dynamic/` 负责动态验证前的准备工作：识别项目如何启动、提取 HTTP 入口、按漏洞类型选择验证策略、解析符号定义。它不直接发 payload，而是服务于 DynamicAnalysisAgent 和 ExploitPipeline。

| 文件 | 功能 |
|---|---|
| `README.md` | 动态分析模块说明，保留为开发上下文。 |
| `endpoint_extractor.py` | 从 Flask/FastAPI/Express/Spring 等源码提取 HTTP endpoints。 |
| `launch_detector.py` | 识别框架、启动命令、端口、health path、docker compose。 |
| `strategy.py` | 按漏洞类型决定 HTTP、Harness、Both 或 not_applicable。 |
| `symbol_resolver.py` | 跨文件符号解析，供调用链扩展和 MCP 使用。 |

### `backend/verifier/`

**文件夹总结：** `backend/verifier/` 是利用验证和证据链核心目录，包含 HTTP 动态验证、Docker 沙箱启动、PoC/Harness 执行、利用模板和 EvidenceCollector。它决定“漏洞是否可复现”和“复现证据如何保存”。

| 文件 | 功能 |
|---|---|
| `README.md` | verifier 模块说明，保留为开发上下文。 |
| `__init__.py` | verifier 包初始化。 |
| `exploit_templates.py` | 利用模板库，提供 payload、注入点和成功特征。 |
| `dynamic_verifier.py` | HTTP 动态验证器，遍历 endpoint、参数和 payload，判断可复现性。 |
| `app_runner.py` | LocalAppRunner 和 DockerAppRunner，启动靶场并返回 base_url。 |
| `docker_project_runner.py` | Deep 模式项目 Docker/compose 启动器，记录沙箱状态和日志。 |
| `harness_verifier.py` | 提取目标函数、生成/执行 Harness，并映射 `target_confirmed` / `mechanism_confirmed`。 |
| `pipeline.py` | ExploitPipeline，总装配利用生成、HTTP 动态验证、Harness 验证和证据链。 |
| `evidence_collector.py` | 合并静态、利用、runtime、sandbox、harness、RAG 和 ACP 工具证据。 |
| `sandbox_manager.py` | 一次性 Docker 沙箱脚本执行器，默认关闭且断网执行。 |
| `exploit_validator.py` | 利用结果校验辅助模块。 |

### `backend/skills/`

**文件夹总结：** `backend/skills/` 存放 Agent 技能说明和 Harness 底层工具。技能文件用于描述工作流和约束；`harness_tools.py` 则是真正执行函数提取、Harness 安全校验和沙箱运行的代码。

| 文件 | 功能 |
|---|---|
| `README.md` | 技能模块说明，保留为开发上下文。 |
| `__init__.py` | skills 包初始化。 |
| `loader.py` | 加载技能 Markdown，供 Agent 输出技能信息。 |
| `harness_tools.py` | Harness 底层工具：函数提取、模板 Harness、目标脚手架、安全校验、Docker/local 执行、verdict 解析。 |
| `static_scanning/SKILL.md` | 静态扫描技能。 |
| `vulnerability_verification/SKILL.md` | 漏洞验证技能。 |
| `exploit_generation/SKILL.md` | 利用生成技能。 |
| `dynamic_exploitation/SKILL.md` | 动态利用和 Harness 技能。 |

### `backend/report/`

**文件夹总结：** `backend/report/` 把数据库中的扫描结果、证据链、知识库建议和摘要转为用户可读报告。它是后端审计结果面向最终交付物的出口。

| 文件 | 功能 |
|---|---|
| `__init__.py` | report 包初始化。 |
| `report_builder.py` | Jinja2 报告构建器，输出 Markdown、HTML、JSON。 |
| `markdown_template.md` | Markdown 报告模板。 |
| `html_template.html` | HTML 报告模板。 |
| `pdf_exporter.py` | PDF 导出封装。 |

### `backend/analytics/`

**文件夹总结：** `backend/analytics/` 负责统计和能力对标，不参与漏洞检测本身。它给前端仪表盘和项目展示提供总览指标、趋势和同类系统比较信息。

| 文件 | 功能 |
|---|---|
| `__init__.py` | analytics 包初始化。 |
| `aggregate.py` | 聚合扫描、漏洞、严重级和趋势统计。 |
| `benchmark.py` | 定性对标数据，比较 AuditAgentX 与同类安全 Agent 系统。 |

## 7. 前端目录 `frontend/`

**文件夹总结：** `frontend/` 是 Vue 3 单页应用，负责把后端审计流程可视化。它不实现漏洞检测算法，而是提供项目创建、扫描状态、漏洞列表、证据链、动态验证、报告和统计分析的人机界面。

| 文件 | 功能 |
|---|---|
| `package.json` | 前端依赖和脚本，使用 Vue 3、Vue Router、Axios、Element Plus、Vite、TypeScript。 |
| `package-lock.json` | npm 锁文件。 |
| `index.html` | Vite HTML 入口。 |
| `vite.config.ts` | Vite 配置。 |
| `tsconfig.json` | TypeScript 配置。 |
| `src/main.ts` | 创建 Vue 应用，安装 Router 和 Element Plus。 |
| `src/App.vue` | 根组件和整体布局。 |
| `src/api/index.ts` | 主要 API 客户端。 |
| `src/api/history.ts` | 历史记录 API 客户端。 |
| `src/pages/HomeView.vue` | 首页和最近扫描概览。 |
| `src/pages/ProjectCreate.vue` | 项目创建、扫描模式和 Deep 动态验证配置。 |
| `src/pages/ScanDashboard.vue` | 扫描工作台，展示漏洞、动态分析、利用代码、Agent 通信流和轮询状态。 |
| `src/pages/FindingDetail.vue` | 漏洞详情，展示证据链、动态验证、Harness、PoC、Agent/MCP 调用。 |
| `src/pages/ReportView.vue` | 报告生成和查看。 |
| `src/pages/HistoryView.vue` | 历史项目和扫描记录。 |
| `src/pages/AnalyticsView.vue` | 统计分析和能力对标。 |

## 8. 规则目录 `rules/`

**文件夹总结：** `rules/` 存放外部规则引擎可读取的规则文件。当前主要是 Semgrep 示例规则和保留目录，未来可扩展更多自定义 Semgrep/YARA 规则。

| 文件 | 功能 |
|---|---|
| `rules/custom/python_dangerous.yml` | 自定义 Semgrep 示例规则，覆盖 Python os.system、pickle.loads、SQL 字符串拼接。 |
| `rules/semgrep/.gitkeep` | 保留 Semgrep 规则目录。 |
| `rules/semgrep/taint_injection.yaml` | Semgrep taint 规则示例。 |
| `rules/yara/.gitkeep` | 保留 YARA 规则目录。 |

## 9. 脚本目录 `scripts/`

**文件夹总结：** `scripts/` 提供离线批处理和评测工具，适合做批量扫描、知识库生成和 OWASP BenchmarkJava 回归评测。它们不是线上 API 的必经路径，但对实验数据和迭代优化很关键。

| 文件 | 功能 |
|---|---|
| `batch_scan.py` | 批量扫描脚本。 |
| `gen_kb.py` | 生成或整理 RAG 知识库数据。 |
| `run_benchmark.py` | 通用 Benchmark/对标脚本。 |
| `run_owasp_benchmark.py` | OWASP BenchmarkJava 分类评测脚本，输出 TP/FP/FN/TN、Recall、FPR、Precision、Score。 |

## 10. 示例目录 `examples/`

**文件夹总结：** `examples/` 存放本地演示材料和安全靶场。它用于验证扫描链路、动态验证链路和报告展示，不代表真实生产系统。

| 文件 | 功能 |
|---|---|
| `sample_pocs/.gitkeep` | 保留示例 PoC 目录。 |
| `sample_reports/.gitkeep` | 保留示例报告目录。 |
| `vulnerable_projects/demo_flask_app/app.py` | Flask 演示漏洞项目，包含 SQLi、命令注入、路径遍历、硬编码密钥等。 |
| `vulnerable_projects/demo_flask_app/requirements.txt` | demo Flask 应用依赖。 |
| `vulnerable_projects/safe_sqli_target/Dockerfile` | 安全 SQLi 模拟靶场镜像。 |
| `vulnerable_projects/safe_sqli_target/server.py` | 安全 SQLi 模拟服务，不执行真实 SQL，只返回模拟响应。 |

## 11. 数据目录 `data/`

**文件夹总结：** `data/` 是运行时数据根目录，保存项目缓存、报告、沙箱和扫描中间产物。Git 中只保留 `.gitkeep`，真实数据库、日志和报告属于本地生成物。

| 文件 | 功能 |
|---|---|
| `data/projects/.gitkeep` | 保留项目缓存目录。 |
| `data/reports/.gitkeep` | 保留报告输出目录。 |
| `data/sandbox/.gitkeep` | 保留沙箱临时目录。 |
| `data/scans/.gitkeep` | 保留扫描中间结果目录。 |

本地生成的 SQLite 数据库、日志、HTML/JSON/Markdown 报告不属于核心源码。

## 12. 测试目录 `tests/`

**文件夹总结：** `tests/` 是项目质量保证目录，覆盖 API、Agent、ACP、RAG、扫描器、污点分析、动态验证、Harness、Docker Deep 模式和报告摘要等核心能力。测试中部分 HTTP/Docker/LLM 使用 fake 或 monkeypatch，是为了稳定验证业务语义，不代表线上逻辑是模拟实现。

| 文件 | 功能 |
|---|---|
| `conftest.py` | Pytest 共享 fixture 和测试环境。 |
| `test_repo_parser.py` | 仓库解析测试。 |
| `test_static_scan.py` | 静态扫描测试。 |
| `test_taint_analysis.py` | 自定义污点、Java/Python 规则和误报降低测试。 |
| `test_call_chain.py` | 调用链和 source→sink 路径测试。 |
| `test_verifier.py` | VerifyAgent 和本地验证工具测试。 |
| `test_verify_parallel.py` | Verify 并发测试。 |
| `test_agent_audit_module.py` | Agent 模块和兜底逻辑测试。 |
| `test_llm_retry.py` | LLM 重试和 JSON 解析测试。 |
| `test_exploit.py` | ExploitAgent 和利用模板测试。 |
| `test_dynamic_verify.py` | DynamicVerifier 状态语义测试。 |
| `test_dynamic_analysis_agent.py` | DynamicAnalysisAgent 计划和策略测试。 |
| `test_harness.py` | Harness 工具、安全策略和 verdict 测试。 |
| `test_docker_deep_mode.py` | Docker Deep 模式、compose 和失败路径测试。 |
| `test_api.py` | FastAPI 接口测试。 |
| `test_analytics.py` | 统计聚合测试。 |
| `test_summary_agent.py` | SummaryAgent 测试。 |
| `test_benchmark.py` | 对标数据结构测试。 |
| `test_rag_retriever.py` | RAG 检索测试。 |
| `test_rag_agent_integration.py` | RAG 与 Agent 集成测试。 |
| `test_acp_models.py` | ACP 模型测试。 |
| `test_acp_adapters.py` | ACP/legacy 适配测试。 |
| `test_acp_dispatch.py` | ACPDispatcher 测试。 |
| `test_acp_agent_flow.py` | ACP Agent 流程和证据链测试。 |
| `test_acp_model_grounding.py` | ACP 消息与 Agent 输出字段对齐测试。 |

## 13. 文档目录 `docs/`

**文件夹总结：** `docs/` 以本集中式说明文档为主，配合 Docker/动态验证专项指南，避免多份旧文档内容冲突。项目级说明、文件索引、能力边界和后续方向都集中维护在本文件。

| 文件 | 功能 |
|---|---|
| `PROJECT_OVERVIEW.md` | 集中式项目说明文档，即本文档。 |
| `DOCKER_DYNAMIC_TESTING_GUIDE.md` | Docker、Deep 模式、真实靶场、动态验证与故障诊断指南。 |
| `DEEPAUDIT_UPGRADE_PROMPT.md` | DeepAudit 式 Harness/动态验证升级的设计与提示词说明。 |

## 14. 安全设计

- LLM Harness 默认 Docker-first，Docker 不可用时返回 `sandbox_failed`，不会偷偷本地执行 LLM 代码。
- 模板 Harness 是可信内置 mock 代码，可本地运行，但只产生 `mechanism_confirmed`。
- Harness 安全策略阻止真实网络、文件删除、反射逃逸、ctypes、multiprocessing 等危险行为。
- PoC 沙箱默认关闭，启用后断网执行。
- DynamicVerifier 只对用户配置的本地或授权 base_url 发包，且 `httpx(trust_env=False)` 不走系统代理。
- Harness 沙箱镜像只提供解释器与依赖，隔离由执行器在 run 时叠加（network=none、read_only、cap_drop=ALL、no-new-privileges、资源与超时限制、只读挂载源码、不挂 docker socket、不继承宿主代理）。
- **平台部署（docker-compose）安全边界**：业务镜像默认不挂宿主 docker socket、不继承宿主敏感环境变量/代理；data/reports 走目录/命名 volume 挂载，不打进镜像；`.dockerignore` 排除 reports/、data/scans/、临时 harness、`.env`、token、代理配置等。仅当需要 Deep 模式整项目容器执行时，才用注释掉的 `project-executor` profile 显式挂载 docker socket（等同宿主 root，风险自负）。
- `.env` 不应提交，不应输出到报告、日志或镜像。

## 15. OWASP BenchmarkJava 现状和后续方向

项目已提供 `scripts/run_owasp_benchmark.py`。早期初步评测说明：注入类漏洞已有一定检测能力，但 Java Web 特有类别仍是短板；当前代码已加入 Java 函数级污点、弱加密、弱哈希、弱随机等增强。后续应继续优先增强：

1. Java Web source/sink/sanitizer 模型。
2. XSS 输出 sink 和 HTML/JS 编码识别。
3. 弱加密、弱哈希、弱随机规则。
4. Trust Boundary Violation 污点传播。
5. Benchmark 分类回归，把每次规则修改与 TP/FP/FN 指标绑定。
