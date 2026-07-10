# backend/agents —— 多智能体与工作流

课件模块②「智能体审计」的落地。多个智能体由 `OrchestratorAgent` 顺序编排，形成
「扫描 → 分析 → 去误报 → 验证 → 利用」的连续工作流。

## 智能体清单

| 智能体 | 文件 | 职责 |
|---|---|---|
| **OrchestratorAgent** | `orchestrator_agent.py` | 总控调度，串联完整链路并落库进度 |
| **RepoParserAgent** | `repo_parser_agent.py` | 仓库解析：语言/框架/依赖/入口/目录树 |
| **ScannerAgent** (StaticScanAgent) | `static_scan_agent.py` | 静态扫描：Semgrep/Gitleaks/自定义规则等工具调用，产出候选漏洞 |
| **AnalysisAgent** (AuditAgent) | `audit_agent.py` | LLM 语义审计，补充工具漏报；**Vulnhuntr 式跨文件调用链补全**（`_expand_call_chain` 递归解析被引用符号，拼出用户输入→sink 完整路径，发现跨文件逻辑漏洞） |
| **VerifyAgent** | `verify_agent.py` | 独立复核：经 MCP+Skill 调本地工具核对，去误报（防幻觉） |
| **ExploitAgent** | `exploit_agent.py` | 生成漏洞利用代码、触发位置、利用路径、验证方法 |
| **DynamicAnalysisAgent** | `dynamic_analysis_agent.py` | 动态验证调度：识别启动方式 + 提取端点 + 策略映射，委托 HTTP/Harness 验证器执行（`plan()` 可单独展示决策；`run()` 委托 ExploitPipeline） |
| **HarnessVerifier** | `../verifier/harness_verifier.py` | DeepAudit 式 Fuzzing Harness 动态验证 |
| **SummaryAgent** | `summary_agent.py` | 结构化报告与执行摘要，并经 RAG 检索标准修复建议（`_retrieve_remediation()`） |
| `verification_tools.py` | — | VerifyAgent 的本地工具实现（读码上下文、启发式复核、SAST 重放） |

## 工作流（对应用户设计的四段式）

```
①ScannerAgent 静态扫描  ──►  ②AnalysisAgent 语义分析(找工具漏报)
        │                                   │
        └───────────────┬───────────────────┘
                        ▼
        ③去误报：Orchestrator 去重/裁决 + VerifyAgent 独立复核(防幻觉)
                        ▼
        ④VerifyAgent + HarnessVerifier 动态验证(再去误报) + ExploitAgent 生成利用代码
                        ▼
                  证据链落库 → 报告
```

- **③去误报**：借鉴 DeepAudit —— VerifyAgent 强制经 MCP 工具 `read_code_context` 核对文件/代码
  真实存在，若参数化查询/安全 API/占位符等被检出则判 false_positive（覆盖 LLM 输出）。
- **④再去误报**：HarnessVerifier 生成 Fuzzing Harness 真跑，只有触发才判 `dynamic_confirmed`，
  把"看起来像漏洞"降级为"动态证明可利用"。

## 关键设计

- **可复现**：`base_agent.py` 落盘每次 prompt / 模型输出 / 参数到 `data/scans/<id>/agent_traces/`。
- **离线兜底**：Analysis/Verify/Exploit/Harness 在 LLM 不可用时均有规则或模板兜底，全链路离线可跑。

项目级 Agent 流程、动态验证与能力边界说明已集中到根目录 `docs/PROJECT_OVERVIEW.md`；验证层细节见 `../verifier/README.md`。
