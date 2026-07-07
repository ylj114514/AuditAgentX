# backend/skills —— Agent Skills 与底层工具

Skill 定义 agent"用哪些 MCP 工具、按什么工作流、验收标准是什么"（借鉴 Claude Agent Skills 形态）。
本目录同时存放供 MCP server 调用的底层工具实现。

## 结构

| 路径 | 职责 |
|---|---|
| `loader.py` | 解析 `SKILL.md`（name/version/tools/workflow）供 agent 加载 |
| `harness_tools.py` | Fuzzing Harness 底层工具：`extract_function` / `build_template_harness` / `run_harness` |
| `vulnerability_verification/SKILL.md` | 静态+动态验证 Skill（8 工具）：read_code_context → sast_replay → verify_source_sink → build_evidence_chain →（可选）dynamic_http_verify / harness 工具 |
| `dynamic_exploitation/SKILL.md` | 动态利用 Skill：extract_function → 生成 Harness → 沙箱执行 → 自我修正 → 证据链 |
| `static_scanning/SKILL.md` | 静态扫描 Skill：编排 Semgrep/Gitleaks/custom 等扫描工具 |
| `exploit_generation/SKILL.md` | 利用生成 Skill：定位 → 生成利用代码/载荷 →（可选）harness 验证 |

## Agent × Skill × MCP 映射（每个该走 Skill 的 Agent 都已加载对应 Skill）

| Agent | 加载的 Skill | 是否经 MCP 工具 |
|---|---|---|
| VerifyAgent | vulnerability-verification | ✅ 经 `AuditMCPClient` 调 4~8 个 MCP 工具 |
| HarnessVerifier | dynamic-exploitation | ✅ 经 `AuditMCPServer` 调 extract_target_function / run_fuzzing_harness |
| StaticScanAgent | static-scanning | 声明式（直接调扫描器注册表） |
| ExploitAgent | exploit-generation | 声明式（LLM 生成，可选调 harness 工具验证） |

> VerifyAgent 的动态工具默认关闭；`run_acp` 从 ACP `context.options`（enable_dynamic/enable_harness/base_url）
> 激活后，`dynamic_http_verify` 等 MCP 工具才会真正调用。未配置 base_url 时裁决为 `not_executed`。

## harness_tools.py 关键能力

- `extract_function(code_root, file, line)`：从源码提取目标漏洞函数（多语言，尽力而为）。
- `build_template_harness(vuln_type, code_snippet)`：LLM 不可用时，按漏洞类型生成可运行的
  mock-based Harness（覆盖命令注入 / SQL 注入 / 路径遍历 / 反序列化 + 通用兜底）。
- `run_harness(harness_code)`：沙箱执行 Harness（Docker 优先，受控本地子进程回退），
  检测统一触发标记 `AUDITAGENTX_VULN_TRIGGERED`。

## Skill 文件格式（SKILL.md）

```markdown
name: skill-name
version: 1.0
tools:
- tool_a
- tool_b
workflow:
1. 第一步
2. 第二步
## Acceptance Criteria
- 验收标准...
```

`loader.load_skill("dynamic-exploitation")` 会解析出 `name / version / tools / workflow / body`。
