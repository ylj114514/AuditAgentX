# backend/mcp —— MCP 工具服务

把静态扫描、验证与动态利用能力封装为 **MCP（Model Context Protocol）工具边界**，供
StaticScanAgent、VerifyAgent 及外部 agent（如 Claude Desktop）统一调用。这对应课件
"智能体能调用外部工具/执行脚本（MCP+Skills）"。

## 文件说明

| 文件 | 职责 |
|---|---|
| `audit_mcp_server.py` | `AuditMCPServer`：进程内 MCP 工具注册表，供后端运行时与测试使用 |
| `audit_mcp_client.py` | `AuditMCPClient`：按 Skill 定义的顺序调用 MCP 工具，供 StaticScanAgent / VerifyAgent 使用 |
| `stdio_server.py` | 可选 stdio 入口，安装官方 `mcp` SDK 后可把同一批工具通过标准 MCP 协议暴露 |

## 提供的 MCP 工具

| 工具 | 用途 |
|---|---|
| `read_code_context` | 读取候选漏洞附近的源码窗口（防幻觉核对） |
| `run_sast_replay` | 在本地代码窗口重放轻量 SAST 检查 |
| `verify_source_sink` | 确定性 source→sink 与误报检查 |
| `build_evidence_chain` | 从工具输出组装结构化证据链 |
| `extract_target_function` | 提取漏洞函数源码，供构建 Harness |
| `generate_fuzzing_harness` | 按漏洞类型生成 mock-based Fuzzing Harness（模板兜底） |
| `run_fuzzing_harness` | 在沙箱执行 Harness，返回是否触发漏洞 |
| `run_semgrep` | 执行 Semgrep SAST 扫描 |
| `run_bandit` | 执行 Bandit Python 安全扫描 |
| `run_gitleaks` | 执行 Gitleaks 密钥扫描 |
| `run_trivy` | 执行 Trivy 依赖/secret/IaC 扫描 |
| `run_custom_rules` | 执行 AuditAgentX 内置离线规则 |
| `check_static_tool_availability` | 预检静态扫描工具安装/可用性，不执行扫描 |

## 运行 stdio MCP server（可选）

```bash
pip install mcp            # 安装官方 MCP Python SDK
python -m backend.mcp.stdio_server
```

之后可在支持 MCP 的客户端（如 Claude Desktop）中挂载该 server，直接调用上述工具。
后端运行时与自动化测试默认使用进程内 `AuditMCPServer`，**不需要**安装可选的 `mcp` 依赖。

## Skill 与 MCP 的关系

Skill（`backend/skills/`）定义"用哪些 MCP 工具、按什么顺序、验收标准是什么"；
MCP server 提供工具的具体执行。StaticScanAgent 和 VerifyAgent 通过 `AuditMCPClient`
按 Skill 编排调用 MCP 工具。
