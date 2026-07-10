# AuditAgentX-ACP 通信协议规范

AuditAgentX-ACP 是本项目多 Agent 通信的统一消息协议，按北邮 ACP（Agent Communication Protocol）字段思想设计。所有 Agent 间的请求/响应均使用 ACPMessage 结构，确保字段接口一致、可追踪、可重建证据链。

## ACP 的三层应用（不止是"消息格式定义"）

1. **统一消息模型**（`models.py`）：header/context/payload/tools/artifacts/status 统一结构。
2. **通信链追踪与可视化**（`trace.py` + 编排器）：每个审计阶段生成一条 ACP 消息并落盘到
   `data/scans/{scan_id}/agent_messages/`，前端「Agent 通信流」页面回放展示。
3. **消息驱动通信 + 跨系统协作**（`dispatcher.py` + `api/routes_acp.py`）：
   ACPDispatcher 按 `message_type` 把请求消息路由到对应 Agent 的 `run_acp()`，返回回复消息；
   并经 `POST /api/acp/message` 对外暴露——**外部系统的 Agent 可用标准 ACP 消息驱动本系统的
   verify / exploit / report**，实现跨系统 Agent 协作（配合 MCP 工具通道，本系统对外同时提供
   「MCP 工具」与「ACP 消息」两种标准协作接口）。

### 对外通信端点

| 端点 | 说明 |
|---|---|
| `GET /api/acp/message-types` | 能力发现：列出本系统可受理的 ACP 请求消息类型 |
| `POST /api/acp/message` | 接收一条 ACPMessage → 分发 → 返回回复 ACPMessage；带 task_id 时往返消息记入该 scan 通信流 |

外部 Agent 发 `verify.request` / `exploit.generate.request` / `report.request`，
本系统返回对应 `*.result` 回复消息（`in_reply_to` 关联原消息，可追溯）。

## 消息结构

```
ACPMessage
├── header: ACPHeader          消息元信息
│   ├── protocol: "AuditAgentX-ACP"
│   ├── version: "1.0"
│   ├── message_id: str        自动生成 UUID
│   ├── conversation_id: str   会话 ID（多消息共享）
│   ├── task_id: str           通常为 scan_id
│   ├── sender: str            发送方 Agent 名称
│   ├── receiver: str          接收方 Agent 名称
│   ├── message_type: str      消息类型（见下方枚举）
│   ├── intent: str            人类可读意图
│   ├── timestamp: str         ISO 8601 UTC
│   ├── trace_id: str          跨消息追踪 ID
│   └── in_reply_to: str|None  被回复消息的 message_id
│
├── context: ACPContext        任务级元信息（所有消息共享）
│   ├── project_id: str
│   ├── scan_id: str
│   ├── code_root: str|None
│   ├── enabled_tools: list[str]
│   ├── enabled_agents: list[str]
│   └── options: dict
│
├── payload: dict              业务数据（由各 Agent 定义）
├── tools: list[ACPToolCall]   MCP tool 调用记录
├── artifacts: list[ACPArtifact] 附件（利用代码、报告等）
├── status: ACPStatus          执行结果
│   ├── state: "success"|"failed"|"skipped"|"pending"
│   ├── verdict: ACPVerdict|None
│   └── confidence: float|None
└── error: str|None            错误信息
```

## 消息类型（ACPMessageType）

| 值 | 含义 |
|---|---|
| `scan.start` | 扫描任务启动 |
| `scan.complete` | 扫描完成 |
| `scan.failed` | 扫描失败 |
| `parse.request` / `parse.result` | 仓库解析 |
| `static_scan.request` / `static_scan.result` | 静态扫描 |
| `audit.request` / `audit.result` | LLM 语义审计 |
| `verify.request` / `verify.result` | 漏洞验证（VerifyAgent） |
| `exploit.generate.request` / `exploit.generate.result` | 利用代码生成（ExploitAgent） |
| `dynamic.verify.request` / `dynamic.verify.result` | 动态 HTTP 验证 |
| `harness.verify.request` / `harness.verify.result` | Fuzzing Harness 验证 |
| `report.request` / `report.result` | 报告生成 |

## 裁决值（ACPVerdict）

| 值 | 含义 | 触发条件 |
|---|---|---|
| `candidate` | 候选（待验证） | 静态扫描发现，未复核 |
| `statically_verified` | 静态确认 | MCP 工具证明 source→sink 可达 |
| `false_positive` | 误报 | 检测到安全 API / 参数化 / 净化 |
| `exploit_generated` | 利用方案已生成 | ExploitAgent 产出利用代码 |
| `dynamic_confirmed` | 动态确认 | HTTP 探测命中成功特征 |
| `not_reproduced` | 动态未复现 | 执行了 HTTP 探测但未命中（载荷失效） |
| `not_executed` | 未执行动态验证 | **base_url 未配置**，从未发起探测 |
| `connection_failed` | 连接失败 | 无法建立 HTTP 连接 |
| `endpoint_not_found` | 端点不存在 | 所有端点返回 404 |
| `request_timeout` | 请求超时 | 目标未在限制时间内响应 |
| `harness_confirmed` | Harness 动态确认 | Fuzzing Harness 触发漏洞标记 |
| `harness_inconclusive` | Harness 不定 | Harness 运行但无触发 |
| `confirmed` | 综合确认 | 静态+动态综合裁决 |
| `needs_review` | 需人工复核 | 证据不足以确定 |

**关键区分**：`not_executed` 和 `not_reproduced` 的语义必须严格区分：
- `not_executed`：**没有发起任何 HTTP 探测**（因为没有配置 base_url 或目标不可达）
- `not_reproduced`：**发起了探测，但所有载荷均未命中成功特征**

## 统一 Finding 字段结构

所有 Agent 的 finding 均统一为：

```json
{
  "finding_id": "uuid",
  "type": "SQL Injection",
  "severity": "high",
  "location": {
    "file": "backend/app.py",
    "start_line": 42,
    "end_line": 42
  },
  "code": {
    "snippet": "cur.execute('SELECT * FROM users WHERE id=' + uid)"
  },
  "source": {
    "agent": "audit_agent",
    "tool": "semgrep",
    "rule_id": "sqli-001"
  },
  "description": "用户输入未转义直接拼接 SQL",
  "extra": {}
}
```

转换函数见 `backend/acp/adapters.py`：
- `raw_finding_to_acp(rf)` — RawFinding → 统一结构
- `audit_finding_to_acp(lf)` — AuditAgent finding → 统一结构
- `acp_to_legacy_finding(acp)` — 统一结构 → 旧散字段（向后兼容）

## Agent ACP 接口

### VerifyAgent.run_acp(request) → reply

- 输入：`message_type=verify.request`，`payload.finding` 为统一 ACPFinding
- 输出：`message_type=verify.result`，`payload.verification` 含：
  - `static_verdict`: confirmed | false_positive | uncertain
  - `dynamic_verdict`: not_executed（默认）| dynamic_confirmed | not_reproduced | ...
  - `final_verdict`: confirmed | false_positive | needs_review
  - `source`, `sink`, `call_path[]`, `evidence_chain{}`
  - `confidence`, `false_positive_reason`, `recommended_poc_strategy`

### ExploitAgent.run_acp(request) → reply

- 输入：`message_type=exploit.generate.request`，`payload.finding + payload.verification`
- 输出：`message_type=exploit.generate.result`，`payload.exploit` 含利用方案，`artifacts` 含利用代码

## 消息追踪（ACPTracer）

```python
from backend.acp.trace import ACPTracer

tracer = ACPTracer(scan_id="abc123")
tracer.save(msg)                    # 保存到 data/scans/abc123/agent_messages/*.json
messages = tracer.load_all()        # 按时间戳排序读回
summary = tracer.summary()          # 摘要列表
```

## MCP 工具（v2.0，共 9 个）

| 工具名 | 用途 |
|---|---|
| `read_code_context` | 读取候选漏洞附近源码 |
| `run_sast_replay` | 本地 SAST replay |
| `verify_source_sink` | source→sink 数据流复核 |
| `build_evidence_chain` | 构建静态证据链 |
| `extract_target_function` | 提取漏洞函数源码 |
| `generate_fuzzing_harness` | 生成模板 Harness |
| `run_fuzzing_harness` | 执行 Harness 并检测触发 |
| `dynamic_http_verify` | HTTP 动态验证（复用 DynamicVerifier） |
| `build_final_evidence` | 汇总静/动/harness 证据链 |
