# {{ project.name }} 安全审计报告

> 生成工具：{{ tool }}　生成时间：{{ generated_at }}

## 1. 执行摘要

{{ summary.executive_summary }}

**总体风险等级：{{ summary.overall_risk | upper }}**

### 1.1 项目概况总结

项目 {{ project.name }} 来源于 {{ project.url or project.local_path }}，主要语言为 {{ project.languages | join("、") or "未识别" }}，框架为 {{ project.frameworks | join("、") or "未识别" }}，共 {{ project.file_count }} 个文件、{{ project.loc }} 行代码。

### 1.2 漏洞结果总结

本次共发现 {{ findings | length }} 条漏洞，其中 Critical {{ stats.critical }} 条、High {{ stats.high }} 条、Medium {{ stats.medium }} 条、Low {{ stats.low }} 条。

**静态分析总结：** {{ summary.static_summary }}

**动态验证总结：** {{ summary.dynamic_summary }}

### 1.3 多智能体工作流

{% for step in summary.workflow_summary or [] %}
{{ loop.index }}. {{ step }}
{% endfor %}

### 1.4 SummaryAgent 修改建议

| 优先级 | 建议 | 说明 |
|---|---|---|
{% for item in summary.remediation_plan or [] -%}
| {{ item.priority }} | {{ item.title }} | {{ item.detail }} |
{% endfor %}

## 2. 项目概况

| 项 | 值 |
|---|---|
| 项目名称 | {{ project.name }} |
| 来源 | {{ project.url or project.local_path }} |
| 语言 | {{ project.languages | join(", ") }} |
| 框架 | {{ project.frameworks | join(", ") }} |
| 文件数 | {{ project.file_count }} |
| 代码行数 | {{ project.loc }} |
| 扫描任务 | {{ scan.id }}（{{ scan.scan_type }} / {{ scan.status }}） |

## 3. 漏洞统计

| 严重级 | 数量 |
|---|---|
| Critical | {{ stats.critical }} |
| High | {{ stats.high }} |
| Medium | {{ stats.medium }} |
| Low | {{ stats.low }} |
| **合计** | **{{ findings | length }}** |

## 4. 漏洞明细

{% for f in findings %}
### 4.{{ loop.index }} {{ f.type }}（{{ f.severity | upper }}）

- 文件：`{{ f.file }}:{{ f.start_line or f.line }}`
- 来源：{{ f.source or "unknown" }}
- 置信度：{{ f.confidence }}
- 已验证：{{ "是" if f.verified else "否" }}
- 状态：{{ f.status }}

```text
{{ f.code_snippet or f.vulnerable_code }}
```

**修复建议：** {{ f.fix_suggestion or "使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。" }}

{% if f.evidence %}
**证据链：**

- Source：`{{ f.evidence.source or "N/A" }}`
- Sink：`{{ f.evidence.sink or "N/A" }}`
{% if f.evidence.call_path %}
- 调用路径：
{% for hop in f.evidence.call_path %}
  {{ loop.index }}. {{ hop.stage or "step" }}：{{ hop.detail or hop }}
{% endfor %}
{% endif %}
{% if f.evidence.exploit %}- 利用路径：{{ f.evidence.exploit.exploit_path or "N/A" }}
- 触发位置：`{{ f.evidence.exploit.trigger_location or "N/A" }}`
- Payload：`{{ (f.evidence.exploit.payloads or []) | join(" / ") or "N/A" }}`
{% endif %}{% if f.evidence.sandbox %}- Docker 沙箱：{{ f.evidence.sandbox.status }}（健康检查 {{ f.evidence.sandbox.health_check }}，镜像 `{{ f.evidence.sandbox.image or "N/A" }}`，启动命令 `{{ f.evidence.sandbox.launch_command or "N/A" }}`）
{% endif %}{% if f.evidence.runtime %}- 动态验证状态：{{ f.evidence.runtime.reproduction_status or ("可复现" if f.evidence.runtime.reproducible else "未复现") }}
- 命中特征：`{{ f.evidence.runtime.matched_indicator or "N/A" }}`
- 响应状态：{{ f.evidence.runtime.response_status or "N/A" }}
- 请求：`{{ (f.evidence.runtime.request or {}).url or "N/A" }}`
- 原因：{{ f.evidence.runtime.reason or "N/A" }}
{% if f.evidence.runtime.evidence_flow %}
- 动态证据流：
{% for step in f.evidence.runtime.evidence_flow %}
  {{ loop.index }}. {{ step.stage }}：{{ step.detail }}
{% endfor %}
{% endif %}
{% endif %}{% if f.evidence.harness %}- Harness：{{ f.evidence.harness.verdict or "N/A" }}，触发={{ "是" if f.evidence.harness.dynamically_triggered else "否" }}
{% endif %}{% if f.evidence.tool_calls %}- 工具调用：
{% for tc in f.evidence.tool_calls %}
  {{ loop.index }}. {{ tc.name or tc.tool_name }}：{{ tc.purpose or "" }}
{% endfor %}
{% endif %}
{% endif %}

{% endfor %}

## 5. 关键风险

{% for r in summary.key_risks %}- {{ r }}
{% endfor %}

## 6. 修改建议

{% for item in summary.remediation_plan or [] -%}
- **{{ item.priority }} {{ item.title }}：** {{ item.detail }}
{% endfor %}

## 7. 结论

{{ summary.conclusion }}

---

*本报告由 AuditAgentX 自动生成，PoC 仅在本地授权沙箱或授权目标环境验证。*
