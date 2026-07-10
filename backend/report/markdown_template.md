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

{% if summary.dynamic_breakdown %}
### 1.3 动态验证拆解

| 项目 | 值 |
|---|---|
| 扫描模式 | {{ summary.dynamic_breakdown.scan_mode }} |
| 启用 Agent | {{ (summary.dynamic_breakdown.enabled_agents or []) | join("、") or "无" }} |
| 动态开关 | Exploit={{ "开" if summary.dynamic_breakdown.enable_exploit else "关" }}；HTTP={{ "开" if summary.dynamic_breakdown.enable_dynamic else "关" }}；Harness={{ "开" if summary.dynamic_breakdown.enable_harness else "关" }} |
| 动态目标 | {{ summary.dynamic_breakdown.dynamic_target_mode or "未配置" }} |
| Runtime 状态分布 | {% for k, v in (summary.dynamic_breakdown.runtime_status_counts or {}).items() %}{{ k }}={{ v }}{% if not loop.last %}；{% endif %}{% else %}无{% endfor %} |
| Sandbox 状态分布 | {% for k, v in (summary.dynamic_breakdown.sandbox_status_counts or {}).items() %}{{ k }}={{ v }}{% if not loop.last %}；{% endif %}{% else %}无{% endfor %} |
| Harness 裁决分布 | {% for k, v in (summary.dynamic_breakdown.harness_verdict_counts or {}).items() %}{{ k }}={{ v }}{% if not loop.last %}；{% endif %}{% else %}无{% endfor %} |
| Harness 确认级别 | 入口级 {{ summary.dynamic_breakdown.harness_target_confirmed or 0 }} 条；函数单元复现 {{ summary.dynamic_breakdown.harness_function_reproduced or 0 }} 条；模板机理级 {{ summary.dynamic_breakdown.harness_mechanism_confirmed or 0 }} 条 |
| 经动态确认 | 运行时确认 {{ summary.dynamic_breakdown.dynamically_verified or 0 }} 条（其中 HTTP 可复现 {{ summary.dynamic_breakdown.http_reproduced or 0 }} 条） |
| 状态分布 | {% for k, v in (summary.dynamic_breakdown.status_counts or {}).items() %}{{ k }}={{ v }}{% if not loop.last %}；{% endif %}{% else %}无{% endfor %} |
| 未复现/未执行原因 | {% for k, v in (summary.dynamic_breakdown.runtime_reason_counts or {}).items() %}{{ k }}（{{ v }}）{% if not loop.last %}；{% endif %}{% else %}无{% endfor %} |

> 说明：Deep 模式的价值不只看“HTTP 可复现条数”，还应同时查看沙箱状态、runtime 状态和 Harness 裁决。`mechanism_confirmed` 仅代表模板机理确认，不等同真实目标函数复现。

{% endif %}

### 1.4 多智能体工作流

{% for step in summary.workflow_summary or [] %}
{{ loop.index }}. {{ step }}
{% endfor %}

### 1.5 SummaryAgent 修改建议

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

{% if evidence_stats %}
### 3.1 证据链覆盖概览

| 维度 | 覆盖条数 |
|---|---|
| 含证据链的漏洞 | {{ evidence_stats.with_evidence }} / {{ findings | length }} |
| 含静态验证判据（逐步核验） | {{ evidence_stats.with_static_chain }} |
| 含利用/PoC 证据 | {{ evidence_stats.with_exploit }} |
| 含 Harness 函数级证据 | {{ evidence_stats.with_harness }} |
| 含运行时（HTTP）证据 | {{ evidence_stats.with_runtime }} |
| **经动态运行时确认** | **{{ evidence_stats.dynamically_verified }}** 条（其中 HTTP 真实可复现 {{ evidence_stats.http_reproduced }} 条） |

> 漏洞按“动态确认 → 严重级 → 置信度”排序，最可信、最严重者优先展示。

{% endif %}
## 4. 漏洞明细

{% for f in findings %}
### 4.{{ loop.index }} {{ f.type }}（{{ f.severity | upper }}）{% if f.evidence and f.evidence.verification and f.evidence.verification.dynamically_verified %} 🟢 动态已确认{% endif %}

- 文件：`{{ f.file }}:{{ f.start_line or f.line }}`
- 来源：{{ f.source or "unknown" }}
- 置信度：{{ f.confidence }}
- 已验证：{{ "是" if f.verified else "否" }}
- 状态：{{ f.status }}
{% set v = (f.evidence.verification if f.evidence and f.evidence.verification else {}) %}{% if f.context or v.context or f.downgrade_reason or v.downgrade_reason or f.confirmed_blockers or v.confirmed_blockers %}- 上下文：{{ f.context or v.context or "N/A" }}；风险修正：{{ f.risk_modifier or v.risk_modifier or "N/A" }}；动态适用：{{ f.dynamic_applicable if f.dynamic_applicable is defined else (v.dynamic_applicable if v.dynamic_applicable is defined else "N/A") }}
{% if f.downgrade_reason or v.downgrade_reason %}- 降级原因：{{ f.downgrade_reason or v.downgrade_reason }}
{% endif %}{% if f.false_positive_reason or v.false_positive_reason %}- 误报原因：{{ f.false_positive_reason or v.false_positive_reason }}
{% endif %}{% if f.confirmed_blockers or v.confirmed_blockers %}- Confirmed 阻断：{{ (f.confirmed_blockers or v.confirmed_blockers) | join("；") }}
{% endif %}{% endif %}

```text
{{ f.code_snippet or f.vulnerable_code }}
```

**修复建议：** {{ f.fix_suggestion or "使用参数化查询、输入白名单校验、安全 API、最小权限和统一异常处理等方式进行加固。" }}

{% if f.evidence %}
**证据链：**

{% if f.evidence.knowledge %}- 知识增强：{{ f.evidence.knowledge.cwe_id or "N/A" }}{% if f.evidence.knowledge.owasp %} / {{ f.evidence.knowledge.owasp | join("、") }}{% endif %}
{% if f.evidence.knowledge.verification_checks %}- 知识库验证条件：
{% for check in f.evidence.knowledge.verification_checks %}
  {{ loop.index }}. {{ check }}
{% endfor %}
{% endif %}{% if f.evidence.knowledge.false_positive_signals %}- 误报判据：
{% for signal in f.evidence.knowledge.false_positive_signals %}
  {{ loop.index }}. {{ signal }}
{% endfor %}
{% endif %}{% if f.evidence.knowledge.remediation %}- 知识库修复建议：{{ f.evidence.knowledge.remediation | join("；") }}
{% endif %}{% endif %}
- Source：`{{ f.evidence.source or "N/A" }}`
- Sink：`{{ f.evidence.sink or "N/A" }}`
{% if f.evidence.data_flow %}- 数据流：
{% for step in f.evidence.data_flow %}  {{ loop.index }}. {% if step is mapping %}{{ step.stage or step.name or "step" }}：{{ step.detail or step.node or step }}{% else %}{{ step }}{% endif %}
{% endfor %}{% endif %}{% if f.evidence.static_evidence_chain and f.evidence.static_evidence_chain.checks %}- **静态验证判据（逐步核验）：**
{% for c in f.evidence.static_evidence_chain.checks %}  {{ loop.index }}. {{ "✓ 通过" if c.passed else "✗ 未通过" }} `{{ c.name }}`{% if c.detail %} —— {{ c.detail }}{% endif %}
{% endfor %}{% if f.evidence.static_evidence_chain.tool_calls %}- 审计工具调用链：{% for tc in f.evidence.static_evidence_chain.tool_calls %}`{{ tc.name or tc }}`{% if tc.success is defined %}{{ "✓" if tc.success else "✗" }}{% endif %}{% if not loop.last %} → {% endif %}{% endfor %}
{% endif %}{% endif %}
{% if f.evidence.call_path %}
- 调用路径：
{% for hop in f.evidence.call_path %}
  {{ loop.index }}. {{ hop.stage or "step" }}：{{ hop.detail or hop }}
{% endfor %}
{% endif %}
{% if f.evidence.exploit %}- 利用路径：{{ f.evidence.exploit.exploit_path or "N/A" }}
- 触发位置：`{{ f.evidence.exploit.trigger_location or "N/A" }}`
- Payload：`{{ (f.evidence.exploit.payloads or []) | join(" / ") or "N/A" }}`
{% if f.evidence.exploit.exploit_code %}
- 利用验证代码：

```python
{{ f.evidence.exploit.exploit_code }}
```
{% endif %}
{% if f.evidence.exploit.verification_method %}- 验证方法：{{ f.evidence.exploit.verification_method }}
{% endif %}
{% endif %}{% if f.evidence.sandbox %}- Docker 沙箱：{{ f.evidence.sandbox.status }}（引擎 {{ (f.evidence.sandbox.docker_engine or {}).status or "未单独检查" }}，健康检查 {{ f.evidence.sandbox.health_check }}，构建 {{ "已尝试" if f.evidence.sandbox.image_build_attempted else "未尝试" }}，启动 {{ "已尝试" if f.evidence.sandbox.container_start_attempted else "未尝试" }}，镜像 `{{ f.evidence.sandbox.image or "N/A" }}`，启动命令 `{{ f.evidence.sandbox.launch_command or "N/A" }}`）
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
{% endif %}{% if f.evidence.harness %}- Harness：{{ f.evidence.harness.verdict or "N/A" }}，触发={{ "是" if f.evidence.harness.dynamically_triggered else "否" }}，级别={{ f.evidence.harness.verification_level or "N/A" }}，类型={{ f.evidence.harness.harness_kind or f.evidence.harness.harness_source or "N/A" }}，原因={{ f.evidence.harness.reason or "N/A" }}
{% if f.evidence.harness.confirmed_blockers %}- Harness confirmed 阻断：{{ f.evidence.harness.confirmed_blockers | join("；") }}
{% endif %}
{% if f.evidence.harness.harness_code %}
- Harness 代码：

```python
{{ f.evidence.harness.harness_code }}
```
{% endif %}
{% if f.evidence.harness.trigger_detail %}- Harness 触发详情：{{ f.evidence.harness.trigger_detail }}
{% endif %}
{% endif %}{% if f.evidence.tool_calls %}- 工具调用：
{% for tc in f.evidence.tool_calls %}
  {{ loop.index }}. {{ tc.name or tc.tool_name }}：{{ tc.purpose or "" }}
{% endfor %}
{% endif %}{% if f.evidence.verification %}- 验证裁决：静态={{ f.evidence.verification.static_verdict or "N/A" }}；动态={{ f.evidence.verification.dynamic_verdict or "N/A" }}；最终={{ f.evidence.verification.final_verdict or "N/A" }}
- 动态确认：{{ "是" if f.evidence.verification.dynamically_verified else "否" }}{% if f.evidence.verification.dynamic_method %}（方法：{{ f.evidence.verification.dynamic_method }}）{% endif %}{% if f.evidence.verification.runtime_verification_status %}；运行时状态：{{ f.evidence.verification.runtime_verification_status }}{% endif %}
{% if f.evidence.verification.context or f.evidence.verification.downgrade_reason or f.evidence.verification.confirmed_blockers %}- 上下文裁决：context={{ f.evidence.verification.context or "N/A" }}；risk_modifier={{ f.evidence.verification.risk_modifier or "N/A" }}；verification_level={{ f.evidence.verification.verification_level or "N/A" }}；harness_kind={{ f.evidence.verification.harness_kind or "N/A" }}；dynamic_applicable={{ f.evidence.verification.dynamic_applicable if f.evidence.verification.dynamic_applicable is defined else "N/A" }}{% if f.evidence.verification.downgrade_reason %}；降级原因={{ f.evidence.verification.downgrade_reason }}{% endif %}{% if f.evidence.verification.confirmed_blockers %}；confirmed_blockers={{ f.evidence.verification.confirmed_blockers | join("；") }}{% endif %}
{% endif %}
{% if f.evidence.verification.mcp_server %}- MCP Server：`{{ f.evidence.verification.mcp_server }}`
{% endif %}{% if f.evidence.verification.skill %}- Skill：`{{ f.evidence.verification.skill.name or f.evidence.verification.skill }}`
{% endif %}{% endif %}{% if f.evidence.logs %}- 证据链日志：{{ f.evidence.logs | join("；") }}
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
