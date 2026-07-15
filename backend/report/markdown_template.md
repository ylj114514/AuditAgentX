# {{ project.name }} 安全审计报告

> 生成工具：{{ tool }}　生成时间：{{ generated_at }}

{% if report.completeness != "complete" %}> **覆盖警告：本报告完整性为 `{{ report.completeness }}`。请先阅读“限制与覆盖缺口”，不得将本报告解释为全量无遗漏审计。**
{% endif %}

## 目录

<ul class="toc" style="list-style: disc; padding-left: 22px;">
{% for item in toc -%}
  <li class="toc-level-{{ item.level }}"{% if item.level == 3 %} style="margin-left: 28px; font-size: 0.92em;"{% else %} style="font-size: 1.04em; font-weight: 600;"{% endif %}><a href="#{{ item.anchor }}">{{ item.title }}</a></li>
{% endfor -%}
</ul>

<a id="executive-summary"></a>
## 1. 执行摘要

{{ summary.executive_summary }}

**总体风险等级：{{ summary.overall_risk | upper }}**

<a id="project-summary"></a>
### 1.1 项目概况总结

项目 {{ project.name }} 来源于 {{ project.url or project.local_path }}，主要语言为 {{ project.languages | join("、") or "未识别" }}，框架为 {{ project.frameworks | join("、") or "未识别" }}，共 {{ project.file_count }} 个文件、{{ project.loc }} 行代码。

<a id="finding-summary"></a>
### 1.2 漏洞结果总结

本次共发现 {{ findings | length }} 条漏洞，其中 Critical {{ stats.critical }} 条、High {{ stats.high }} 条、Medium {{ stats.medium }} 条、Low {{ stats.low }} 条。

**静态分析总结：** {{ summary.static_summary }}

**动态验证总结：** {{ summary.dynamic_summary }}

{% if summary.dynamic_breakdown %}
<a id="dynamic-breakdown"></a>
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

<a id="agent-workflow"></a>
### 1.4 多智能体工作流

{% for step in summary.workflow_summary or [] %}
{{ loop.index }}. {{ step }}
{% endfor %}

<a id="summary-agent-remediation"></a>
### 1.5 SummaryAgent 修改建议

| 优先级 | 建议 | 说明 |
|---|---|---|
{% for item in summary.remediation_plan or [] -%}
| {{ item.priority }} | {{ item.title }} | {{ item.detail }} |
{% endfor %}

<a id="project-overview"></a>
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
| 报告 ID / Schema | {{ report.id }} / {{ schema_version }} |
| 完整性 | {{ report.completeness }} |

<a id="scope-config"></a>
### 2.1 审计范围与配置

| 项目 | 值 |
|---|---|
| 扫描模式 | {{ scope.scan_mode or "unknown" }} |
| 启用 Agent | {{ scope.enabled_agents | join("、") or "无" }} |
| 测试/样例代码 | {{ "包含" if scope.include_test_findings else "排除" }} |
| 最大文件数 | {{ scope.limits.max_files or "未记录" }} |
| 最大复核候选 | {{ scope.limits.max_verify_candidates or "未记录" }} |
| 严重度阈值 | {{ scope.limits.severity_threshold or "未记录" }} |

{% if scope.excluded_paths %}**排除项：**
{% for item in scope.excluded_paths %}- `{{ item.path }}`：{{ item.reason }}
{% endfor %}{% endif %}

<a id="tool-matrix"></a>
### 2.2 工具执行矩阵

| 工具 | 请求 | 状态 | 成功 | Partial | Findings | 原因 |
|---|---|---|---|---|---:|---|
{% for tool_status in methodology.tools -%}
| {{ tool_status.name }} | {{ "是" if tool_status.requested else "否" }} | {{ tool_status.status }} | {{ "是" if tool_status.success else "否" }} | {{ "是" if tool_status.partial_results else "否" }} | {{ tool_status.finding_count or 0 }} | {{ tool_status.error or "-" }} |
{% endfor %}

<a id="limitations"></a>
### 2.3 限制与覆盖缺口

{% for item in limitations %}- **{{ item.category }}{% if item.tool %} / {{ item.tool }}{% endif %}：** {{ item.detail }}。影响：{{ item.impact }}
{% else %}- 未记录到已知覆盖缺口。
{% endfor %}

<a id="finding-statistics"></a>
## 3. 漏洞统计

| 严重级 | 数量 |
|---|---|
| Critical | {{ stats.critical }} |
| High | {{ stats.high }} |
| Medium | {{ stats.medium }} |
| Low | {{ stats.low }} |
| **合计** | **{{ findings | length }}** |

<a id="status-source"></a>
### 3.1 状态与来源

**状态分布：** {% for key, value in metrics.by_status.items() %}`{{ key }}`={{ value }}{% if not loop.last %}；{% endif %}{% else %}无{% endfor %}

**来源分布：** {% for key, value in metrics.by_source.items() %}`{{ key }}`={{ value }}{% if not loop.last %}；{% endif %}{% else %}无{% endfor %}

**可行动风险：** {{ metrics.actionable_total }}；**动态确认：** {{ metrics.dynamically_verified }}。

{% if evidence_stats %}
<a id="evidence-coverage"></a>
### 3.2 证据链覆盖概览

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
<a id="finding-details"></a>
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

{% if report.options.include_fix %}**修复建议：** {{ f.fix_suggestion or "not_available：未记录针对该 finding 的具体修复建议。" }}
{% else %}**修复建议：** omitted_by_report_option
{% endif %}

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
  {{ loop.index }}. {{ hop.stage or "step" }}{% if hop.file %} `{{ hop.file }}:{{ hop.line or "?" }}`{% endif %}{% if hop.symbol %} `{{ hop.symbol }}`{% endif %}：{{ hop.detail or hop }}
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
{% endif %}{% if f.evidence.poc_file %}- PoC 制品：`{{ f.evidence.poc_file.path }}`（SHA-256: `{{ f.evidence.poc_file.sha256 }}`）
{% endif %}{% if f.evidence.reproduction_metadata %}- 复现元数据：源码 commit=`{{ f.evidence.reproduction_metadata.source_commit or "N/A" }}`；沙箱镜像=`{{ f.evidence.reproduction_metadata.sandbox_image or "N/A" }}`；请求 hash=`{{ f.evidence.reproduction_metadata.request_hash or "N/A" }}`；响应 hash=`{{ f.evidence.reproduction_metadata.response_hash or "N/A" }}`
{% endif %}{% if f.evidence.sandbox %}- Docker 沙箱：{{ f.evidence.sandbox.status }}（引擎 {{ (f.evidence.sandbox.docker_engine or {}).status or "未单独检查" }}，健康检查 {{ f.evidence.sandbox.health_check }}，构建 {{ "已尝试" if f.evidence.sandbox.image_build_attempted else "未尝试" }}，启动 {{ "已尝试" if f.evidence.sandbox.container_start_attempted else "未尝试" }}，镜像 `{{ f.evidence.sandbox.image or "N/A" }}`，启动命令 `{{ f.evidence.sandbox.launch_command or "N/A" }}`）
{% endif %}{% if f.evidence.runtime %}- 动态验证状态：{{ f.evidence.runtime.reproduction_status or ("可复现" if f.evidence.runtime.reproducible else "未复现") }}
- 命中特征：`{{ f.evidence.runtime.matched_indicator or "N/A" }}`
- 响应状态：{{ f.evidence.runtime.response_status or "N/A" }}
- 请求：`{{ (f.evidence.runtime.request or {}).url or "N/A" }}`
- 原因：{{ f.evidence.runtime.reason or "N/A" }}
{% if f.evidence.runtime.request %}- 请求方法/URL：`{{ f.evidence.runtime.request.method or "N/A" }} {{ f.evidence.runtime.request.url or "N/A" }}`
{% endif %}{% if f.evidence.runtime.elapsed_seconds is defined %}- 耗时：{{ f.evidence.runtime.elapsed_seconds }} 秒
{% endif %}{% if f.evidence.runtime.response_excerpt %}- 响应摘录：

```text
{{ f.evidence.runtime.response_excerpt }}
```
{% endif %}{% if f.evidence.runtime.baseline_record %}- Baseline：`{{ f.evidence.runtime.baseline_record }}`
{% endif %}{% if f.evidence.runtime.attack_record %}- Attack：`{{ f.evidence.runtime.attack_record }}`
{% endif %}{% if f.evidence.runtime.confirmation_record %}- Confirmation：`{{ f.evidence.runtime.confirmation_record }}`
{% endif %}
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

### 漏洞利用链

- 链状态：**{{ f.exploit_chain.status }}**
- 前置条件：{{ f.exploit_chain.preconditions | join("；") or "未记录" }}
- 入口：`{{ f.exploit_chain.entry_point or "not_available" }}`
- 验证方法：{{ f.exploit_chain.verification_method or "not_executed" }}
- 观测结果：`{{ f.exploit_chain.observed_result or "not_available" }}`
- 影响：{{ f.exploit_chain.impact }}
{% if f.exploit_chain.stages %}
{% for stage in f.exploit_chain.stages %}  {{ loop.index }}. **{{ stage.stage }}**{% if stage.sequence %} #{{ stage.sequence }}{% endif %}{% if stage.file %} `{{ stage.file }}:{{ stage.line or "?" }}`{% endif %}{% if stage.symbol %} `{{ stage.symbol }}`{% endif %}：{{ stage.detail }}
{% endfor %}
{% else %}  - 未生成可用利用链；请查看证据可用性和限制说明。
{% endif %}

**证据可用性：** static={{ f.evidence_availability.static_chain }}；exploit={{ f.evidence_availability.exploit }}；runtime={{ f.evidence_availability.runtime }}；harness={{ f.evidence_availability.harness }}

{% endfor %}

<a id="key-risks"></a>
## 5. 关键风险

{% for r in summary.key_risks %}- {{ r }}
{% endfor %}

<a id="remediation"></a>
## 6. 修改建议

{% for item in summary.remediation_plan or [] -%}
- **{{ item.priority }} {{ item.title }}：** {{ item.detail }}
{% endfor %}

<a id="conclusion"></a>
## 7. 结论

{{ summary.conclusion }}

<a id="appendix"></a>
## 8. 附录

<a id="finding-index"></a>
### 8.1 Finding 索引

| ID | 类型 | 严重度 | 状态 | 位置 |
|---|---|---|---|---|
{% for item in appendices.finding_index -%}
| {{ item.id }} | {{ item.type }} | {{ item.severity }} | {{ item.status }} | `{{ item.file }}:{{ item.line }}` |
{% endfor %}

<a id="status-glossary"></a>
### 8.2 状态术语

{% for key, value in appendices.status_glossary.items() %}- `{{ key }}`：{{ value }}
{% endfor %}

<a id="redaction-policy"></a>
### 8.3 脱敏策略

策略版本 {{ redaction.policy_version }}；已处理：{{ redaction.categories | join("、") }}。

---

*本报告由 AuditAgentX 自动生成，PoC 仅在本地授权沙箱或授权目标环境验证。*
