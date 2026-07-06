# {{ project.name }} 安全审计报告

> 生成工具：{{ tool }}　生成时间：{{ generated_at }}

## 1. 执行摘要

{{ summary.executive_summary }}

**总体风险等级：{{ summary.overall_risk | upper }}**

## 2. 项目概况

| 项 | 值 |
|---|---|
| 项目名称 | {{ project.name }} |
| 来源 | {{ project.url or project.local_path }} |
| 语言 | {{ project.languages | join(", ") }} |
| 框架 | {{ project.frameworks | join(", ") }} |
| 文件数 | {{ project.file_count }} |
| 代码行数 | {{ project.loc }} |

## 3. 审计范围与方法

- 静态工具扫描：Semgrep / Bandit / Gitleaks / Trivy / 自定义规则
- LLM 多智能体语义审计：AuditAgent
- 独立验证：VerifyAgent 交叉复核，降低误报
- PoC 沙箱验证：PocAgent（可选）

## 4. 漏洞统计

| 严重级 | 数量 |
|---|---|
| Critical | {{ stats.critical }} |
| High | {{ stats.high }} |
| Medium | {{ stats.medium }} |
| Low | {{ stats.low }} |
| **合计** | **{{ findings | length }}** |

## 5. 漏洞明细

{% for f in findings %}
### 5.{{ loop.index }} {{ f.type }}（{{ f.severity | upper }}）

- 文件：`{{ f.file }}:{{ f.start_line or f.line }}`
- 置信度：{{ f.confidence }}
- 已验证：{{ "是" if f.verified else "否" }}
- 状态：{{ f.status }}

```
{{ f.code_snippet or f.vulnerable_code }}
```

**修复建议：** {{ f.fix_suggestion or "使用参数化查询 / 输入校验 / 最小权限等通用加固手段。" }}

{% endfor %}

## 6. 关键风险

{% for r in summary.key_risks %}- {{ r }}
{% endfor %}

## 7. 结论

{{ summary.conclusion }}

---
*本报告由 AuditAgentX 自动生成，PoC 仅在本地授权沙箱环境验证。*
