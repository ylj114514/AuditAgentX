# Static Scanning Skill

name: static-scanning
version: 1.0

tools:
- check_static_tool_availability
- run_semgrep
- run_gitleaks
- run_bandit
- run_trivy
- run_custom_rules

workflow:
1. 通过 check_static_tool_availability 预检启用工具是否安装/可用。
2. 汇总启用的扫描工具（用户选择 + 始终附加 custom 规则兜底）。
3. 逐工具在代码根目录执行，产出各自命中。
4. 将各工具输出归一化为统一的 RawFinding（type/file/line/severity/source/rule_id）。
5. 合并去重，作为候选漏洞交给 AuditAgent 语义分析与 VerifyAgent 复核。

## Acceptance Criteria

- 缺少外部工具时，custom 正则规则必须保证离线可产出候选。
- 每条候选必须带 source（发现工具）与可定位的 file:line。
- 本 Skill 为确定性工具编排，不依赖 LLM。
