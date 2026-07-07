# backend/scanners —— 静态扫描层

课件模块②的静态扫描部分。多个扫描器**并行**产出候选漏洞，归一化为 `RawFinding`。
注意：静态分析**不只是正则**——正则仅为离线兜底，专业工具（Semgrep 等）为主力。

## 扫描器清单

| 扫描器 | 文件 | 技术 | 说明 |
|---|---|---|---|
| **Semgrep** | `semgrep_runner.py` | AST 语义 + **taint mode** | 官方 `auto` 规则 + 项目自定义 `rules/semgrep/*.yaml` 污点规则 |
| **Bandit** | `bandit_runner.py` | Python AST | Python 专项安全检查 |
| **Gitleaks** | `gitleaks_runner.py` | 熵值 + 规则 | 硬编码密钥检测 |
| **Trivy** | `trivy_runner.py` | CVE 库比对 | 依赖组件漏洞（SCA） |
| **CustomTaint** | `custom_rules.py` + `taint_rules.py` | **轻量污点分析** | 离线兜底，source→sink 可达性分析 |

`registry.py` 统一调度：`run_scanners(target, enabled_tools)` 始终追加 `custom` 兜底，
外部工具未安装时自动跳过，保证离线也能出结果。

## 污点分析升级（custom_rules，替代单行正则）

**旧版**：单行匹配危险函数 → 误报高（看到 `.execute(` 就报，不管是否拼接用户输入）。
**新版**（借鉴 Semgrep taint mode）：

```
漏洞 = 用户可控输入(source) 经数据流到达危险函数(sink) 且中途无净化(sanitizer)
```

- `taint_rules.py` 分开定义 **source**（`request.args` / `$_GET` / `req.body` …）、
  **sink**（SQL/命令/路径/SSRF/SSTI/XSS 执行点）、**sanitizer**（`int()`/`escape`/`secure_filename` …）、
  **injection marker**（拼接/格式化痕迹）。
- 注入类判定：sink 行须有 injection marker（排除静态字面量），再在函数窗口内追踪 source 可达性：
  - source 可达且无净化 → 维持高危，置信度 0.75~0.85，附 `taint_flow`（source_line → sink_line）
  - 有净化 → 降为 medium，置信度 0.5
  - 无 source → 降为 low，置信度 0.25（疑似噪音）
- 非注入类（硬编码密钥/反序列化/弱加密）：本身即问题，直接命中；密钥占位值（`your-`/`example`）跳过。

效果：demo 靶场上 SQL 注入误报从 4 条（含 3 条静态 create/delete/insert）降到 1 条真漏洞。

`RawFinding.extra` 携带污点证据：`confidence` / `source_line` / `sanitized` / `taint_flow` / `analysis="taint"`。

## Semgrep 自定义 taint 规则

`rules/semgrep/taint_injection.yaml` 用 Semgrep 原生 `mode: taint` 定义
SQL注入/命令注入/路径遍历的 pattern-sources / pattern-sinks / pattern-sanitizers。
安装 Semgrep 后 `semgrep_runner` 会自动加载（`--config rules/semgrep`），获得工业级污点追踪。
