# backend/scanners —— 静态扫描层

课件模块②的静态扫描部分。多个扫描器**并行**产出候选漏洞，归一化为 `RawFinding`。
注意：静态分析**不只是正则**——正则仅为离线兜底，专业工具（Semgrep 等）为主力。

## 扫描器清单

| 扫描器 | 文件 | 技术 | 说明 |
|---|---|---|---|
| **Semgrep** | `semgrep_runner.py` | AST 语义 + **taint mode** | 官方 `auto` 规则 + 项目自定义 `rules/semgrep/*.yaml` 污点规则 |
| **Bandit** | `bandit_runner.py` | Python AST | Python 专项安全检查 |
| **Gitleaks** | `gitleaks_runner.py` | 熵值 + 规则 | 硬编码密钥检测 |
| **Trivy** | `trivy_runner.py` | SCA + secret + IaC | 依赖 CVE、容器/基础设施配置和密钥扫描 |
| **CustomTaint** | `custom_rules.py` + `taint_rules.py` | **轻量污点分析** | 离线兜底，source→sink 可达性分析 |

`registry.py` 统一调度：`run_scanners(target, enabled_tools)` 始终追加 `custom` 兜底，
外部工具未安装时在 `scanner_status` 中明确返回 `not_installed`，不能把“没执行”伪装成“零发现”。
同一 `file:line` 的同类跨工具命中会合并，并保留 `corroborating_sources/rules`。

## 污点分析升级（custom_rules，替代单行正则）

**旧版**：单行匹配危险函数 → 误报高（看到 `.execute(` 就报，不管是否拼接用户输入）。
**新版**（借鉴 Semgrep taint mode）：

```
漏洞 = 用户可控输入(source) 经数据流到达危险函数(sink) 且中途无净化(sanitizer)
```

- `taint_rules.py` 分开定义 **source**（`request.args` / `$_GET` / `req.body` …）、
  **sink**（SQL/命令/路径/SSRF/SSTI/XSS 执行点）、**sanitizer**（`int()`/`escape`/`secure_filename` …）、
  **injection marker**（拼接/格式化痕迹）。
- 注入类采用顺序敏感的赋值传播：只允许 sink 之前的 source，且 source/sanitizer 必须位于
  sink 实际引用变量的同一条数据依赖上；无可达 source 直接抑制。
- SQL/NoSQL/LDAP/XPath 只追踪主查询参数，参数化 SQL 的 bind 参数不再被错当成查询污点。
- Python 增加文件内 1-hop AST 跨函数分析；Java 按源码顺序执行 AST 污点状态，安全重赋值会断链。
- 反序列化必须证明不可信 source；弱哈希/弱随机必须有密码、令牌、会话等安全上下文。
- 每条可动态验证的候选携带 `dynamic_verification`（HTTP / browser / harness / timing）策略提示。

效果：demo 靶场上 SQL 注入误报从 4 条（含 3 条静态 create/delete/insert）降到 1 条真漏洞。

`RawFinding.extra` 携带污点证据：`confidence` / `source_line` / `sanitized` / `taint_flow` / `analysis="taint"`。

## 语言与漏洞覆盖

- 仓库识别覆盖 Python、JavaScript/TypeScript、Java/Kotlin、Go、PHP、Ruby、C/C++、C#、
  Rust、Swift、Dart、Scala、Objective-C、R、Lua、Perl、Elixir/Erlang、Haskell、Clojure、
  Groovy、F#/VB、PowerShell、Shell、Solidity、Terraform/HCL、SQL、GraphQL、HTML/Vue/Svelte，
  并识别 Dockerfile/Jenkinsfile/Makefile/CMakeLists。
- Semgrep `auto` 负责其解析器支持语言的 AST/官方规则覆盖；CustomTaint 为常见 Web source→sink
  提供跨语言离线兜底；Trivy 负责语言无关的依赖和 IaC 层。
- 内置候选类别包括 SQL/NoSQL/命令/代码/LDAP/XPath/Regex 注入、路径遍历、SSRF、
  SSTI、XSS、开放重定向、Header/Log 注入、不安全反序列化、密钥、弱算法/随机、
  TLS/JWT 验证关闭、Debug/CORS 配置等。

这里的“广语言覆盖”是多引擎编排覆盖，不代表每种语言都有同等深度的跨过程 AST/CFG 分析；
Python 和 Java 的内置分析深于其它语言，其余语言主要依赖 Semgrep/Trivy 和轻量流分析。

## Semgrep 自定义 taint 规则

`rules/semgrep/taint_injection.yaml` 用 Semgrep 原生 `mode: taint` 定义
SQL注入/命令注入/路径遍历的 pattern-sources / pattern-sinks / pattern-sanitizers。
安装 Semgrep 后 `semgrep_runner` 会自动加载（`--config rules/semgrep`），获得工业级污点追踪。
