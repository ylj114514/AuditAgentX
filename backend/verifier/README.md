# backend/verifier —— 漏洞验证、利用与证据链模块

本目录负责把"候选漏洞"变成"已验证、可利用、有证据链"的结论，是课件模块③（漏洞自动利用）
与动态检测的核心，深度借鉴 [DeepAudit](https://github.com/lintsinghua/DeepAudit) 的动态验证思路。

## 文件说明

| 文件 | 职责 |
|---|---|
| `exploit_validator.py` | 结果裁决：去重、误报过滤、风险评级 |
| `exploit_templates.py` | 9 类漏洞的利用载荷/成功特征模板库（离线兜底） |
| `dynamic_verifier.py` | **HTTP 动态验证**：对运行中的靶场发 payload、采集 request/response、判定可复现 |
| `harness_verifier.py` | **Fuzzing Harness 动态验证**（DeepAudit 式）：生成 mock 验证脚本 → 沙箱执行 → 自我修正重试 |
| `app_runner.py` | 靶场启动器：本地子进程 / Docker 两种 provider（端口分配、健康检查工具） |
| `docker_project_runner.py` | **Docker-first Deep Mode**：从 GitHub 项目 code_root 构建/复用 Dockerfile → build → run → 健康检查 → base_url，退出自动清理并采集容器日志；含内置 SandboxBuilder（`build_dockerfile`） |
| `sandbox_manager.py` | Docker 沙箱执行封装 |

## 扫描模式（Quick / Standard / Deep）

由 `api/routes_scans.resolve_scan_mode()` 把模式映射为 enabled_agents + options：

| 模式 | 内容 |
|---|---|
| **Quick** | 仅静态扫描；不 LLM 审计、不复核、不动态、不启动 Docker |
| **Standard** | + AuditAgent 语义审计 + VerifyAgent 复核去误报 + source→sink 证据链 + 报告；不主动动态请求 |
| **Deep** | + Docker-first：`dynamic_target.mode="docker_project"`，在沙箱启动项目 → 提取端点 → HTTP 动态验证（High/Critical 且策略 http/both）+ Harness 验证 |

## Docker-first Deep Mode 流程

```
GitHub URL → clone → launch_detector 生成 launch_plan
  → DockerProjectRunner（优先项目 Dockerfile，否则 SandboxBuilder 生成临时 Dockerfile）
  → docker build + run + 端口映射 → 健康检查 → base_url
  → endpoint_extractor 提取候选路由 → ExploitAgent payload → DynamicVerifier 对容器发包
  → 采集 request/response/容器日志 → EvidenceCollector（含 sandbox 字段）→ 前端/报告
```

**安全边界**：仅本地 Docker 沙箱/授权目标；容器限内存、扫描后销毁。
Docker 失败时如实标记 `sandbox_start_failed` / `health_check_failed` / `dependency_install_failed`，
**绝不造假复现结果**；静态类漏洞（硬编码密钥等）标记 `not_runtime_verifiable`。
| `poc_runner.py` | PoC 生成 + 沙箱执行调度 |
| `evidence_collector.py` | **证据链汇总**：source→sink→call_path→exploit→runtime→harness |
| `pipeline.py` | `ExploitPipeline`：把利用生成 + HTTP 动态 + Harness 动态 + 证据链一体化装配 |

## 两种动态验证的区别（重点）

| | HTTP 动态验证 (`dynamic_verifier`) | Fuzzing Harness (`harness_verifier`) |
|---|---|---|
| 前提 | 目标 Web 服务**必须运行** | 目标**无需运行**（提取函数隔离测试） |
| 做法 | 对端点发攻击 payload，看响应特征 | mock 危险 sink，喂 payload，看是否触发 |
| 适用 | 有靶场/授权环境的 Web 漏洞 | 代码审计场景（目标通常没起服务） |
| 判定 | reproducible（响应命中特征） | confirmed_dynamic（harness 打印触发标记） |

## Fuzzing Harness 闭环（DeepAudit 精髓）

```
extract_function(提取漏洞函数)
    → 生成 Harness（LLM，或 LLM 不可用时按类型模板兜底）
    → 沙箱执行（Docker 优先，受控本地子进程回退）
    → 检测触发标记 AUDITAGENTX_VULN_TRIGGERED
    → 未触发/报错则把执行输出回喂 LLM 自我修正，重试（bounded）
    → verdict: confirmed_dynamic / not_reproduced / inconclusive
```

**安全约束**：Harness 由提示词强制 mock 所有危险 sink（os.system/execute/open/pickle.loads 等），
只在本地隔离环境短时运行，绝不真实执行系统命令、删除文件或发起网络请求。

## 证据链结构（evidence_collector 输出）

```jsonc
{
  "source": "...", "sink": "...", "data_flow": "...",
  "call_path": [{"stage":"source",...},{"stage":"sink",...}],   // 逐跳调用路径
  "exploit":  { "trigger_location", "exploit_path", "payloads", "exploit_code", ... },
  "runtime":  { "reproducible", "request", "response_status", ... },   // HTTP 动态
  "harness":  { "verdict", "dynamically_triggered", "harness_code", "trigger_detail", ... },  // Harness 动态
  "logs": [ ... ]
}
```

详见根目录 `docs/dynamic_exploitation.md` 与 `docs/deepaudit_learnings.md`。
