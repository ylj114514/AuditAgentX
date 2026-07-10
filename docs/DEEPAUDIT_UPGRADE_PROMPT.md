# AuditAgentX 深度分析能力升级 —— 修改 Prompt（对标 DeepAudit）

> 参考开源项目 **DeepAudit**（github.com/lintsinghua/DeepAudit，v3.0.0）：国内首个开源代码漏洞挖掘多智能体系统，
> 四智能体（Orchestrator / Recon / Analysis / Verification），核心是 **AST + RAG 深度理解 + 跨文件调用链**
> 以及 **在 Docker 沙箱里对「真实项目」跑 PoC 做自动验证（失败自我修正重试），并在报告阶段剔除验证未通过的误报**。
> 本 prompt 目标：让 AuditAgentX 从「mock harness 自证」升级为「**真实项目沙箱 + 入口可达性 + 真实 PoC 执行**」，
> 真正把项目分析透。

---

## 0. 铁律（贯穿全程，违反即为不合格）

1. **诚实第一，杜绝"自我感动"**：绝不把「被验证对象自报的成功」当独立事实。任何"确认"必须有**框架侧独立观测**的证据。
   - 沿用现有 `harness_tools` 的**框架 nonce** 机制：真实调用证明由框架插桩打印随机 nonce 判定，脚本自报字段一律不采信。
2. **同一概念只有一个 canonical 定义**：目标/入口级确认判据只保留 `backend/skills/harness_tools.py::is_target_harness_confirmed` 一处，三处调用方（verify_agent / dynamic_analysis_agent / evidence_collector / pipeline）全部 import 共用，禁止各写一套。
3. **分层不越界**（沿用七层架构）：发现层只产候选、验证层只降误报、复现层只执行不裁决、`FinalVerdictResolver` 是唯一裁决入口、ReportBuilder 只展示。
4. **降级要诚实**：无法证明的一律显式标注真实原因（`sandbox_start_failed` / `not_runtime_verifiable` / `entrypoint_unreachable` 等），绝不伪造证据、绝不静默升级。
5. **每改一处必须有断言在"框架事实"上的回归测试**；保持全测试绿（当前基线 **215 passed**）；Python 3.9（用 `Optional[...]`）；不 `git commit/push`（用户要可回溯）。

---

## 1. 现状缺口（相对 DeepAudit）

| 能力 | DeepAudit | AuditAgentX 现状 | 差距 |
|---|---|---|---|
| 入口点提取 | Recon 提取 API/entry points | `dynamic/endpoint_extractor.py` 已有路由正则 | 未接入"可达性" |
| 跨文件调用链 | 解决"跨文件调用盲点" | `interproc_taint.py`(1-hop)、`java_taint.py`、`symbol_resolver.py` | **无全项目调用图 / 无入口→sink 可达性** |
| 沙箱验证对象 | **真实项目**跑 PoC | Harness 只跑**内联 mock**代码，容器**不挂载项目源码、不装依赖** | **核心差距：没真跑项目** |
| 最高档确认 | PoC 在沙箱成功=真实可利用 | `entrypoint_reproduced`/`entrypoint_reachable` **无处产出→不可达** | **该档形同虚设** |
| 误报剔除 | 报告阶段剔除验证未过项 | 有静态复核，但动态未真正参与"剔除" | 动态验证结果未闭环回裁决 |

---

## 2. 目标能力（对标 DeepAudit，分 5 块实现）

### A. Recon 强化：入口点 + 框架 + 攻击面（复用并扩展 `endpoint_extractor.py`）
- 扩展 `extract_endpoints`：除路径/方法/框架外，**解析出每个路由绑定的 handler 函数（文件:函数名:行）**——这是可达性分析的起点。
  - Flask/FastAPI：装饰器下一行的 `def`；Django：`urls.py` 的 `path(view=...)`；Express：`app.get('/x', handler)` 的 handler 标识符。
- 输出结构：`{path, methods, framework, file, handler: {name, file, lineno}}`。
- 交付：`tests/test_endpoint_handler_extraction.py` 用最小 Flask/FastAPI 样例断言 handler 被正确解析。

### B. 跨文件调用图 + 入口→sink 可达性（新增 `backend/dynamic/reachability.py`）
> 这是"真正分析好项目"的核心之一，也是用户已拍板要实现的**入口可达性证明**。
- 新增 `build_call_graph(code_root) -> dict`：AST 遍历全项目 Python 文件，构建 `caller_func -> {callee_func_names}` 调用图（复用 `symbol_resolver` 做函数定义索引，复用 `interproc_taint` 的 `_call_name`）。
  - 至少支持 Python；Java/其它语言优雅降级（返回空图 + 标注 `unsupported_language`）。
- 新增 `prove_entrypoint_reachable(func, code_root, endpoints) -> dict`：
  - 从每个 endpoint 的 handler 出发，在调用图上做 BFS/DFS，看能否**传递地到达** `func`（漏洞函数）。
  - 返回 `{reachable: bool, path: [handler → ... → func], entrypoint: {path, method, handler}, method: "static_callgraph"}`。
  - **诚实标注**：`method="static_callgraph"` 表示"静态调用图证明存在可达路径"，**不等于**"载荷实际穿越"（后者由 D 的真实 HTTP 复现提供）。
- 交付：`tests/test_reachability.py`——构造"handler→中间函数→sink 函数"跨文件样例断言 `reachable=True`；构造"孤立 sink 函数（无入口调用）"断言 `reachable=False`（防止"同文件有路由就算可达"的假可达）。

### C. 让最高档确认真正可产出（打通 `entrypoint_reproduced` / `entrypoint_reachable`）
> 现状：`harness_tools.LEVEL_ENTRYPOINT` 有定义，但无处 set；`harness_verifier` 硬编码 `entrypoint_reachable: False`；
> `pipeline._harness_target_blockers` 因此永远阻断——最高档不可达。本块把它诚实打通。
- **组合判据**（写进 canonical `is_target_harness_confirmed`）：`entrypoint_reproduced` 成立 ⟺
  1. **函数级真实调用已被框架 nonce 证明**（现有 `function_reproduced`：scaffold + nonce，真实目标函数被真正调用 + sink 被攻击输入触发）；**并且**
  2. **入口可达性成立**：B 的 `prove_entrypoint_reachable(...).reachable == True`（静态调用图证明 HTTP 入口能走到该函数）。
- 在 `harness_verifier._finalize_verdict` 里：拿到 function_reproduced 后调用 B，把真实结果写入 `entrypoint_reachable`（不再硬编码 False），可达则 `verification_level=LEVEL_ENTRYPOINT`。
- **报告如实分档展示**：`entrypoint_reproduced`（①真实调用+②静态可达）＞ `function_reproduced`（仅①）＞ `mechanism_confirmed`（仅机理）；并在证据链里写明"②为静态可达性证明"。
- 交付：回归测试证明——只有①②同时成立才 `entrypoint_reproduced`；缺任一档降级；断言在框架合成结果上。

### D. 真实项目沙箱 PoC 验证（DeepAudit 核心：跑真项目，不是 mock）
> DeepAudit 的 Verification Agent「写 PoC 脚本并在 Docker 沙箱执行，失败自我修正重试」，对象是**真实项目**。
> AuditAgentX 已有 `docker_project_runner`（把项目在 Docker 跑起来）+ `dynamic_verifier`（真发 HTTP）。本块把它做实并闭环。
- **强化 `docker_project_runner`**：确保 deep 模式**真的挂载项目源码 + 安装依赖 + 起服务**，健康检查必须**确认应用真的响应**（探测已知端点返回非连接错误），而不是"容器在跑就算成功"（防止 D 层的自我感动）。失败如实标 `sandbox_start_failed`/`health_check_failed`。
- **ExploitAgent → DynamicVerifier 闭环**：对可达的漏洞，向 B 找到的**真实入口 endpoint** 发攻击载荷，`dynamic_verifier._judge` 命中即 `http_reproduced`（这是最强档，端到端真实复现）。
- **自我修正重试**（借鉴 DeepAudit）：PoC/harness 首次失败时，把 stderr/未命中原因回喂给生成器重试（现有 `harness_max_retries` 已是雏形，扩展到 HTTP PoC）。
- 交付：`test_docker_project_health_is_real`（模拟"容器起了但应用没响应"→ 必须判 health_check_failed，不得升 confirmed）。

### E. 验证闭环剔除误报（DeepAudit：报告阶段剔除验证未过项）
- 在 `FinalVerdictResolver`（或现有裁决点）中明确：
  - HTTP 真实复现 (`http_reproduced`) 或 `entrypoint_reproduced` → `confirmed`；
  - `function_reproduced` / `mechanism_confirmed` → **保持 needs_review**（有支撑但未端到端证明，不自动 confirmed）；
  - 动态明确"可达且已跑但未复现" → 可作为**降权/误报**信号（但 HTTP 失败 ≠ 一定误报，要区分 `not_reproduced` 与 `connection_failed`）。
- 报告新增"验证闭环"小节：每条漏洞展示 `入口可达性 / 真实调用证明 / HTTP 复现 / 最终档位`，让"分析透没透"一目了然。

---

## 3. 涉及文件（改动清单）

- `backend/dynamic/endpoint_extractor.py`（A：handler 解析）
- `backend/dynamic/reachability.py`（B：**新增**，调用图 + 可达性）
- `backend/skills/harness_tools.py`（C：canonical 判据纳入 entrypoint_reachable；勿破坏 nonce 机制）
- `backend/verifier/harness_verifier.py`（C：`_finalize_verdict` 真实计算 entrypoint_reachable）
- `backend/verifier/pipeline.py`（C/D：`_harness_target_blockers` 与新判据对齐；闭环 HTTP 复现）
- `backend/verifier/docker_project_runner.py`（D：真实挂载/装依赖/健康检查）
- `backend/verifier/dynamic_verifier.py`（D：对真实入口发包；自我修正）
- `backend/agents/exploit_agent.py`（D：针对可达入口生成 PoC）
- `backend/verifier/verdict_resolver.py`（E：唯一裁决，闭环剔除）
- `backend/report/*`（E：验证闭环展示）
- 对应 `tests/` 回归测试（每块都要）

---

## 4. 验收标准

1. 全测试绿（≥215 passed + 新增回归），且新测试**断言在框架独立观测的事实上**，不得断言自报字段。
2. **可复现的对抗性验证**：
   - 只自报的脚本仍无法达 `entrypoint_reproduced`（沿用现有 nonce 防线）；
   - "孤立 sink 函数（无入口调用）"即使函数级真实调用成立，也只到 `function_reproduced`，**不得** `entrypoint_reproduced`；
   - "容器起了但应用不响应"必须判 `health_check_failed`，不得升 confirmed。
3. 真跑通至少一个轻量真实靶场（如 Vulnerable-Flask-App）：deep 报告出现**真实 `http_reproduced` 或 `entrypoint_reproduced`** 证据（Docker 就绪时）。
4. 报告能清晰展示"入口可达性 / 真实调用 / HTTP 复现 / 最终档位"四要素。

---

## 5. 诚实边界（写进报告，不藏）

- 静态可达性 ≠ 载荷实际穿越；两者在证据链里分别标注。
- 无 Docker / 项目起不来 / 非 Python 时如实降级，绝不为"好看"造证据。
- `mechanism_confirmed` 永远封顶 0.75、不升 confirmed；`function_reproduced` 不自动 confirmed。
- 目标不是"100% 全确认"，而是**每一档都有与之匹配的真实证据**——这正是相对 DeepAudit 也要坚持的底线。
