# backend/dynamic —— 动态分析规则库

为 `DynamicAnalysisAgent` 提供动态验证的三类决策规则：**启动方式识别、端点提取、策略映射**。
纯规则/确定性逻辑，不依赖 LLM，离线可用。

## 文件说明

| 文件 | 职责 |
|---|---|
| `strategy.py` | 漏洞类型 → 动态验证策略映射（http / harness / both / not_applicable），覆盖 30+ 漏洞类型 |
| `launch_detector.py` | 自动识别项目启动方式（Flask/FastAPI/Django/Express/Spring/PHP/Docker），推断启动命令与端口 |
| `endpoint_extractor.py` | 自动提取路由/端点（多框架正则），确定动态验证攻击面 |
| `symbol_resolver.py` | **Vulnhuntr 式跨文件符号解析**：按名字找函数/类定义源码，供 AuditAgent 递归补全调用链 |

## symbol_resolver.py（Vulnhuntr 式调用链补全）

传统做法只给 LLM「命中文件的局部片段」，看不到跨文件调用，跨文件逻辑漏洞会漏。
参照 [protectai/vulnhuntr](https://github.com/protectai/vulnhuntr)：从命中点出发，递归向其他文件
索要被引用的函数/类定义，拼出「用户输入 → 跨文件传播 → sink」的完整链路。

- `resolve_symbol(code_root, symbol)`：Python 用标准库 `ast` 精确索引定义，其他语言正则兜底；返回定义源码。
- `extract_referenced_symbols(code_snippet)`：从片段抽取被调用符号名（过滤内置/关键字）。
- `AuditAgent._expand_call_chain()`：广度优先递归补全（限深度/总量），结果作为 `cross_file_call_chain` 喂给 LLM。
- 已封装为 MCP 工具 `resolve_symbol`，外部 agent 也可调用。**不引入 jedi 等第三方依赖，离线可用。**

## strategy.py：策略取值

| 策略 | 含义 | 例子 |
|---|---|---|
| `http` | 适合对运行中靶场发 HTTP 载荷 | SSRF / XSS / IDOR / Open Redirect |
| `harness` | 适合函数级 Fuzzing Harness（无需靶场） | 反序列化 / 代码注入 / LDAP 注入 |
| `both` | 两者都适用（优先 harness，有靶场再补 http） | SQL 注入 / 命令注入 / 路径遍历 / SSTI |
| `not_applicable` | 静态类，无运行时触发点（**dynamic_not_applicable**） | 硬编码密钥 / 弱加密 / CVE 依赖 / 缺失安全头 |

`resolve_strategy(vuln_type)` 支持精确匹配、别名（sqli/rce/lfi…）、子串匹配、默认兜底。
`is_dynamic_applicable(vuln_type)` 快速判断是否适合动态验证。

## launch_detector.py

`detect_launch(code_root)` 返回 `{framework, command, port, health_path, dockerfile, compose, confidence, notes}`。
- Docker/compose 优先（最可靠），其次按框架特征文件识别（manage.py→Django、FastAPI()→FastAPI、Flask()→Flask、package.json→Node、pom.xml+spring→Spring Boot、index.php→PHP）。
- `command` 中的 `{port}` 占位符由 `LocalAppRunner` 分配端口时填充。

## endpoint_extractor.py

`extract_endpoints(code_root)` 返回 `{endpoints:[{path,methods,framework,file}], count, frameworks}`。
支持 Flask `@app.route`、FastAPI `@app.get`、Express `app.post`、Django `path()/re_path()`、
Spring `@GetMapping`、PHP `Route::get`。路径自动归一化（`<int:id>`/`{id}`/`:id`/Django 命名组 → 占位）。
`candidate_endpoints(code_root)` 返回去重路径列表并附常见兜底端点，供动态验证使用。

## 使用方（DynamicAnalysisAgent）

```python
agent = DynamicAnalysisAgent()
plan = agent.plan(findings, code_root)   # 决策：启动识别 + 端点 + 策略，供展示
agent.run(findings, code_root=code_root, enable_harness=True)  # 执行动态验证
```
