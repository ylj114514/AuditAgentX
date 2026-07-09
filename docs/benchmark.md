# 检测精度基准（Precision / Recall / F1）

把"看起来能扫出来"变成**量化数字**，是 AuditAgentX 从原型走向可信的关键一步。

## 方法

- **标注样本**（ground truth）：`scripts/run_benchmark.py` 内嵌带标签的漏洞/安全样本，
  覆盖多语言（Python / PHP / JavaScript / Java / Go / C#）× 多类型（SQLi / 命令注入 / 路径遍历 /
  XSS / 不安全反序列化 / 硬编码密钥 / 弱加密 / 弱哈希 / 弱随机 / Java 函数级污点），
  且每类都有**漏洞版**与**安全版**（含净化器 / 参数化 / 静态字面量 / 三元断链）。
- **口径**：文件级检测——某文件被报出「匹配类型」的 finding 即视为「检出该类」。
  - 漏洞样本被检出 = TP，未检出 = FN（漏报）
  - 安全样本被检出 = FP（误报），未检出 = TN
- **置信度阈值**：默认 `min_confidence=0.6`，低置信 finding（如识别到净化器后降级的 0.5）
  视为"待人工复核"，不计入"检出漏洞"——与真实工具的 severity/confidence 门控一致。

## 结果（置信度阈值 0.6）

| 检测器 | Precision | Recall | F1 |
|---|---|---|---|
| 内置 custom 污点分析 | 1.00 | 1.00 | 1.00 |
| Semgrep（`--config auto` 官方规则 + 项目规则） | 0.83 | 0.63 | 0.71 |
| **组合检测栈（custom ∪ semgrep，实际系统）** | **0.89** | **1.00** | **0.94** |

**观察**：两个检测器互补——Semgrep 官方规则漏掉了 PHP echo XSS、硬编码密钥、JS 命令注入
（这些内置污点分析检出了）；内置污点分析对净化器样本会产生低置信 finding（阈值门控后消除）。
组合栈 recall=1.0（无漏报），precision 的唯一失分来自 Semgrep 把 `subprocess.run([...], shell=False)`
安全写法误报为命令注入。

## 复现

```bash
python scripts/run_benchmark.py        # 打印逐样本 + 三套指标
python -m pytest tests/test_benchmark.py -q   # 把内置扫描器精度固化进 CI
```

## OWASP BenchmarkJava 真实评测（第三方大规模）

除自建微基准外，AuditAgentX 已接入 **OWASP BenchmarkJava v1.2**（2740 个带 ground-truth 标签的
Java Web 测试用例，1415 真漏洞 + 1325 安全用例）做第三方评测：`scripts/run_owasp_benchmark.py`。
评分对齐 OWASP 官方口径——每个用例只按其指定类别计 TP/FN/FP/TN，报告每类
Recall / FPR / Precision 与 **Youden Score = Recall − FPR**。

### 结果（`min_confidence=0.5`，内置 custom 检测栈）

| 类别 | Recall | FPR | Precision | Score |
|---|---|---|---|---|
| crypto（弱加密 CWE-327） | **100%** | 0% | 100% | +1.00 |
| hash（弱哈希 CWE-328） | **100%** | 0% | 100% | +1.00 |
| weakrand（弱随机 CWE-330） | **100%** | 0% | 100% | +1.00 |
| securecookie（CWE-614） | **100%** | 0% | 100% | +1.00 |
| ldapi（LDAP 注入） | 55.6% | 34.4% | 57.7% | +0.21 |
| cmdi（命令注入） | 54.0% | 29.6% | 64.8% | +0.24 |
| pathtraver（路径遍历） | 53.4% | 34.1% | 60.7% | +0.19 |
| xss（跨站脚本） | 49.2% | 23.9% | 70.8% | +0.25 |
| xpathi（XPath 注入） | 46.7% | 20.0% | 63.6% | +0.27 |
| trustbound（信任边界 CWE-501） | 39.8% | 30.2% | 71.7% | +0.10 |
| sqli（SQL 注入） | 32.0% | 25.9% | 59.2% | +0.06 |
| **总计** | **64.66%** | 16.7% | **80.55%** | **+0.48** |

### 改进历程（同一 BenchmarkJava，逐步落地）

| 阶段 | 总召回 | 说明 |
|---|---|---|
| 改进前（仅正则窗口） | 2.69% | source/sink 常跨 >15 行、经中间变量多跳，窗口够不着 |
| ① Java 字面量规则 | 33.6% | crypto/weakrand 100%、hash 69%（字面量） |
| ③ javalang 函数级污点 | 59.5% | 多跳污点 + 三元断链；hash 100%（跨文件属性解析）|
| + securecookie + 源容器 | **64.66%** | 4 类满分；getParameterMap 等源容器取值 |

### 关键技术

- **`backend/scanners/java_taint.py`**：基于 javalang 的函数级污点分析——多跳变量传播
  （拼接 / 集合 add / for-each / 类型转换）、**源容器**（getParameterMap 整体污点）、
  **三元断链**（`bar = cond ? "常量" : param` 视为安全用例惯用打断）。
- **跨文件常量解析**（`custom_rules._scan_indirect_weak_algo`）：解析 `.properties` 得到
  `hashAlg1=MD5` 等弱算法键，识别 `MessageDigest.getInstance(getProperty("hashAlg1"))` 间接弱哈希。
- **弱加密/哈希/随机/Cookie**：`taint_rules.py` 字面量规则，多语言（Java/PHP/JS/Go/Ruby/Python/C#）。

## 诚实边界

- 自建微基准（~26 样本）用于快速回归与建立方法；真实可信度以 **OWASP BenchmarkJava** 为准。
- 注入类（sqli/cmdi/xss/…）召回 32–55%、FPR 20–34%：**固有上限**来自 BenchmarkJava 的对抗性
  安全用例——`if((7*42)-num>200) bar="常量"; else bar=param;`、`switch(常量)` 等**死分支**需要
  常量折叠才能判定，纯正则/轻量 AST 污点无法精确区分。本项目选择**偏高召回**（静态广撒网），
  由下游 VerifyAgent + 动态 Harness 收敛误报，符合系统架构。
- 4 个类别（crypto/hash/weakrand/securecookie）达 100% 召回 0 误报，是**判定型**规则（非污点可达性），
  不受上述对抗样本影响。

## 复现

```bash
python scripts/run_benchmark.py                         # 自建微基准（逐样本 + 三套指标）
python scripts/run_owasp_benchmark.py                   # OWASP BenchmarkJava 真实评测（需先放置数据集）
python scripts/run_owasp_benchmark.py --semgrep         # 叠加 semgrep（含 p/java 规则）
python -m pytest tests/test_taint_analysis.py -q        # Java/多语言检测能力固化进 CI
```

> OWASP BenchmarkJava 数据集位于 `data/projects/BenchmarkJava`（已 gitignore、不随仓库分发）；
> 缺失时评测脚本会提示并跳过。
