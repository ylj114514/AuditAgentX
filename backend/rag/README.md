# backend/rag —— 安全知识增强（RAG）

借鉴 [DeepAudit](https://github.com/lintsinghua/DeepAudit) 的 RAG 思路（CWE/CVE 知识增强审计），
用**轻量、离线、确定性**的知识检索为多个智能体提供 CWE/OWASP 安全知识，提升判定准确性与修复建议质量。
不依赖向量库 / 付费 embedding，纯关键词 + 元数据打分检索。

## 文件说明

| 路径 | 职责 |
|---|---|
| `models.py` | `SecurityKnowledgeItem`：一条结构化知识（CWE/OWASP/source/sink/验证要点/误报信号/修复/引用） |
| `retriever.py` | `SecurityKnowledgeRetriever`：关键词 + CWE 精确匹配(+20) + 类型匹配(+16) + source/sink 加权检索 |
| `sources/cwe_core.json` | CWE 核心知识库（17 条，覆盖 strategy.py 全部支持的漏洞类型） |
| `sources/verification_playbooks.json` | 验证 playbook 知识 |
| `sources/remediation_guides.json` | 修复指南知识 |

## 知识库覆盖（17 类 CWE）

SQL注入(89) · 命令注入(78) · 路径遍历/LFI/RFI(22) · XSS(79) · SSRF(918) · 反序列化(502) ·
硬编码密钥(798) · 代码注入(94) · SSTI(1336) · XXE(611) · 文件上传(434) · IDOR/越权(639) ·
开放重定向(601) · NoSQL/LDAP/XPath 注入(943) · 弱加密/弱哈希(327) · 依赖 CVE(1104) · 配置不当(16)

> 测试 `test_rag_agent_integration.py` 保证知识库**覆盖 strategy.py 的所有漏洞类型（0 未命中）**。

## 三处接入（谁用、怎么用）

| 智能体 | 用途 | 接入点 |
|---|---|---|
| **AuditAgent** | 审计发现阶段：按命中类型检索知识作 `security_knowledge` 喂 LLM，帮更准判断"像哪类 CWE"、用误报信号降误报 | `_retrieve_knowledge()` |
| **VerifyAgent** | 复核阶段：经 MCP 工具 `retrieve_security_knowledge` 检索，写入证据链 `knowledge` 字段 | MCP + Skill |
| **ReportAgent** | 报告阶段：按漏洞类型检索**标准修复建议**，让报告引用 CWE/OWASP 措施而非泛泛而谈 | `_retrieve_remediation()` |

## MCP 工具（对外暴露）

`retrieve_security_knowledge` / `retrieve_verification_playbook` / `retrieve_remediation_advice`，
外部 agent 也可经 MCP 调用本知识库。

## 扩充知识库

编辑 `sources/*.json` 追加条目（字段见 `models.py`），或用 `scripts/gen_kb.py` 批量生成。
`load_default_items()` 带 LRU 缓存，测试中改库后需 `.cache_clear()`。

## 进阶方向（可选）

当前为关键词检索（Phase 1）。若需语义检索，可在 retriever 增加本地 `sentence-transformers`
embedding + faiss/chromadb 作为 Phase 2，与关键词版并存。
