# AuditAgentX API 文档

基础地址：`http://localhost:8000`　交互式文档：`/docs`（Swagger UI）

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/api/projects` | 创建项目 |
| GET | `/api/projects` | 项目列表 |
| POST | `/api/projects/{project_id}/parse` | 解析项目元信息 |
| GET | `/api/projects/{project_id}/tree` | 获取目录树 |
| POST | `/api/scans` | 创建扫描任务（后台异步执行） |
| GET | `/api/scans/{scan_id}` | 查询扫描状态与进度 |
| GET | `/api/scans/{scan_id}/findings` | 获取漏洞列表 |
| GET | `/api/findings/{finding_id}` | 获取漏洞详情 |
| GET | `/api/findings/{finding_id}/evidence` | 获取证据链 |
| POST | `/api/reports` | 生成报告 |
| GET | `/api/reports/{report_id}/download` | 下载报告 |
| GET | `/api/agents` | 列出系统内置智能体 |

## 典型调用顺序

```bash
# 1. 创建项目
curl -X POST localhost:8000/api/projects -H "Content-Type: application/json" \
  -d '{"name":"demo","source_type":"local","local_path":"examples/vulnerable_projects/demo_flask_app"}'

# 2. 解析（返回 project_id 假设为 proj_xxx）
curl -X POST localhost:8000/api/projects/proj_xxx/parse

# 3. 创建扫描
curl -X POST localhost:8000/api/scans -H "Content-Type: application/json" \
  -d '{"project_id":"proj_xxx","enabled_tools":["custom","semgrep"],"enabled_agents":["audit","verify"]}'

# 4. 轮询状态（scan_xxx）
curl localhost:8000/api/scans/scan_xxx

# 5. 查看漏洞
curl localhost:8000/api/scans/scan_xxx/findings

# 6. 生成报告
curl -X POST localhost:8000/api/reports -H "Content-Type: application/json" \
  -d '{"scan_id":"scan_xxx","format":"html"}'
```

字段详情见 md 规划文档第 7 节与 `backend/schemas.py`。
