# Docker 与真实动态验证操作手册

本手册面向 AuditAgentX 的本地课程实验。动态验证只能用于你拥有或明确获授权的代码、Docker 本地靶场和回环地址；请不要填写公网第三方站点。

## 1. 先确认基础环境

在 PowerShell 中进入项目根目录后执行：

```powershell
docker version
docker compose version
python --version
node --version
```

`docker version` 必须同时显示 Client 和 Server。只有 Client 或出现 named-pipe / daemon 错误时，先启动 Docker Desktop，等待状态变为 Running 后再扫描。

本机启动开发环境：

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn backend.main:app --reload --host 127.0.0.1 --port 8000
```

另开一个 PowerShell：

```powershell
cd frontend
npm install
npm run dev
```

前端地址以 Vite 输出为准，通常是 `http://127.0.0.1:5173`。后端 API 是 `http://127.0.0.1:8000`。

## 2. Deep 模式的两条运行路径

| 路径 | 适用项目 | 前端选择 | 优点 | 限制 |
|---|---|---|---|---|
| 自动构建 | 单体 Flask、FastAPI、Django、Node/Express、Spring、PHP | `自动构建 Docker 沙箱` | 自动识别框架、依赖、端口和源码路由 | 不会默认执行不可信项目 Compose |
| URL 模式 | 已手工启动的服务、多服务项目、需要登录/数据库初始化的靶场 | `已运行靶场 URL` | 启动链路可控，最适合 DVWA/Juice Shop/NodeGoat | 当前不会自动登录或管理复杂会话 |

自动构建时，`install_command`、`run_command`、`port`、`健康检查路径` 都可以留空。灰色文字只是示例，不会提交。系统会从框架特征、依赖清单、Dockerfile 和受限 README 指令推断启动计划。

当前自动识别会处理嵌套服务目录，例如 `backend/main.py`、`server/package.json`、`app/requirements.txt`；构建容器会在对应工作目录安装依赖和启动，而不是一律在仓库根目录执行。

## 3. 项目 Dockerfile / Compose 复选框该怎么用

默认不信任被扫描仓库的 Dockerfile 与 Compose。这是因为它们本身属于不可信输入，可能包含宿主机卷挂载、Docker Socket、特权容器或危险构建步骤。

当项目是单服务应用时，保持默认关闭即可。AuditAgentX 会生成受限 Dockerfile，容器有内存、进程数、能力和提权限制。

只有同时满足以下条件才勾选“我已审查该项目，允许使用项目自带 Dockerfile / docker-compose”：

1. 项目是本地授权靶场，且确实需要 MySQL、MongoDB、Redis 等多服务依赖。
2. 你已阅读 Compose，确认没有 `privileged`、`network_mode: host`、`/var/run/docker.sock`、宿主机绝对路径卷、`devices`、`cap_add` 等危险项。
3. 你接受该项目的构建步骤会在 Docker 中运行。

即使勾选，后端仍会拒绝上述高风险 Compose 配置。DVWA、NodeGoat、crAPI 等项目优先选择“手工启动 + URL 模式”，可把项目启动问题与扫描器问题分开诊断。

## 4. 第一个真实回归：项目自带 Flask 靶场

这是最短的端到端验收路径：

```powershell
python -c "from pathlib import Path; from backend.verifier.pipeline import ExploitPipeline; findings=[{'type':'SQL Injection','file':'app.py','start_line':28,'status':'needs_review','severity':'high','confidence':0.7,'code_snippet':'sqlite execute concatenation','_verify':{}}]; ExploitPipeline(scan_id='manual_demo').run(findings, enable_exploit=False, enable_dynamic=True, enable_harness=False, dynamic_target={'mode':'docker_project','scan_id':'manual_demo'}, code_root=Path('examples/vulnerable_projects/demo_flask_app')); print(findings[0]['runtime_verification_status']); print(findings[0]['_dynamic']['confirmed_record'])"
```

预期结果是 `dynamic_confirmed`。证据应同时包含：

- 良性基线：`GET /user?id=1` 返回 200；
- 攻击请求：相同端点的 SQL 载荷返回 500；
- 攻击后新增的容器日志中出现 `sqlite3.OperationalError`；
- 静态定位到 `app.py` 的 SQL 字符串拼接位置。

这四项缺一不可。单独的 Harness 触发、单次 500、服务已启动或载荷成功发送都不能算漏洞确认。

## 5. 前端操作流程

1. 打开“创建项目”，填写 Git 仓库 URL 或上传本地项目。
2. 选择 `Deep Docker 沙箱`。
3. 单服务项目选择“自动构建 Docker 沙箱”；无法识别时再填写真实命令，例如 `python app.py` 或 `npm start`。
4. 多服务项目先按其官方文档手工启动，再选择“已运行靶场 URL”，填写 `http://127.0.0.1:<端口>`。
5. 等待扫描完成，在漏洞详情里检查“运行时证据”：请求、基线、响应/容器日志差异、判据名称和 Docker 状态。

## 6. 推荐开源靶场与启动方式

### we45/Vulnerable-Flask-App

仓库：<https://github.com/we45/Vulnerable-Flask-App>

它是单体 Flask 项目，适合作为自动构建回归目标。仓库较旧，若 Python 依赖与当前基础镜像不兼容，报告会明确显示 `dependency_install_failed`，而不会伪装成“没有漏洞”。这种情况下优先用项目官方 Dockerfile（人工审查后勾选复选框）或选择 URL 模式。

### OWASP Juice Shop

仓库：<https://github.com/juice-shop/juice-shop>

官方容器启动：

```powershell
docker run --rm --name audit-juice -p 127.0.0.1:3000:3000 bkimminich/juice-shop
```

随后在前端选择 URL 模式并填写 `http://127.0.0.1:3000`。它适合验证 Node、JSON API、SPA 发现和路由提取；涉及登录的挑战目前需要手工准备会话。

### DVWA

仓库：<https://github.com/digininja/DVWA>

```powershell
git clone https://github.com/digininja/DVWA.git
cd DVWA
docker compose up -d
```

默认 URL 是 `http://127.0.0.1:4280`。先在浏览器完成数据库初始化并设置安全等级，再使用 URL 模式。DVWA 需要登录和状态管理，因此适合检验启动/路由/基础注入，不应在当前版本中把未建立双账号和会话的 IDOR 结果称为确认。

## 7. 看懂失败状态

| 状态 | 含义 | 下一步 |
|---|---|---|
| `started` | 容器已启动且本地健康检查可访问 | 查看 HTTP 基线和攻击记录 |
| `dependency_install_failed` | 真实依赖安装失败 | 阅读 `logs_excerpt`；调整基础镜像、锁定依赖或改用官方容器 |
| `health_check_failed` | 容器存在但 HTTP 未就绪 | 核对端口、监听地址、健康路径和容器日志 |
| `launch_not_detected` | 没有安全可执行的 Web 启动方式 | 填写 `run_command`/`port`，或用 URL 模式 |
| `not_web_target` | 原生 CLI、库或系统项目 | 做静态分析/函数级验证，不要强行当 Web 服务 |
| `not_reproduced` | 已发出真实探测但未满足证据判据 | 不是“无漏洞”；检查认证、路由、参数、载荷和判据 |
| `dynamic_confirmed` | 同入口基线与攻击证据满足专用判据 | 再人工复查 source-to-sink 和影响范围 |

## 8. 当前可信度边界

已能作为端到端确认依据的重点类型是：错误/日志可观测 SQL 注入、带唯一回显标记的命令注入、路径穿越读取特征内容、SSTI 表达式求值，以及稳定的成对时间差异。

当前 XSS 只做候选探测，不会因文本反射自动确认；SSRF 需要独立回连服务；IDOR/认证绕过需要至少两个已认证身份；文件上传需要上传后再访问的完整链路。这些限制会在报告中保留，而不是被 Harness 或模板代码掩盖。

## 9. 维护与验证命令

```powershell
python -m pytest tests -q
cd frontend
npm run build
```

动态验证核心回归：

```powershell
python -m pytest tests/test_runtime_surface.py tests/test_dynamic_verify.py tests/test_docker_deep_mode.py tests/test_adversarial_verification.py -q
```
