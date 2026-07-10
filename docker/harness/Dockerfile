# AuditAgentX 固定预构建 Harness 验证镜像（Python）
#
# 目的：为「函数级 / 模块级真实源码 Harness」提供一个固定、最小、预装常见框架依赖的
# 验证镜像，让 scaffold 能 `import` 项目真实模块跑真实代码——而不是每个候选临时 build 镜像。
#
# 构建：
#   docker build -t auditagentx-harness-python:latest docker/harness
# 启用（在 .env 或环境变量）：
#   harness_sandbox_image=auditagentx-harness-python:latest
#
# 安全：本镜像只提供解释器与依赖；真正的隔离由执行器在 run 时叠加
# （network=none、read_only、cap_drop=ALL、no-new-privileges、pids/mem/cpu/timeout 限制、
#  仅只读挂载 /target 源码 + 独立临时 harness 目录、不挂 docker socket、不继承宿主代理）。
FROM python:3.11-slim

# 覆盖大多数真实 Python 项目 import 所需的常见 web / 模板 / 序列化 / DB 框架。
# 仅安装库本体，不安装编译链，保持镜像小、攻击面低。
RUN pip install --no-cache-dir \
        flask \
        fastapi \
        starlette \
        httpx \
        jinja2 \
        pyyaml \
        lxml \
        requests \
        sqlalchemy \
        werkzeug \
        markupsafe \
        itsdangerous \
        click \
    && rm -rf /root/.cache /tmp/*

# 默认以 nobody 运行（执行器还会再叠加 user/cap/network 等限制）。
USER 65534:65534

# 不设 ENTRYPOINT：执行器以 `python -c <harness>` 方式一次性调用。
