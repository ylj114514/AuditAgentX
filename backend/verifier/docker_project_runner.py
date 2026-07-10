"""DockerProjectRunner —— Docker-first Deep Mode 沙箱：在容器内启动 GitHub 项目。

流程：code_root + launch_plan → 生成/复用 Dockerfile → build → run → 健康检查 → base_url。
退出时自动 docker rm -f 清理容器，并采集 docker logs 摘要。

安全边界：仅用于本地 Docker 沙箱 / 授权目标；容器限内存，扫描后即销毁。
失败时如实返回状态（sandbox_start_failed / health_check_failed / dependency_install_failed），
绝不造假复现结果。

复用：端口分配 / 健康检查复用 app_runner 的 _free_port / _wait_healthy，不重复实现。
"""
from __future__ import annotations

import json as _json
import logging
import re
import subprocess
import time
from contextlib import contextmanager
from pathlib import Path

from backend.verifier.app_runner import _free_port, _wait_healthy, get_docker_client

logger = logging.getLogger(__name__)

# 沙箱状态
STARTED = "started"
SANDBOX_START_FAILED = "sandbox_start_failed"
HEALTH_CHECK_FAILED = "health_check_failed"
DEPENDENCY_INSTALL_FAILED = "dependency_install_failed"
LAUNCH_NOT_DETECTED = "launch_not_detected"   # 预检：无法自动识别启动方式，未尝试构建
NOT_WEB_TARGET = "not_web_target"             # 原生 CLI/系统项目：HTTP 项目沙箱不适用
UNSAFE_PROJECT_CONFIG = "unsafe_project_config"  # 项目容器配置违反沙箱策略


def _first_line(text: str, limit: int = 200) -> str:
    """取错误信息的首个有效行，便于生成可读 reason。"""
    for line in str(text).splitlines():
        line = line.strip()
        if line:
            return line[:limit]
    return str(text)[:limit]


def _diagnostic_tail(text: str, limit: int = 1200) -> str:
    """保留 Compose 错误末尾；真正原因通常在大量 Pulling/Waiting 输出之后。"""
    lines = [line.strip() for line in str(text).splitlines() if line.strip()]
    return "\n".join(lines[-12:])[-limit:]


def _transient_pull_failure(text: str) -> bool:
    lower = str(text).lower()
    return any(token in lower for token in (
        " eof", "context canceled", "tls handshake timeout", "i/o timeout",
        "connection reset", "temporary failure", "unexpected status from head request",
        "auth.docker.io", "registry-1.docker.io",
    ))


def build_dockerfile(launch_plan: dict, port: int) -> str:
    """SandboxBuilder：按 launch_plan 生成最小 Dockerfile（无项目 Dockerfile 时）。"""
    framework = (launch_plan.get("framework") or "").lower()
    install = launch_plan.get("install_command")
    run = launch_plan.get("run_command") or launch_plan.get("command") or ""
    run = run.replace("{port}", str(port))
    workdir = _safe_workdir(launch_plan.get("working_dir"))
    app_workdir = "/app" + ("/" + workdir if workdir else "")

    if "node" in framework or "express" in framework:
        install = install or "npm install"
        return (
            "FROM node:20-slim\n"
            "WORKDIR /app\n"
            "COPY . /app\n"
            f"WORKDIR {app_workdir}\n"
            f"RUN {install}\n"
            f"EXPOSE {port}\n"
            f"CMD {_cmd_json(run)}\n"
        )
    if "php" in framework:
        return (
            "FROM php:8.2-cli\n"
            "WORKDIR /app\n"
            "COPY . /app\n"
            f"WORKDIR {app_workdir}\n"
            + (f"RUN {install}\n" if install else "")
            + f"EXPOSE {port}\n"
            f"CMD {_cmd_json(run)}\n"
        )
    if "spring" in framework or "java" in framework:
        return (
            "FROM eclipse-temurin:17-jdk\n"
            "WORKDIR /app\n"
            "COPY . /app\n"
            f"WORKDIR {app_workdir}\n"
            + (f"RUN {install}\n" if install else "")
            + f"EXPOSE {port}\n"
            f"CMD {_cmd_json(run)}\n"
        )
    # 默认 Python
    install = install or "pip install --no-cache-dir -r requirements.txt"
    return (
        "FROM python:3.11-slim\n"
        "WORKDIR /app\n"
        "COPY . /app\n"
        f"WORKDIR {app_workdir}\n"
        # 不能用 `|| pip install flask ...` 吞掉真实依赖失败；否则容器“构建成功”但实际
        # 项目依赖缺失，最终把问题伪装成无意义的健康检查失败。
        f"RUN {install}\n"
        f"EXPOSE {port}\n"
        f"CMD {_cmd_json(run)}\n"
    )


def _safe_workdir(value: str | None) -> str:
    """把源码识别出的相对工作目录转为 Docker 内安全路径。"""
    raw = str(value or ".").replace("\\", "/").strip("/")
    if not raw or raw == ".":
        return ""
    parts = [part for part in raw.split("/") if part and part not in {".", ".."}]
    return "/".join(parts)


def _cmd_json(run_command: str) -> str:
    """把启动命令转成 Dockerfile CMD。

    使用 ``sh -c`` 而不是简单 split 成 argv，原因：
    - Java/Spring 常见 ``target/*.jar`` 需要 shell 展开通配符；
    - 用户手动填写的命令可能包含引号、环境变量或 ``&&``；
    - npm/pip 等命令以 shell 运行更贴近日常启动方式。
    """
    return _json.dumps(["sh", "-c", run_command or "true"], ensure_ascii=False)


class DockerProjectRunner:
    """上下文管理器：进入返回 self（含 base_url / metadata），退出清理容器。"""

    def __init__(self, code_root: Path, launch_plan: dict | None = None,
                 *, env: dict | None = None, scan_id: str | None = None,
                 trust_project_container_config: bool = False,
                 build_timeout: int = 600, health_timeout: int = 40) -> None:
        # Compose 命令会以 code_root 作为 cwd；这里必须先绝对化，否则 `-f` 收到相对
        # 路径时会被 cwd 再拼接一次（data/projects/.../data/projects/...）。
        self.code_root = Path(code_root).resolve()
        self.launch_plan = launch_plan or {}
        self.env = env or {}
        self.scan_id = scan_id or "adhoc"
        self.trust_project_container_config = bool(trust_project_container_config)
        self.build_timeout = build_timeout
        self.health_timeout = health_timeout

        self.base_url: str | None = None
        self.metadata: dict = {
            "mode": "docker_project",
            "code_root": str(self.code_root),
            "launch_plan": self.launch_plan,
            "image": f"auditagentx-{re.sub(r'[^a-z0-9]', '', self.scan_id.lower())[:20] or 'scan'}",
            "container_id": None,
            "base_url": None,
            "port": self.launch_plan.get("port") or 8000,
            "health_path": self.launch_plan.get("health_path") or "/",
            "working_dir": _safe_workdir(self.launch_plan.get("working_dir")) or ".",
            "health_check": "failed",
            "launch_command": (self.launch_plan.get("run_command")
                               or self.launch_plan.get("command")),
            "image_build_attempted": False,
            "container_start_attempted": False,
            "logs_excerpt": "",
            "status": SANDBOX_START_FAILED,
            "reason": "",
            "diagnostics": [],
            "trust_project_container_config": self.trust_project_container_config,
        }
        self._client = None
        self._container = None
        # docker compose 编排（多服务项目）时记录，供清理使用
        self._compose_project: str | None = None
        self._compose_file: str | None = None
        self._generated_dockerfile_name: str | None = None

    def __enter__(self) -> "DockerProjectRunner":
        try:
            self._start()
        except _DependencyError as e:
            self.metadata["status"] = DEPENDENCY_INSTALL_FAILED
            self.metadata["logs_excerpt"] = str(e)[:800]
            self.metadata["reason"] = "镜像构建时依赖安装失败：" + _first_line(str(e))
            logger.warning("沙箱依赖安装失败: %s", e)
        except Exception as e:  # noqa: BLE001
            self.metadata["status"] = SANDBOX_START_FAILED
            self.metadata["logs_excerpt"] = _diagnostic_tail(str(e), 1200)
            self.metadata["reason"] = "沙箱构建/启动失败：" + _diagnostic_tail(str(e), 500)
            logger.warning("沙箱启动失败: %s", e)
        return self

    def __exit__(self, *exc) -> None:
        self._cleanup()

    # ---------- 内部 ----------
    def _start(self) -> None:
        if not self.code_root.exists() or not self.code_root.is_dir():
            raise RuntimeError(f"code_root 不存在或不是目录: {self.code_root}")
        internal_port = int(self.metadata["port"])
        host_port = _free_port()
        base_url = f"http://127.0.0.1:{host_port}"
        image_tag = self.metadata["image"]

        if self.launch_plan.get("runtime_kind") == "native_cli":
            self.metadata["status"] = NOT_WEB_TARGET
            self.metadata["reason"] = (
                "项目被识别为原生 CLI/系统软件，不存在可自动健康检查的 HTTP 服务；"
                "HTTP 项目沙箱不适用，已保留静态验证与函数级 Harness 结果。"
            )
            self.metadata["diagnostics"].append(
                f"non-web runtime detected from {self.launch_plan.get('source_evidence') or 'project structure'}"
            )
            return

        project_dockerfile = (self.code_root / "Dockerfile").exists()
        has_dockerfile = project_dockerfile and self.trust_project_container_config
        run_command = self.launch_plan.get("run_command") or self.launch_plan.get("command")
        compose = self.launch_plan.get("compose")

        if project_dockerfile and not self.trust_project_container_config:
            self.metadata["diagnostics"].append(
                "ignored untrusted project Dockerfile; using generated restricted Dockerfile"
            )

        # 0) 多服务项目：若检测到 docker-compose，优先按项目既定方式编排启动
        #    （单容器无法提供 DB/Redis 等依赖服务，这是真实开源项目动态验证失败的高频原因）。
        if compose and (self.code_root / compose).exists():
            policy = _validate_compose_policy(self.code_root / compose)
            if not policy["allowed"]:
                self.metadata["status"] = UNSAFE_PROJECT_CONFIG
                self.metadata["reason"] = "项目 docker-compose 被安全策略阻止：" + policy["reason"]
                self.metadata["diagnostics"].extend(policy["checks"])
                return
            if not self.trust_project_container_config:
                self.metadata["diagnostics"].append(
                    "compose configuration auto-approved by restricted policy; direct project Dockerfile remains disabled"
                )
            self.metadata["container_start_attempted"] = True
            self.metadata["diagnostics"].append(f"using docker compose file: {compose}")
            self._run_compose(compose, self.launch_plan.get("port"))
            return

        # 1) 启动预检：既没有项目自带 Dockerfile，也没识别到启动命令 —— 无法自动容器化。
        #    直接如实返回 launch_not_detected（附手动步骤），避免生成 CMD 为空的坏容器
        #    再报出不可诊断的 "no command specified"（旧 bug 根因）。
        if not has_dockerfile and not run_command:
            self.metadata["status"] = LAUNCH_NOT_DETECTED
            steps = self.launch_plan.get("manual_steps") or []
            hint = "；".join(steps) if steps else "未在项目中识别到 Web 服务的启动方式"
            compose_note = (
                "（检测到 docker-compose，属多服务编排，当前单容器沙箱不自动编排；"
                "请先手动 `docker compose up`，再用 url 模式指定 base_url）"
                if compose else ""
            )
            self.metadata["reason"] = (
                f"无法自动识别项目启动方式：{hint}{compose_note}。"
                "可在动态验证选项中手动提供启动命令（run_command），"
                "或改用 url 模式指定一个已运行的授权靶场 base_url。"
                "界面输入框中的灰色文字只是示例 placeholder，不会作为实际命令提交。"
            )
            logger.info("沙箱预检未通过（不构建）：%s", self.metadata["reason"])
            return

        # 未安装 docker SDK / 引擎不可用时抛异常 -> sandbox_start_failed
        self._client = get_docker_client()

        # 1) 构建镜像：优先项目 Dockerfile，否则生成临时 Dockerfile
        if not has_dockerfile:
            command_policy = _validate_generated_launch_plan(self.launch_plan)
            if not command_policy["allowed"]:
                self.metadata["status"] = UNSAFE_PROJECT_CONFIG
                self.metadata["reason"] = "自动启动命令被安全策略阻止：" + command_policy["reason"]
                self.metadata["diagnostics"].extend(command_policy["checks"])
                return
            dockerfile = build_dockerfile(self.launch_plan, internal_port)
            dockerfile_name = self._next_generated_dockerfile_name()
            (self.code_root / dockerfile_name).write_text(dockerfile, encoding="utf-8")
            self._generated_dockerfile_name = dockerfile_name
            self.metadata["diagnostics"].append(f"generated {dockerfile_name} from launch_plan")
        else:
            dockerfile_name = "Dockerfile"
            self.metadata["diagnostics"].append("using project Dockerfile")
        self.metadata["dockerfile"] = dockerfile_name

        try:
            self.metadata["image_build_attempted"] = True
            self._client.images.build(
                path=str(self.code_root), dockerfile=dockerfile_name,
                tag=image_tag, rm=True, forcerm=True,
            )
        except Exception as e:  # noqa: BLE001
            msg = str(e).lower()
            if any(k in msg for k in ("pip install", "npm install", "composer",
                                      "could not find", "no matching distribution")):
                raise _DependencyError(str(e)) from e
            raise

        # 2) 启动容器（注入默认监听环境变量，确保服务绑定 0.0.0.0 可被端口映射访问）
        run_env = {
            "APP_HOST": "0.0.0.0", "HOST": "0.0.0.0", "FLASK_RUN_HOST": "0.0.0.0",
            "PORT": str(internal_port), "FLASK_RUN_PORT": str(internal_port),
            **self.env,
        }
        self.metadata["container_start_attempted"] = True
        self._container = self._client.containers.run(
            image=image_tag, detach=True, remove=False,
            ports={f"{internal_port}/tcp": host_port},
            environment=run_env, mem_limit="512m",
            pids_limit=256,
            security_opt=["no-new-privileges"],
            cap_drop=["ALL"],
        )
        self.metadata["container_id"] = self._container.id[:12]

        # 3) 健康检查
        health_url = base_url.rstrip("/") + (self.metadata["health_path"] or "/")
        if _wait_healthy(health_url, self.health_timeout):
            self.base_url = base_url
            self.metadata.update({
                "base_url": base_url, "health_check": "passed",
                "status": STARTED, "reason": "",
            })
        else:
            self.metadata["status"] = HEALTH_CHECK_FAILED
            self.metadata["health_check"] = "failed"
            self.metadata["reason"] = (
                f"容器已启动但 {self.health_timeout}s 内健康检查未通过"
                f"（health_path={self.metadata['health_path']}，容器端口 {internal_port}）："
                "可能应用未监听 0.0.0.0、实际端口与探测端口不一致、启动过慢或已崩溃，"
                "详见 logs_excerpt。"
            )
        self.metadata["logs_excerpt"] = self._logs()

    def _logs(self) -> str:
        if not self._container:
            return ""
        try:
            self._container.reload()
            return self._container.logs().decode("utf-8", errors="ignore")[-3000:]
        except Exception:  # noqa: BLE001
            return ""

    def runtime_logs(self) -> str:
        """返回运行中容器/Compose 的最新日志，供动态判据做请求前后差分。

        仅作为已运行本地沙箱的辅助证据，不能单独把日志出现当成漏洞确认；调用方仍须
        保存对应 HTTP 请求、良性基线和漏洞类型专用判据。
        """
        return self._compose_logs() if self._compose_project else self._logs()

    # ---------- docker compose 多服务编排 ----------
    def _run_compose(self, compose_file: str, port_hint) -> None:
        """用 `docker compose up` 启动多服务项目，探测对外发布端口并健康检查。

        失败时如实返回状态与 reason，绝不造假复现结果。退出时 `docker compose down` 清理。
        """
        project = "aax" + (re.sub(r"[^a-z0-9]", "", self.scan_id.lower())[:20] or "scan")
        self._compose_project = project
        self._compose_file = str(self.code_root / compose_file)
        self.metadata["mode"] = "docker_compose"
        self.metadata["launch_command"] = f"docker compose -f {compose_file} up -d --build"

        # Docker Desktop 的内部代理在 Compose 并发拉取多个镜像时容易出现 auth.docker.io
        # EOF。先解析镜像清单并逐个顺序预拉取，既能复用缓存，也避免并发鉴权风暴。
        self._prefetch_compose_images(project)

        up_cmd = ["docker", "compose", "-p", project, "-f", self._compose_file,
                  "up", "-d", "--build"]
        proc = None
        for attempt in range(1, 4):
            try:
                proc = subprocess.run(up_cmd, cwd=str(self.code_root), capture_output=True,
                                      text=True, encoding="utf-8", errors="replace",
                                      timeout=self.build_timeout)
            except FileNotFoundError as e:
                raise RuntimeError("docker compose CLI 不可用（需 Docker Compose v2）") from e
            except subprocess.TimeoutExpired as e:
                raise RuntimeError(f"docker compose up 超时（>{self.build_timeout}s）") from e
            err = (proc.stderr or proc.stdout or "").strip()
            if proc.returncode == 0 or not _transient_pull_failure(err) or attempt == 3:
                break
            self.metadata["diagnostics"].append(
                f"compose image pull transient failure; retry {attempt}/3: {_diagnostic_tail(err, 240)}"
            )
            time.sleep(attempt * 2)

        if proc is None or proc.returncode != 0:
            err = (proc.stderr or proc.stdout or "").strip()
            low = err.lower()
            if any(k in low for k in ("pip install", "npm install", "could not find",
                                      "no matching distribution", "failed to solve")):
                raise _DependencyError(err)
            raise RuntimeError(_diagnostic_tail(err) or "docker compose up 失败")

        # 探测对外发布的 HTTP 端口
        host_port = self._compose_published_port(project, port_hint)
        if not host_port:
            self.metadata["status"] = HEALTH_CHECK_FAILED
            self.metadata["reason"] = (
                "docker compose 已启动，但未找到对外发布的 HTTP 端口，无法探测："
                "请在 compose 文件里为 Web 服务映射端口（ports: '<host>:<container>'）。"
            )
            self.metadata["logs_excerpt"] = self._compose_logs()
            return

        base_url = f"http://127.0.0.1:{host_port}"
        health_url = base_url.rstrip("/") + (self.metadata["health_path"] or "/")
        if _wait_healthy(health_url, self.health_timeout):
            self.base_url = base_url
            self.metadata.update({
                "base_url": base_url, "port": host_port,
                "health_check": "passed", "status": STARTED, "reason": "",
            })
        else:
            self.metadata["status"] = HEALTH_CHECK_FAILED
            self.metadata["health_check"] = "failed"
            self.metadata["reason"] = (
                f"docker compose 服务已启动但 {self.health_timeout}s 内健康检查未通过"
                f"（探测端口 {host_port}，health_path={self.metadata['health_path']}）："
                "可能 Web 服务尚未就绪、端口映射不对或依赖服务未启动，详见 logs_excerpt。"
            )
        self.metadata["logs_excerpt"] = self._compose_logs()

    def _prefetch_compose_images(self, project: str) -> None:
        """顺序准备 Compose 镜像；已存在的镜像直接复用，瞬时网络错误自动重试。"""
        cmd = ["docker", "compose", "-p", project, "-f", self._compose_file,
               "config", "--images"]
        proc = subprocess.run(
            cmd, cwd=str(self.code_root), capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=60,
        )
        if proc.returncode != 0:
            raise RuntimeError("无法解析 Compose 镜像清单：" + _diagnostic_tail(proc.stderr or proc.stdout))
        images = list(dict.fromkeys(
            line.strip() for line in (proc.stdout or "").splitlines() if line.strip()
        ))
        self.metadata["diagnostics"].append(f"compose images discovered: {len(images)}")

        for index, image in enumerate(images, start=1):
            cached = subprocess.run(
                ["docker", "image", "inspect", image], capture_output=True,
                text=True, encoding="utf-8", errors="replace", timeout=30,
            )
            if cached.returncode == 0:
                self.metadata["diagnostics"].append(
                    f"compose image {index}/{len(images)} cached: {image}"
                )
                continue

            last_error = ""
            for attempt in range(1, 4):
                try:
                    pulled = subprocess.run(
                        ["docker", "pull", image], capture_output=True, text=True,
                        encoding="utf-8", errors="replace",
                        timeout=min(self.build_timeout, 180),
                    )
                except subprocess.TimeoutExpired:
                    last_error = "镜像拉取超时（单镜像超过 180 秒，Docker 网络/代理可能停滞）"
                    if attempt < 3:
                        time.sleep(attempt * 2)
                        continue
                    break
                if pulled.returncode == 0:
                    self.metadata["diagnostics"].append(
                        f"compose image {index}/{len(images)} pulled: {image}"
                    )
                    last_error = ""
                    break
                last_error = (pulled.stderr or pulled.stdout or "").strip()
                if not _transient_pull_failure(last_error) or attempt == 3:
                    break
                time.sleep(attempt * 2)
            if last_error:
                raise RuntimeError(
                    f"拉取 Compose 镜像失败 ({index}/{len(images)} {image})："
                    + _diagnostic_tail(last_error)
                )

    def _compose_published_port(self, project: str, port_hint) -> int | None:
        """解析 `docker compose ps --format json`，返回一个对外发布的 TCP 端口。

        兼容两种输出：整体 JSON 数组，或每行一个 JSON 对象（不同 compose 版本）。
        优先匹配 port_hint（容器内目标端口），否则取第一个已发布端口。
        """
        try:
            cmd = ["docker", "compose", "-p", project]
            if self._compose_file:
                cmd += ["-f", self._compose_file]
            cmd += ["ps", "--format", "json"]
            proc = subprocess.run(
                cmd,
                cwd=str(self.code_root), capture_output=True, text=True,
                encoding="utf-8", errors="replace", timeout=30)
        except Exception:  # noqa: BLE001
            return None
        raw = (proc.stdout or "").strip()
        if not raw:
            return None
        services: list = []
        try:
            parsed = _json.loads(raw)
            services = parsed if isinstance(parsed, list) else [parsed]
        except Exception:  # noqa: BLE001
            for line in raw.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    services.append(_json.loads(line))
                except Exception:  # noqa: BLE001
                    continue
        published: list[dict] = []
        for svc in services:
            for pub in (svc.get("Publishers") or []):
                pp = pub.get("PublishedPort")
                if pp and str(pub.get("Protocol", "tcp")) == "tcp":
                    published.append({
                        "service": str(svc.get("Service") or svc.get("Name") or "").lower(),
                        "target": int(pub.get("TargetPort") or 0),
                        "host": int(pp),
                    })
        if not published:
            return None
        if port_hint:
            for item in published:
                if item["target"] == int(port_hint) or item["host"] == int(port_hint):
                    return item["host"]

        # 多服务 Compose 不能取“第一个已发布端口”：它可能是 Postgres、Mailhog 或 MCP。
        # 优先选择名称像 Web/API/Gateway 的服务，再参考常见 HTTP 端口。
        web_words = ("web", "gateway", "frontend", "api", "nginx", "proxy")
        common_http = {80, 443, 3000, 5000, 8000, 8080, 8081, 8888}
        published.sort(key=lambda item: (
            0 if any(word in item["service"] for word in web_words) else 1,
            0 if item["target"] in common_http or item["host"] in common_http else 1,
            item["host"],
        ))
        self.metadata["diagnostics"].append(
            "compose published ports: "
            + ", ".join(f"{item['service']}:{item['host']}->{item['target']}" for item in published[:12])
        )
        return published[0]["host"]

    def _compose_logs(self) -> str:
        if not (self._compose_project and self._compose_file):
            return ""
        try:
            proc = subprocess.run(
                ["docker", "compose", "-p", self._compose_project, "-f",
                 self._compose_file, "logs", "--no-color", "--tail", "50"],
                cwd=str(self.code_root), capture_output=True, text=True,
                encoding="utf-8", errors="replace", timeout=30)
            return (proc.stdout or "")[-1500:]
        except Exception:  # noqa: BLE001
            return ""

    def _cleanup(self) -> None:
        if self._container is not None:
            try:
                self._container.remove(force=True)
            except Exception as e:  # noqa: BLE001
                logger.warning("清理容器失败: %s", e)
        # compose 编排：down 清理所有服务与卷
        if self._compose_project and self._compose_file:
            try:
                subprocess.run(
                    ["docker", "compose", "-p", self._compose_project, "-f",
                     self._compose_file, "down", "-v"],
                    cwd=str(self.code_root), capture_output=True, text=True,
                    encoding="utf-8", errors="replace", timeout=60)
            except Exception as e:  # noqa: BLE001
                logger.warning("清理 compose 项目失败: %s", e)
        # 清理本次生成的临时 Dockerfile；不要碰用户已有的同名文件。
        tmp = self.code_root / self._generated_dockerfile_name if self._generated_dockerfile_name else None
        if tmp and tmp.exists():
            try:
                tmp.unlink()
            except OSError:
                pass

    def _next_generated_dockerfile_name(self) -> str:
        stem = "Dockerfile.auditagentx"
        suffix = re.sub(r"[^a-z0-9]", "", self.scan_id.lower())[:12] or "scan"
        candidate = f"{stem}.{suffix}"
        index = 1
        while (self.code_root / candidate).exists():
            index += 1
            candidate = f"{stem}.{suffix}.{index}"
        return candidate


class _DependencyError(Exception):
    """依赖安装失败的内部异常。"""


@contextmanager
def docker_project_sandbox(code_root: Path, launch_plan: dict | None = None,
                           *, env: dict | None = None, scan_id: str | None = None,
                           trust_project_container_config: bool = False):
    """便捷上下文管理器，yield DockerProjectRunner 实例。"""
    runner = DockerProjectRunner(
        code_root, launch_plan, env=env, scan_id=scan_id,
        trust_project_container_config=trust_project_container_config,
    )
    with runner:
        yield runner


def _validate_compose_policy(path: Path) -> dict:
    """拒绝可突破 Docker 沙箱边界的 Compose 配置。仅在用户显式信任时仍执行本检查。"""
    try:
        import yaml
        data = yaml.safe_load(path.read_text(encoding="utf-8", errors="ignore")) or {}
    except Exception as exc:  # noqa: BLE001
        return {"allowed": False, "reason": f"无法安全解析 Compose: {exc}", "checks": []}

    services = data.get("services") or {}
    if not isinstance(services, dict) or not services:
        return {"allowed": False, "reason": "Compose 未定义 services", "checks": []}

    blocked: list[str] = []
    dangerous_keys = {"privileged", "devices", "cap_add", "pid", "ipc", "uts", "userns_mode"}
    for name, service in services.items():
        if not isinstance(service, dict):
            blocked.append(f"service {name}: invalid definition")
            continue
        for key in dangerous_keys:
            value = service.get(key)
            if value not in (None, False, [], ""):
                blocked.append(f"service {name}: forbidden {key}")
        if str(service.get("network_mode") or "").lower() == "host":
            blocked.append(f"service {name}: forbidden network_mode=host")
        for volume in service.get("volumes") or []:
            raw = volume if isinstance(volume, str) else str((volume or {}).get("source") or "")
            # 短语法 ./keys:/app/keys 中的 ":/" 是容器目标分隔符，不代表宿主机绝对路径。
            # 只检查 source 部分；Windows 盘符和 Unix/UNC 绝对路径仍然拒绝。
            if re.match(r"^[A-Za-z]:[\\/]", raw):
                source = raw
            else:
                source = raw.split(":", 1)[0]
            if source and (
                source.startswith(("/", "\\", "~"))
                or bool(re.match(r"^[A-Za-z]:[\\/]", source))
                or "docker.sock" in source.lower()
            ):
                blocked.append(f"service {name}: forbidden host volume {raw[:120]}")
    return {
        "allowed": not blocked,
        "reason": "; ".join(blocked) if blocked else "",
        "checks": blocked or ["compose policy passed"],
    }


def _validate_generated_launch_plan(plan: dict) -> dict:
    """只允许已知的依赖安装器和 Web 服务启动命令进入 Docker build/CMD。"""
    from backend.dynamic.launch_detector import README_INSTALL_PATTERNS, README_RUN_PATTERNS

    install = str(plan.get("install_command") or "").strip()
    run = str(plan.get("run_command") or plan.get("command") or "").strip()
    workdir = _safe_workdir(plan.get("working_dir"))
    checks: list[str] = []
    normalized_run = run.replace("{port}", str(plan.get("port") or 8000))
    if install and not any(pattern.fullmatch(install) for pattern in README_INSTALL_PATTERNS):
        checks.append(f"unapproved install_command: {install[:160]}")
    if normalized_run and not any(pattern.fullmatch(normalized_run) for pattern in README_RUN_PATTERNS):
        checks.append(f"unapproved run_command: {run[:160]}")
    raw_workdir = str(plan.get("working_dir") or ".")
    if ".." in raw_workdir.replace("\\", "/").split("/"):
        checks.append(f"unsafe working_dir: {raw_workdir[:160]}")
    elif raw_workdir not in {"", "."} and not workdir:
        checks.append(f"invalid working_dir: {raw_workdir[:160]}")
    return {
        "allowed": not checks,
        "reason": "; ".join(checks),
        "checks": checks or ["generated launch command policy passed"],
    }
