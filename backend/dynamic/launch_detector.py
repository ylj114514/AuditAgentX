"""自动识别项目启动方式（用于动态验证时起靶场）。

支持 Flask / FastAPI / Django / Node(Express) / Spring Boot / PHP / 通用 Docker，
并在结构化配置不足时从 README 的运行说明中提取经过白名单校验的 Web 启动命令。
返回推断的启动命令、监听端口线索、健康检查路径及推断来源等。
"""
from __future__ import annotations

import json
import re
import shlex
from pathlib import Path

SKIP_DIRS = {".git", "node_modules", "vendor", "dist", "build", "__pycache__", ".venv", "venv"}

README_NAMES = (
    "README.md", "README.rst", "README.txt", "README",
    "readme.md", "readme.rst", "readme.txt", "readme",
)

# README 属于不可信输入。只允许会启动常见本地 Web 服务的单条命令进入 launch_plan；
# git/curl/bash/make 等通用命令即使出现在文档中也不能被扫描器自动执行。
README_RUN_PATTERNS = (
    re.compile(r"^(?:python(?:3)?\s+)(?:-m\s+)?(?:uvicorn|flask|gunicorn|http\.server)\b.+", re.I),
    re.compile(r"^(?:uvicorn|gunicorn|flask)\b.+", re.I),
    re.compile(r"^python(?:3)?\s+[\w./\\-]+\.py(?:\s+.*)?$", re.I),
    re.compile(r"^python(?:3)?\s+manage\.py\s+runserver\b.*", re.I),
    re.compile(r"^(?:npm|yarn|pnpm)\s+(?:start|run\s+(?:start|dev|serve))\b.*", re.I),
    re.compile(r"^node\s+[\w./\\-]+\.(?:js|mjs|cjs)(?:\s+.*)?$", re.I),
    re.compile(r"^java\s+-jar\s+[^\s]+\.jar(?:\s+.*)?$", re.I),
    re.compile(r"^(?:mvnw?|\.\/mvnw)\s+(?:spring-boot:run|quarkus:dev)\b.*", re.I),
    re.compile(r"^(?:gradle|\.\/gradlew)\s+(?:bootRun|quarkusDev)\b.*", re.I),
    re.compile(r"^php\s+-S\s+(?:0\.0\.0\.0|127\.0\.0\.1|localhost):\d+\b.*", re.I),
)

README_INSTALL_PATTERNS = (
    re.compile(r"^(?:python(?:3)?\s+-m\s+)?pip(?:3)?\s+install\b.+", re.I),
    re.compile(r"^(?:npm\s+(?:install|ci)|yarn\s+install|pnpm\s+install)\b.*", re.I),
    re.compile(r"^composer\s+install\b.*", re.I),
    re.compile(r"^(?:mvnw?|\.\/mvnw)\s+.+\bpackage\b.*", re.I),
    re.compile(r"^(?:gradle|\.\/gradlew)\s+.+\bbuild\b.*", re.I),
)


def detect_launch(code_root: Path | None) -> dict:
    """返回结构化 launch_plan：

    {framework, runtime_kind, install_command, run_command, command(兼容旧字段), port,
     health_path, dockerfile, compose, confidence, source, source_evidence,
     notes, manual_steps}
    """
    result = {
        "framework": None, "runtime_kind": "unknown",
        "install_command": None, "run_command": None,
        "command": None, "port": None, "health_path": "/",
        "dockerfile": None, "compose": None, "confidence": "low",
        "source": None, "source_evidence": None,
        "notes": [], "manual_steps": [], "working_dir": ".",
    }
    if not code_root or not Path(code_root).exists():
        result["notes"].append("code_root 不存在，无法识别启动方式")
        return result
    root = Path(code_root)

    # Docker 优先（最可靠）。真实开源项目常把 Compose 放在 deploy/docker、docker 等
    # 子目录；只检查仓库根目录会把 crAPI 这类多服务项目误判成单个前端 Node 服务。
    dockerfile_port = None
    compose_path = _find_compose(root)
    if compose_path:
        compose_rel = _rel_posix(root, compose_path)
        result["compose"] = compose_rel
        result["source"] = "docker_compose"
        result["source_evidence"] = compose_rel
        result["confidence"] = "high"
        result["notes"].append(f"发现 {compose_rel}，可用 docker compose up 起靶场")
    if (root / "Dockerfile").exists():
        result["dockerfile"] = "Dockerfile"
        cmd, port = _parse_dockerfile(root / "Dockerfile")
        if cmd:
            result["command"] = cmd
        if port:
            result["port"] = port
            dockerfile_port = port
        if not compose_path:
            result["source"] = "dockerfile"
            result["source_evidence"] = "Dockerfile"
        result["confidence"] = "high"

    # 框架识别
    detected = (_detect_django(root) or _detect_fastapi(root) or _detect_flask(root)
                or _detect_node(root) or _detect_spring(root) or _detect_php(root))
    if detected:
        result.update({k: v for k, v in detected.items() if v})
        result["runtime_kind"] = "web"
        result["source"] = result.get("source") or "framework"
        result["source_evidence"] = result.get("source_evidence") or detected.get("evidence")
        result["confidence"] = "medium" if not result["dockerfile"] else "high"
        # Dockerfile 的 EXPOSE 端口是权威：项目自带 Dockerfile 会被直接构建运行，
        # 容器实际监听端口由 Dockerfile/应用决定，不能被框架启发式端口（如 Flask 默认
        # 5000）覆盖，否则端口映射错配导致健康检查必然失败（VFA EXPOSE 5050 即此坑）。
        if dockerfile_port:
            result["port"] = dockerfile_port
        # run_command 兼容旧 command 字段
        if result.get("command") and not result.get("run_command"):
            result["run_command"] = result["command"]
        elif result.get("run_command") and not result.get("command"):
            result["command"] = result["run_command"]
        # 补依赖安装命令
        if not result.get("install_command"):
            result["install_command"] = _install_command(root, result.get("framework"))

    # 框架启发式未能给出可执行命令时，再读取 README。README 是不可信输入，
    # _detect_readme_launch 只返回白名单内的单条 Web 启动/安装命令。
    if not result.get("run_command") and not result.get("command"):
        readme = _detect_readme_launch(root)
        if readme:
            for key in ("framework", "install_command", "run_command", "command", "port", "health_path"):
                if readme.get(key) not in (None, "") and result.get(key) in (None, ""):
                    result[key] = readme[key]
            result["source"] = "readme"
            result["source_evidence"] = readme["evidence"]
            result["confidence"] = "medium"
            result["runtime_kind"] = "web"
            result["notes"].append(
                f"从 {readme['readme']} 的运行说明识别启动命令: {readme['run_command']}"
            )

    if result.get("command") and not result.get("run_command"):
        result["run_command"] = result["command"]
    elif result.get("run_command") and not result.get("command"):
        result["command"] = result["run_command"]

    if result.get("dockerfile") or result.get("compose"):
        # 容器配置只能说明存在容器入口；是否为 Web 服务仍由端口/框架/命令共同判断。
        if result.get("port") or result.get("run_command"):
            result["runtime_kind"] = "web_candidate"

    if not result.get("run_command") and not result.get("dockerfile") and not result.get("compose"):
        native = _detect_native_cli(root)
        if native:
            result.update(native)
            result["notes"].append(
                "项目被识别为原生 CLI/系统软件，不存在可自动探测的 HTTP 服务；"
                "Deep 模式将跳过 HTTP 项目沙箱，继续静态验证与函数级 Harness。"
            )
            result["manual_steps"].append(
                "如项目另有独立 Web 管理端，请手动提供该子项目的 run_command/port，或使用 url 模式。"
            )
        else:
            result["notes"].append("未识别到可安全自动执行的 Web 启动方式，建议手动指定启动命令")
            result["manual_steps"].append("请手动提供 install_command / run_command / port")
    return result


def _find_compose(root: Path) -> Path | None:
    """查找最可信的 Compose 主文件，优先根目录与常见部署目录，排除 vendor。"""
    names = {"docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"}
    candidates = _find_files(root, names, limit=80)
    if not candidates:
        return None

    def rank(path: Path) -> tuple[int, int, str]:
        rel = path.relative_to(root)
        parts = [part.lower() for part in rel.parts]
        # override/minimal/dev 文件不是主文件（names 已过滤大部分，这里保留防御性排序）。
        variant = 1 if any(token in path.stem.lower() for token in ("override", "minimal", "dev")) else 0
        conventional = 0 if any(part in {"deploy", "deployment", "docker", ".docker"} for part in parts[:-1]) else 1
        return (variant, len(parts) + conventional, rel.as_posix())

    return min(candidates, key=rank)


def _detect_native_cli(root: Path) -> dict | None:
    """识别明显不是 HTTP 服务的原生/系统项目，避免把“不适用”伪装成 Docker 故障。"""
    markers = (
        "configure.ac", "configure.in", "CMakeLists.txt", "meson.build",
        "Makefile.am", "Cargo.toml",
    )
    found = [name for name in markers if (root / name).exists()]
    native_sources = any(root.rglob("*.c")) or any(root.rglob("*.cc")) or any(root.rglob("*.cpp"))
    if not found or not native_sources:
        return None
    return {
        "framework": "Native CLI/System",
        "runtime_kind": "native_cli",
        "source": "project_structure",
        "source_evidence": ", ".join(found[:4]),
        "confidence": "high",
    }


def _detect_readme_launch(root: Path) -> dict | None:
    """从 README 提取受限的 Web 启动计划，不执行任意文档命令。"""
    candidates: list[Path] = []
    for name in README_NAMES:
        path = root / name
        if path.is_file() and path not in candidates:
            candidates.append(path)
    docs = root / "docs"
    if docs.is_dir():
        for path in sorted(docs.glob("README*"))[:4]:
            if path.is_file() and path not in candidates:
                candidates.append(path)

    for path in candidates:
        lines = _read(path)[:300_000].splitlines()
        commands = [_clean_readme_command(line) for line in lines]
        commands = [command for command in commands if command]
        run = next((command for command in commands if _matches_any(command, README_RUN_PATTERNS)), None)
        if not run:
            continue
        install = next((command for command in commands if _matches_any(command, README_INSTALL_PATTERNS)), None)
        port = _command_port(run) or _framework_default_port(run)
        framework = _framework_from_command(run)
        rel = _rel_posix(root, path)
        return {
            "framework": framework,
            "install_command": install,
            "run_command": run,
            "command": run,
            "port": port,
            "health_path": "/",
            "readme": rel,
            "evidence": f"{rel}: {run}",
        }
    return None


def _clean_readme_command(line: str) -> str | None:
    text = line.strip()
    if not text or text.startswith(("#", "<!--", "```", "~~~")):
        return None
    text = re.sub(r"^(?:\$|>|PS>|C:\\>)\s*", "", text, flags=re.I).strip()
    text = re.sub(r"^[-*+]\s+", "", text).strip()
    # 不接受复合 shell、重定向、命令替换或环境变量赋值，防止 README 注入。
    if any(token in text for token in ("&&", "||", ";", "|", ">", "<", "`", "$(")):
        return None
    if re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", text):
        return None
    return text[:500]


def _matches_any(command: str, patterns: tuple[re.Pattern, ...]) -> bool:
    return any(pattern.fullmatch(command) for pattern in patterns)


def _command_port(command: str) -> int | None:
    patterns = (
        r"(?:--port|--server\.port)\s*[= ]\s*(\d{2,5})",
        r"(?:0\.0\.0\.0|127\.0\.0\.1|localhost):(\d{2,5})",
        r"runserver\s+(?:0\.0\.0\.0:)?(\d{2,5})",
    )
    for pattern in patterns:
        match = re.search(pattern, command, re.I)
        if match:
            port = int(match.group(1))
            if 1 <= port <= 65535:
                return port
    return None


def _framework_default_port(command: str) -> int:
    lower = command.lower()
    if any(token in lower for token in ("uvicorn", "gunicorn", "fastapi", "manage.py runserver")):
        return 8000
    if any(token in lower for token in ("npm ", "yarn ", "pnpm ", "node ")):
        return 3000
    if "flask" in lower or re.search(r"python(?:3)?\s+.+\.py", lower):
        return 5000
    return 8080


def _framework_from_command(command: str) -> str:
    lower = command.lower()
    if "uvicorn" in lower or "gunicorn" in lower:
        return "Python Web"
    if "flask" in lower:
        return "Flask"
    if "manage.py runserver" in lower:
        return "Django"
    if any(token in lower for token in ("npm ", "yarn ", "pnpm ", "node ")):
        return "Node"
    if any(token in lower for token in ("java -jar", "spring-boot:run", "bootrun")):
        return "Java"
    if lower.startswith("php "):
        return "PHP"
    return "Python Web"


def _install_command(root: Path, framework: str | None) -> str | None:
    """根据依赖清单文件推断依赖安装命令。"""
    if (root / "requirements.txt").exists():
        return "pip install --no-cache-dir -r requirements.txt"
    if (root / "pyproject.toml").exists():
        return "pip install --no-cache-dir ."
    if (root / "Pipfile").exists():
        return "pipenv install --deploy"
    if (root / "package.json").exists():
        return "npm install"
    if (root / "composer.json").exists():
        return "composer install --no-dev"
    if (root / "pom.xml").exists():
        return "mvn -q -DskipTests package"
    if (root / "build.gradle").exists():
        return "gradle build -x test"
    return None


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def _find_files(root: Path, names: set[str], limit: int = 5000) -> list[Path]:
    out: list[Path] = []
    for p in root.rglob("*"):
        if len(out) >= limit:
            break
        if p.is_dir() or any(part in SKIP_DIRS for part in p.parts):
            continue
        if p.name in names:
            out.append(p)
    return out


def _detect_django(root: Path) -> dict | None:
    if (root / "manage.py").exists():
        return {"framework": "Django", "command": "python manage.py runserver 0.0.0.0:{port}",
                "port": 8000, "health_path": "/"}
    return None


def _detect_fastapi(root: Path) -> dict | None:
    for f in _find_files(root, {"main.py", "app.py", "asgi.py"}):
        text = _read(f)
        if "FastAPI(" in text or "fastapi" in text.lower():
            module = _python_module(root, f)
            var = _find_asgi_var(text) or "app"
            nested_manifest = (f.parent / "requirements.txt").exists() or (f.parent / "pyproject.toml").exists()
            workdir = _rel_posix(root, f.parent) if nested_manifest else "."
            command_module = f.stem if nested_manifest else module
            return {"framework": "FastAPI",
                    "command": f"uvicorn {command_module}:{var} --host 0.0.0.0 --port {{port}}",
                    "port": 8000, "health_path": "/", "working_dir": workdir,
                    "install_command": _install_command(f.parent, "FastAPI")}
    return None


def _detect_flask(root: Path) -> dict | None:
    for f in _find_files(root, {"app.py", "main.py", "wsgi.py", "run.py", "server.py"}):
        text = _read(f)
        if "Flask(" in text or "from flask" in text:
            nested_manifest = (f.parent / "requirements.txt").exists() or (f.parent / "pyproject.toml").exists()
            workdir = _rel_posix(root, f.parent) if nested_manifest else "."
            command = f"python {f.name}" if nested_manifest else f"python {_rel_posix(root, f)}"
            return {"framework": "Flask", "command": command,
                    "port": _flask_port(text) or 5000, "health_path": "/",
                    "working_dir": workdir,
                    "install_command": _install_command(f.parent, "Flask")}
    return None


def _detect_node(root: Path) -> dict | None:
    packages = _find_files(root, {"package.json"})
    ranked: list[tuple[int, Path, dict]] = []
    for pkg in packages:
        try:
            data = json.loads(_read(pkg) or "{}")
        except json.JSONDecodeError:
            continue
        scripts = data.get("scripts") or {}
        deps = {**(data.get("dependencies") or {}), **(data.get("devDependencies") or {})}
        # 有真正启动脚本的服务优先；纯前端也保留为 Node 候选，允许用户手动覆盖。
        score = (4 if "start" in scripts else 0) + (2 if "dev" in scripts else 0)
        score += 2 if any(name in deps for name in ("express", "fastify", "koa", "nestjs")) else 0
        ranked.append((score, pkg, data))
    if not ranked:
        return None
    _, pkg, data = max(ranked, key=lambda item: item[0])
    scripts = data.get("scripts") or {}
    deps = {**(data.get("dependencies") or {}), **(data.get("devDependencies") or {})}
    fw = "Express" if "express" in deps else "Node"
    cmd = "npm start" if "start" in scripts else ("npm run dev" if "dev" in scripts else "node index.js")
    script_text = str(scripts.get("start") or scripts.get("dev") or "")
    port = _command_port(script_text) or 3000
    workdir = _rel_posix(root, pkg.parent)
    install = "npm ci" if (pkg.parent / "package-lock.json").exists() else "npm install"
    return {"framework": fw, "command": cmd, "port": port, "health_path": "/",
            "working_dir": workdir, "install_command": install,
            "evidence": _rel_posix(root, pkg)}


def _detect_spring(root: Path) -> dict | None:
    if (root / "pom.xml").exists() or (root / "build.gradle").exists():
        text = _read(root / "pom.xml") + _read(root / "build.gradle")
        if "spring-boot" in text or "springframework" in text:
            return {"framework": "Spring Boot",
                    "command": "java -jar target/*.jar", "port": 8080, "health_path": "/actuator/health"}
    return None


def _detect_php(root: Path) -> dict | None:
    if (root / "index.php").exists() or (root / "composer.json").exists():
        return {"framework": "PHP", "command": "php -S 0.0.0.0:{port} -t .",
                "port": 8080, "health_path": "/index.php"}
    return None


def _find_asgi_var(text: str) -> str | None:
    m = re.search(r"(\w+)\s*=\s*FastAPI\(", text)
    return m.group(1) if m else None


def _flask_port(text: str) -> int | None:
    m = re.search(r"\.run\([^)]*port\s*=\s*(\d+)", text)
    return int(m.group(1)) if m else None


def _parse_dockerfile(path: Path) -> tuple[str | None, int | None]:
    text = _read(path)
    port = None
    m = re.search(r"EXPOSE\s+(\d+)", text)
    if m:
        port = int(m.group(1))
    cmd = None
    mc = re.search(r'CMD\s+(\[.*\]|.+)', text)
    if mc:
        raw = mc.group(1).strip()
        if raw.startswith("["):
            try:
                argv = json.loads(raw)
                cmd = " ".join(shlex.quote(str(item)) for item in argv) if isinstance(argv, list) else raw
            except json.JSONDecodeError:
                cmd = raw
        else:
            cmd = raw
    return cmd, port


def _rel_posix(root: Path, file_path: Path) -> str:
    try:
        return file_path.relative_to(root).as_posix()
    except ValueError:
        return file_path.name


def _python_module(root: Path, file_path: Path) -> str:
    """Return an importable module path for uvicorn, relative to project root."""
    rel = Path(_rel_posix(root, file_path))
    without_suffix = rel.with_suffix("")
    parts = [p for p in without_suffix.parts if p not in (".", "")]
    return ".".join(parts) if parts else file_path.stem
