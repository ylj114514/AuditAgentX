"""自动识别项目启动方式（用于动态验证时起靶场）。

支持 Flask / FastAPI / Django / Node(Express) / Spring Boot / PHP / 通用 Docker，
返回推断的启动命令、监听端口线索、健康检查路径等。
"""
from __future__ import annotations

import json
import re
from pathlib import Path

SKIP_DIRS = {".git", "node_modules", "vendor", "dist", "build", "__pycache__", ".venv", "venv"}


def detect_launch(code_root: Path | None) -> dict:
    """返回 {framework, command, port, health_path, dockerfile, compose, confidence, notes}。"""
    result = {
        "framework": None, "command": None, "port": None,
        "health_path": "/", "dockerfile": None, "compose": None,
        "confidence": "low", "notes": [],
    }
    if not code_root or not Path(code_root).exists():
        result["notes"].append("code_root 不存在，无法识别启动方式")
        return result
    root = Path(code_root)

    # Docker 优先（最可靠）
    for name in ("docker-compose.yml", "docker-compose.yaml"):
        if (root / name).exists():
            result["compose"] = name
            result["notes"].append(f"发现 {name}，可用 docker compose up 起靶场")
    if (root / "Dockerfile").exists():
        result["dockerfile"] = "Dockerfile"
        cmd, port = _parse_dockerfile(root / "Dockerfile")
        if cmd:
            result["command"] = cmd
        if port:
            result["port"] = port

    # 框架识别
    detected = (_detect_django(root) or _detect_fastapi(root) or _detect_flask(root)
                or _detect_node(root) or _detect_spring(root) or _detect_php(root))
    if detected:
        result.update({k: v for k, v in detected.items() if v})
        result["confidence"] = "medium" if not result["dockerfile"] else "high"
    if not result["framework"]:
        result["notes"].append("未识别到已知 Web 框架，建议手动指定启动命令")
    return result


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
            module = f.stem
            var = _find_asgi_var(text) or "app"
            return {"framework": "FastAPI",
                    "command": f"uvicorn {module}:{var} --host 0.0.0.0 --port {{port}}",
                    "port": 8000, "health_path": "/"}
    return None


def _detect_flask(root: Path) -> dict | None:
    for f in _find_files(root, {"app.py", "main.py", "wsgi.py", "run.py", "server.py"}):
        text = _read(f)
        if "Flask(" in text or "from flask" in text:
            return {"framework": "Flask", "command": f"python {f.name}",
                    "port": _flask_port(text) or 5000, "health_path": "/"}
    return None


def _detect_node(root: Path) -> dict | None:
    pkg = root / "package.json"
    if not pkg.exists():
        return None
    try:
        data = json.loads(_read(pkg) or "{}")
    except json.JSONDecodeError:
        data = {}
    scripts = data.get("scripts", {})
    deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
    fw = "Express" if "express" in deps else "Node"
    cmd = "npm start" if "start" in scripts else "node index.js"
    return {"framework": fw, "command": cmd, "port": 3000, "health_path": "/"}


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
        cmd = mc.group(1).strip()
    return cmd, port
