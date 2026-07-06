"""识别依赖清单与框架。"""
from __future__ import annotations

from pathlib import Path

DEP_FILES = [
    "requirements.txt", "pyproject.toml", "Pipfile",
    "package.json", "composer.json", "pom.xml", "build.gradle",
    "go.mod", "Gemfile", "Cargo.toml",
]

FRAMEWORK_HINTS = {
    "fastapi": "FastAPI", "flask": "Flask", "django": "Django",
    "vue": "Vue", "react": "React", "express": "Express",
    "thinkphp": "ThinkPHP", "laravel": "Laravel",
    "spring-boot": "Spring Boot", "spring": "Spring", "gin-gonic": "Gin",
}


def parse_dependencies(root: Path) -> tuple[list[str], list[str]]:
    """返回 (依赖清单文件相对路径, 推断出的框架)。"""
    found_files: list[str] = []
    frameworks: set[str] = set()

    for name in DEP_FILES:
        fp = root / name
        if fp.exists():
            found_files.append(name)
            try:
                text = fp.read_text(encoding="utf-8", errors="ignore").lower()
            except OSError:
                continue
            for hint, fw in FRAMEWORK_HINTS.items():
                if hint in text:
                    frameworks.add(fw)

    return found_files, sorted(frameworks)
