"""识别依赖清单与框架。"""
from __future__ import annotations

from pathlib import Path
import os

DEP_FILES = [
    "requirements.txt", "pyproject.toml", "Pipfile",
    "poetry.lock", "uv.lock", "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "composer.json", "composer.lock", "pom.xml", "build.gradle", "build.gradle.kts",
    "go.mod", "go.sum", "Gemfile", "Gemfile.lock", "Cargo.toml", "Cargo.lock",
    "Package.swift", "Podfile", "pubspec.yaml", "mix.exs", "rebar.config", "stack.yaml",
    "packages.config", "Directory.Packages.props", "packages.lock.json",
]

FRAMEWORK_HINTS = {
    "fastapi": "FastAPI", "flask": "Flask", "django": "Django",
    "vue": "Vue", "react": "React", "express": "Express",
    "thinkphp": "ThinkPHP", "laravel": "Laravel",
    "spring-boot": "Spring Boot", "spring": "Spring", "gin-gonic": "Gin",
    "nestjs": "NestJS", "next": "Next.js", "nuxt": "Nuxt", "svelte": "Svelte",
    "koa": "Koa", "hapi": "Hapi", "rails": "Ruby on Rails", "sinatra": "Sinatra",
    "aspnetcore": "ASP.NET Core", "microsoft.aspnet": "ASP.NET",
    "ktor": "Ktor", "playframework": "Play Framework", "vapor": "Vapor",
    "actix-web": "Actix Web", "rocket": "Rocket", "axum": "Axum",
    "phoenix": "Phoenix", "flutter": "Flutter", "shelf": "Dart Shelf",
}


def parse_dependencies(root: Path) -> tuple[list[str], list[str]]:
    """返回 (依赖清单文件相对路径, 推断出的框架)。"""
    root = root.resolve()
    found_files: list[str] = []
    frameworks: set[str] = set()

    wanted = {name.lower() for name in DEP_FILES}
    skip = {".git", "node_modules", "vendor", "dist", "build", "target", ".venv", "venv"}
    # One pruned traversal. The old implementation called root.rglob once for
    # every manifest name, walking a PHP vendor tree dozens of times.
    for current, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = [d for d in dirs if d.lower() not in skip and not (Path(current) / d).is_symlink()]
        for filename in files:
            if filename.lower() not in wanted:
                continue
            fp = Path(current) / filename
            try:
                if fp.is_symlink():
                    continue
                fp.resolve().relative_to(root)
            except (OSError, ValueError):
                continue
            found_files.append(fp.relative_to(root).as_posix())
            try:
                text = fp.read_text(encoding="utf-8", errors="ignore").lower()
            except OSError:
                continue
            for hint, fw in FRAMEWORK_HINTS.items():
                if hint in text:
                    frameworks.add(fw)

    return found_files, sorted(frameworks)
