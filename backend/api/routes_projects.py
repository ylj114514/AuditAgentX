"""项目管理接口（md 7.1 / 7.2 / 7.3）。"""
from __future__ import annotations

import json

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.core import ids
from backend.models import Project
from backend.schemas import ProjectCreate, ProjectOut
from backend.repository.git_client import prepare_workspace
from backend.agents.repo_parser_agent import RepoParserAgent

router = APIRouter(prefix="/api/projects", tags=["projects"])


@router.post("", response_model=ProjectOut)
def create_project(payload: ProjectCreate, db: Session = Depends(get_db)) -> ProjectOut:
    pid = ids.project_id()
    project = Project(
        id=pid, name=payload.name, source_type=payload.source_type,
        url=payload.url, local_path=payload.local_path, branch=payload.branch,
        description=payload.description, status="created",
    )
    db.add(project)
    db.commit()
    return ProjectOut(project_id=pid, status="created", message="Project created successfully")


@router.get("")
def list_projects(db: Session = Depends(get_db)) -> dict:
    rows = db.query(Project).order_by(Project.created_at.desc()).all()
    return {"total": len(rows), "projects": [
        {"project_id": p.id, "name": p.name, "status": p.status,
         "source_type": p.source_type, "url": p.url} for p in rows
    ]}


@router.post("/{project_id}/parse")
def parse_project(project_id: str, db: Session = Depends(get_db)) -> dict:
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(404, "project not found")
    code_root = prepare_workspace(
        project.id, project.source_type, project.url, project.local_path, project.branch,
    )
    metadata = RepoParserAgent().run(code_root)
    project.language_summary = ", ".join(metadata.get("languages", []))
    project.metadata_json = json.dumps(
        {k: v for k, v in metadata.items() if k not in ("_files", "tree")}, ensure_ascii=False
    )
    project.status = "parsed"
    db.commit()
    return {
        "project_id": project.id, "status": "parsed",
        "metadata": {k: v for k, v in metadata.items() if k not in ("_files", "tree")},
    }


@router.get("/{project_id}/tree")
def get_tree(project_id: str, db: Session = Depends(get_db)) -> dict:
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(404, "project not found")
    meta = json.loads(project.metadata_json or "{}")
    return {"project_id": project.id, "tree": meta.get("tree", [])}
