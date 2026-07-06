"""仓库解析智能体测试。"""
from pathlib import Path

from backend.agents.repo_parser_agent import RepoParserAgent

DEMO = Path(__file__).resolve().parent.parent / "examples" / "vulnerable_projects" / "demo_flask_app"


def test_repo_parser_extracts_metadata():
    meta = RepoParserAgent().run(DEMO)
    assert "Python" in meta["languages"]
    assert meta["file_count"] >= 1
    assert meta["loc"] > 0
    assert "Flask" in meta["frameworks"]
