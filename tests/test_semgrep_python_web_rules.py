"""Executable regression coverage for AuditAgentX's local Python web rules."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest


RULES = Path(__file__).resolve().parent.parent / "rules" / "semgrep" / "taint_injection.yaml"


def _scan_rule_ids(target: Path) -> set[str]:
    if not shutil.which("semgrep"):
        pytest.skip("semgrep is not installed")
    # The repository path contains non-ASCII characters on this Windows host;
    # Semgrep's local-config parser requires an ASCII rule path.
    local_rules = target / "auditagentx_rules.yaml"
    shutil.copy2(RULES, local_rules)
    completed = subprocess.run(
        ["semgrep", "scan", "--config", str(local_rules), "--json", str(target)],
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        env={**os.environ, "PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8"},
    )
    assert completed.returncode in {0, 1}, f"{completed.stderr}\n{completed.stdout}"
    rule_ids = set()
    for result in json.loads(completed.stdout)["results"]:
        check_id = result["check_id"]
        marker = check_id.find("auditagentx-")
        rule_ids.add(check_id[marker:] if marker >= 0 else check_id)
    return rule_ids


def test_local_python_web_rules_detect_tainted_web_inputs_at_security_sinks(tmp_path: Path):
    (tmp_path / "vulnerable.py").write_text(
        """
import os
import pickle
import subprocess
from pathlib import Path

import requests
import yaml
from flask import request
from lxml import etree


def handler(cursor):
    sql = request.get_json()["sql"]
    cursor.executescript(sql)

    command = request.view_args["command"]
    subprocess.check_output(command, shell=True)

    url = request.query_params["url"]
    requests.patch(url)

    filename = request.path_params["filename"]
    Path(filename).write_text("audit")

    payload = request.data
    pickle.loads(payload)
    yaml.unsafe_load(payload)
    etree.fromstring(
        payload,
        parser=etree.XMLParser(load_dtd=True, resolve_entities=True),
    )
""",
        encoding="utf-8",
    )

    rule_ids = _scan_rule_ids(tmp_path)

    assert {
        "auditagentx-python-sql-injection-taint",
        "auditagentx-python-command-injection-taint",
        "auditagentx-python-ssrf-taint",
        "auditagentx-python-path-traversal-taint",
        "auditagentx-python-unsafe-deserialization-taint",
        "auditagentx-python-unsafe-yaml-load-taint",
        "auditagentx-python-xxe-taint",
    } <= rule_ids


def test_local_python_web_rules_ignore_parameterized_or_safe_operations(tmp_path: Path):
    (tmp_path / "safe.py").write_text(
        """
import pickle
import subprocess

import requests
import yaml
from flask import request
from lxml import etree


def handler(cursor):
    cursor.execute("SELECT * FROM users WHERE id = ?", (request.args["id"],))
    subprocess.run(["echo", request.args["message"]], shell=False)
    requests.get("https://api.example.invalid/health")
    open("/srv/audit.log", "a")
    pickle.loads(b"trusted-cache")
    yaml.safe_load(request.data)
    etree.fromstring(
        request.data,
        parser=etree.XMLParser(load_dtd=False, resolve_entities=False),
    )
""",
        encoding="utf-8",
    )

    rule_ids = _scan_rule_ids(tmp_path)

    assert not {
        "auditagentx-python-sql-injection-taint",
        "auditagentx-python-command-injection-taint",
        "auditagentx-python-ssrf-taint",
        "auditagentx-python-path-traversal-taint",
        "auditagentx-python-unsafe-deserialization-taint",
        "auditagentx-python-unsafe-yaml-load-taint",
        "auditagentx-python-xxe-taint",
    } & rule_ids
