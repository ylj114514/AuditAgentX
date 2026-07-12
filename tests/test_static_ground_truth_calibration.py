import json
import subprocess

import pytest

from backend.rag.ground_truth import DEFAULT_MANIFEST, calibrate_findings, load_manifest
from backend.repository import git_client


REPO = "https://github.com/digininja/DVWA"
COMMIT = "d45ba3c4e7efa7f023f25f58ab4af9912c887057"


def _manifest(tmp_path):
    path = tmp_path / "ground-truth.json"
    path.write_text(json.dumps({
        "schema_version": 1,
        "targets": [{
            "repository": REPO,
            "commit_sha": COMMIT,
            "provenance": ["https://github.com/digininja/DVWA/blob/" + COMMIT + "/vulnerabilities/api/help/help.php"],
            "labels": [{
                "id": "dvwa-api-command-injection-high",
                "label": "true_positive",
                "vulnerability_type": "Command Injection",
                "aliases": ["tainted-exec", "OS Command Injection"],
                "path": "vulnerabilities/api/src/HealthController.php",
                "role": "primary_implementation",
                "rationale": "Official DVWA API help documents command injection.",
            }, {
                "id": "dvwa-sqli-impossible",
                "label": "false_positive",
                "vulnerability_type": "SQL Injection",
                "aliases": ["tainted-sql-string"],
                "path": "vulnerabilities/sqli/source/impossible.php",
                "role": "mitigation_reference",
                "rationale": "Official impossible level uses parameterized SQL.",
            }],
        }],
    }), encoding="utf-8")
    return path


def test_ground_truth_promotes_and_rejects_only_exact_scoped_matches(tmp_path):
    findings = [
        {"type": "tainted-exec", "file": "src/vulnerabilities/api/src/HealthController.php",
         "start_line": 88, "status": "unverified", "verified": False},
        {"type": "tainted-sql-string", "file": "vulnerabilities/sqli/source/impossible.php",
         "start_line": 20, "status": "needs_review", "verified": False},
        {"type": "SQL Injection", "file": "unrelated.php", "start_line": 1,
         "status": "needs_review", "verified": False},
    ]

    summary = calibrate_findings(findings, REPO + ".git", COMMIT, _manifest(tmp_path))

    assert summary == {"matched": 2, "confirmed": 1, "false_positive": 1}
    assert findings[0]["status"] == "confirmed"
    assert findings[0]["verified"] is True
    assert findings[0]["_ground_truth"]["label_id"] == "dvwa-api-command-injection-high"
    assert findings[0]["_evidence"]["evidence_complete"] is True
    assert findings[0]["_evidence"]["actionable"] is True
    assert findings[1]["status"] == "false_positive"
    assert findings[2]["status"] == "needs_review"


def test_ground_truth_refuses_mutable_or_mismatched_target(tmp_path):
    manifest = _manifest(tmp_path)
    findings = [{"type": "tainted-exec", "file": "vulnerabilities/api/src/HealthController.php"}]

    assert calibrate_findings(findings, REPO, "master", manifest)["matched"] == 0
    assert calibrate_findings(findings, REPO, "0" * 40, manifest)["matched"] == 0
    assert findings[0].get("status") is None


def test_manifest_rejects_abbreviated_sha_and_missing_provenance(tmp_path):
    path = _manifest(tmp_path)
    data = json.loads(path.read_text(encoding="utf-8"))
    data["targets"][0]["commit_sha"] = "d45ba3c"
    data["targets"][0]["provenance"] = []
    path.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ValueError):
        load_manifest(path)


def test_repository_manifest_is_valid_and_pinned():
    manifest = load_manifest(DEFAULT_MANIFEST)
    target = manifest["targets"][0]
    assert target["commit_sha"] == COMMIT
    assert target["excluded_modules"][0]["module"] == "bac"


def test_git_client_checks_out_full_commit_without_branch_fallback(monkeypatch, tmp_path):
    calls = []

    def fake_run(args):
        calls.append(args)
        stdout = (COMMIT + "\n").encode() if args[-2:] == ["rev-parse", "HEAD"] else b""
        return subprocess.CompletedProcess(args, 0, stdout=stdout, stderr=b"")

    monkeypatch.setattr(git_client, "_run_git", fake_run)
    dest = tmp_path / "repo"
    git_client._git_clone(REPO, dest, COMMIT)

    assert calls[0][:2] == ["git", "init"]
    assert any("fetch" in call and call[-2:] == ["origin", COMMIT] for call in calls)
    assert not any("--branch" in call for call in calls)
