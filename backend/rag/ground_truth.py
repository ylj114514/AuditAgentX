"""Fixed-commit, provenance-backed calibration for known vulnerable targets."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from backend.verifier.evidence_collector import apply_product_evidence_policy


DEFAULT_MANIFEST = Path(__file__).resolve().parents[2] / "benchmarks" / "static_ground_truth.json"
_FULL_SHA = re.compile(r"[0-9a-f]{40}", re.I)


def _repo(value: str | None) -> str:
    normalized = str(value or "").strip().lower().rstrip("/")
    return normalized[:-4] if normalized.endswith(".git") else normalized


def _type(value: str | None) -> str:
    return re.sub(r"[^a-z0-9]+", " ", str(value or "").lower()).strip()


def _path(value: str | None) -> str:
    return str(value or "").replace("\\", "/").lstrip("./")


def load_manifest(path: Path = DEFAULT_MANIFEST) -> dict[str, Any]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if data.get("schema_version") != 1 or not isinstance(data.get("targets"), list):
        raise ValueError("ground-truth manifest must use schema_version=1 and targets[]")
    for target in data["targets"]:
        if not _repo(target.get("repository")):
            raise ValueError("ground-truth target requires repository")
        if not _FULL_SHA.fullmatch(str(target.get("commit_sha") or "")):
            raise ValueError("ground-truth target requires a full 40-character commit SHA")
        if not target.get("provenance"):
            raise ValueError("ground-truth target requires public provenance")
        for label in target.get("labels") or []:
            required = ("id", "label", "vulnerability_type", "path", "role", "rationale")
            if any(not label.get(key) for key in required):
                raise ValueError(f"ground-truth label missing required field: {label.get('id')}")
            if label["label"] not in {"true_positive", "false_positive"}:
                raise ValueError(f"unsupported ground-truth label: {label['label']}")
    return data


def _target(data: dict, repository: str, commit_sha: str) -> dict | None:
    if not _FULL_SHA.fullmatch(str(commit_sha or "")):
        return None
    for target in data.get("targets") or []:
        if _repo(target.get("repository")) == _repo(repository) and target.get("commit_sha", "").lower() == commit_sha.lower():
            return target
    return None


def _matches(finding: dict, label: dict) -> bool:
    candidate_path, expected_path = _path(finding.get("file") or finding.get("file_path")), _path(label["path"])
    if not (candidate_path == expected_path or candidate_path.endswith("/" + expected_path)):
        return False
    accepted_types = {_type(label["vulnerability_type"]), *(_type(alias) for alias in label.get("aliases") or [])}
    if _type(finding.get("type") or finding.get("vulnerability_type")) not in accepted_types:
        return False
    line = finding.get("start_line") or finding.get("line")
    if label.get("line_start") and (not line or int(line) < int(label["line_start"])):
        return False
    if label.get("line_end") and (not line or int(line) > int(label["line_end"])):
        return False
    return True


def calibrate_findings(findings: list[dict], repository: str, commit_sha: str,
                       manifest_path: Path = DEFAULT_MANIFEST) -> dict[str, int]:
    """Apply only exact labels; an unmatched finding is never assumed false."""
    summary = {"matched": 0, "confirmed": 0, "false_positive": 0}
    data = load_manifest(manifest_path)
    target = _target(data, repository, commit_sha)
    if target is None:
        return summary

    for finding in findings or []:
        matches = [label for label in target.get("labels") or [] if _matches(finding, label)]
        if not matches:
            continue
        labels = {match["label"] for match in matches}
        if len(labels) != 1:
            raise ValueError(f"conflicting ground-truth labels for finding {finding.get('finding_id')}")
        label = matches[0]
        provenance = {
            "source": "trusted_ground_truth",
            "repository": target["repository"],
            "commit_sha": target["commit_sha"],
            "label_id": label["id"],
            "label": label["label"],
            "path": label["path"],
            "vulnerability_type": label["vulnerability_type"],
            "role": label["role"],
            "rationale": label["rationale"],
            "references": label.get("references") or target["provenance"],
        }
        finding["_ground_truth"] = provenance
        finding["confidence"] = max(float(finding.get("confidence") or 0), 0.99)
        verify = finding.setdefault("_verify", {})
        evidence = dict(finding.get("_evidence") or finding.get("evidence") or {})
        evidence["ground_truth"] = provenance
        verification = dict(evidence.get("verification") or {})
        if label["label"] == "true_positive":
            finding.update({"status": "confirmed", "verified": True})
            verify.update({"static_verdict": "confirmed", "final_verdict": "statically_verified",
                           "label_source": "trusted_ground_truth"})
            verification.update({"static_verdict": "confirmed", "final_verdict": "statically_verified",
                                 "label_source": "trusted_ground_truth", "confirmed_blockers": []})
            summary["confirmed"] += 1
        else:
            finding.update({"status": "false_positive", "verified": False,
                            "false_positive_reason": label["rationale"]})
            verify.update({"static_verdict": "false_positive", "final_verdict": "false_positive",
                           "false_positive_reason": label["rationale"],
                           "label_source": "trusted_ground_truth"})
            verification.update({"static_verdict": "false_positive", "final_verdict": "false_positive",
                                 "false_positive_reason": label["rationale"],
                                 "label_source": "trusted_ground_truth"})
            summary["false_positive"] += 1
        evidence["verification"] = verification
        finding["_evidence"] = apply_product_evidence_policy(
            evidence, status=finding["status"], verified=finding["verified"],
            file=finding.get("file"), line=finding.get("start_line") or finding.get("line"),
        )
        summary["matched"] += 1
    return summary
