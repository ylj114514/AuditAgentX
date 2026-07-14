import { strict as assert } from "node:assert";
import test from "node:test";
import { canDisplayDetailedPoc } from "../src/utils/pocDisplay.ts";

function confirmedFinding() {
  return { status: "confirmed" };
}

function persistedArtifact(overrides: Record<string, unknown> = {}) {
  return {
    persistence_status: "persisted",
    sha256: "a".repeat(64),
    ...overrides,
  };
}

function httpConfirmedEvidence() {
  return {
    verification: { dynamic_method: "http_dynamic", dynamically_verified: true },
    runtime: { reproduction_status: "dynamic_confirmed", reproducible: true },
    artifacts: { validated_poc: persistedArtifact() },
  };
}

function executedNoHitReplayEvidence() {
  return {
    verification: {
      dynamic_method: "http_executed_not_reproduced",
      execution_completed_without_hit: true,
      dynamically_verified: false,
    },
    runtime: { reproduction_status: "not_reproduced", reproducible: false },
    artifacts: { validated_poc: persistedArtifact() },
  };
}

function targetHarnessConfirmedEvidence() {
  return {
    verification: { dynamic_method: "target_harness", dynamically_verified: true },
    harness: {
      verdict: "target_confirmed",
      dynamically_triggered: true,
      function_extracted: true,
      target_function_called: true,
      verification_level: "entrypoint_reproduced",
      entrypoint_reachable: true,
    },
    artifacts: { validated_poc: persistedArtifact() },
  };
}

test("allows persisted PoC code for an actual confirmed HTTP reproduction", () => {
  assert.equal(canDisplayDetailedPoc({ finding: confirmedFinding(), evidence: httpConfirmedEvidence() }), true);
});

test("allows a persisted replay for a confirmed HTTP request executed without a hit", () => {
  assert.equal(canDisplayDetailedPoc({
    finding: confirmedFinding(),
    evidence: executedNoHitReplayEvidence(),
  }), true);
});

test("allows a persisted replay when completed-without-hit is supplied as the compatibility flag", () => {
  const evidence = executedNoHitReplayEvidence();
  evidence.verification = { execution_completed_without_hit: true };

  assert.equal(canDisplayDetailedPoc({ finding: confirmedFinding(), evidence }), true);
});

test("rejects an executed no-hit replay without a persisted artifact", () => {
  const evidence = executedNoHitReplayEvidence();
  evidence.artifacts.validated_poc = persistedArtifact({ sha256: "" });

  assert.equal(canDisplayDetailedPoc({ finding: confirmedFinding(), evidence }), false);
});

test("allows persisted PoC code for an entrypoint-confirmed target harness", () => {
  assert.equal(canDisplayDetailedPoc({ finding: confirmedFinding(), evidence: targetHarnessConfirmedEvidence() }), true);
});

test("rejects a static confirmation without a runtime reproduction", () => {
  const evidence = httpConfirmedEvidence();
  evidence.verification = { dynamic_method: "static_confirmation", dynamically_verified: false };
  evidence.runtime = { reproduction_status: "not_reproduced", reproducible: false };
  assert.equal(canDisplayDetailedPoc({ finding: confirmedFinding(), evidence }), false);
});

test("rejects function-only and synthetic harness evidence", () => {
  const functionOnly = targetHarnessConfirmedEvidence();
  functionOnly.verification = { dynamic_method: "function_harness", dynamically_verified: false };
  functionOnly.harness.verdict = "function_reproduced";
  const synthetic = targetHarnessConfirmedEvidence();
  synthetic.harness.verdict = "synthetic_demo_only";

  assert.equal(canDisplayDetailedPoc({ finding: confirmedFinding(), evidence: functionOnly }), false);
  assert.equal(canDisplayDetailedPoc({ finding: confirmedFinding(), evidence: synthetic }), false);
});

test("rejects unresolved, failed, and blocked runtime outcomes", () => {
  for (const status of ["endpoint_unresolved", "failed", "blocked"]) {
    const evidence = httpConfirmedEvidence();
    evidence.runtime = { reproduction_status: status, reproducible: false };
    assert.equal(canDisplayDetailedPoc({ finding: confirmedFinding(), evidence }), false, status);
  }
});

test("rejects downgraded findings and revoked, incomplete artifacts", () => {
  const downgraded = httpConfirmedEvidence();
  downgraded.verification.downgrade_reason = "context conflict";
  const revoked = httpConfirmedEvidence();
  revoked.artifacts.validated_poc = persistedArtifact({ revoked_by_finding_status: "false_positive" });
  const missingHash = httpConfirmedEvidence();
  missingHash.artifacts.validated_poc = persistedArtifact({ sha256: "" });

  assert.equal(canDisplayDetailedPoc({ finding: confirmedFinding(), evidence: downgraded }), false);
  assert.equal(canDisplayDetailedPoc({ finding: confirmedFinding(), evidence: revoked }), false);
  assert.equal(canDisplayDetailedPoc({ finding: confirmedFinding(), evidence: missingHash }), false);
  assert.equal(canDisplayDetailedPoc({ finding: { status: "needs_review" }, evidence: httpConfirmedEvidence() }), false);
  assert.equal(canDisplayDetailedPoc({
    finding: { status: "confirmed", verification: { status: "needs_review" } },
    evidence: httpConfirmedEvidence(),
  }), false);
});
