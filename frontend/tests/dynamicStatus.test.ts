import { strict as assert } from "node:assert";
import test from "node:test";
import { evidenceLevelMeta, runtimeStatusMeta } from "../src/utils/dynamicStatus.ts";

const executedNoHitVerification = {
  dynamic_method: "http_executed_not_reproduced",
  execution_completed_without_hit: true,
  evidence_level: "http_executed_not_reproduced",
};

const executedNoHitRuntime = { reproduction_status: "not_reproduced", reproducible: false, skipped: false };
const confirmedFinding = { status: "confirmed", verification: executedNoHitVerification };

test("labels a confirmed executed no-hit HTTP request as successful without claiming a hit", () => {
  const runtimeMeta = runtimeStatusMeta(executedNoHitRuntime, confirmedFinding);
  const evidenceMeta = evidenceLevelMeta(executedNoHitVerification, confirmedFinding, executedNoHitRuntime);

  assert.deepEqual(runtimeMeta, {
    label: "确认：已执行但未复现",
    tone: "success",
    trustworthyPositive: true,
  });
  assert.deepEqual(evidenceMeta, runtimeMeta);
  assert.equal(runtimeMeta.label.includes("动态确认"), false);
  assert.equal(runtimeMeta.label.includes("HTTP 命中"), false);
  assert.equal(runtimeMeta.label.includes("未命中"), false);
});

test("recognizes the completed-without-hit compatibility flag", () => {
  const verification = { execution_completed_without_hit: true };

  assert.equal(
    runtimeStatusMeta(executedNoHitRuntime, { status: "confirmed", verification }).label,
    "确认：已执行但未复现",
  );
});

test("accepts final or product confirmation when the HTTP campaign completed without a hit", () => {
  const finalStatusFinding = { final_status: "confirmed" };
  const productStatusFinding = { product_status: "confirmed" };
  const recordedNoHitRuntime = {
    ...executedNoHitRuntime,
    records: [{ role: "attack", url: "http://127.0.0.1:8080/search", method: "GET", status_code: 200 }],
  };

  assert.equal(
    runtimeStatusMeta(recordedNoHitRuntime, finalStatusFinding, {}).label,
    "确认：已执行但未复现",
  );
  assert.equal(
    evidenceLevelMeta({}, productStatusFinding, recordedNoHitRuntime).label,
    "确认：已执行但未复现",
  );
});

test("does not elevate pending, review, skipped, or failed HTTP outcomes", () => {
  const noHitMethod = { dynamic_method: "http_executed_not_reproduced" };
  for (const finding of [
    { status: "needs_review", verification: noHitMethod },
    { status: "validation_pending", verification: noHitMethod },
    { status: "endpoint_unresolved", verification: noHitMethod },
    { status: "sandbox_start_failed", verification: noHitMethod },
    { status: "not_executed", verification: noHitMethod },
    { status: "confirmed", verification: { dynamic_method: "http_executed_not_reproduced", final_verdict: "needs_review" } },
  ]) {
    assert.notEqual(runtimeStatusMeta(executedNoHitRuntime, finding).tone, "success");
  }
  assert.notEqual(
    runtimeStatusMeta({ ...executedNoHitRuntime, skipped: true }, confirmedFinding).tone,
    "success",
  );
});
