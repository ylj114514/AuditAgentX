import { strict as assert } from "node:assert";
import test from "node:test";
import { evidenceLevelMeta, runtimeStatusMeta } from "../src/utils/dynamicStatus.ts";

const executedNoHitVerification = {
  dynamic_method: "http_executed_not_reproduced",
  execution_completed_without_hit: true,
  evidence_level: "http_executed_not_reproduced",
};

const executedNoHitRuntime = { reproduction_status: "not_reproduced", reproducible: false };
const confirmedFinding = { status: "confirmed", verification: executedNoHitVerification };

test("labels a confirmed executed no-hit HTTP request as successful without claiming a hit", () => {
  const runtimeMeta = runtimeStatusMeta(executedNoHitRuntime, confirmedFinding);
  const evidenceMeta = evidenceLevelMeta(executedNoHitVerification, confirmedFinding, executedNoHitRuntime);

  assert.deepEqual(runtimeMeta, {
    label: "已确认：HTTP 请求已执行但未复现（未命中）",
    tone: "success",
    trustworthyPositive: true,
  });
  assert.deepEqual(evidenceMeta, runtimeMeta);
  assert.equal(runtimeMeta.label.includes("动态确认"), false);
  assert.equal(runtimeMeta.label.includes("HTTP 命中"), false);
  assert.equal(runtimeMeta.label.includes("未命中"), true);
});

test("recognizes the completed-without-hit compatibility flag", () => {
  const verification = { execution_completed_without_hit: true };

  assert.equal(
    runtimeStatusMeta(executedNoHitRuntime, { status: "confirmed", verification }).label,
    "已确认：HTTP 请求已执行但未复现（未命中）",
  );
});
