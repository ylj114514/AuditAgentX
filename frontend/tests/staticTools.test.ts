import { strict as assert } from "node:assert";
import test from "node:test";
import {
  DEFAULT_STATIC_TOOLS,
  normalizeStaticTools,
} from "../src/utils/staticTools.ts";

test("defaults to all user-selectable static scanners", () => {
  assert.deepEqual(DEFAULT_STATIC_TOOLS, ["semgrep", "bandit", "gitleaks", "trivy"]);
});

test("keeps selected scanners in the stable supported order", () => {
  assert.deepEqual(
    normalizeStaticTools(["trivy", "semgrep", "trivy", "bandit"]),
    ["semgrep", "bandit", "trivy"],
  );
});

test("drops unknown scanner values without adding built-in rules to the request", () => {
  assert.deepEqual(normalizeStaticTools(["custom", "unknown", "gitleaks"]), ["gitleaks"]);
});
