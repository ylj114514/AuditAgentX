export type PocDisplayInput = {
  finding?: unknown;
  evidence?: unknown;
};

type UnknownRecord = Record<string, unknown>;

function asRecord(value: unknown): UnknownRecord {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as UnknownRecord
    : {};
}

function normalized(value: unknown): string {
  return String(value ?? "").trim().toLowerCase();
}

function statusValues(finding: UnknownRecord, verification: UnknownRecord): string[] {
  const findingVerification = asRecord(finding.verification);
  return [
    finding.status,
    finding.final_status,
    finding.product_status,
    findingVerification.status,
    findingVerification.final_verdict,
    verification.status,
    verification.final_verdict,
  ].map(normalized).filter(Boolean);
}

function hasNonConfirmableStatus(finding: UnknownRecord, verification: UnknownRecord): boolean {
  return statusValues(finding, verification).some((status) => (
    ["needs_review", "validation_pending", "not_executed", "endpoint_unresolved",
      "endpoint_not_found", "blocked", "inconclusive", "failed"].includes(status)
    || status.includes("sandbox_")
    || status.includes("_failed")
  ));
}

function isConfirmedProductFinding(finding: UnknownRecord, verification: UnknownRecord): boolean {
  return statusValues(finding, verification).includes("confirmed")
    && !hasNonConfirmableStatus(finding, verification);
}

function hasExecutedHttpRequest(runtime: UnknownRecord): boolean {
  const records = [
    ...(Array.isArray(runtime.records) ? runtime.records : []),
    ...(Array.isArray(runtime.confirmation_records) ? runtime.confirmation_records : []),
  ];
  return records.some((record) => {
    const item = asRecord(record);
    return ["attack", "confirmation", "authorization_attack"].includes(normalized(item.role))
      && Boolean(item.url && item.method)
      && (item.status_code !== undefined || item.status !== undefined || item.error);
  });
}

function isConfirmedExecutedNoHit(
  runtime: UnknownRecord,
  finding: UnknownRecord,
  verification: UnknownRecord,
): boolean {
  const noHitMethod = normalized(verification.dynamic_method) === "http_executed_not_reproduced"
    || verification.execution_completed_without_hit === true;
  return normalized(runtime.reproduction_status) === "not_reproduced"
    && runtime.skipped !== true
    && !hasNonConfirmableStatus(finding, verification)
    && (hasExecutedHttpRequest(runtime) || noHitMethod)
    && (isConfirmedProductFinding(finding, verification) || noHitMethod);
}

function isRevoked(artifact: UnknownRecord): boolean {
  return artifact.usable === false || Boolean(artifact.revoked_by_finding_status);
}

function isPersistedArtifact(artifact: UnknownRecord): boolean {
  return normalized(artifact.persistence_status) === "persisted"
    && typeof artifact.sha256 === "string"
    && artifact.sha256.trim().length > 0
    && !isRevoked(artifact);
}

function hasDowngrade(verification: UnknownRecord): boolean {
  const blockers = verification.confirmed_blockers;
  return Boolean(verification.downgrade_reason)
    || Boolean(verification.poc_revoked_by_finding_status)
    || (Array.isArray(blockers) && blockers.length > 0)
    || normalized(verification.final_verdict).includes("downgrad");
}

function hasActualHttpConfirmation(evidence: UnknownRecord, verification: UnknownRecord): boolean {
  const runtime = asRecord(evidence.runtime);
  return normalized(verification.dynamic_method) === "http_dynamic"
    && verification.dynamically_verified === true
    && normalized(runtime.reproduction_status) === "dynamic_confirmed"
    && runtime.reproducible === true;
}

function hasTargetHarnessConfirmation(evidence: UnknownRecord, verification: UnknownRecord): boolean {
  const harness = asRecord(evidence.harness);
  return normalized(verification.dynamic_method) === "target_harness"
    && verification.dynamically_verified === true
    && normalized(harness.verdict) === "target_confirmed"
    && harness.dynamically_triggered === true
    && harness.function_extracted === true
    && harness.target_function_called === true
    && normalized(harness.verification_level) === "entrypoint_reproduced"
    && harness.entrypoint_reachable === true;
}

function hasExecutedNoHitHttpReplay(evidence: UnknownRecord, verification: UnknownRecord): boolean {
  const runtime = asRecord(evidence.runtime);
  return isConfirmedExecutedNoHit(runtime, {}, verification);
}

/**
 * Canonical, side-effect-free authorization gate for detailed PoC code.
 *
 * A visible finding alone is never enough: code is released only for a current
 * confirmed finding with an immutable, non-revoked primary artifact and either
 * a real HTTP reproduction, entrypoint-confirmed target Harness proof, or an
 * explicitly labeled HTTP request replay that executed without a hit.
 */
export function canDisplayDetailedPoc({ finding, evidence }: PocDisplayInput): boolean {
  const currentFinding = asRecord(finding);
  const findingVerification = asRecord(currentFinding.verification);
  const proof = asRecord(evidence);
  const verification = asRecord(proof.verification);
  const artifacts = asRecord(proof.artifacts);
  const artifact = asRecord(artifacts.validated_poc || proof.poc_file);

  const runtime = asRecord(proof.runtime);
  const executedNoHitReplay = isConfirmedExecutedNoHit(runtime, currentFinding, verification);
  if (hasDowngrade(verification)) return false;
  if (!isPersistedArtifact(artifact)) return false;

  if (executedNoHitReplay) return true;
  if (!isConfirmedProductFinding(currentFinding, findingVerification)) return false;

  return hasActualHttpConfirmation(proof, verification)
    || hasTargetHarnessConfirmation(proof, verification)
    || hasExecutedNoHitHttpReplay(proof, verification);
}

export function hasDisplayablePocCode(value: unknown): boolean {
  const code = String(value ?? "").trim();
  return Boolean(code) && !/^(?:暂无|无|n\/?a|not generated|no (?:exploit|poc|code)|placeholder)(?:[\s:：].*)?$/i.test(code);
}

export function isTargetHarnessConfirmedEvidence(evidence: unknown): boolean {
  const proof = asRecord(evidence);
  return hasTargetHarnessConfirmation(proof, asRecord(proof.verification));
}
