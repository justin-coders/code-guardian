/**
 * Code Guardian Core — Finding Contract
 *
 * A Finding is an *interpretation* of evidence: "this observed condition is a
 * problem or noteworthy condition".
 *
 * Severity and confidence are independent dimensions and must never be
 * collapsed into a single score:
 *   severity   = how bad the condition is if it is true
 *   confidence = how certain the analysis is that the condition is true
 *
 * Findings reference evidence by ID (`evidence: ["evidence-123"]`) rather than
 * embedding evidence objects.
 *
 * Fingerprint lifecycle: a finding has two stages relative to fingerprinting.
 *
 *   raw       — produced by a Rule/Analyzer (`createFinding`). A canonical
 *               fingerprint has not been generated yet, so `fingerprint` is
 *               absent. Validated by `validateRawFinding`.
 *   canonical — promoted later by the Finding Engine, which assigns a stable
 *               fingerprint. Validated by `validateFinding`, which requires a
 *               non-empty `fingerprint`.
 *
 * The factory never invents a fingerprint: generating one is deferred to the
 * future Finding Engine. This module defines the shape/constants/factory only;
 * `createFinding` is a shape/draft factory whose output must be validated.
 */

/** Severity vocabulary: consequence if the finding is true. */
export const FINDING_SEVERITIES = Object.freeze([
  "info",
  "low",
  "medium",
  "high",
  "critical",
]);

/**
 * Finding lifecycle vocabulary. Only `open` is produced during this phase;
 * the wider vocabulary exists so lifecycle management can be added later
 * without a breaking contract change.
 */
export const FINDING_STATUSES = Object.freeze([
  "open",
  "acknowledged",
  "suppressed",
  "resolved",
  "regressed",
]);

/** Status assigned to newly created findings. */
export const DEFAULT_FINDING_STATUS = "open";

/** Lower bound of normalized confidence. */
export const CONFIDENCE_MIN = 0;

/** Upper bound of normalized confidence. */
export const CONFIDENCE_MAX = 1;

/**
 * Finding stages relative to canonical fingerprint generation.
 *
 * `RAW` findings may exist before the Finding Engine runs; `CANONICAL` findings
 * have had a stable fingerprint assigned and are the ones persisted/baselined.
 */
export const FINDING_STAGES = Object.freeze({
  RAW: "raw",
  CANONICAL: "canonical",
});

/**
 * Confidence is normalized to the inclusive range [0, 1].
 * @param {unknown} value
 * @returns {boolean}
 */
export function isValidConfidence(value) {
  return (
    typeof value === "number" &&
    Number.isFinite(value) &&
    value >= CONFIDENCE_MIN &&
    value <= CONFIDENCE_MAX
  );
}

/**
 * Whether a finding has been assigned a canonical fingerprint.
 *
 * Uses the presence of a non-empty `fingerprint` as the discriminator; the
 * Finding Engine is the only component that should create such a finding.
 *
 * @param {unknown} finding
 * @returns {boolean}
 */
export function hasFingerprint(finding) {
  return (
    finding !== null &&
    typeof finding === "object" &&
    typeof finding.fingerprint === "string" &&
    finding.fingerprint.trim().length > 0
  );
}

/**
 * Build a *raw* Finding object (stage `FINDING_STAGES.RAW`).
 *
 * `evidence` accepts evidence reference IDs (strings), not evidence objects.
 * `impact`/`remediation` are optional this phase.
 *
 * A raw finding deliberately has no `fingerprint`: canonical fingerprint
 * generation is deferred to the future Finding Engine. If the caller supplies a
 * fingerprint it is preserved, but the factory never invents one. Raw findings
 * are validated with `validateRawFinding`; the Finding Engine promotes them to
 * canonical findings validated with `validateFinding`.
 *
 * @param {object} [input]
 * @returns {object} A Finding-shaped draft (validate before use).
 */
export function createFinding(input = {}) {
  const finding = {
    id: input.id,
    ruleId: input.ruleId,
    category: input.category,
    severity: input.severity,
    confidence: input.confidence,
    title: input.title,
    description: input.description ?? "",
    evidence: input.evidence ?? [],
    status: input.status ?? DEFAULT_FINDING_STATUS,
    metadata: input.metadata ?? {},
  };
  if (input.fingerprint !== undefined) {
    finding.fingerprint = input.fingerprint;
  }
  if (input.impact !== undefined) {
    finding.impact = input.impact;
  }
  if (input.remediation !== undefined) {
    finding.remediation = input.remediation;
  }
  return finding;
}
