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
 * embedding evidence objects. Fingerprint *generation* is a later concern; the
 * contract only permits/requires a stable fingerprint string.
 *
 * This module defines the shape/constants/factory only.
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
 * Build a Finding object.
 *
 * `evidence` accepts evidence reference IDs (strings), not evidence objects.
 * `impact`/`remediation` are optional this phase.
 *
 * @param {object} [input]
 * @returns {object} A Finding-shaped object.
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
    fingerprint: input.fingerprint,
    metadata: input.metadata ?? {},
  };
  if (input.impact !== undefined) {
    finding.impact = input.impact;
  }
  if (input.remediation !== undefined) {
    finding.remediation = input.remediation;
  }
  return finding;
}
