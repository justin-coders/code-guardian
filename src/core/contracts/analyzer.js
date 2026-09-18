/**
 * Code Guardian Core — Analyzer Contract
 *
 * An Analyzer is a domain-level intelligence module ("how a domain is
 * analyzed"). It consumes the shared AnalysisContext, selects applicable
 * rules, and returns a validated AnalysisResult.
 *
 * The contract intentionally has no transport concerns: analyzers never format
 * MCP responses and never fetch their own repository model.
 *
 * This module defines the shape/constants/factories only.
 */

/** Fields every Analyzer must declare. */
export const ANALYZER_REQUIRED_FIELDS = Object.freeze([
  "id",
  "version",
  "canAnalyze",
  "analyze",
]);

/** Fields every analyzer result must declare (Phase 7 Blueprint §16). */
export const ANALYSIS_RESULT_FIELDS = Object.freeze([
  "findings",
  "evidence",
  "metrics",
  "metadata",
]);

/**
 * Build a standard analyzer result. Returning this shape (rather than `null`)
 * is what makes analyzer output validatable.
 *
 * @param {object} [input]
 * @param {Array} [input.findings] Findings produced by the analyzer.
 * @param {Array} [input.evidence] New Evidence objects collected.
 * @param {object} [input.metrics] Numeric/derived measurements.
 * @param {object} [input.metadata] Analyzer/run metadata.
 * @returns {object} An AnalysisResult-shaped object.
 */
export function createAnalysisResult(input = {}) {
  return {
    findings: input.findings ?? [],
    evidence: input.evidence ?? [],
    metrics: input.metrics ?? {},
    metadata: input.metadata ?? {},
  };
}

/**
 * Build the result of `analyzer.canAnalyze(context)`.
 *
 * @param {object} [input]
 * @param {boolean} [input.applicable] Whether the analyzer can operate.
 * @param {string} [input.reason] Optional explanation when not applicable.
 * @returns {object} An applicability result.
 */
export function createApplicability(input = {}) {
  const applicability = { applicable: input.applicable };
  if (input.reason !== undefined) {
    applicability.reason = input.reason;
  }
  return applicability;
}
