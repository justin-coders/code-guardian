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

/**
 * Descriptive fields an Analyzer may declare.
 *
 * These are *not* required by the Core contract: `validateAnalyzer` is the
 * authority on executability (identity, version, and the two functions). The
 * Phase 9 analyzer framework additionally requires `name` and `scope` before it
 * will register an analyzer, because a registry entry has to be identifiable and
 * attributable in a report — a requirement of the framework, not of the
 * contract.
 */
export const ANALYZER_DESCRIPTIVE_FIELDS = Object.freeze([
  "name",
  "scope",
  "description",
  "metadata",
]);

/**
 * Build an Analyzer descriptor.
 *
 * Executable behavior (`canAnalyze`, `analyze`) and identity are supplied by the
 * caller; nothing is defaulted that would imply a detection decision. This is a
 * shape/draft factory (see Core `CONTRACT_FACTORY_SEMANTICS`): run
 * `validateAnalyzer` before treating the result as a contract instance.
 *
 * @param {object} [input]
 * @param {string} [input.id] Stable analyzer ID, e.g. "security.node".
 * @param {string} [input.name] Short human-readable name.
 * @param {string} [input.version] Analyzer version, e.g. "1.0.0".
 * @param {string} [input.scope] Domain namespace, e.g. "security".
 * @param {string} [input.description] Longer explanation.
 * @param {Function} [input.canAnalyze] `(context) => Applicability`.
 * @param {Function} [input.analyze] `(context) => AnalysisResult`.
 * @param {object} [input.metadata] Optional declarative metadata.
 * @returns {object} An Analyzer-shaped draft; validate before use.
 */
export function createAnalyzer(input = {}) {
  return {
    id: input.id,
    name: input.name,
    version: input.version,
    scope: input.scope,
    description: input.description ?? "",
    canAnalyze: input.canAnalyze,
    analyze: input.analyze,
    metadata: input.metadata ?? {},
  };
}

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
