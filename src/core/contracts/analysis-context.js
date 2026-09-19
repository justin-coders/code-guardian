/**
 * Code Guardian Core — AnalysisContext Contract
 *
 * The AnalysisContext is the shared boundary between the Core and analyzers.
 *
 * Ownership rule (Phase 7 Blueprint §18): the Core constructs the context,
 * including the RepositoryModel. Analyzers only consume it — an analyzer must
 * never build its own repository scanner, otherwise every analyzer would
 * re-discover the same facts.
 *
 * The context is a composite contract: `validateAnalysisContext` validates the
 * nested `repository` as a RepositoryModel, each `rules` entry as a Rule, and
 * each `evidence` entry as an Evidence object (it reuses the same nested
 * collectors rather than importing one contract module from another).
 *
 * This module defines the shape/constants/factory only. `createAnalysisContext`
 * is a shape/draft factory whose output must be validated.
 */

/** Fields every AnalysisContext must declare. */
export const ANALYSIS_CONTEXT_FIELDS = Object.freeze([
  "repository",
  "configuration",
  "execution",
  "rules",
  "evidence",
  "options",
]);

/**
 * Build an AnalysisContext.
 *
 * `repository` is required and has no default: the Core is responsible for
 * supplying the shared RepositoryModel.
 *
 * @param {object} [input]
 * @param {object} [input.repository] Shared RepositoryModel (required).
 * @param {object} [input.configuration] Resolved Guardian configuration.
 * @param {object} [input.execution] Execution policy/facilities descriptor.
 * @param {Array} [input.rules] Rules available to the analyzer.
 * @param {Array} [input.evidence] Evidence collected so far.
 * @param {object} [input.options] Analysis options.
 * @returns {object} An AnalysisContext-shaped draft; validate before use.
 */
export function createAnalysisContext(input = {}) {
  return {
    repository: input.repository,
    configuration: input.configuration ?? {},
    execution: input.execution ?? {},
    rules: input.rules ?? [],
    evidence: input.evidence ?? [],
    options: input.options ?? {},
  };
}
