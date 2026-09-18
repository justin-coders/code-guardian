/**
 * Code Guardian Core — Rule Contract
 *
 * A Rule defines *what should be detected*. An Analyzer defines *how a domain
 * is analyzed* and selects the rules that apply (Phase 4 §4.11).
 *
 * The contract deliberately separates metadata (declarative, serializable)
 * from executable behavior (`detect`, a function). `detect` receives the shared
 * AnalysisContext and returns findings; it must not crawl the filesystem on its
 * own and must not know about MCP, HTTP, or the CLI.
 *
 * This module defines the shape/constants/factory only.
 */

/** Version pattern for rules, analyzers and models (e.g. "1.0.0", "1.2.0-beta.1"). */
export const VERSION_PATTERN = /^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)*$/;

/** Fields every Rule must declare. */
export const RULE_REQUIRED_FIELDS = Object.freeze([
  "id",
  "version",
  "category",
  "title",
  "description",
  "severity",
  "applicability",
  "detect",
  "remediation",
  "metadata",
]);

/**
 * Applicability selectors a rule may use to decide whether it runs.
 * All are optional; a rule with no selectors is universally applicable.
 */
export const RULE_APPLICABILITY_KEYS = Object.freeze([
  "languages",
  "frameworks",
  "files",
  "capabilities",
]);

/** Declarative rule metadata keys (all optional). */
export const RULE_METADATA_KEYS = Object.freeze([
  "references",
  "tags",
  "frameworks",
  "introducedIn",
  "deprecated",
  "falsePositives",
]);

/**
 * Build a Rule object.
 *
 * Identity, severity and executable `detect` behavior are supplied by the
 * caller; nothing is defaulted that would imply a detection decision.
 *
 * @param {object} [input]
 * @param {string} [input.id] Stable rule ID, e.g. "security.hardcoded-secret".
 * @param {string} [input.version] Rule version, e.g. "1.0.0".
 * @param {string} [input.category] Rule category, e.g. "security".
 * @param {string} [input.title] Short human-readable title.
 * @param {string} [input.description] Longer explanation.
 * @param {string} [input.severity] One of `FINDING_SEVERITIES`.
 * @param {object} [input.applicability] Applicability selectors.
 * @param {Function} [input.detect] `(context) => Finding[] | Promise<Finding[]>`.
 * @param {object} [input.remediation] Optional remediation metadata.
 * @param {object} [input.metadata] Optional declarative metadata.
 * @returns {object} A Rule-shaped object.
 */
export function createRule(input = {}) {
  return {
    id: input.id,
    version: input.version,
    category: input.category,
    title: input.title,
    description: input.description ?? "",
    severity: input.severity,
    applicability: input.applicability ?? {},
    detect: input.detect,
    remediation: input.remediation ?? {},
    metadata: input.metadata ?? {},
  };
}
