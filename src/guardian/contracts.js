/**
 * Code Guardian — Guardian Core Contracts (Official Roadmap Phase 19)
 *
 * The vocabulary of the canonical analysis engine. This module holds names and
 * closed vocabularies only: no orchestration, no I/O, no dependencies beyond
 * nothing at all.
 *
 * ### What the Guardian Core is
 *
 * Phase 19 unifies the independent analyzers under one orchestration layer with
 * the conceptual operation `guardian.audit(repository, options)`. The Core owns
 * the *pipeline* — configuration, repository model, analyzer selection, context,
 * execution, evidence, finding aggregation, risk and the canonical result — and
 * owns nothing that an existing layer already owns:
 *
 *   RepositoryModel construction   the accepted scanner → builder pipeline
 *   AnalysisContext                `buildAnalysisContext`
 *   analyzer selection/registry    the accepted `createAnalyzerRegistry`
 *   analyzer execution             the accepted `createAnalyzerEngine`
 *   finding normalization          the accepted Finding Engine
 *   rule applicability             the accepted `evaluateRuleApplicability`
 *
 * ### Everything here is closed
 *
 * A version, an option key, a risk vocabulary word or a result field that is not
 * listed here does not exist. Consumers can exhaustively switch on the values, and
 * adding one is a visible contract change rather than an accidental new string.
 *
 * This module performs no I/O and reads no clock.
 */

/** Engine name recorded on a canonical result. */
export const GUARDIAN_ENGINE_NAME = "code-guardian";

/**
 * Version of the Guardian Core (orchestration semantics, result shape).
 * Semver, matching the Core convention for analyzers, rules and models.
 */
export const GUARDIAN_ENGINE_VERSION = "1.0.0";

/**
 * Version of the canonical Guardian result schema.
 *
 * Semver, matching the accepted `AnalysisRunResult.version` convention rather
 * than the architecture sketch's `"1"`: a validated version in this codebase is a
 * semver string, and the result is validated by the same `VERSION_PATTERN`.
 */
export const GUARDIAN_RESULT_SCHEMA_VERSION = "1.0.0";

/**
 * Version of the risk aggregation contract.
 *
 * Separate from the result schema version because the risk vocabulary and its
 * aggregation rules can change without changing the result shape, and a consumer
 * that baselines risk needs to detect exactly that.
 */
export const RISK_CONTRACT_VERSION = "1.0.0";

/**
 * The closed set of keys an `audit()` options object may carry.
 *
 * An unknown key is a configuration error rather than a silently ignored option:
 * an ignored option is a capability the caller believed they had.
 *
 * `analyzers`  analyzer ids to run, or the string `"all"` (default)
 * `rules`      Rule contracts made available on the AnalysisContext
 * `evidence`   Evidence contracts carried into the run
 * `configuration` declarative data exposed to analyzers as `context.configuration`
 * `execution`  execution policy descriptor exposed as `context.execution`
 * `analysis`   declarative analysis options exposed as `context.options`
 * `failFast`   stop at the first analyzer failure (opt-in)
 * `scan`       scanner options used only when the repository input is a path
 * `clock`      millisecond clock; a runtime dependency, not declarative config
 */
export const AUDIT_OPTION_KEYS = Object.freeze([
  "analyzers",
  "rules",
  "evidence",
  "configuration",
  "execution",
  "analysis",
  "failFast",
  "scan",
  "clock",
]);

/**
 * Option keys whose values must be plain, bounded, declarative data.
 *
 * `rules` and `evidence` are Core contract objects (a Rule carries a `detect`
 * function) and are validated by the AnalysisContext validator instead; `clock`
 * is an injected runtime function; `analyzers` and `failFast` are validated as
 * their own shapes.
 */
export const DECLARATIVE_AUDIT_KEYS = Object.freeze(["configuration", "analysis", "scan"]);

/** The value that selects every registered analyzer. */
export const GUARDIAN_SELECTION_ALL = "all";

/** Finding severities, in ascending order of severity. The risk vocabulary. */
export const RISK_SEVERITIES = Object.freeze(["info", "low", "medium", "high", "critical"]);

/**
 * The closed set of limitation reason codes a risk profile may record.
 *
 * A limitation names *what could not be established*, never a defect. The
 * analyzer-scoped reasons carry the offending analyzer id (`analyzer-failed:security.rules`
 * etc.) so a consumer can attribute the limitation without parsing prose.
 */
export const RISK_LIMITATION_KINDS = Object.freeze({
  /** The repository scan did not cover the repository completely. */
  REPOSITORY_INCOMPLETE: "repository-coverage-incomplete",
  /** The scan stopped at a bound, so the inventory is not the complete set. */
  REPOSITORY_TRUNCATED: "repository-scan-truncated",
  /** An analyzer failed, so its domain has no answer. */
  ANALYZER_FAILED: "analyzer-failed",
  /** An analyzer was skipped (fail-fast), so its domain has no answer. */
  ANALYZER_SKIPPED: "analyzer-skipped",
});

/** Fields the canonical Guardian result declares. */
export const GUARDIAN_RESULT_FIELDS = Object.freeze([
  "schemaVersion",
  "engine",
  "repository",
  "analysis",
  "analyzers",
  "findings",
  "evidence",
  "metrics",
  "risk",
  "scan",
]);

/** Fields each per-analyzer attribution summary declares. */
export const GUARDIAN_ANALYZER_SUMMARY_FIELDS = Object.freeze([
  "id",
  "name",
  "version",
  "scope",
  "status",
  "applicability",
  "findings",
  "evidence",
  "metrics",
  "errors",
]);

/**
 * Keys that must never appear anywhere on the canonical result.
 *
 * The Core reports facts, findings and a documented risk *profile*; it never
 * emits a collapsed score, a grade, a readiness verdict or a bare quality number.
 * This is the Guardian-level counterpart of the analyzer framework's
 * `ANALYSIS_JUDGMENT_KEYS` (which additionally forbids `risk`, correctly, because
 * the analyzer framework must not interpret — the Guardian Core is the first layer
 * permitted a documented risk profile, and exactly one).
 */
export const FORBIDDEN_GUARDIAN_RESULT_KEYS = Object.freeze([
  "score",
  "grade",
  "verdict",
  "productionReady",
  "quality",
]);

/** Upper bound on explicitly selected analyzer ids. */
export const MAX_AUDIT_ANALYZERS = 1000;

/** Upper bound on a recorded limitation string. */
export const MAX_LIMITATION_LENGTH = 200;
