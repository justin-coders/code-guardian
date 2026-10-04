/**
 * Code Guardian — Dependency Analysis Rule Pack Contracts (Official Roadmap Phase 15)
 *
 * The dependency domain's vocabulary for the official roadmap's **Phase 15 — Dependency
 * Analyzer**, which asks for "a dedicated dependency analysis layer" over eight domains:
 *
 *   outdated dependencies · known vulnerabilities · unused dependencies · duplicate versions ·
 *   dependency concentration · lockfile integrity · package manager consistency ·
 *   supply-chain risk indicators
 *
 * ### Substrate vs analysis, kept apart on purpose
 *
 * The existing `dependency.inventory.declarations` and `dependency.graph.inventory` rules state
 * *facts*: which dependencies a manifest declared, which relationships a lockfile recorded. This
 * pack adds *analysis* — the eight domains above — and never renames or deletes the inventory
 * rules. A declaration finding rests on a manifest; an analysis finding rests on a comparison,
 * a measurement or an advisory, and its `metadata.basis` says which.
 *
 * ### Two sources of truth, never merged
 *
 * The central requirement of this phase is that the analyzer distinguish
 * *what the repository establishes* from *what external dependency intelligence establishes*:
 *
 *   repository fact    package X, declared range Y, resolved version Z, manifest M
 *   external fact      advisory A, source S, revision R, affected range
 *
 * External intelligence is **time-sensitive data** (the roadmap says so explicitly). It enters
 * through `context.options.dependencyIntelligence` — a versioned dataset, never a live lookup,
 * never a network call from a rule — and every finding it produces records the source id and the
 * source *revision* that produced it. When the dataset is absent, stale or malformed the domain
 * answers `unknown`, never `clean`.
 *
 * ### No score, no remediation
 *
 * There is no dependency score, grade or percentage anywhere in the pack, and no rule upgrades,
 * edits or removes anything. Findings and measured facts are the whole output.
 */

/** Version of the pack as a whole (analyzer version, rule set revision). */
export const DEPENDENCY_ANALYSIS_RULE_PACK_VERSION = "1.0.0";

/** Initial version of every rule in the pack. */
export const DEPENDENCY_ANALYSIS_RULE_VERSION = "1.0.0";

/**
 * Analyzer identity.
 *
 * Distinct from the internal dependency *substrate* integration analyzer (`dependency`), which
 * ships the two inventory rules. This pack is the official Phase 15 analyzer.
 */
export const DEPENDENCY_ANALYSIS_ANALYZER_ID = "dependency-analysis";
export const DEPENDENCY_ANALYSIS_ANALYZER_NAME = "Dependency Analysis";
export const DEPENDENCY_ANALYSIS_ANALYZER_SCOPE = "dependency-analysis";

/** Category recorded on every dependency-analysis finding (Core Finding contract). */
export const DEPENDENCY_ANALYSIS_CATEGORY = "dependency";

/** Every rule id in this pack must live in this namespace. */
export const DEPENDENCY_ANALYSIS_RULE_ID_PREFIX = "dependency.";

/** The rules this pack ships, one per official roadmap domain. */
export const DEPENDENCY_ANALYSIS_RULE_IDS = Object.freeze({
  OUTDATED: "dependency.outdated.version",
  VULNERABILITY: "dependency.vulnerability.advisory",
  UNUSED: "dependency.unused.declared",
  DUPLICATE_VERSIONS: "dependency.duplicate-versions.resolved",
  CONCENTRATION: "dependency.concentration.measured",
  LOCKFILE_INTEGRITY: "dependency.lockfile.integrity",
  MANAGER_CONSISTENCY: "dependency.manager.consistency",
  SUPPLY_CHAIN: "dependency.supply-chain.indicator",
});

/** The `metadata.state` vocabulary (see the module header). */
export const DEPENDENCY_ANALYSIS_STATES = Object.freeze({
  ESTABLISHED: "established",
  DETECTED: "detected",
  UNKNOWN: "unknown",
  NOT_APPLICABLE: "not_applicable",
});

/**
 * Confidence policy, chosen to match the *evidence strength* behind each claim.
 *
 *   OBSERVED_FACT           the repository established the fact (a resolved version, a git
 *                           specifier). Strongest repository-only claim.
 *   MEASURED_RELATIONSHIP   the finding aggregates established relationships into a count.
 *   EXTERNAL_MATCH          the finding rested on external intelligence as well as a repository
 *                           fact, and records the source revision it used.
 *   STRUCTURAL_INDICATOR    a bounded indicator (a possibly-unused dependency). Weakest, and
 *                           worded as an indicator.
 */
export const DEPENDENCY_ANALYSIS_CONFIDENCE = Object.freeze({
  OBSERVED_FACT: 0.9,
  MEASURED_RELATIONSHIP: 0.8,
  EXTERNAL_MATCH: 0.7,
  STRUCTURAL_INDICATOR: 0.5,
});

/** The `metadata.basis` values this pack records. */
export const DEPENDENCY_ANALYSIS_BASES = Object.freeze({
  MANIFEST_DECLARATION: "manifest-declaration",
  LOCKFILE_RESOLUTION: "lockfile-resolution",
  DEPENDENCY_GRAPH: "dependency-graph",
  IMPORT_USAGE: "import-usage",
  EXTERNAL_ADVISORY: "external-advisory",
  EXTERNAL_RELEASE: "external-release",
  PACKAGE_MANAGER: "package-manager",
});

/**
 * Decision thresholds and bounds.
 *
 * Every threshold is a *reporting* choice, stated once here rather than sprinkled through rules,
 * deterministic (a pure function of the frozen model) and bounded (no rule may emit unbounded
 * output).
 *
 *   MAX_FINDINGS             findings one rule reports before it caps and records the cap.
 *   CONCENTRATION_INDEGREE   the number of packages that depend on one package from which the
 *                            concentration rule reports a measurement.
 *   MAX_SOURCES/ADVISORIES/RELEASES/VERSIONS  external dataset bounds; an over-large dataset is
 *                            refused (unknown) rather than silently truncated.
 *   MAX_RANGE_TERMS          alternative ranges one advisory may state before it is refused.
 */
export const DEPENDENCY_ANALYSIS_LIMITS = Object.freeze({
  MAX_FINDINGS: 200,
  CONCENTRATION_INDEGREE: 10,
  MAX_SOURCES: 64,
  MAX_ADVISORIES: 1000,
  MAX_RELEASES: 5000,
  MAX_VERSIONS_PER_PACKAGE: 200,
  MAX_RANGE_TERMS: 32,
});

/**
 * The external-intelligence dataset the analyzer consumes from
 * `context.options.dependencyIntelligence`.
 *
 * It is plain, versioned data: sources (each with an id and a revision), advisories and release
 * metadata. Nothing about it is a judgment; it is the same class of fact the model records,
 * just externally sourced.
 */
export const DEPENDENCY_INTELLIGENCE_STATES = Object.freeze({
  ABSENT: "absent",
  VALID: "valid",
  INVALID: "invalid",
});

/** Ecosystem ids whose version semantics this build compares. */
export const SEMVER_ECOSYSTEMS = Object.freeze(["node"]);

/** Dependency spec kinds that are supply-chain *source* indicators (not ordinary registries). */
export const UNUSUAL_SOURCE_SPEC_KINDS = Object.freeze(["git", "url", "alias"]);

/**
 * Package-manager identity derived from lockfile basenames.
 *
 * A closed map keyed by the lockfile file name the scanner observes; a basename not in this map
 * establishes no manager identity.
 */
export const PACKAGE_MANAGER_BY_LOCKFILE = Object.freeze({
  "package-lock.json": "npm",
  "npm-shrinkwrap.json": "npm",
  "yarn.lock": "yarn",
  "pnpm-lock.yaml": "pnpm",
  "bun.lockb": "bun",
  "Cargo.lock": "cargo",
  "poetry.lock": "poetry",
  "Pipfile.lock": "pipenv",
  "go.sum": "go-modules",
  "composer.lock": "composer",
  "Gemfile.lock": "bundler",
});

/** The lockfile basenames this build's scanner interprets (others are recorded unsupported). */
export const INTERPRETED_LOCKFILES = Object.freeze(["package-lock.json", "npm-shrinkwrap.json"]);
