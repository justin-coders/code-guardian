/**
 * Code Guardian — Architecture Analysis Rule Pack Contracts (Official Roadmap Phase 14)
 *
 * The architecture domain's vocabulary for the official roadmap's **Phase 14 — Architecture
 * Analyzer**, which moves the product "from directory inspection to actual structural
 * analysis". This pack is that analyzer's rule vocabulary, its state vocabulary, its
 * documented thresholds and its evidence/confidence policy.
 *
 * ### The nine official domains, one rule each
 *
 *   module boundaries · dependency direction · circular dependencies · layer violations ·
 *   coupling · cohesion indicators · large modules · boundary leakage · architecture patterns
 *
 * Every rule id maps to exactly one domain, and `ARCHITECTURE_ANALYSIS_RULE_IDS` is the single
 * place the shipped ids are declared. A rule id is namespace-shaped
 * (`architecture.module.boundary`), lives in the `architecture.` namespace and appears in every
 * fingerprint the rule produces, so renaming one is a breaking identity change and
 * `architectureAnalysisRuleSetIssues()` fails the registry if a declared rule is missing or an
 * id leaves the namespace.
 *
 * ### Evidence first, and never one universal architecture
 *
 * The roadmap's two principles are the pack's two principles:
 *
 *   1. **Evidence-driven.** Every rule reads the frozen RepositoryModel through the query API
 *      and reports a relationship the repository *establishes* — an import edge, a declared
 *      local-package dependency, a manifest that names a package. A directory name, a file
 *      name, a comment, a doc example or a string literal is never evidence.
 *   2. **No universal architecture.** There is no controllers→services→repositories stereotype,
 *      no "more layers is better", no architecture score, grade or percentage anywhere in the
 *      pack. A layer direction is tested only when the repository *declares* one; a pattern is
 *      claimed only from multiple independent pieces of evidence; an unmapped domain answers
 *      `unknown`, never a fabricated violation.
 *
 * ### The state vocabulary
 *
 * Architecture claims have their own axis, carried as `metadata.state` on every finding while
 * the Rule Engine's outcome vocabulary carries the evaluation outcome:
 *
 *   established      the repository establishes the subject the finding reports (a module, an
 *                    import direction, a measured coupling, a declared layer direction)
 *   detected         an indicator was observed whose strength is below a direct relationship
 *                    — a large module, a cohesion indicator
 *   unknown          the domain applies but the evidence does not establish the answer — an
 *                    incomplete import graph, or no repository-declared layer model
 *   not_applicable   the domain genuinely has no subject over established coverage
 *
 * `unknown` is never clean, and `not_applicable` is never used because evidence is missing.
 */

/** Version of the pack as a whole (analyzer version, rule set revision). */
export const ARCHITECTURE_ANALYSIS_RULE_PACK_VERSION = "1.0.0";

/** Initial version of every rule in the pack. */
export const ARCHITECTURE_ANALYSIS_RULE_VERSION = "1.0.0";

/**
 * Analyzer identity.
 *
 * Distinct from the internal architecture *graph* integration analyzer (`architecture`) that
 * ships one inventory rule over the architecture graph. This pack is the official Phase 14
 * analyzer: the nine roadmap domains, over the import/symbol/architecture graph substrate.
 */
export const ARCHITECTURE_ANALYSIS_ANALYZER_ID = "architecture-analysis";
export const ARCHITECTURE_ANALYSIS_ANALYZER_NAME = "Architecture Analysis";
export const ARCHITECTURE_ANALYSIS_ANALYZER_SCOPE = "architecture-analysis";

/** Category recorded on every architecture-analysis finding (Core Finding contract). */
export const ARCHITECTURE_ANALYSIS_CATEGORY = "architecture";

/** Every rule id in this pack must live in this namespace. */
export const ARCHITECTURE_ANALYSIS_RULE_ID_PREFIX = "architecture.";

/** The rules this pack ships, one per official roadmap domain. */
export const ARCHITECTURE_ANALYSIS_RULE_IDS = Object.freeze({
  MODULE_BOUNDARY: "architecture.module.boundary",
  DEPENDENCY_DIRECTION: "architecture.dependency.direction",
  DEPENDENCY_CYCLE: "architecture.dependency.cycle",
  LAYER_VIOLATION: "architecture.layer.violation",
  COUPLING_MEASURED: "architecture.coupling.measured",
  COHESION_INDICATOR: "architecture.cohesion.indicator",
  MODULE_LARGE: "architecture.module.large",
  BOUNDARY_LEAKAGE: "architecture.boundary.leakage",
  PATTERN_ESTABLISHED: "architecture.pattern.established",
});

/** The `metadata.state` vocabulary (see the module header). */
export const ARCHITECTURE_ANALYSIS_STATES = Object.freeze({
  ESTABLISHED: "established",
  DETECTED: "detected",
  UNKNOWN: "unknown",
  NOT_APPLICABLE: "not_applicable",
});

/**
 * Confidence policy.
 *
 * Confidence is the rule's assertion, chosen to match the *evidence strength* the model
 * establishes:
 *
 *   OBSERVED_RELATIONSHIP   the model established the exact relation the finding names (a
 *                           resolved import edge, a declared dependency). Strongest.
 *   MEASURED_RELATIONSHIP   the finding aggregates established relations into a measurement
 *                           (a module's outgoing dependency count) without naming one edge.
 *   STRUCTURAL_INDICATOR    the finding reports a shape (a large module, a cohesion
 *                           indicator) whose reading is bounded and documented. Weakest, and
 *                           worded as an indicator.
 */
export const ARCHITECTURE_ANALYSIS_CONFIDENCE = Object.freeze({
  OBSERVED_RELATIONSHIP: 0.9,
  MEASURED_RELATIONSHIP: 0.8,
  STRUCTURAL_INDICATOR: 0.6,
});

/** The asset `metadata.basis` values this pack records. */
export const ARCHITECTURE_ANALYSIS_BASES = Object.freeze({
  IMPORT_GRAPH: "import-graph",
  SYMBOL_GRAPH: "symbol-graph",
  DECLARED_DEPENDENCY: "declared-dependency",
  MANIFEST: "manifest",
});

/**
 * Decision thresholds and bounds.
 *
 * Every threshold is a *reporting* choice, stated once here rather than sprinkled through
 * rules, so a reviewer can see exactly where the analyzer draws its line. Each is deterministic
 * (a pure function of the frozen model) and bounded (no rule may emit unbounded output).
 *
 *   MAX_FINDINGS              how many findings one rule reports before it caps and records the
 *                             cap. The roadmap forbids unbounded output.
 *   COUPLING_OUTGOING         the number of distinct modules a module depends on from which the
 *                             coupling rule reports a measurement. It reports the *count*, never
 *                             a verdict — the roadmap asks for measured coupling, not taste.
 *   LARGE_MODULE_FILES        the number of module sources in one module from which it is
 *                             reported as large.
 *   LARGE_MODULE_DECLARATIONS the total module-scope declarations across a module from which it
 *                             is reported as large (only when the symbol graph is established).
 *   COHESION_MIN_MEMBERS      the module size from which a module with no internal import edge is
 *                             reported as a cohesion *indicator*.
 *   MAX_CYCLE_MEMBERS         the members of one cycle named in a finding before the rest are
 *                             summarized. A cycle description must stay bounded.
 */
export const ARCHITECTURE_ANALYSIS_LIMITS = Object.freeze({
  MAX_FINDINGS: 200,
  COUPLING_OUTGOING: 10,
  LARGE_MODULE_FILES: 20,
  LARGE_MODULE_DECLARATIONS: 200,
  COHESION_MIN_MEMBERS: 4,
  MAX_CYCLE_MEMBERS: 20,
});

/** The repository-relative label for the module that owns root-level files. */
export const ROOT_MODULE_PATH = "(repository root)";

/** Media type of the architecture pattern vocabulary: the one pattern this build establishes. */
export const ARCHITECTURE_PATTERNS = Object.freeze({
  WORKSPACE_MONOREPO: "workspace-monorepo",
});

/** The dependency spec kinds that establish a repository-*declared* local-package direction. */
export const LOCAL_PACKAGE_SPEC_KINDS = Object.freeze(["workspace", "local"]);
