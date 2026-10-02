/**
 * Code Guardian — Code Quality Rule Pack Contracts (Official Roadmap Phase 12)
 *
 * The code-quality domain's vocabulary: which rules exist, which model facts the pack
 * consumes, and the confidence policy its rules assert. Nothing here redefines a framework
 * concept — rule identity comes from the Core Rule contract, severities from the Core
 * Finding contract, and outcome vocabulary from the Phase 10 Rule Engine.
 *
 * ### The nine official-roadmap domains
 *
 *   linting · formatting · type checking · dead code · complexity · duplication ·
 *   unsafe patterns · maintainability · configuration consistency
 *
 * Every rule id maps to exactly one of them, and `CODE_QUALITY_RULE_IDS` is the single
 * place the shipped ids are declared. A rule id is namespace-shaped
 * (`code-quality.linting.unconfigured`) and appears in every finding fingerprint the rule
 * will ever produce, so renaming one is a breaking identity change and
 * `codeQualityRuleSetIssues()` fails the registry if a declared rule is missing or an id
 * leaves the `code-quality.` namespace.
 *
 * ### The five states, and how they map onto the Rule Engine
 *
 * The roadmap requires the analyzer to distinguish `observed`/`detected`, `verified`,
 * `failed`, `unknown` and `not_applicable`. Those are *claims about a domain*, and this
 * pack keeps them as `metadata.state` on each finding while the Rule Engine's own outcome
 * vocabulary carries the evaluation outcome:
 *
 *   detected         a quality artifact was observed (a configuration, a script, a declared
 *                    dependency) but nothing established it runs
 *   verified         the tool is configured **and** a CI workflow is observed containing
 *                    that tool's documented invocation — the strongest claim this phase can
 *                    make, and never a claim that the run passed
 *   failed           an expected operation demonstrably failed (a manifest whose parse
 *                    failed, so its declared scripts cannot be read)
 *   unknown          the domain applies but the evidence does not establish the answer —
 *                    an incomplete scan, an unread workflow, or a domain whose measurement
 *                    the model does not provide (duplication)
 *   not_applicable   the domain genuinely has no subject over complete coverage
 *
 * `unknown` is never `clean`, and `not_applicable` is never used because evidence is
 * missing — the summary module derives both from the model's own coverage, exactly as the
 * Phase 10/11 packs do.
 *
 * ### No execution claim, ever
 *
 * A configuration is not execution, presence is not correctness, and an invocation is not
 * successful completion. `verified` here means "configured **and** observed invoked in CI",
 * and the conservatism is deliberate: this build reads no lint report, no formatter diff and
 * no compiler diagnostic.
 */

/** Version of the pack as a whole (analyzer version, rule set revision). */
export const CODE_QUALITY_RULE_PACK_VERSION = "1.0.0";

/** Initial version of every rule in the pack. */
export const CODE_QUALITY_RULE_VERSION = "1.0.0";

/** Analyzer identity. `code-quality` is the domain namespace, not a rule. */
export const CODE_QUALITY_ANALYZER_ID = "code-quality";
export const CODE_QUALITY_ANALYZER_NAME = "Code Quality";
export const CODE_QUALITY_ANALYZER_SCOPE = "code-quality";

/** Category recorded on every code-quality finding (Core Finding contract). */
export const CODE_QUALITY_CATEGORY = "code-quality";

/** Every code-quality rule id must live in this namespace. */
export const CODE_QUALITY_RULE_ID_PREFIX = "code-quality.";

/**
 * The rules this pack ships.
 *
 * Each id maps to one official-roadmap analysis domain; the pack deliberately stops at ten,
 * because the roadmap says to establish a *correct* analyzer rather than the largest
 * possible one.
 */
export const CODE_QUALITY_RULE_IDS = Object.freeze({
  LINTING_UNCONFIGURED: "code-quality.linting.unconfigured",
  FORMATTING_UNCONFIGURED: "code-quality.formatting.unconfigured",
  TYPE_CHECKING_UNCONFIGURED: "code-quality.type-checking.unconfigured",
  DEAD_CODE_UNUSED_EXPORT: "code-quality.dead-code.unused-export",
  DEAD_CODE_ORPHAN_MODULE: "code-quality.dead-code.orphan-module",
  COMPLEXITY_LARGE_MODULE: "code-quality.complexity.large-module",
  DUPLICATION_UNMEASURED: "code-quality.duplication.unmeasured",
  UNSAFE_PATTERN_DYNAMIC_SCOPE: "code-quality.unsafe-pattern.dynamic-scope",
  MAINTAINABILITY_NO_TOOLING: "code-quality.maintainability.no-quality-tooling",
  CONFIGURATION_INCONSISTENT: "code-quality.configuration.inconsistent",
});

/**
 * The five official-roadmap states a quality finding may assert.
 *
 * These are the *claim* states; the Rule Engine's outcome statuses are a different axis (a
 * `detected` finding is a `violation` outcome, a clean domain is `pass`).
 */
export const CODE_QUALITY_STATES = Object.freeze({
  DETECTED: "detected",
  VERIFIED: "verified",
  FAILED: "failed",
  UNKNOWN: "unknown",
  NOT_APPLICABLE: "not_applicable",
});

/**
 * Confidence policy.
 *
 * Confidence is the rule's assertion, never a framework default. The levels are chosen to
 * match the *evidence strength* the Phase 12 acquisition establishes:
 *
 *   OBSERVED_ARTIFACT     the model directly observed the artifact the finding names (a
 *                         configuration file, a declared dependency, a declared script).
 *   OBSERVED_CONTENT      a bounded content read matched a closed pattern (a CI workflow
 *                         contains a tool's invocation; a module source contains a
 *                         dynamic-scope construct). Direct evidence about the bytes.
 *   DERIVED_CONDITION     the finding compares two observations (a configuration with no
 *                         execution path) rather than naming one artifact.
 *   GAP_CONDITION         the finding asserts a gap over established coverage, so it rests
 *                         on the model's own completeness rather than on bytes.
 *   STRUCTURAL_INDICATOR  the finding reports a structural shape of a graph (an export with
 *                         no established references, a large module). It is the weakest
 *                         claim and is worded as an *indicator*, never a verdict.
 */
export const CODE_QUALITY_CONFIDENCE = Object.freeze({
  OBSERVED_ARTIFACT: 0.9,
  OBSERVED_CONTENT: 0.9,
  DERIVED_CONDITION: 0.6,
  GAP_CONDITION: 0.6,
  STRUCTURAL_INDICATOR: 0.5,
});

/**
 * The quality-domain vocabulary, re-declared from the scanner's own policy.
 *
 * Re-declared rather than imported, because the rules layer must not depend on the
 * acquisition layer; `tests/code-quality-rules.test.js` builds a real model from a real scan
 * and fails if these drift from `policies/quality.js`.
 */
export const QUALITY_TOOL_IDS = Object.freeze([
  "biome",
  "black",
  "clang-format",
  "clippy",
  "dotnet-format",
  "eslint",
  "flake8",
  "flow",
  "gofmt",
  "golangci-lint",
  "mypy",
  "oxlint",
  "prettier",
  "pylint",
  "pyright",
  "ruff",
  "rustfmt",
  "stylelint",
  "tsc",
]);

/** Quality tool id → the roadmap domain it serves. Pinned by a test against the scanner. */
export const QUALITY_TOOL_DOMAINS = Object.freeze({
  biome: "linting",
  black: "formatting",
  "clang-format": "formatting",
  clippy: "linting",
  "dotnet-format": "formatting",
  eslint: "linting",
  flake8: "linting",
  flow: "type-checking",
  gofmt: "formatting",
  "golangci-lint": "linting",
  mypy: "type-checking",
  oxlint: "linting",
  prettier: "formatting",
  pylint: "linting",
  pyright: "type-checking",
  ruff: "linting",
  rustfmt: "formatting",
  stylelint: "linting",
  tsc: "type-checking",
});

/**
 * Model `signal` values this pack consumes from configuration entities.
 *
 * A `configuration` entity carries the scanner signal that produced it, so a rule can tell a
 * linter from a formatter from a compiler configuration without re-deriving either.
 */
export const QUALITY_CONFIGURATION_SIGNALS = Object.freeze({
  LINT: "lint-configuration",
  FORMAT: "format-configuration",
  BUILD: "build-configuration",
});

/**
 * The build-configuration basenames that establish **type checking** specifically.
 *
 * `build-configuration` also covers bundler configurations (`vite.config.ts`,
 * `webpack.config.js`, `babel.config.js`), which are build facts and not type-checking ones.
 * Matching on the basename keeps the two apart without reading either file.
 */
export const TYPE_CHECK_CONFIG_BASENAMES = Object.freeze(["tsconfig.json", "jsconfig.json"]);

/** Dependency names that establish a quality tool, by domain, across ecosystems. */
export const QUALITY_DEPENDENCY_NAMES = Object.freeze({
  linting: Object.freeze([
    "eslint",
    "biome",
    "oxlint",
    "stylelint",
    "ruff",
    "flake8",
    "pylint",
    "golangci-lint",
    "clippy",
  ]),
  formatting: Object.freeze([
    "prettier",
    "black",
    "rustfmt",
    "clang-format",
    "dotnet-format",
  ]),
  "type-checking": Object.freeze(["typescript", "flow-bin", "mypy", "pyright"]),
});

/**
 * Decision thresholds the structural rules use.
 *
 * A threshold is a *reporting* choice, stated once here rather than sprinkled through rules,
 * so a reviewer can see exactly where the analyzer draws its line.
 *
 *   MAX_STRUCTURAL_FINDINGS  how many structural indicators one rule reports before it caps
 *                            and records the cap. The roadmap forbids unbounded output.
 *   LARGE_MODULE_SYMBOLS     the number of module-scope declarations from which a module is
 *                            reported as large. It is a **module-size** indicator, never a
 *                            cyclomatic-complexity measurement, and the finding says so.
 */
export const CODE_QUALITY_LIMITS = Object.freeze({
  MAX_STRUCTURAL_FINDINGS: 25,
  LARGE_MODULE_SYMBOLS: 40,
});

/**
 * The asset `metadata.basis` values this pack records.
 *
 * A basis names *what the observation rested on*, so a consumer can tell a finding that rests
 * on a configuration file from one that rests on read bytes or on a graph shape.
 */
export const CODE_QUALITY_BASES = Object.freeze({
  CONFIGURATION: "configuration",
  MANIFEST_SCRIPT: "manifest-script",
  DEPENDENCY: "dependency",
  CI_CONTENT: "ci-content",
  IMPORT_GRAPH: "import-graph",
  SYMBOL_GRAPH: "symbol-graph",
  LANGUAGE: "language",
});
