/**
 * Code Guardian — Testing Rule Pack Contracts (Official Roadmap Phase 11)
 *
 * The testing domain's vocabulary: which rules exist, which model facts the pack
 * consumes, and the confidence policy its rules assert. Nothing here redefines a
 * framework concept — rule identity comes from the Core Rule contract, severities
 * from the Core Finding contract, and outcome vocabulary from the Phase 10 Rule
 * Engine.
 *
 * ### Rule identity is a long-term contract
 *
 * A rule id is namespace-shaped (`testing.framework.unestablished`) and appears in
 * every finding fingerprint the rule will ever produce. Renaming a rule id is a
 * breaking identity change, so `TESTING_RULE_IDS` is the single place the shipped
 * ids are declared and `testingRuleSetIssues()` fails the registry if a declared
 * rule is missing or an id leaves the `testing.` namespace.
 *
 * ### The five roadmap states, and how they map onto the Rule Engine
 *
 * The official roadmap requires the analyzer to distinguish `detected`,
 * `verified`, `failed`, `unknown` and `not_applicable`. Those are *claims about a
 * domain*, and this pack keeps them as `metadata.state` on each finding while the
 * Rule Engine's own outcome vocabulary carries the evaluation outcome:
 *
 *   detected        an artifact/capability was observed (a finding's state)
 *   verified         the capability is *established to work* — a test script is
 *                    configured and CI is observed executing a test command
 *   failed           an expected operation demonstrably failed (a configuration or
 *                    manifest that could not be parsed)
 *   unknown          the domain applies but the evidence does not establish the
 *                    answer → Rule Engine `unknown`. This covers an incomplete scan
 *                    and every *open* domain — integration, E2E, isolation — whose
 *                    markers cannot prove the capability's absence
 *   not_applicable   the domain genuinely has no subject → Rule Engine
 *                    `not-applicable`
 *
 * `unknown` is never `clean`, and `not_applicable` is never used because evidence is
 * missing. Which of the two an unobserved domain gets depends on its *evidence model*:
 * a **closed** domain (a named artifact — a file, a configuration, a coverage flag, a
 * structural indicator) is `not_applicable` when a complete scan observed none of it,
 * while an **open** domain applies whenever a testing subject exists and is therefore
 * `unknown`. The summary module encodes both and derives the scan-dependent half from
 * the model's own coverage.
 *
 * ### Runner vocabulary is re-declared, and pinned
 *
 * `TEST_RUNNER_IDS` and `COVERAGE_COMMAND_IDS` are the scanner's acquisition
 * vocabulary. They are re-declared here rather than imported, because the rules
 * layer must not depend on the acquisition layer; a test in
 * `tests/testing-analyzer.test.js` builds a real model from a real scan and fails
 * if these constants ever drift from it. `node-test` is present deliberately: the
 * correction Phase 11 mandates is that the Node built-in runner is no longer
 * omitted.
 */

/** Version of the pack as a whole (analyzer version, rule set revision). */
export const TESTING_RULE_PACK_VERSION = "1.0.0";

/** Initial version of every rule in the pack. */
export const TESTING_RULE_VERSION = "1.0.0";

/** Analyzer identity. `testing` is the domain namespace, not a rule. */
export const TESTING_ANALYZER_ID = "testing";
export const TESTING_ANALYZER_NAME = "Testing";
export const TESTING_ANALYZER_SCOPE = "testing";

/** Category recorded on every testing finding (Core Finding contract). */
export const TESTING_CATEGORY = "testing";

/** Every testing rule id must live in this namespace. */
export const TESTING_RULE_ID_PREFIX = "testing.";

/**
 * The rules this pack ships.
 *
 * Each id maps to one official-roadmap analysis domain; the pack deliberately
 * stops at eleven, because the roadmap says to optimize for truthful testing
 * intelligence rather than a large number of checks.
 */
export const TESTING_RULE_IDS = Object.freeze({
  FRAMEWORK_UNESTABLISHED: "testing.framework.unestablished",
  NODE_BUILT_IN_RUNNER: "testing.framework.node-built-in-runner",
  CONFIGURATION_ABSENT: "testing.configuration.absent",
  SCRIPT_MISSING: "testing.script.missing",
  SCRIPT_UNRECOGNIZED: "testing.script.unrecognized-runner",
  CI_TESTS_NOT_EXECUTED: "testing.ci.tests-not-executed",
  COVERAGE_UNCONFIGURED: "testing.coverage.unconfigured",
  INTEGRATION_UNDETERMINED: "testing.integration.undetermined",
  E2E_UNDETERMINED: "testing.e2e.undetermined",
  ISOLATION_UNDETERMINED: "testing.isolation.undetermined",
  FLAKY_INDICATOR: "testing.flaky.potential-indicator",
});

/**
 * The five official-roadmap states a testing finding may assert.
 *
 * These are the *claim* states; the Rule Engine's outcome statuses are a different
 * axis (a `detected` finding is a `violation` outcome, a clean domain is `pass`).
 */
export const TESTING_STATES = Object.freeze({
  DETECTED: "detected",
  VERIFIED: "verified",
  FAILED: "failed",
  UNKNOWN: "unknown",
  NOT_APPLICABLE: "not_applicable",
});

/**
 * Confidence policy.
 *
 * Confidence is the rule's assertion, never a framework default. The levels are
 * chosen to match the *evidence strength* the Phase 11 acquisition establishes:
 *
 *   OBSERVED_CONTENT   a bounded content read matched a pattern (a test source
 *                      references `node:test`; a workflow contains a test command).
 *                      Direct evidence, but still not proof the suite passes.
 *   OBSERVED_ARTIFACT  the model directly observed the artifact the finding names
 *                      (a test file, a test configuration, a manifest).
 *   DECLARED_COMMAND   a test-related script name or command was declared.
 *   GAP_CONDITION      the finding asserts a gap over established coverage, so it
 *                      rests on the model's own completeness rather than on bytes.
 */
export const TESTING_CONFIDENCE = Object.freeze({
  OBSERVED_CONTENT: 0.9,
  OBSERVED_ARTIFACT: 0.85,
  DECLARED_COMMAND: 0.75,
  GAP_CONDITION: 0.6,
});

/**
 * The test runners a command or source can establish.
 *
 * Re-declared from the scanner's policy (see the module note) so a rule can name a
 * runner id in a finding without importing acquisition. Sorted for readability;
 * membership is pinned by a test against a real scan.
 */
export const TEST_RUNNER_IDS = Object.freeze([
  "ava",
  "cargo-test",
  "ctest",
  "cypress",
  "dotnet-test",
  "go-test",
  "gradle-test",
  "jasmine",
  "jest",
  "jest-integration",
  "maven-test",
  "mocha",
  "node-test",
  "package-script-test",
  "phpunit",
  "playwright",
  "pytest",
  "rspec",
  "vitest",
]);

/** Runner levels a record may declare. */
export const TEST_RUNNER_LEVELS = Object.freeze(["unit", "integration", "e2e"]);

/** Coverage-command ids a command or workflow can establish. */
export const COVERAGE_COMMAND_IDS = Object.freeze([
  "go-cover",
  "istanbul",
  "jest-collect-coverage",
  "node-test-coverage",
  "pytest-cov",
  "v8-coverage",
  "v8-provider",
]);

/**
 * The asset `metadata.basis` values this pack records.
 *
 * A basis names *what the observation rested on*, so a consumer can tell a finding
 * that rests on a declared script from one that rests on read bytes.
 */
export const TESTING_BASES = Object.freeze({
  FILE_INVENTORY: "test-file-inventory",
  CONFIGURATION: "test-configuration",
  MANIFEST_SCRIPT: "manifest-script",
  CI_CONTENT: "ci-content",
  TEST_CONTENT: "test-content",
});

/** The `metadata.state` a clean pass records when a domain was established. */
export const ASSET_BASIS = TESTING_BASES.FILE_INVENTORY;
