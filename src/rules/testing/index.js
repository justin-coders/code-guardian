/**
 * Code Guardian — Testing Rule Pack Boundary (Official Roadmap Phase 11)
 *
 * The stable import surface for the testing domain. Consumers import from here
 * rather than reaching into the individual rule modules.
 *
 * ### Phase numbering: this pack is the official roadmap's Phase 11
 *
 * The official roadmap's Phase 11 is **"Testing Analyzer"**, and this pack plus
 * `analyzer.js` is that analyzer:
 *
 *   Repository → RepositoryModel → TestingAnalyzer → applicable rules → evidence → findings
 *
 * "Official Roadmap Phase 11" is the only numbering that says where the *product*
 * is. A bare `Phase 8C`/`Phase 10` in comments names the repository's *internal*
 * implementation increment for a consumed layer, not this milestone.
 *
 * ### Dependency direction
 *
 * Enforced by an architectural test in `tests/testing-analyzer.test.js`:
 *
 *   core ← repository/model ← analysis ← rules ← rules/testing
 *
 * The pack reads the frozen RepositoryModel through the query API and nothing else.
 * It must never import `node:fs`, `node:fs/promises`, `node:path`, `child_process`,
 * `node:net`, `node:http`, `node:https`, the filesystem boundary, the execution
 * boundary, `src/tools.js`, `tool-registry`, a transport, or an MCP/CLI module. It
 * reads no file contents of its own, runs no command, and consults no clock, random
 * source or environment: testing findings here are deterministic, evidence-first, and
 * scoped to what the repository model can actually prove.
 *
 * ### The five states, and where they come from
 *
 * The pack distinguishes the roadmap's `detected`, `verified`, `failed`, `unknown`
 * and `not_applicable` in two complementary places: the **Rule Engine outcome**
 * (`pass` / `violation` / `unknown` / `not-applicable` / `failed`) and each finding's
 * `metadata.state`. `summarizeTesting()` aggregates both into the per-domain map the
 * analyzer attaches as `metadata.testingSummary`. `unknown` is never clean, and
 * `not_applicable` is only used when the domain genuinely has no subject over a
 * complete scan — never because evidence is missing. The *open* domains (integration,
 * E2E, isolation) are therefore never `not_applicable` while a testing subject exists:
 * absence of their markers does not establish absence of the capability, so they are
 * `unknown` instead.
 *
 * ### Supported evidence
 *
 * Every fact the rules read is a RepositoryModel fact acquired by the scanner:
 *
 *   test files/directories/configuration   the scanner's name-convention signals
 *   test framework                         a configuration file's name, a file-name
 *                                          convention whose runner is documented, or a
 *                                          test source's own `node:test` reference
 *   test scripts                           the bounded `package.json` script commands
 *                                          the acquisition layer classified
 *   CI test execution                       bounded workflow content, classified into
 *                                          the closed runner vocabulary
 *   coverage configuration                  coverage flags in a script or workflow
 *   integration / E2E                       named artifacts, runner levels and commands
 *   potential flaky patterns                structural indicators in a test source
 *
 * ### Supported frameworks
 *
 * The pack reports a framework only when the model established it: a configuration file
 * (`jest`, `vitest`, `playwright`, `cypress`, `mocha`, `karma`, `pytest`, `tox`,
 * `phpunit`, `rspec`), a file-name convention whose runner is documented (`pytest`,
 * `go-test`, `dart-test`, `rspec`, `junit`, `phpunit`), or a test source that references
 * the Node built-in runner (`node-test`). It deliberately claims no framework for a project
 * merely because of its language.
 *
 * ### The Node built-in test runner
 *
 * Phase 11's mandated correction: `node:test` / `node --test` is now established from
 * evidence — a test file's own reference, or a configured command — and never from the
 * project being Node. The scanner reads the bounded test-file prefix for this, so the
 * detection is content-backed, and `testing.framework.node-built-in-runner` reports it.
 *
 * ### Limitations, stated rather than hidden
 *
 *   - **Test evidence is capped.** The scanner caps test/CI evidence per signal, so a
 *     repository with more than that many test files has a *truncated* test inventory.
 *     Every absence-shaped claim over it is `unknown`, never a pass, which is why a large
 *     repository reports more `unknown` than a small one. This is deliberate.
 *   - **No execution.** The analyzer runs no test command. `verified` therefore means
 *     "a test script is configured and CI is observed executing a matching runner", not
 *     "the suite passed", and the `failed` state is only reachable from a failure the
 *     model observed (a `package.json` that could not be parsed), never from a test run.
 *   - **No coverage results.** Only coverage *configuration* is read; no percentage or
 *     threshold is ever asserted.
 *   - **Test isolation is never established.** Isolation would need a test database,
 *     container, fixture lifecycle or parallel-execution setting, none of which the model
 *     records; the domain is `unknown` whenever a testing subject exists.
 *   - **E2E and integration are never `verified`.** Neither domain has an execution
 *     path in this phase. E2E is `detected` from a Playwright/Cypress configuration or
 *     directory and `unknown` otherwise (never "verified" from a config alone);
 *     integration is `detected` from a named `integration` artifact or an
 *     integration-level command and `unknown` otherwise.
 *   - **Flaky patterns are structural.** The pack reports shapes
 *     (`Date.now()`, `Math.random()`, `sleep`, an outbound call, an explicit retry) as
 *     *potential* patterns; establishing flakiness would need repeated execution.
 */

export {
  ASSET_BASIS,
  COVERAGE_COMMAND_IDS,
  TESTING_ANALYZER_ID,
  TESTING_ANALYZER_NAME,
  TESTING_ANALYZER_SCOPE,
  TESTING_BASES,
  TESTING_CATEGORY,
  TESTING_CONFIDENCE,
  TESTING_RULE_ID_PREFIX,
  TESTING_RULE_IDS,
  TESTING_RULE_PACK_VERSION,
  TESTING_RULE_VERSION,
  TESTING_STATES,
  TEST_RUNNER_IDS,
  TEST_RUNNER_LEVELS,
} from "./contracts.js";

export {
  ciInventory,
  frameworkInventory,
  frameworkNamed,
  frameworkNames,
  hasTestingSubject,
  inventoryAbsence,
  manifestInventory,
  nodeManifestFacts,
  queryFor,
  testConfigurations,
  testDirectories,
  testFiles,
  testInventory,
  testingSignals,
} from "./signals.js";

export { summarizeTesting } from "./summary.js";

export { testingRules } from "./rules/index.js";

export { createTestingRuleRegistry, testingRuleSetIssues } from "./registry.js";

export { createTestingAnalyzer } from "./analyzer.js";
