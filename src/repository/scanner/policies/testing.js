/**
 * Code Guardian — Testing Acquisition Policy (Official Roadmap Phase 11)
 *
 * The scanner's one place that interprets a *command string* into the closed
 * vocabulary of test runners and coverage invocations. It exists because the
 * testing facts Phase 11 needs cannot all be read from a file's name: whether a
 * `package.json` `test` script actually runs a test runner, and whether a CI
 * workflow actually executes tests, are facts about **command text**.
 *
 * ### Pure, bounded, evidence-shaped
 *
 * `classifyTestCommand` is a pure function of one string. It consults no
 * filesystem, clock, environment or process; matching is a fixed set of linear
 * regular expressions over a bounded input, so a hostile command cannot make the
 * scanner super-linear. It returns a sorted, de-duplicated list of the closed
 * runner ids below — never a framework *guess* from the repository's language.
 *
 * ### Matching is deliberately narrow
 *
 * A runner id is reported only when its own documented invocation appears. In
 * particular `node-test` requires the literal `node --test` (or an `--test` flag
 * passed to `node`), so a Node project that merely *is* JavaScript does not get a
 * built-in-runner signal — the correction Phase 11 mandates is evidence-driven,
 * not language-driven. A generic `npm test` / `yarn test` is recorded as
 * `package-script-test`: it is evidence that *a* test script is invoked, not
 * evidence of which runner the script delegates to.
 */

/**
 * The closed vocabulary of test invocations a command can establish, and whether
 * each names an *integration-level* or *end-to-end* runner. The flags are data so a
 * rule can classify a workflow's commands without re-deriving them.
 */
export const TEST_RUNNER_DEFINITIONS = Object.freeze([
  { id: "node-test", matcher: /(^|[\s;&|(])node(?:\.exe)?\s+[^\n]*--test\b/, level: "unit" },
  { id: "node-test", matcher: /require\(\s*['"]node:test['"]\s*\)/, level: "unit" },
  { id: "node-test", matcher: /\bfrom\s+['"]node:test['"]/, level: "unit" },
  { id: "vitest", matcher: /(^|[\s;&|(])vitest\b/, level: "unit" },
  { id: "jest", matcher: /(^|[\s;&|(])jest\b/, level: "unit" },
  { id: "mocha", matcher: /(^|[\s;&|(])mocha\b/, level: "unit" },
  { id: "ava", matcher: /(^|[\s;&|(])ava\b/, level: "unit" },
  { id: "jasmine", matcher: /(^|[\s;&|(])jasmine\b/, level: "unit" },
  { id: "pytest", matcher: /(^|[\s;&|(])pytest\b/, level: "unit" },
  { id: "pytest", matcher: /python[0-9.]*\s+-m\s+(?:pytest|unittest)\b/, level: "unit" },
  { id: "go-test", matcher: /(^|[\s;&|(])go\s+test\b/, level: "unit" },
  { id: "cargo-test", matcher: /(^|[\s;&|(])cargo\s+test\b/, level: "unit" },
  { id: "dotnet-test", matcher: /(^|[\s;&|(])dotnet\s+test\b/, level: "unit" },
  { id: "maven-test", matcher: /(^|[\s;&|(])(?:mvn|maven)\b[^\n]*\btest\b/, level: "unit" },
  { id: "gradle-test", matcher: /(^|[\s;&|(])(?:gradle|\.\/gradlew|gradlew)\b[^\n]*\btest\b/, level: "unit" },
  { id: "phpunit", matcher: /(^|[\s;&|(])phpunit\b/, level: "unit" },
  { id: "rspec", matcher: /(^|[\s;&|(])(?:rspec|rake\s+spec)\b/, level: "unit" },
  { id: "ctest", matcher: /(^|[\s;&|(])ctest\b/, level: "unit" },
  // Integration / end-to-end runners, recognised by their own binaries.
  { id: "playwright", matcher: /(^|[\s;&|(])playwright\s+(?:test|run)\b/, level: "e2e" },
  { id: "cypress", matcher: /(^|[\s;&|(])cypress\s+run\b/, level: "e2e" },
  {
    id: "jest-integration",
    matcher: /jest\b[^\n]*--testPathPattern(?:s)?[^\n]*integrat/i,
    level: "integration",
  },
  // A package-manager test invocation: evidence of *a* test script, not of a
  // specific runner. Kept last so a specific runner in the same command wins the
  // more informative id alongside it.
  {
    id: "package-script-test",
    matcher: /(^|[\s;&|(])(?:npm|pnpm|yarn|bun)\s+(?:run\s+)?test(?:s|[:][a-z0-9:_-]+)?\b/,
    level: "unit",
  },
]);

/** Every runner id this policy can report. */
export const TEST_RUNNER_IDS = Object.freeze([
  ...new Set(TEST_RUNNER_DEFINITIONS.map((definition) => definition.id)),
].sort());

/** Level ids a runner definition may declare. */
export const TEST_RUNNER_LEVELS = Object.freeze(["unit", "integration", "e2e"]);

/**
 * Coverage invocation flags, recognised separately from test execution because
 * Phase 11 must not conflate "coverage is configured" with "a test runner ran".
 */
export const COVERAGE_COMMAND_DEFINITIONS = Object.freeze([
  { id: "node-test-coverage", matcher: /--experimental-test-coverage\b/ },
  { id: "v8-coverage", matcher: /--coverage\b|--cov\b/ },
  { id: "v8-provider", matcher: /--coverage-provider[=\s]+v8\b/ },
  { id: "istanbul", matcher: /(^|[\s;&|(])(?:nyc|c8|istanbul)\b/ },
  { id: "pytest-cov", matcher: /(^|[\s;&|(])coverage\s+run\b|--cov\b/ },
  { id: "go-cover", matcher: /-cover(?:profile|mode)?\b/ },
  { id: "jest-collect-coverage", matcher: /--collectCoverage\b/ },
]);

/** Every coverage-command id this policy can report. */
export const COVERAGE_COMMAND_IDS = Object.freeze(
  COVERAGE_COMMAND_DEFINITIONS.map((definition) => definition.id).sort(),
);

/**
 * Whether the inspected prefix of a file looks binary. Test files and workflows
 * are text; a NUL byte in the prefix means anything read from it must be recorded
 * as not-inspected rather than interpreted.
 */
export function looksBinary(text) {
  return typeof text === "string" && text.includes("\u0000");
}

/**
 * Classify one command string into the closed runner vocabulary.
 *
 * @param {unknown} command A command string as written in a script or workflow.
 * @returns {{ runners: string[], levels: string[], coverage: string[] }} Frozen,
 *   sorted, de-duplicated. Empty when nothing recognisable is present.
 */
export function classifyTestCommand(command) {
  if (typeof command !== "string" || command === "") {
    return Object.freeze({ runners: [], levels: [], coverage: [] });
  }

  const runners = new Set();
  const levels = new Set();
  for (const definition of TEST_RUNNER_DEFINITIONS) {
    if (definition.matcher.test(command)) {
      runners.add(definition.id);
      levels.add(definition.level);
    }
  }

  const coverage = new Set();
  for (const definition of COVERAGE_COMMAND_DEFINITIONS) {
    if (definition.matcher.test(command)) coverage.add(definition.id);
  }

  return Object.freeze({
    runners: Object.freeze([...runners].sort()),
    levels: Object.freeze([...levels].sort()),
    coverage: Object.freeze([...coverage].sort()),
  });
}

/**
 * Whether a command string invokes a test runner.
 *
 * @param {unknown} command
 * @returns {boolean}
 */
export function commandRunsTests(command) {
  return classifyTestCommand(command).runners.length > 0;
}
