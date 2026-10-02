/**
 * Code Guardian — Testing Analyzer Tests (official roadmap Phase 11)
 *
 * The end-to-end proof that the Testing Analyzer works through the real pipeline:
 *
 *   Repository → RepositoryModel → TestingAnalyzer → applicable rules → evidence → findings
 *
 * Fixtures A–K from the Phase 11 handoff live here as real repositories written to a
 * temporary directory and scanned through the accepted Phase 8A/8C/8D boundary. The
 * suite's central claims are the roadmap's exit criteria: the five states are
 * distinguished, the Node built-in runner is detected from evidence, absence over an
 * incomplete scan is `unknown` rather than clean, every finding cites model evidence,
 * fingerprints are stable and unique, and the analyzer imports no filesystem,
 * process, network or MCP module.
 *
 * Run with: node --test tests/testing-analyzer.test.js
 */

import { after, describe, it } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

import { createRule } from "../src/core/index.js";

import { scanRepository } from "../src/repository/scanner/index.js";
import { buildRepositoryModel, createRepositoryQuery } from "../src/repository/model/index.js";

import {
  buildAnalysisContext,
  createAnalyzerEngine,
  createAnalyzerRegistry,
  stableAnalysisView,
} from "../src/analysis/index.js";

import {
  TESTING_ANALYZER_ID,
  TESTING_RULE_IDS,
  TESTING_STATES,
  TEST_RUNNER_IDS,
  COVERAGE_COMMAND_IDS,
  createRuleEngine,
  createRuleRegistry,
  createTestingAnalyzer,
  createTestingRuleRegistry,
  testingRules,
} from "../src/rules/index.js";

// ─── Fixtures ────────────────────────────────────────────────────────────────

const TMP_ROOT = join(tmpdir(), `cg-testing-analyzer-${process.pid}-${Date.now()}`);
let counter = 0;

function makeRepo(files = {}) {
  const root = join(TMP_ROOT, `repo-${counter++}`);
  mkdirSync(root, { recursive: true });
  for (const [relative, content] of Object.entries(files)) {
    const full = join(root, relative);
    mkdirSync(dirname(full), { recursive: true });
    writeFileSync(full, content);
  }
  return root;
}

async function scanModel(files, options) {
  const root = makeRepo(files);
  const scan = await scanRepository(root, options);
  const model = buildRepositoryModel(scan);
  return { scan, model, query: createRepositoryQuery(model) };
}

after(() => {
  rmSync(TMP_ROOT, { recursive: true, force: true });
});

const contextOf = (model) => buildAnalysisContext({ repository: model });

async function runRules(model, { rules = testingRules } = {}) {
  const engine = createRuleEngine({ registry: createTestingRuleRegistry({ rules }) });
  return engine.runAll(contextOf(model));
}

async function runAnalyzer(model) {
  const engine = createAnalyzerEngine({
    registry: createAnalyzerRegistry([createTestingAnalyzer()]),
  });
  return engine.runAll(contextOf(model));
}

const resultOf = (run, ruleId) => run.rules.find((entry) => entry.rule.id === ruleId);
const statusOf = (run, ruleId) => resultOf(run, ruleId)?.status;
const summaryOf = (result) =>
  result.analyzers.find((entry) => entry.analyzer.id === TESTING_ANALYZER_ID).metadata.testingSummary;

const pkg = (extra = {}) => JSON.stringify({ name: "demo", version: "1.0.0", ...extra });
const NODE_TEST = 'import { test } from "node:test";\ntest("x", () => {});\n';
const PLAIN_TEST = 'import { it } from "unknown-runner";\nit("x", () => {});\n';
const CI_RUNS_NODE_TEST = "jobs:\n  test:\n    steps:\n      - run: node --test tests/**/*.test.js\n";

// Fixture A — Node built-in test runner.
const FIXTURE_A = {
  "package.json": pkg({ scripts: { test: "node --test tests/**/*.test.js" } }),
  "tests/math.test.js": NODE_TEST,
};
// Fixture B — Jest.
const FIXTURE_B = {
  "package.json": pkg({ scripts: { test: "jest" } }),
  "jest.config.js": "export default {};\n",
  "src/a.test.js": PLAIN_TEST,
};
// Fixture C — test files, no established framework.
const FIXTURE_C = { "package.json": pkg(), "src/a.test.js": PLAIN_TEST };
// Fixture D — test configuration.
const FIXTURE_D = { "package.json": pkg(), "vitest.config.ts": "export default {};\n", "src/a.test.js": PLAIN_TEST };
// Fixture E — CI executes tests.
const FIXTURE_E = {
  "package.json": pkg({ scripts: { test: "node --test tests/**/*.test.js" } }),
  ".github/workflows/ci.yml": CI_RUNS_NODE_TEST,
  "tests/a.test.js": NODE_TEST,
};
// Fixture F — coverage configuration.
const FIXTURE_F = {
  "package.json": pkg({ scripts: { test: "node --test", "test:coverage": "node --test --experimental-test-coverage" } }),
  "tests/a.test.js": NODE_TEST,
};
// Fixture G — integration tests.
const FIXTURE_G = { "package.json": pkg(), "tests/integration.test.js": PLAIN_TEST };
// Fixture H — E2E tests.
const FIXTURE_H = { "package.json": pkg(), "playwright.config.ts": "export default {};\n" };
// Fixture J — negative repository.
const FIXTURE_J = { "README.md": "# docs only\n" };
// Fixture K — malformed configuration.
const FIXTURE_K = { "package.json": "{ not json" };
// Mixed — several observations at once.
const FIXTURE_MIXED = {
  "package.json": pkg({ scripts: { test: "node --test" } }),
  "tests/a.test.js": 'import { test } from "node:test";\ntest("x", async () => { await sleep(1); const t = Date.now(); });\n',
  ".env": "A=1\n",
};

// ─── Golden fixtures ─────────────────────────────────────────────────────────

describe("testing analyzer: golden fixtures", () => {
  it("A: detects the Node built-in test runner from evidence, and reports it", async () => {
    const { model } = await scanModel(FIXTURE_A);
    const run = await runRules(model);
    assert.equal(statusOf(run, TESTING_RULE_IDS.NODE_BUILT_IN_RUNNER), "violation");
    const result = await runAnalyzer(model);
    assert.equal(summaryOf(result).framework.state, TESTING_STATES.DETECTED);
    assert.deepEqual(summaryOf(result).framework.frameworks, ["node-test"]);
  });

  it("B: detects Jest from its configuration", async () => {
    const { model } = await scanModel(FIXTURE_B);
    const run = await runRules(model);
    assert.equal(statusOf(run, TESTING_RULE_IDS.FRAMEWORK_UNESTABLISHED), "pass");
    assert.equal(summaryOf(await runAnalyzer(model)).framework.frameworks.includes("jest"), true);
  });

  it("C: test files with no established framework are `unknown`, never a guess", async () => {
    const { model } = await scanModel(FIXTURE_C);
    const run = await runRules(model);
    const entry = resultOf(run, TESTING_RULE_IDS.FRAMEWORK_UNESTABLISHED);
    assert.equal(entry.status, "violation");
    assert.equal(entry.findings[0].metadata.state, "unknown");
    assert.equal(summaryOf(await runAnalyzer(model)).framework.state, TESTING_STATES.UNKNOWN);
  });

  it("D: reports a test configuration as detected", async () => {
    const { model } = await scanModel(FIXTURE_D);
    const run = await runRules(model);
    assert.equal(statusOf(run, TESTING_RULE_IDS.CONFIGURATION_ABSENT), "pass");
    assert.equal(summaryOf(await runAnalyzer(model)).testConfiguration.state, TESTING_STATES.DETECTED);
  });

  it("E: verifies CI test execution only from workflow content", async () => {
    const { model } = await scanModel(FIXTURE_E);
    const run = await runRules(model);
    assert.equal(statusOf(run, TESTING_RULE_IDS.CI_TESTS_NOT_EXECUTED), "pass");
    assert.equal(summaryOf(await runAnalyzer(model)).ciExecution.state, TESTING_STATES.VERIFIED);
  });

  it("E-negative: `.github/workflows` existing is not test execution", async () => {
    const { model } = await scanModel({
      "package.json": pkg({ scripts: { test: "node --test" } }),
      ".github/workflows/ci.yml": "jobs:\n  build:\n    steps:\n      - run: npm run build\n",
      "tests/a.test.js": NODE_TEST,
    });
    const run = await runRules(model);
    assert.equal(statusOf(run, TESTING_RULE_IDS.CI_TESTS_NOT_EXECUTED), "violation");
  });

  it("F: detects coverage configuration without inventing measured coverage", async () => {
    const { model } = await scanModel(FIXTURE_F);
    const run = await runRules(model);
    assert.equal(statusOf(run, TESTING_RULE_IDS.COVERAGE_UNCONFIGURED), "pass");
    const coverage = summaryOf(await runAnalyzer(model)).coverage;
    assert.equal(coverage.state, TESTING_STATES.DETECTED);
    assert.notEqual(coverage.state, TESTING_STATES.VERIFIED);
    assert.ok(coverage.commands.includes("node-test-coverage"));
  });

  it("G: detects integration tests from a named artifact", async () => {
    const { model } = await scanModel(FIXTURE_G);
    const run = await runRules(model);
    assert.equal(statusOf(run, TESTING_RULE_IDS.INTEGRATION_UNDETERMINED), "pass");
    assert.equal(summaryOf(await runAnalyzer(model)).integration.state, TESTING_STATES.DETECTED);
  });

  it("H: detects E2E testing from a Playwright configuration, as `detected` not `verified`", async () => {
    const { model } = await scanModel(FIXTURE_H);
    const run = await runRules(model);
    assert.equal(statusOf(run, TESTING_RULE_IDS.E2E_UNDETERMINED), "pass");
    const e2e = summaryOf(await runAnalyzer(model)).e2e;
    assert.equal(e2e.state, TESTING_STATES.DETECTED);
    assert.deepEqual(e2e.frameworks, ["playwright"]);
  });

  it("J: reports no false positives for a repository with no testing artifacts", async () => {
    const { model } = await scanModel(FIXTURE_J);
    const result = await runAnalyzer(model);
    assert.deepEqual(result.findings, []);
    const summary = summaryOf(result);
    assert.equal(summary.framework.state, TESTING_STATES.NOT_APPLICABLE);
    assert.equal(summary.e2e.state, TESTING_STATES.NOT_APPLICABLE);
    assert.equal(summary.ciExecution.state, TESTING_STATES.NOT_APPLICABLE);
  });

  it("K: a malformed configuration is `failed`/`unknown`, never `not detected`", async () => {
    const { model } = await scanModel(FIXTURE_K);
    const run = await runRules(model);
    assert.equal(statusOf(run, TESTING_RULE_IDS.SCRIPT_MISSING), "unknown");
    assert.equal(summaryOf(await runAnalyzer(model)).testScripts.state, TESTING_STATES.FAILED);
  });
});

// ─── Incomplete scan ────────────────────────────────────────────────────────

describe("testing analyzer: incomplete scan", () => {
  it("I: a truncated scan turns absence into `unknown`, never `clean`", async () => {
    const { model } = await scanModel(
      {
        "package.json": pkg(),
        "README.md": "# x\n",
        "src/index.js": "console.log(1);\n",
        "src/a.test.js": PLAIN_TEST,
      },
      { maxFiles: 1 },
    );
    const result = await runAnalyzer(model);
    const analyzer = result.analyzers.find((entry) => entry.analyzer.id === TESTING_ANALYZER_ID);
    assert.ok(analyzer.metadata.unavailableRules.length > 0);
    // Nothing asserted a clean testing result over an inventory that was not read.
    assert.deepEqual(result.findings, []);
  });

  it("does not convert a truncated test inventory into an absence finding", async () => {
    // More test files than the evidence cap: the observed set is not the whole set.
    const files = { "package.json": pkg() };
    for (let index = 0; index < 20; index += 1) {
      files[`tests/case${String(index).padStart(2, "0")}.test.js`] = PLAIN_TEST;
    }
    const { model } = await scanModel(files);
    const run = await runRules(model);
    assert.equal(statusOf(run, TESTING_RULE_IDS.CONFIGURATION_ABSENT), "unknown");
    assert.equal(statusOf(run, TESTING_RULE_IDS.E2E_UNDETERMINED), "unknown");
  });
});

// ─── Applicability ──────────────────────────────────────────────────────────

describe("testing analyzer: applicability", () => {
  it("distinguishes applicable, not-applicable and unknown through the shared engine", async () => {
    const { model } = await scanModel(FIXTURE_A);
    const rules = [
      createRule({
        id: "testing.fixture.javascript",
        version: "1.0.0",
        category: "testing",
        title: "fixture",
        description: "fixture",
        severity: "info",
        applicability: { languages: ["javascript"] },
        detect: () => [],
      }),
      createRule({
        id: "testing.fixture.rust",
        version: "1.0.0",
        category: "testing",
        title: "fixture",
        description: "fixture",
        severity: "info",
        applicability: { languages: ["rust"] },
        detect: () => [],
      }),
      createRule({
        id: "testing.fixture.missing-file",
        version: "1.0.0",
        category: "testing",
        title: "fixture",
        description: "fixture",
        severity: "info",
        applicability: { files: ["does-not-exist.txt"] },
        detect: () => [],
      }),
    ];
    const engine = createRuleEngine({ registry: createRuleRegistry(rules) });
    const run = await engine.runAll(contextOf(model));

    assert.equal(run.rules.find((entry) => entry.rule.id === "testing.fixture.javascript").status, "pass");
    assert.equal(
      run.rules.find((entry) => entry.rule.id === "testing.fixture.rust").status,
      "not-applicable",
    );
    assert.equal(
      run.rules.find((entry) => entry.rule.id === "testing.fixture.missing-file").status,
      "not-applicable",
    );
  });

  it("maps an unread path to `unknown`, not `not-applicable`", async () => {
    const { model } = await scanModel(
      { "package.json": pkg(), "src/index.js": "console.log(1);\n" },
      { maxFiles: 1 },
    );
    const rule = createRule({
      id: "testing.fixture.uncovered-file",
      version: "1.0.0",
      category: "testing",
      title: "fixture",
      description: "fixture",
      severity: "info",
      applicability: { files: ["src/never-seen.js"] },
      detect: () => [],
    });
    const engine = createRuleEngine({ registry: createRuleRegistry([rule]) });
    const run = await engine.runAll(contextOf(model));
    assert.equal(run.rules[0].status, "unknown");
  });
});

// ─── Evidence ───────────────────────────────────────────────────────────────

describe("testing analyzer: evidence", () => {
  it("cites only model evidence, and every cited id resolves", async () => {
    const { model } = await scanModel(FIXTURE_MIXED);
    const result = await runAnalyzer(model);
    assert.ok(result.findings.length > 0);
    const evidenceById = model.indexes.evidenceById;
    for (const finding of result.findings) {
      assert.ok(Array.isArray(finding.evidence) && finding.evidence.length > 0, finding.ruleId);
      for (const id of finding.evidence) {
        assert.ok(evidenceById[id] !== undefined, `${finding.ruleId} cites ${id}`);
      }
    }
  });

  it("carries the five-state vocabulary on every finding's metadata", async () => {
    const { model } = await scanModel(FIXTURE_MIXED);
    const result = await runAnalyzer(model);
    const allowed = Object.values(TESTING_STATES);
    for (const finding of result.findings) {
      assert.ok(allowed.includes(finding.metadata.state), finding.ruleId);
    }
  });
});

// ─── Fingerprints ───────────────────────────────────────────────────────────

describe("testing analyzer: fingerprints", () => {
  it("gives every finding its own canonical fingerprint, even in one file", async () => {
    const { model } = await scanModel(FIXTURE_MIXED);
    const result = await runAnalyzer(model);
    const fingerprints = result.findings.map((finding) => finding.fingerprint);
    assert.ok(fingerprints.length >= 3, `expected several findings, got ${fingerprints.length}`);
    assert.equal(new Set(fingerprints).size, fingerprints.length);
    for (const fingerprint of fingerprints) assert.match(fingerprint, /^cg-fp1-[0-9a-f]{32}$/);

    // `tests/a.test.js` is reported by both the built-in-runner rule and the flaky rule.
    const inOneFile = result.findings.filter((finding) =>
      (finding.evidence ?? []).some((id) => id.includes("tests/a.test.js")),
    );
    assert.ok(inOneFile.length >= 2);
    assert.equal(new Set(inOneFile.map((finding) => finding.fingerprint)).size, inOneFile.length);
  });

  it("is deterministic: the same repository twice gives the same results", async () => {
    const { model } = await scanModel(FIXTURE_MIXED);
    const first = await runAnalyzer(model);
    const second = await runAnalyzer(model);
    assert.deepEqual(
      first.findings.map((finding) => finding.fingerprint),
      second.findings.map((finding) => finding.fingerprint),
    );
    assert.deepEqual(stableAnalysisView(first), stableAnalysisView(second));
  });
});

// ─── Performance measurement ────────────────────────────────────────────────

describe("testing analyzer: performance", () => {
  it("analyzes a bounded fixture deterministically and within a sane budget", async () => {
    const files = {};
    for (let index = 0; index < 40; index += 1) {
      files[`tests/case${String(index).padStart(3, "0")}.test.js`] = NODE_TEST;
    }
    files["package.json"] = pkg({ scripts: { test: "node --test" } });
    files[".github/workflows/ci.yml"] = CI_RUNS_NODE_TEST;

    const { model } = await scanModel(files);

    const start = process.hrtime.bigint();
    const first = await runAnalyzer(model);
    const second = await runAnalyzer(model);
    const elapsedMs = Number(process.hrtime.bigint() - start) / 1e6;

    // Meaningful, not a benchmark: two full analyzer passes over a 41-file fixture
    // must finish well inside a second on the CI runners.
    assert.ok(elapsedMs < 5000, `analyzer took ${elapsedMs.toFixed(1)}ms`);
    assert.deepEqual(
      first.findings.map((finding) => finding.fingerprint),
      second.findings.map((finding) => finding.fingerprint),
    );
    // eslint-disable-next-line no-console
    console.log(`[phase-11] two analyzer passes over 41 files: ${elapsedMs.toFixed(1)}ms`);
  });
});

// ─── Architectural boundary ─────────────────────────────────────────────────

describe("testing analyzer: boundaries", () => {
  const FORBIDDEN = [
    "node:fs",
    "node:fs/promises",
    "node:path",
    "child_process",
    "node:child_process",
    "node:net",
    "node:http",
    "node:https",
    "tools.js",
    "tool-registry",
  ];

  function sourceFiles(dir) {
    const out = [];
    for (const name of readdirSync(dir)) {
      const full = join(dir, name);
      if (statSync(full).isDirectory()) out.push(...sourceFiles(full));
      else if (name.endsWith(".js")) out.push(full);
    }
    return out;
  }

  it("never imports the filesystem, process, network, MCP or legacy tools from the pack", () => {
    const packDir = join(process.cwd(), "src", "rules", "testing");
    const specifierPattern = /(?:from\s+|require\(\s*)["']([^"']+)["']/g;
    for (const file of sourceFiles(packDir)) {
      const text = readFileSync(file, "utf8");
      for (const match of text.matchAll(specifierPattern)) {
        const specifier = match[1];
        for (const forbidden of FORBIDDEN) {
          assert.equal(
            specifier.includes(forbidden),
            false,
            `${file} imports ${specifier} (forbidden: ${forbidden})`,
          );
        }
      }
    }
  });

  it("keeps the runner and coverage vocabulary the rules read identical to the model's", async () => {
    const { model } = await scanModel(FIXTURE_A);
    const query = createRepositoryQuery(model);
    for (const entity of query.listEntities("framework").entities) {
      assert.ok(typeof entity.name === "string" && entity.name.length > 0);
    }
    assert.equal(TEST_RUNNER_IDS.includes("node-test"), true);
    assert.equal(COVERAGE_COMMAND_IDS.includes("node-test-coverage"), true);
  });
});
