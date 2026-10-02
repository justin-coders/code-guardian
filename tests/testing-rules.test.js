/**
 * Code Guardian — Testing Acquisition & Rule Unit Tests (official roadmap Phase 11)
 *
 * Unit-level proof for the pieces the Testing Analyzer rests on: the bounded test
 * command classifier, the structural flaky-indicator matcher, the scanner's
 * content-backed Node built-in runner detection (the correction Phase 11 mandates),
 * the CI test-execution acquisition, the manifest test-script extraction, and the
 * model projections that carry those facts into the rules layer.
 *
 * Every fixture is a real repository written to a temporary directory and scanned
 * through the accepted Phase 8A boundary and Phase 8C scanner, so "the built-in
 * runner was detected" means a file's literal `node:test` reference was read — never
 * that the project is JavaScript.
 *
 * Run with: node --test tests/testing-rules.test.js
 */

import { after, describe, it } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

import { scanRepository } from "../src/repository/scanner/index.js";
import {
  CI_TEST_EXECUTION,
  CI_TEST_EXECUTION_REASONS,
} from "../src/repository/scanner/detectors/cicd.js";
import {
  TESTING_ACQUISITION_LIMITS,
  TEST_FLAKY_INDICATOR_IDS,
  TEST_FLAKY_INDICATORS,
  detectTestFlakyIndicators,
} from "../src/repository/scanner/detectors/testing.js";
import {
  COVERAGE_COMMAND_IDS as SCANNER_COVERAGE_IDS,
  TEST_RUNNER_IDS as SCANNER_RUNNER_IDS,
  classifyTestCommand,
} from "../src/repository/scanner/policies/testing.js";
import {
  CI_TEST_EXECUTION_STATES,
  TEST_FLAKY_INDICATORS as MODEL_FLAKY_INDICATORS,
  buildRepositoryModel,
  createRepositoryQuery,
} from "../src/repository/model/index.js";

import {
  COVERAGE_COMMAND_IDS,
  TESTING_RULE_IDS,
  TEST_RUNNER_IDS,
  createTestingAnalyzer,
  createTestingRuleRegistry,
  testingRules,
  testingRuleSetIssues,
} from "../src/rules/index.js";

// ─── Fixtures ────────────────────────────────────────────────────────────────

const TMP_ROOT = join(tmpdir(), `cg-testing-rules-${process.pid}-${Date.now()}`);
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

const pkg = (extra = {}) => JSON.stringify({ name: "demo", version: "1.0.0", ...extra });

const NODE_TEST_FILE =
  'import { test } from "node:test";\nimport assert from "node:assert";\ntest("adds", () => { assert.equal(1 + 1, 2); });\n';

const PLAIN_TEST_FILE = 'import { it, expect } from "some-unknown-runner";\nit("works", () => expect(1).toBe(1));\n';

// ─── Command classification ─────────────────────────────────────────────────

describe("testing acquisition: command classification", () => {
  it("recognises the Node built-in runner only from its own invocation", () => {
    assert.deepEqual(classifyTestCommand("node --test tests/**/*.test.js").runners, [
      "node-test",
    ]);
    assert.deepEqual(classifyTestCommand("node --test --experimental-test-coverage src").runners, [
      "node-test",
    ]);
    // A Node project is not evidence of the built-in runner.
    assert.equal(classifyTestCommand("node src/server.js").runners.length, 0);
    assert.equal(classifyTestCommand("npm run build").runners.length, 0);
  });

  it("recognises the common runners and the generic package script", () => {
    assert.ok(classifyTestCommand("vitest run").runners.includes("vitest"));
    assert.ok(classifyTestCommand("jest --ci").runners.includes("jest"));
    assert.ok(classifyTestCommand("pytest -q").runners.includes("pytest"));
    assert.ok(classifyTestCommand("go test ./...").runners.includes("go-test"));
    assert.ok(classifyTestCommand("cargo test").runners.includes("cargo-test"));
    assert.ok(classifyTestCommand("npm test").runners.includes("package-script-test"));
    assert.ok(classifyTestCommand("npm run test:unit").runners.includes("package-script-test"));
  });

  it("recognises integration and end-to-end invocations", () => {
    assert.ok(classifyTestCommand("playwright test").levels.includes("e2e"));
    assert.ok(classifyTestCommand("cypress run").levels.includes("e2e"));
    assert.ok(
      classifyTestCommand("jest --testPathPattern integration").runners.includes("jest-integration"),
    );
  });

  it("classifies coverage flags separately from test execution", () => {
    assert.ok(
      classifyTestCommand("node --test --experimental-test-coverage tests").coverage.includes(
        "node-test-coverage",
      ),
    );
    assert.ok(classifyTestCommand("jest --coverage").coverage.includes("v8-coverage"));
    assert.deepEqual(classifyTestCommand("node --test tests").coverage, []);
  });

  it("is total and deterministic for non-strings and unknown commands", () => {
    assert.deepEqual(classifyTestCommand(null), { runners: [], levels: [], coverage: [] });
    assert.deepEqual(classifyTestCommand(""), { runners: [], levels: [], coverage: [] });
    const first = classifyTestCommand("jest");
    const second = classifyTestCommand("jest");
    assert.deepEqual(first, second);
  });

  it("keeps the rules layer's runner vocabulary pinned to the acquisition layer's", () => {
    assert.deepEqual([...TEST_RUNNER_IDS].sort(), [...SCANNER_RUNNER_IDS].sort());
    assert.deepEqual([...COVERAGE_COMMAND_IDS].sort(), [...SCANNER_COVERAGE_IDS].sort());
  });
});

// ─── Flaky indicator matcher ────────────────────────────────────────────────

describe("testing acquisition: structural flaky indicators", () => {
  it("matches each documented shape and nothing more", () => {
    assert.deepEqual(detectTestFlakyIndicators("const t = Date.now();"), ["time-dependent"]);
    assert.deepEqual(detectTestFlakyIndicators("Math.random()"), ["uncontrolled-randomness"]);
    assert.deepEqual(detectTestFlakyIndicators("await sleep(100)"), ["sleep-based-sync"]);
    assert.deepEqual(detectTestFlakyIndicators("await fetch(url)"), ["network-dependent"]);
    assert.deepEqual(detectTestFlakyIndicators("retries: 2"), ["retry-configuration"]);
    assert.deepEqual(detectTestFlakyIndicators("const x = 1 + 1;"), []);
  });

  it("is total and deterministic", () => {
    assert.deepEqual(detectTestFlakyIndicators(null), []);
    assert.deepEqual(detectTestFlakyIndicators(7), []);
    assert.deepEqual(detectTestFlakyIndicators(""), []);
    assert.deepEqual(
      detectTestFlakyIndicators("Date.now(); Math.random(); Date.now();"),
      ["time-dependent", "uncontrolled-randomness"],
    );
  });

  it("pins the model's indicator vocabulary to the acquisition layer's", () => {
    assert.deepEqual([...MODEL_FLAKY_INDICATORS].sort(), [...TEST_FLAKY_INDICATOR_IDS].sort());
  });

  it("pins the model's CI test-execution states to the acquisition layer's", () => {
    assert.deepEqual(
      [...CI_TEST_EXECUTION_STATES].sort(),
      Object.values(CI_TEST_EXECUTION).sort(),
    );
  });
});

// ─── Scanner: Node built-in runner (mandatory correction) ────────────────────

describe("testing acquisition: Node built-in runner", () => {
  it("detects `node:test` from a test file's content, not from the language", async () => {
    const { scan, model } = await scanModel({
      "package.json": pkg({ scripts: { test: "node --test" } }),
      "tests/math.test.js": NODE_TEST_FILE,
    });
    assert.ok(scan.tests.frameworks.includes("node-test"));
    assert.ok(model.tests.frameworks.includes("node-test"));
    const entity = model.tests.entries.find((entry) => entry.path === "tests/math.test.js");
    assert.equal(entity.frameworkId, "framework:node-test");
  });

  it("does not detect it for a Node project without the reference", async () => {
    const { scan } = await scanModel({
      "package.json": pkg({ scripts: { start: "node src/server.js" } }),
      "src/app.test.js": PLAIN_TEST_FILE,
      "src/server.js": "console.log('hi');\n",
    });
    assert.equal(scan.tests.frameworks.includes("node-test"), false);
  });

  it("does not override a framework the file name already established", async () => {
    const { scan } = await scanModel({
      "package.json": pkg(),
      "pkg/handler_test.go": "package main\nfunc TestX(t *testing.T) {}\n",
    });
    assert.ok(scan.tests.frameworks.includes("go-test"));
    assert.equal(scan.tests.frameworks.includes("node-test"), false);
  });
});

// ─── Scanner: manifest test scripts ─────────────────────────────────────────

describe("testing acquisition: manifest test scripts", () => {
  it("records only test-related script names with their classified commands", async () => {
    const { scan } = await scanModel({
      "package.json": JSON.stringify({
        name: "demo",
        scripts: {
          build: "tsc",
          test: "node --test tests/**/*.test.js",
          "test:coverage": "node --test --experimental-test-coverage tests",
          lint: "eslint .",
        },
      }),
    });
    const metadata = scan.manifests[0].parse.metadata;
    assert.deepEqual(
      metadata.testScripts.map((script) => script.name),
      ["test", "test:coverage"],
    );
    assert.equal(metadata.testScript, "node --test tests/**/*.test.js");
    assert.deepEqual(metadata.testScripts[0].runners, ["node-test"]);
    assert.deepEqual(metadata.testScripts[1].coverage, ["node-test-coverage"]);
  });

  it("records a failed manifest parse without inventing script facts", async () => {
    const { scan, model } = await scanModel({ "package.json": "{ not json" });
    assert.equal(scan.manifests[0].parse.status, "failed");
    assert.equal(scan.manifests[0].parse.metadata, undefined);
    assert.equal(model.manifests.entries[0].parse.metadata, undefined);
  });
});

// ─── Scanner: CI test execution ─────────────────────────────────────────────

describe("testing acquisition: CI test execution", () => {
  it("establishes test execution from a workflow's content", async () => {
    const { scan, model } = await scanModel({
      ".github/workflows/ci.yml": "jobs:\n  test:\n    steps:\n      - run: npm test\n",
    });
    const entry = scan.cicd.evidence.find((item) => item.path === ".github/workflows/ci.yml");
    assert.equal(entry.testExecution, "detected");
    assert.ok(entry.testRunners.includes("package-script-test"));
    assert.equal(model.ci.entries[0].testExecution, "detected");
  });

  it("does not mistake a build-only workflow for test execution", async () => {
    const { scan } = await scanModel({
      ".github/workflows/ci.yml": "jobs:\n  build:\n    steps:\n      - run: npm run build\n",
    });
    const entry = scan.cicd.evidence.find((item) => item.path === ".github/workflows/ci.yml");
    assert.equal(entry.testExecution, CI_TEST_EXECUTION.NONE);
    assert.deepEqual(entry.testRunners, []);
  });

  it("records an unreadable workflow as unknown, never as `no tests`", async () => {
    // A binary workflow file cannot be interpreted.
    const { scan } = await scanModel({
      ".github/workflows/ci.yml": "jobs:\u0000binary",
    });
    const entry = scan.cicd.evidence.find((item) => item.path === ".github/workflows/ci.yml");
    assert.equal(entry.testExecution, CI_TEST_EXECUTION.UNKNOWN);
    assert.equal(entry.reason, "not-text");
  });

  it("documents the reasons a workflow's test execution is not established", () => {
    assert.deepEqual([...CI_TEST_EXECUTION_REASONS], [
      "unreadable",
      "too-large",
      "not-text",
      "budget-exhausted",
    ]);
  });
});

// ─── Model projections ──────────────────────────────────────────────────────

describe("testing acquisition: model projections", () => {
  it("carries flaky indicators onto the test entity", async () => {
    const { model } = await scanModel({
      "tests/timing.test.js":
        'import { test } from "node:test";\ntest("x", async () => { await sleep(1); const t = Date.now(); });\n',
    });
    const entity = model.tests.entries.find((entry) => entry.path === "tests/timing.test.js");
    assert.deepEqual(entity.indicators, ["sleep-based-sync", "time-dependent"]);
  });

  it("projects CI test-execution facts onto the cicd entity", async () => {
    const { model } = await scanModel({
      ".github/workflows/ci.yml": "steps:\n  - run: pytest -q\n",
    });
    const entity = model.ci.entries[0];
    assert.equal(entity.provider, "github-actions");
    assert.equal(entity.testExecution, "detected");
    assert.ok(entity.testRunners.includes("pytest"));
  });

  it("rejects a malformed evidence-cap invariant the same way for both sections", async () => {
    assert.ok(TESTING_ACQUISITION_LIMITS.maxFiles > 0);
    assert.ok(TESTING_ACQUISITION_LIMITS.maxFileBytes > 0);
  });
});

// ─── Rule set ───────────────────────────────────────────────────────────────

describe("testing rules: rule set", () => {
  it("ships every declared rule under the namespace, frozen and sorted", () => {
    assert.deepEqual(
      testingRules.map((rule) => rule.id),
      [...testingRules.map((rule) => rule.id)].sort(),
    );
    assert.equal(Object.isFrozen(testingRules), true);
    for (const rule of testingRules) {
      assert.match(rule.id, /^testing\./);
      assert.equal(typeof rule.detect, "function");
      assert.deepEqual({ ...rule.applicability }, {});
      assert.ok(rule.description.length > 0);
      assert.ok(["info", "low", "medium", "high", "critical"].includes(rule.severity));
    }
  });

  it("fails the registry when a declared rule is missing or misnamed", () => {
    const dropped = testingRules.filter((rule) => rule.id !== TESTING_RULE_IDS.FRAMEWORK_UNESTABLISHED);
    const issues = testingRuleSetIssues(dropped);
    assert.ok(issues.some((issue) => issue.includes(TESTING_RULE_IDS.FRAMEWORK_UNESTABLISHED)));
    assert.throws(() => createTestingRuleRegistry({ rules: dropped }));
  });

  it("accepts an extra project-local rule without editing the pack contract", () => {
    const extra = {
      id: "testing.project-local.fixture",
      version: "1.0.0",
      category: "testing",
      title: "fixture",
      description: "fixture",
      severity: "info",
      applicability: {},
      detect: () => [],
      remediation: {},
      metadata: {},
    };
    assert.deepEqual(testingRuleSetIssues([...testingRules, extra]), []);
  });
});

// ─── Analyzer descriptor ────────────────────────────────────────────────────

describe("testing rules: analyzer descriptor", () => {
  it("is an ordinary Analyzer descriptor the registry can hold", () => {
    const analyzer = createTestingAnalyzer();
    assert.equal(analyzer.id, "testing");
    assert.equal(typeof analyzer.analyze, "function");
    assert.equal(analyzer.canAnalyze().applicable, true);
  });
});
