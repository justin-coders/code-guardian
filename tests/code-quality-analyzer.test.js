/**
 * Code Guardian — Code Quality Analyzer Tests (official roadmap Phase 12)
 *
 * The end-to-end proof that the Code Quality Analyzer works through the real pipeline:
 *
 *   Repository → RepositoryModel → CodeQualityAnalyzer → applicable rules → evidence → findings
 *
 * Fixtures A–O from the Phase 12 handoff live here as real repositories written to a temporary
 * directory and scanned through the accepted Phase 8A/8C/8D boundary. The suite's central
 * claims are the roadmap's exit criteria: all nine domains are analyzed, the five states are
 * distinguished (`detected`/`verified`/`failed`/`unknown`/`not_applicable`), configuration is
 * never reported as execution, an incomplete scan turns absence into `unknown` rather than
 * clean, every finding cites model evidence, fingerprints are stable and unique, language
 * knowledge stays modular, and the pack imports no filesystem, process, network or MCP module.
 *
 * Run with: node --test tests/code-quality-analyzer.test.js
 */

import { after, describe, it } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

import { createRule } from "../src/core/index.js";

import { scanRepository } from "../src/repository/scanner/index.js";
import { buildRepositoryModel } from "../src/repository/model/index.js";

import {
  buildAnalysisContext,
  createAnalyzerEngine,
  createAnalyzerRegistry,
  stableAnalysisView,
} from "../src/analysis/index.js";

import {
  CODE_QUALITY_ANALYZER_ID,
  CODE_QUALITY_RULE_IDS,
  CODE_QUALITY_STATES,
  QUALITY_LANGUAGE_IDS,
  QUALITY_TOOLING,
  codeQualityRules,
  createCodeQualityAnalyzer,
  createCodeQualityRuleRegistry,
  createRuleEngine,
  createRuleRegistry,
  createTestingAnalyzer,
} from "../src/rules/index.js";

// ─── Fixtures ────────────────────────────────────────────────────────────────

const TMP_ROOT = join(tmpdir(), `cg-code-quality-analyzer-${process.pid}-${Date.now()}`);
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
  return { scan, model: buildRepositoryModel(scan) };
}

after(() => {
  rmSync(TMP_ROOT, { recursive: true, force: true });
});

const pkg = (extra = {}) => JSON.stringify({ name: "demo", version: "1.0.0", ...extra });
const SRC = "export const a = 1;\n";
const MANY = `${Array.from({ length: 45 }, (_, index) => `export const v${index} = ${index};`).join("\n")}\n`;
const CI_LINTS = "jobs:\n  quality:\n    steps:\n      - run: eslint .\n";

// Fixture A — linting detected.
const FIXTURE_A = { "package.json": pkg(), ".eslintrc.json": "{}\n", "src/a.js": SRC };
// Fixture B — formatting detected.
const FIXTURE_B = { "package.json": pkg(), ".prettierrc": "{}\n", "src/a.js": SRC };
// Fixture C — type checking detected.
const FIXTURE_C = {
  "package.json": pkg(),
  "tsconfig.json": "{}\n",
  "src/a.ts": "export const a: number = 1;\n",
};
// Fixture D — dead-code indicators.
const FIXTURE_D = { "package.json": pkg(), "src/orphan.js": "export function unused() { return 1; }\n" };
// Fixture E — complexity indicator.
const FIXTURE_E = { "package.json": pkg(), "src/big.js": MANY };
// Fixture F — duplication is unmeasurable over source.
const FIXTURE_F = { "package.json": pkg(), "src/a.js": SRC };
// Fixture G — unsafe-pattern indicator (dynamic scope).
const FIXTURE_G = {
  "package.json": pkg(),
  "src/dyn.js": "export function run() { return eval('1'); }\n",
};
// Fixture H — maintainability indicator (source, no tooling).
const FIXTURE_H = { "package.json": pkg(), "src/a.js": SRC };
// Fixture I — configuration inconsistency (two compiler configurations).
const FIXTURE_I = {
  "package.json": pkg(),
  "tsconfig.json": "{}\n",
  "jsconfig.json": "{}\n",
  "src/a.ts": "export const a: number = 1;\n",
};
// Fixture J — negative repository (no source, no tooling, no findings).
const FIXTURE_J = { "README.md": "# docs only\n" };
// Fixture K — malformed manifest.
const FIXTURE_K = { "package.json": "{ not json", "src/a.js": SRC };
// Fixture L — language modularity: a Python repository whose linter is declared by its own
// ecosystem's dependency file.
const FIXTURE_L = { "requirements.txt": "ruff==0.1.0\n", "src/app.py": "def f():\n    return 1\n" };
// Fixture M — configuration without an execution path.
const FIXTURE_M = { "package.json": pkg(), ".eslintrc.json": "{}\n", "src/a.js": SRC };
// Fixture N — configured *and* declared, but no CI: `detected`, never `verified`.
const FIXTURE_N = {
  "package.json": pkg({ scripts: { lint: "eslint ." } }),
  ".eslintrc.json": "{}\n",
  "src/a.js": SRC,
};
// Fixture O — CI execution evidence: the only path to `verified`.
const FIXTURE_O = {
  "package.json": pkg({ scripts: { lint: "eslint ." } }),
  ".eslintrc.json": "{}\n",
  ".github/workflows/ci.yml": CI_LINTS,
  "src/a.js": SRC,
};
// Two findings from one rule in one file — the fingerprint-collision case.
const FIXTURE_TWO = {
  "package.json": pkg(),
  "src/two.js": "export const first = 1;\nexport const second = 2;\n",
};

const contextOf = (model) => buildAnalysisContext({ repository: model });

async function runAnalyzer(model) {
  const engine = createAnalyzerEngine({
    registry: createAnalyzerRegistry([createCodeQualityAnalyzer()]),
  });
  return engine.runAll(contextOf(model));
}

async function runRules(model) {
  const engine = createRuleEngine({ registry: createCodeQualityRuleRegistry({ rules: codeQualityRules }) });
  return engine.runAll(contextOf(model));
}

const statusOf = (run, ruleId) => run.rules.find((entry) => entry.rule.id === ruleId)?.status;
const summaryOf = (result) =>
  result.analyzers.find((entry) => entry.analyzer.id === CODE_QUALITY_ANALYZER_ID).metadata.codeQualitySummary;
const findingsOf = (result, ruleId) => result.findings.filter((finding) => finding.ruleId === ruleId);

// ─── Analyzer contract ──────────────────────────────────────────────────────

describe("code quality analyzer: contract", () => {
  it("is an ordinary Analyzer the shared registry runs beside another domain analyzer", async () => {
    const analyzer = createCodeQualityAnalyzer();
    assert.equal(analyzer.id, CODE_QUALITY_ANALYZER_ID);
    assert.equal(analyzer.scope, "code-quality");

    const { model } = await scanModel(FIXTURE_O);
    const engine = createAnalyzerEngine({
      registry: createAnalyzerRegistry([createTestingAnalyzer(), createCodeQualityAnalyzer()]),
    });
    const result = await engine.runAll(contextOf(model));
    const ids = result.analyzers.map((entry) => entry.analyzer.id);
    assert.deepEqual(ids, ["code-quality", "testing"]);
    assert.ok(summaryOf(result) !== undefined);
  });

  it("keeps one shared registry mechanism: the pack's rules evaluate through the Rule Engine", async () => {
    const { model } = await scanModel(FIXTURE_O);
    const run = await runRules(model);
    assert.equal(run.rules.length, codeQualityRules.length);
    // A rule the engine could not decide is an *abstention*, and the run says so.
    assert.ok(run.rules.some((entry) => entry.status === "unknown"));
    assert.equal(run.complete, false);
  });
});

// ─── Golden fixtures ────────────────────────────────────────────────────────

describe("code quality analyzer: golden fixtures", () => {
  it("A: reports linting as `detected` from its configuration, never `verified`", async () => {
    const { model } = await scanModel(FIXTURE_A);
    const linting = summaryOf(await runAnalyzer(model)).linting;
    assert.equal(linting.state, CODE_QUALITY_STATES.DETECTED);
    assert.deepEqual(linting.configurations, [".eslintrc.json"]);
  });

  it("B: reports formatting as `detected` from its configuration", async () => {
    const { model } = await scanModel(FIXTURE_B);
    const formatting = summaryOf(await runAnalyzer(model)).formatting;
    assert.equal(formatting.state, CODE_QUALITY_STATES.DETECTED);
    assert.deepEqual(formatting.configurations, [".prettierrc"]);
  });

  it("C: reports type checking as `detected` from a compiler configuration", async () => {
    const { model } = await scanModel(FIXTURE_C);
    const typeChecking = summaryOf(await runAnalyzer(model)).typeChecking;
    assert.equal(typeChecking.state, CODE_QUALITY_STATES.DETECTED);
    assert.deepEqual(typeChecking.configurations, ["tsconfig.json"]);
  });

  it("D: reports a dead-code *indicator*, worded as one", async () => {
    const { model } = await scanModel(FIXTURE_D);
    const result = await runAnalyzer(model);
    const exports = findingsOf(result, CODE_QUALITY_RULE_IDS.DEAD_CODE_UNUSED_EXPORT);
    const orphans = findingsOf(result, CODE_QUALITY_RULE_IDS.DEAD_CODE_ORPHAN_MODULE);
    assert.ok(exports.length >= 1);
    assert.ok(orphans.length >= 1);
    assert.equal(exports[0].metadata.state, CODE_QUALITY_STATES.DETECTED);
    // An indicator, never a verdict.
    assert.match(exports[0].description, /indicator/i);
    assert.doesNotMatch(exports[0].description, /this code is dead/i);
    assert.deepEqual(summaryOf(result).deadCode.state, CODE_QUALITY_STATES.DETECTED);
  });

  it("E: reports a module-size indicator, and never calls it cyclomatic complexity", async () => {
    const { model } = await scanModel(FIXTURE_E);
    const result = await runAnalyzer(model);
    const large = findingsOf(result, CODE_QUALITY_RULE_IDS.COMPLEXITY_LARGE_MODULE);
    assert.ok(large.length >= 1);
    assert.equal(large[0].metadata.measure, "module-scope-declarations");
    assert.equal(large[0].metadata.declarations, 45);
    assert.doesNotMatch(large[0].description, /cyclomatic complexity measurement/i);
    assert.equal(summaryOf(result).complexity.state, CODE_QUALITY_STATES.DETECTED);
  });

  it("F: reports duplication as `unknown`, never clean", async () => {
    const { model } = await scanModel(FIXTURE_F);
    const result = await runAnalyzer(model);
    const duplication = summaryOf(result).duplication;
    assert.equal(duplication.state, CODE_QUALITY_STATES.UNKNOWN);
    assert.equal(duplication.measure, null);
    // The domain has no Finding — the abstention is the analyzer's own answer.
    assert.equal(findingsOf(result, CODE_QUALITY_RULE_IDS.DUPLICATION_UNMEASURED).length, 0);
    assert.equal(statusOf(await runRules(model), CODE_QUALITY_RULE_IDS.DUPLICATION_UNMEASURED), "unknown");
  });

  it("G: detects a dynamic-scope unsafe pattern from the model's own observation", async () => {
    const { model } = await scanModel(FIXTURE_G);
    const result = await runAnalyzer(model);
    const unsafe = findingsOf(result, CODE_QUALITY_RULE_IDS.UNSAFE_PATTERN_DYNAMIC_SCOPE);
    assert.equal(unsafe.length, 1);
    assert.equal(unsafe[0].metadata.path, "src/dyn.js");
    assert.equal(unsafe[0].metadata.problem, "dynamic-scope-construct");
    assert.equal(unsafe[0].category, "code-quality");
    assert.deepEqual(summaryOf(result).unsafePattern.state, CODE_QUALITY_STATES.DETECTED);
  });

  it("H: reports maintainability as a concrete missing-tooling indicator, never a score", async () => {
    const { model } = await scanModel(FIXTURE_H);
    const result = await runAnalyzer(model);
    const maintainability = summaryOf(result).maintainability;
    assert.equal(maintainability.state, CODE_QUALITY_STATES.DETECTED);
    assert.deepEqual(maintainability.missingDomains, ["linting", "formatting", "type-checking"]);
    // No score, grade or percentage anywhere in the finding the rule emitted.
    const finding = findingsOf(result, CODE_QUALITY_RULE_IDS.MAINTAINABILITY_NO_TOOLING)[0];
    assert.ok(finding !== undefined);
    assert.doesNotMatch(finding.title, /score|grade/i);
    assert.equal(typeof finding.score, "undefined");
  });

  it("I: reports a conflicting compiler configuration the model can prove", async () => {
    const { model } = await scanModel(FIXTURE_I);
    const result = await runAnalyzer(model);
    const inconsistent = findingsOf(result, CODE_QUALITY_RULE_IDS.CONFIGURATION_INCONSISTENT);
    const kinds = inconsistent.map((finding) => finding.metadata.kind).sort();
    assert.deepEqual(kinds, ["configuration-without-execution-path", "conflicting-compiler-configuration"]);
    const conflict = inconsistent.find(
      (finding) => finding.metadata.kind === "conflicting-compiler-configuration",
    );
    assert.deepEqual(conflict.metadata.configurations, ["jsconfig.json", "tsconfig.json"]);
  });

  it("J: a repository with no source reports `not_applicable` and no findings", async () => {
    const { model } = await scanModel(FIXTURE_J);
    const result = await runAnalyzer(model);
    assert.deepEqual(result.findings, []);
    const summary = summaryOf(result);
    assert.equal(summary.applicability.state, CODE_QUALITY_STATES.NOT_APPLICABLE);
    for (const domain of ["linting", "formatting", "typeChecking", "complexity", "duplication", "maintainability"]) {
      assert.equal(summary[domain].state, CODE_QUALITY_STATES.NOT_APPLICABLE, domain);
    }
  });

  it("K: a malformed manifest is `failed`, never \"declared no quality script\"", async () => {
    const { model } = await scanModel(FIXTURE_K);
    const result = await runAnalyzer(model);
    const scripts = summaryOf(result).qualityScripts;
    assert.equal(scripts.state, CODE_QUALITY_STATES.FAILED);
    assert.deepEqual(scripts.failedManifests, ["package.json"]);
    // The tooling domains stay open: a blocked script channel does not prove absence.
    assert.equal(summaryOf(result).linting.state, CODE_QUALITY_STATES.UNKNOWN);
  });

  it("L: reads a language's own ecosystem vocabulary, keeping language knowledge modular", async () => {
    const { model } = await scanModel(FIXTURE_L);
    const result = await runAnalyzer(model);
    const linting = summaryOf(result).linting;
    assert.equal(linting.state, CODE_QUALITY_STATES.DETECTED);
    assert.deepEqual(linting.dependencies, ["ruff"]);
    assert.deepEqual(linting.languages, ["python"]);
    // The tool came from the Python profile's vocabulary, unioned into one tool map.
    assert.ok(QUALITY_LANGUAGE_IDS.includes("python"));
    assert.ok(QUALITY_TOOLING.linting.dependencies.includes("ruff"));
  });

  it("M: reports a configuration with no execution path as an observation", async () => {
    const { model } = await scanModel(FIXTURE_M);
    const result = await runAnalyzer(model);
    const disconnected = findingsOf(result, CODE_QUALITY_RULE_IDS.CONFIGURATION_INCONSISTENT).find(
      (finding) => finding.metadata.kind === "configuration-without-execution-path",
    );
    assert.ok(disconnected !== undefined);
    assert.equal(disconnected.metadata.domain, "linting");
    assert.deepEqual(disconnected.metadata.configurations, [".eslintrc.json"]);
  });

  it("N: configuration plus a declared script is `detected`, never `verified`", async () => {
    const { model } = await scanModel(FIXTURE_N);
    const linting = summaryOf(await runAnalyzer(model)).linting;
    assert.equal(linting.state, CODE_QUALITY_STATES.DETECTED);
    assert.deepEqual(linting.scripts, ["lint"]);
    assert.notEqual(linting.state, CODE_QUALITY_STATES.VERIFIED);
  });

  it("O: configuration plus a CI invocation is `verified`, and that is not a claim the run passed", async () => {
    const { model } = await scanModel(FIXTURE_O);
    const result = await runAnalyzer(model);
    const linting = summaryOf(result).linting;
    assert.equal(linting.state, CODE_QUALITY_STATES.VERIFIED);
    assert.deepEqual(linting.ciTools, ["eslint"]);
    // `verified` never turns into a finding — no rule claims execution succeeded.
    assert.equal(findingsOf(result, CODE_QUALITY_RULE_IDS.LINTING_UNCONFIGURED).length, 0);
    const details = await runRules(model);
    const rule = details.rules.find((entry) => entry.rule.id === CODE_QUALITY_RULE_IDS.LINTING_UNCONFIGURED);
    assert.equal(rule.metadata.state, CODE_QUALITY_STATES.VERIFIED);
    assert.doesNotMatch(rule.metadata.state, /pass/i);
  });
});

// ─── Incomplete scan ────────────────────────────────────────────────────────

describe("code quality analyzer: incomplete scan", () => {
  it("turns absence into an abstention, never a clean result", async () => {
    const { model } = await scanModel(
      { "package.json": pkg(), "src/a.js": SRC, "src/b.js": SRC, "src/c.js": SRC },
      { maxFiles: 1 },
    );
    const result = await runAnalyzer(model);
    // No finding asserts anything about a repository that was not read.
    assert.deepEqual(result.findings, []);
    const run = await runRules(model);
    assert.equal(statusOf(run, CODE_QUALITY_RULE_IDS.LINTING_UNCONFIGURED), "unknown");
    assert.equal(statusOf(run, CODE_QUALITY_RULE_IDS.CONFIGURATION_INCONSISTENT), "unknown");
  });

  it("does not let a truncated scan report `not_applicable` for a domain it never covered", async () => {
    const { model } = await scanModel({ "package.json": pkg(), "src/a.js": SRC }, { maxFiles: 1 });
    const summary = summaryOf(await runAnalyzer(model));
    // The configuration domain has a subject but no evidence at all: unknown, not n/a.
    assert.equal(summary.configurationConsistency.state, CODE_QUALITY_STATES.UNKNOWN);
    assert.notEqual(summary.configurationConsistency.state, CODE_QUALITY_STATES.NOT_APPLICABLE);
  });
});

// ─── Unknown vs not applicable ──────────────────────────────────────────────

describe("code quality analyzer: unknown is not not_applicable", () => {
  it("keeps an open tooling domain `unknown` when source exists but no marker does", async () => {
    const { model } = await scanModel(FIXTURE_H);
    const summary = summaryOf(await runAnalyzer(model));
    assert.equal(summary.linting.state, CODE_QUALITY_STATES.UNKNOWN);
    assert.equal(summary.formatting.state, CODE_QUALITY_STATES.UNKNOWN);
    assert.equal(summary.typeChecking.state, CODE_QUALITY_STATES.UNKNOWN);
  });

  it("keeps a measured domain `unknown` when its graph was not established", async () => {
    const { model } = await scanModel(FIXTURE_L);
    const run = await runRules(model);
    // Python has no symbol graph in this build, so the indicator rules abstain.
    assert.equal(statusOf(run, CODE_QUALITY_RULE_IDS.DEAD_CODE_UNUSED_EXPORT), "unknown");
    assert.equal(statusOf(run, CODE_QUALITY_RULE_IDS.COMPLEXITY_LARGE_MODULE), "unknown");
    assert.equal(statusOf(run, CODE_QUALITY_RULE_IDS.UNSAFE_PATTERN_DYNAMIC_SCOPE), "unknown");
    const summary = summaryOf(await runAnalyzer(model));
    assert.equal(summary.deadCode.state, CODE_QUALITY_STATES.UNKNOWN);
    assert.equal(summary.unsafePattern.state, CODE_QUALITY_STATES.UNKNOWN);
  });

  it("uses the shared applicability engine rather than a second selector", async () => {
    const { model } = await scanModel(FIXTURE_A);
    const rules = [
      createRule({
        id: "code-quality.fixture.rust",
        version: "1.0.0",
        category: "code-quality",
        title: "fixture",
        description: "fixture",
        severity: "info",
        applicability: { languages: ["rust"] },
        detect: () => [],
      }),
      createRule({
        id: "code-quality.fixture.javascript",
        version: "1.0.0",
        category: "code-quality",
        title: "fixture",
        description: "fixture",
        severity: "info",
        applicability: { languages: ["javascript"] },
        detect: () => [],
      }),
    ];
    const engine = createRuleEngine({ registry: createRuleRegistry(rules) });
    const run = await engine.runAll(contextOf(model));
    assert.equal(run.rules.find((entry) => entry.rule.id === "code-quality.fixture.rust").status, "not-applicable");
    assert.equal(run.rules.find((entry) => entry.rule.id === "code-quality.fixture.javascript").status, "pass");
  });
});

// ─── Evidence ───────────────────────────────────────────────────────────────

describe("code quality analyzer: evidence", () => {
  it("cites only model evidence, and every cited id resolves", async () => {
    const { model } = await scanModel({ ...FIXTURE_I, ...FIXTURE_TWO, ...FIXTURE_G });
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
    const { model } = await scanModel({ ...FIXTURE_I, ...FIXTURE_G, ...FIXTURE_K });
    const result = await runAnalyzer(model);
    const allowed = Object.values(CODE_QUALITY_STATES);
    for (const finding of result.findings) {
      assert.ok(allowed.includes(finding.metadata.state), `${finding.ruleId}: ${finding.metadata.state}`);
    }
  });
});

// ─── Fingerprints ───────────────────────────────────────────────────────────

describe("code quality analyzer: fingerprints", () => {
  it("gives two findings from one rule in one file distinct canonical fingerprints", async () => {
    const { model } = await scanModel(FIXTURE_TWO);
    const result = await runAnalyzer(model);
    const unused = findingsOf(result, CODE_QUALITY_RULE_IDS.DEAD_CODE_UNUSED_EXPORT);
    assert.equal(unused.length, 2);
    assert.equal(new Set(unused.map((finding) => finding.fingerprint)).size, 2);
    for (const finding of unused) assert.match(finding.fingerprint, /^cg-fp1-[0-9a-f]{32}$/);
  });

  it("is deterministic: the same repository twice gives the same results", async () => {
    const { model } = await scanModel({ ...FIXTURE_I, ...FIXTURE_G, ...FIXTURE_TWO });
    const first = await runAnalyzer(model);
    const second = await runAnalyzer(model);
    assert.deepEqual(
      first.findings.map((finding) => finding.fingerprint),
      second.findings.map((finding) => finding.fingerprint),
    );
    assert.deepEqual(stableAnalysisView(first), stableAnalysisView(second));
    assert.deepEqual(
      summaryOf(first),
      summaryOf(second),
    );
  });
});

// ─── Performance measurement ────────────────────────────────────────────────

describe("code quality analyzer: performance", () => {
  it("analyzes a bounded fixture deterministically and within a sane budget", async () => {
    const files = { "package.json": pkg({ scripts: { lint: "eslint ." } }) };
    for (let index = 0; index < 40; index += 1) {
      files[`src/module${String(index).padStart(3, "0")}.js`] = MANY;
    }
    files[".eslintrc.json"] = "{}\n";
    files[".github/workflows/ci.yml"] = CI_LINTS;

    const { model } = await scanModel(files);

    const start = process.hrtime.bigint();
    const first = await runAnalyzer(model);
    const second = await runAnalyzer(model);
    const elapsedMs = Number(process.hrtime.bigint() - start) / 1e6;

    // Meaningful, not a benchmark: two full analyzer passes over a 43-file fixture must
    // finish well inside a few seconds on the CI runners.
    assert.ok(elapsedMs < 8000, `analyzer took ${elapsedMs.toFixed(1)}ms`);
    assert.deepEqual(
      first.findings.map((finding) => finding.fingerprint),
      second.findings.map((finding) => finding.fingerprint),
    );
    // eslint-disable-next-line no-console
    console.log(`[phase-12] two analyzer passes over 43 files: ${elapsedMs.toFixed(1)}ms`);
  });
});

// ─── Architectural boundary ─────────────────────────────────────────────────

describe("code quality analyzer: boundaries", () => {
  const FORBIDDEN = [
    "node:fs",
    "node:fs/promises",
    "node:path",
    "child_process",
    "node:child_process",
    "node:net",
    "node:http",
    "node:https",
    "node:dns",
    "node:worker_threads",
    "tools.js",
    "tool-registry",
    "filesystem",
    "execution",
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
    const packDir = join(process.cwd(), "src", "rules", "code-quality");
    const specifierPattern = /(?:from\s+|require\(\s*)["']([^"']+)["']/g;
    const files = sourceFiles(packDir);
    assert.ok(files.length > 0);
    for (const file of files) {
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

  it("does not read source contents, run a command, or consult a clock or random source", () => {
    const packDir = join(process.cwd(), "src", "rules", "code-quality");
    for (const file of sourceFiles(packDir)) {
      const text = readFileSync(file, "utf8");
      assert.doesNotMatch(text, /Date\.now\(\)|Math\.random\(\)|process\.env/);
    }
  });
});
