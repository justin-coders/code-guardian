/**
 * Code Guardian — Architecture Analysis Analyzer Tests (official roadmap Phase 14)
 *
 * The end-to-end proof that the Architecture Analysis Analyzer works through the real pipeline:
 *
 *   Repository → Scanner(facts) → RepositoryModel → ArchitectureAnalyzer → architecture rules
 *              → evidence → findings
 *
 * Fixtures A–L from the Phase 14 handoff live here as real repositories written to a temporary
 * directory and scanned through the accepted scanner/model boundary. The suite's central claims
 * are the roadmap's exit criteria: all nine domains are analyzed, findings are evidence-driven,
 * an incomplete graph turns absence into `unknown` rather than clean, no universal architecture
 * is imposed, fingerprints are stable and unique, and the pack imports no filesystem, process,
 * network or MCP module.
 *
 * Run with: node --test tests/architecture-analyzer.test.js
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
  ARCHITECTURE_ANALYSIS_ANALYZER_ID,
  ARCHITECTURE_ANALYSIS_RULE_IDS,
  ARCHITECTURE_ANALYSIS_STATES,
  architectureAnalysisRules,
  createArchitectureAnalysisAnalyzer,
  createArchitectureAnalysisRuleRegistry,
  createRuleEngine,
  createRuleRegistry,
} from "../src/rules/index.js";

// ─── Fixtures ────────────────────────────────────────────────────────────────

const TMP_ROOT = join(tmpdir(), `cg-architecture-analysis-${process.pid}-${Date.now()}`);
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

const contextOf = (model) => buildAnalysisContext({ repository: model });

async function runAnalyzer(model) {
  const engine = createAnalyzerEngine({
    registry: createAnalyzerRegistry([createArchitectureAnalysisAnalyzer()]),
  });
  return engine.runAll(contextOf(model));
}

async function runRules(model) {
  const engine = createRuleEngine({
    registry: createArchitectureAnalysisRuleRegistry({ rules: architectureAnalysisRules }),
  });
  return engine.runAll(contextOf(model));
}

const summaryOf = (result) =>
  result.analyzers.find((entry) => entry.analyzer.id === ARCHITECTURE_ANALYSIS_ANALYZER_ID).metadata
    .architectureSummary;
const statusOf = (run, ruleId) => run.rules.find((entry) => entry.rule.id === ruleId)?.status;
const findingsOf = (result, ruleId) =>
  result.findings.filter((finding) => finding.ruleId === ruleId);

const pkg = (extra = {}) => `${JSON.stringify({ name: "demo", version: "1.0.0", ...extra })}\n`;

// Fixture A — clean modular structure, A → B → C.
const FIXTURE_A = {
  "src/a/a.js": "import { b } from '../b/b.js';\nexport const a = b;\n",
  "src/b/b.js": "import { c } from '../c/c.js';\nexport const b = c;\n",
  "src/c/c.js": "export const c = 1;\n",
};
// Fixture B — direct cycle, A ↔ B.
const FIXTURE_B = {
  "src/a/a.js": "import '../b/b.js';\nexport const a = 1;\n",
  "src/b/b.js": "import '../a/a.js';\nexport const b = 1;\n",
};
// Fixture C — longer cycle, A → B → C → A.
const FIXTURE_C = {
  "src/a/a.js": "import '../b/b.js';\nexport const a = 1;\n",
  "src/b/b.js": "import '../c/c.js';\nexport const b = 1;\n",
  "src/c/c.js": "import '../a/a.js';\nexport const c = 1;\n",
};
// Fixture D — declared direction (a declares a workspace dependency on b) with a real reverse
// import (b's code imports a's code).
const FIXTURE_D = {
  "package.json": `${JSON.stringify({ name: "root", private: true, workspaces: ["packages/*"] })}\n`,
  "packages/a/package.json": `${JSON.stringify({ name: "a", dependencies: { b: "workspace:*" } })}\n`,
  "packages/b/package.json": `${JSON.stringify({ name: "b" })}\n`,
  "packages/a/src/a.js": "export const a = 1;\n",
  "packages/b/src/b.js": "import '../../a/src/a.js';\nexport const b = 1;\n",
};
// Fixture E — coupling: a hub module depending on ten distinct modules.
const FIXTURE_E = {
  "src/hub/hub.js": `${Array.from({ length: 10 }, (_, index) => `import '../m${index}/x.js';`).join("\n")}\nexport const hub = 1;\n`,
  ...Object.fromEntries(
    Array.from({ length: 10 }, (_, index) => [`src/m${index}/x.js`, "export const x = 1;\n"]),
  ),
};
// Fixture F — large module: twenty module sources in one directory.
const FIXTURE_F = Object.fromEntries(
  Array.from({ length: 20 }, (_, index) => [
    `src/big/f${String(index).padStart(2, "0")}.js`,
    "export const v = 0;\n",
  ]),
);
// Fixture G — boundary leakage: lib publishes index.js, app imports index.js and internal.js.
const FIXTURE_G = {
  "src/lib/index.js": "export { internal } from './internal.js';\n",
  "src/lib/internal.js": "export const internal = 1;\n",
  "src/app/app.js": "import '../lib/index.js';\nimport '../lib/internal.js';\nexport const app = 1;\n",
};
// Fixture H — architecture pattern: a workspace monorepo with two named packages.
const FIXTURE_H = {
  "package.json": `${JSON.stringify({ name: "root", private: true, workspaces: ["packages/*"] })}\n`,
  "packages/a/package.json": `${JSON.stringify({ name: "a" })}\n`,
  "packages/b/package.json": `${JSON.stringify({ name: "b" })}\n`,
  "packages/a/src/a.js": "export const a = 1;\n",
  "packages/b/src/b.js": "export const b = 1;\n",
};
// Fixture I — ambiguous pattern: two named packages, but no `workspaces` declaration.
const FIXTURE_I = {
  "package.json": pkg(),
  "packages/a/package.json": `${JSON.stringify({ name: "a" })}\n`,
  "packages/b/package.json": `${JSON.stringify({ name: "b" })}\n`,
  "packages/a/src/a.js": "export const a = 1;\n",
  "packages/b/src/b.js": "export const b = 1;\n",
};
// Fixture J — incomplete graph: more files than the scan budget, so the scan truncates.
const FIXTURE_J = {
  "src/a/a.js": "import '../b/b.js';\nexport const a = 1;\n",
  "src/b/b.js": "export const b = 1;\n",
  "src/c/c.js": "export const c = 1;\n",
  "src/d/d.js": "export const d = 1;\n",
  "src/e/e.js": "export const e = 1;\n",
};
// Fixture K — unsupported language: only Python source, which this build does not interpret.
const FIXTURE_K = {
  "src/app.py": "import os\n\ndef f():\n    return 1\n",
  "src/lib.py": "def g():\n    return 2\n",
};
// Fixture L — deterministic repeat.
const FIXTURE_L = { ...FIXTURE_B, ...FIXTURE_G, "package.json": pkg() };
// Negative — directory names alone establish nothing.
const FIXTURE_NAMES = {
  "src/controllers/home.js": "export const home = 1;\n",
  "src/services/user.js": "export const user = 1;\n",
  "src/repositories/db.js": "export const db = 1;\n",
};
// Negative — vocabulary in comments, docs and string literals is not structure.
const FIXTURE_VOCABULARY = {
  "src/a/a.js": "// import '../b/b.js'\nconst note = \"import '../b/b.js'\";\nexport const a = note;\n",
  "docs/example.md": "```js\nimport x from '../b/b.js';\n```\n",
};
// Negative — a registry dependency is not a declared local-package direction.
const FIXTURE_REGISTRY_DEPS = {
  "package.json": pkg({ dependencies: { express: "^4.0.0" } }),
  "src/a/a.js": "export const a = 1;\n",
  "src/b/b.js": "export const b = 1;\n",
};

// ─── Analyzer contract ──────────────────────────────────────────────────────

describe("architecture analysis analyzer: contract", () => {
  it("is an ordinary Analyzer the shared registry runs beside another domain analyzer", async () => {
    const analyzer = createArchitectureAnalysisAnalyzer();
    assert.equal(analyzer.id, ARCHITECTURE_ANALYSIS_ANALYZER_ID);
    assert.equal(analyzer.scope, "architecture-analysis");

    const { model } = await scanModel(FIXTURE_A);
    const engine = createAnalyzerEngine({
      registry: createAnalyzerRegistry([analyzer]),
    });
    const result = await engine.runAll(contextOf(model));
    assert.equal(result.analyzers.length, 1);
    assert.ok(summaryOf(result) !== undefined);
  });

  it("keeps one shared registry mechanism: the pack's rules evaluate through the Rule Engine", async () => {
    const { model } = await scanModel(FIXTURE_A);
    const run = await runRules(model);
    assert.equal(run.rules.length, architectureAnalysisRules.length);
  });

  it("covers every one of the nine official domains with one rule id each", () => {
    const ids = Object.values(ARCHITECTURE_ANALYSIS_RULE_IDS).sort();
    assert.equal(ids.length, 9);
    const shipped = architectureAnalysisRules.map((rule) => rule.id).sort();
    assert.deepEqual(shipped, ids);
  });
});

// ─── Golden fixtures ────────────────────────────────────────────────────────

describe("architecture analysis analyzer: golden fixtures", () => {
  it("A: a clean modular structure reports its modules and directions, and no cycle", async () => {
    const { model } = await scanModel(FIXTURE_A);
    const result = await runAnalyzer(model);
    const summary = summaryOf(result);

    assert.deepEqual(summary.moduleBoundaries.modules, ["src/a", "src/b", "src/c"]);
    assert.equal(summary.moduleBoundaries.state, ARCHITECTURE_ANALYSIS_STATES.ESTABLISHED);
    assert.equal(summary.dependencyDirection.count, 2);
    assert.equal(summary.circularDependencies.count, 0);
    assert.equal(summary.circularDependencies.state, ARCHITECTURE_ANALYSIS_STATES.NOT_APPLICABLE);
    assert.equal(findingsOf(result, ARCHITECTURE_ANALYSIS_RULE_IDS.DEPENDENCY_CYCLE).length, 0);
  });

  it("B: a direct cycle is reported from the actual graph cycle", async () => {
    const { model } = await scanModel(FIXTURE_B);
    const result = await runAnalyzer(model);
    const cycles = findingsOf(result, ARCHITECTURE_ANALYSIS_RULE_IDS.DEPENDENCY_CYCLE);
    assert.equal(cycles.length, 1);
    assert.equal(cycles[0].severity, "medium");
    assert.deepEqual(cycles[0].metadata.modules, ["src/a", "src/b"]);
    assert.equal(summaryOf(result).circularDependencies.count, 1);
  });

  it("C: a longer cycle is reported with all participating modules", async () => {
    const { model } = await scanModel(FIXTURE_C);
    const result = await runAnalyzer(model);
    const cycles = findingsOf(result, ARCHITECTURE_ANALYSIS_RULE_IDS.DEPENDENCY_CYCLE);
    assert.equal(cycles.length, 1);
    assert.deepEqual(cycles[0].metadata.modules, ["src/a", "src/b", "src/c"]);
  });

  it("D: a reverse import against a declared direction is a layer violation", async () => {
    const { model } = await scanModel(FIXTURE_D);
    const result = await runAnalyzer(model);
    const violations = findingsOf(result, ARCHITECTURE_ANALYSIS_RULE_IDS.LAYER_VIOLATION);
    assert.equal(violations.length, 1);
    assert.equal(violations[0].metadata.dependencyName, "b");
    assert.equal(violations[0].metadata.specKind, "workspace");
    assert.equal(summaryOf(result).layerViolations.count, 1);
  });

  it("E: a module depending on many modules is reported with measured counts", async () => {
    const { model } = await scanModel(FIXTURE_E);
    const result = await runAnalyzer(model);
    const coupling = findingsOf(result, ARCHITECTURE_ANALYSIS_RULE_IDS.COUPLING_MEASURED);
    assert.equal(coupling.length, 1);
    assert.equal(coupling[0].metadata.module, "src/hub");
    assert.equal(coupling[0].metadata.outgoingModules, 10);
    assert.match(coupling[0].description, /measured relationship/i);
  });

  it("F: a module crossing the documented size threshold is reported", async () => {
    const { model } = await scanModel(FIXTURE_F);
    const result = await runAnalyzer(model);
    const large = findingsOf(result, ARCHITECTURE_ANALYSIS_RULE_IDS.MODULE_LARGE);
    assert.equal(large.length, 1);
    assert.equal(large[0].metadata.module, "src/big");
    assert.equal(large[0].metadata.files, 20);
    assert.equal(large[0].metadata.fileThreshold, 20);
  });

  it("G: an import past a published entry file is boundary leakage", async () => {
    const { model } = await scanModel(FIXTURE_G);
    const result = await runAnalyzer(model);
    const leaks = findingsOf(result, ARCHITECTURE_ANALYSIS_RULE_IDS.BOUNDARY_LEAKAGE);
    assert.equal(leaks.length, 1);
    assert.equal(leaks[0].metadata.to, "src/lib");
    assert.deepEqual(leaks[0].metadata.leakedFiles, ["src/lib/internal.js"]);
    assert.deepEqual(leaks[0].metadata.entryFiles, ["src/lib/index.js"]);
  });

  it("H: a workspace monorepo is established from multiple independent facts", async () => {
    const { model } = await scanModel(FIXTURE_H);
    const result = await runAnalyzer(model);
    const patterns = findingsOf(result, ARCHITECTURE_ANALYSIS_RULE_IDS.PATTERN_ESTABLISHED);
    assert.equal(patterns.length, 1);
    assert.equal(patterns[0].metadata.pattern, "workspace-monorepo");
    assert.equal(patterns[0].evidence.length > 0, true);
  });

  it("I: an ambiguous pattern produces no confident pattern finding", async () => {
    const { model } = await scanModel(FIXTURE_I);
    const result = await runAnalyzer(model);
    assert.equal(findingsOf(result, ARCHITECTURE_ANALYSIS_RULE_IDS.PATTERN_ESTABLISHED).length, 0);
    const state = summaryOf(result).architecturePatterns.state;
    assert.notEqual(state, ARCHITECTURE_ANALYSIS_STATES.ESTABLISHED);
  });

  it("J: an incomplete graph is never a clean architecture result", async () => {
    const { model } = await scanModel(FIXTURE_J, { maxFiles: 3 });
    const run = await runRules(model);
    // No cycle was observed, but the import graph is incomplete, so the rule abstains.
    assert.equal(statusOf(run, ARCHITECTURE_ANALYSIS_RULE_IDS.DEPENDENCY_CYCLE), "unknown");
    assert.equal(summaryOf(await runAnalyzer(model)).circularDependencies.state, ARCHITECTURE_ANALYSIS_STATES.UNKNOWN);
  });

  it("K: an unsupported language answers `unknown`, never a false clean", async () => {
    const { model } = await scanModel(FIXTURE_K);
    const run = await runRules(model);
    assert.equal(statusOf(run, ARCHITECTURE_ANALYSIS_RULE_IDS.DEPENDENCY_CYCLE), "unknown");
    assert.equal(statusOf(run, ARCHITECTURE_ANALYSIS_RULE_IDS.MODULE_BOUNDARY), "unknown");
    const summary = summaryOf(await runAnalyzer(model));
    assert.equal(summary.moduleBoundaries.state, ARCHITECTURE_ANALYSIS_STATES.UNKNOWN);
  });

  it("L: the same model twice gives identical findings, fingerprints and summary", async () => {
    const { model } = await scanModel(FIXTURE_L);
    const first = await runAnalyzer(model);
    const second = await runAnalyzer(model);
    assert.deepEqual(
      first.findings.map((finding) => finding.fingerprint),
      second.findings.map((finding) => finding.fingerprint),
    );
    assert.deepEqual(stableAnalysisView(first), stableAnalysisView(second));
    assert.deepEqual(summaryOf(first), summaryOf(second));
  });
});

// ─── Negative fixtures ──────────────────────────────────────────────────────

describe("architecture analysis analyzer: negative fixtures", () => {
  it("does not create architecture judgments from directory names alone", async () => {
    const { model } = await scanModel(FIXTURE_NAMES);
    const result = await runAnalyzer(model);
    const judgmentIds = [
      ARCHITECTURE_ANALYSIS_RULE_IDS.LAYER_VIOLATION,
      ARCHITECTURE_ANALYSIS_RULE_IDS.BOUNDARY_LEAKAGE,
      ARCHITECTURE_ANALYSIS_RULE_IDS.DEPENDENCY_CYCLE,
      ARCHITECTURE_ANALYSIS_RULE_IDS.PATTERN_ESTABLISHED,
      ARCHITECTURE_ANALYSIS_RULE_IDS.COUPLING_MEASURED,
    ];
    for (const id of judgmentIds) {
      assert.equal(findingsOf(result, id).length, 0, id);
    }
    const summary = summaryOf(result);
    assert.equal(summary.layerViolations.model, "not-established");
    assert.equal(summary.architecturePatterns.patterns.length, 0);
  });

  it("does not create findings from comments, docs or string literals", async () => {
    const { model } = await scanModel(FIXTURE_VOCABULARY);
    const result = await runAnalyzer(model);
    assert.equal(findingsOf(result, ARCHITECTURE_ANALYSIS_RULE_IDS.DEPENDENCY_CYCLE).length, 0);
    assert.equal(findingsOf(result, ARCHITECTURE_ANALYSIS_RULE_IDS.BOUNDARY_LEAKAGE).length, 0);
    assert.equal(findingsOf(result, ARCHITECTURE_ANALYSIS_RULE_IDS.COUPLING_MEASURED).length, 0);
  });

  it("does not treat a registry dependency as a declared local-package direction", async () => {
    const { model } = await scanModel(FIXTURE_REGISTRY_DEPS);
    const run = await runRules(model);
    assert.equal(statusOf(run, ARCHITECTURE_ANALYSIS_RULE_IDS.LAYER_VIOLATION), "unknown");
    const summary = summaryOf(await runAnalyzer(model));
    assert.equal(summary.layerViolations.model, "not-established");
    assert.equal(summary.layerViolations.count, 0);
  });
});

// ─── Applicability ──────────────────────────────────────────────────────────

describe("architecture analysis analyzer: applicability", () => {
  it("uses the shared applicability engine rather than a second selector", async () => {
    const { model } = await scanModel(FIXTURE_A);
    const rules = [
      createRule({
        id: "architecture.fixture.rust",
        version: "1.0.0",
        category: "architecture",
        title: "fixture",
        description: "fixture",
        severity: "info",
        applicability: { languages: ["rust"] },
        detect: () => [],
      }),
      createRule({
        id: "architecture.fixture.javascript",
        version: "1.0.0",
        category: "architecture",
        title: "fixture",
        description: "fixture",
        severity: "info",
        applicability: { languages: ["javascript"] },
        detect: () => [],
      }),
    ];
    const engine = createRuleEngine({ registry: createRuleRegistry(rules) });
    const run = await engine.runAll(contextOf(model));
    assert.equal(
      run.rules.find((entry) => entry.rule.id === "architecture.fixture.rust").status,
      "not-applicable",
    );
    assert.equal(
      run.rules.find((entry) => entry.rule.id === "architecture.fixture.javascript").status,
      "pass",
    );
  });
});

// ─── Evidence and fingerprints ──────────────────────────────────────────────

describe("architecture analysis analyzer: evidence", () => {
  it("cites only model evidence, and every cited id resolves", async () => {
    const { model } = await scanModel({ ...FIXTURE_B, ...FIXTURE_G, ...FIXTURE_F });
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

  it("carries the state vocabulary on every finding's metadata", async () => {
    const { model } = await scanModel({ ...FIXTURE_B, ...FIXTURE_G, ...FIXTURE_D });
    const result = await runAnalyzer(model);
    const allowed = Object.values(ARCHITECTURE_ANALYSIS_STATES);
    for (const finding of result.findings) {
      assert.ok(allowed.includes(finding.metadata.state), `${finding.ruleId}: ${finding.metadata.state}`);
    }
  });
});

describe("architecture analysis analyzer: fingerprints", () => {
  it("gives every finding from one rule a distinct canonical fingerprint", async () => {
    const { model } = await scanModel(FIXTURE_E);
    const result = await runAnalyzer(model);
    assert.equal(new Set(result.findings.map((finding) => finding.fingerprint)).size, result.findings.length);
    for (const finding of result.findings) {
      assert.match(finding.fingerprint, /^cg-fp1-[0-9a-f]{32}$/);
    }
  });
});

// ─── Performance measurement ────────────────────────────────────────────────

describe("architecture analysis analyzer: performance", () => {
  it("analyzes a bounded fixture deterministically and within a sane budget", async () => {
    const files = { "package.json": pkg() };
    for (let group = 0; group < 40; group += 1) {
      const imports = [];
      for (let index = 0; index < 5; index += 1) {
        const target = (group + index + 1) % 40;
        imports.push(`import '../m${String(target).padStart(3, "0")}/x.js';`);
      }
      files[`src/m${String(group).padStart(3, "0")}/x.js`] = `${imports.join("\n")}\nexport const v = ${group};\n`;
    }

    const { model } = await scanModel(files);

    const start = process.hrtime.bigint();
    const first = await runAnalyzer(model);
    const second = await runAnalyzer(model);
    const elapsedMs = Number(process.hrtime.bigint() - start) / 1e6;

    // Meaningful, not a benchmark: two full analyzer passes over a 40-module graph must finish
    // well inside a few seconds on the CI runners.
    assert.ok(elapsedMs < 8000, `analyzer took ${elapsedMs.toFixed(1)}ms`);
    assert.deepEqual(
      first.findings.map((finding) => finding.fingerprint),
      second.findings.map((finding) => finding.fingerprint),
    );
    // eslint-disable-next-line no-console
    console.log(`[phase-14] two analyzer passes over 40 modules: ${elapsedMs.toFixed(1)}ms`);
  });
});

// ─── Architectural boundary ─────────────────────────────────────────────────

describe("architecture analysis analyzer: boundaries", () => {
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
    const packDir = join(process.cwd(), "src", "rules", "architecture-analysis");
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
    const packDir = join(process.cwd(), "src", "rules", "architecture-analysis");
    for (const file of sourceFiles(packDir)) {
      const text = readFileSync(file, "utf8");
      assert.doesNotMatch(text, /Date\.now\(\)|Math\.random\(\)|process\.env/);
    }
  });
});
