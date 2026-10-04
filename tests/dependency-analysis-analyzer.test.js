/**
 * Code Guardian — Dependency Analysis Analyzer Tests (official roadmap Phase 15)
 *
 * The end-to-end proof that the Dependency Analysis Analyzer works through the real pipeline:
 *
 *   Repository → Scanner(facts) → RepositoryModel → DependencyAnalyzer → dependency rules
 *              → evidence → findings
 *
 * Fixtures A–M from the Phase 15 handoff live here as real repositories written to a temporary
 * directory and scanned through the accepted scanner/model boundary. The suite's central claims
 * are the roadmap's exit criteria: all eight domains are analyzed, findings cite model evidence,
 * external intelligence is versioned and never invented, an incomplete acquisition turns absence
 * into `unknown` rather than clean, and the pack imports no filesystem, process, network or MCP
 * module.
 *
 * Run with: node --test tests/dependency-analysis-analyzer.test.js
 */

import { after, describe, it } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

import { scanRepository } from "../src/repository/scanner/index.js";
import { buildRepositoryModel } from "../src/repository/model/index.js";

import {
  buildAnalysisContext,
  createAnalyzerEngine,
  createAnalyzerRegistry,
  stableAnalysisView,
} from "../src/analysis/index.js";

import {
  DEPENDENCY_ANALYSIS_ANALYZER_ID,
  DEPENDENCY_ANALYSIS_RULE_IDS,
  DEPENDENCY_ANALYSIS_STATES,
  createDependencyAnalysisAnalyzer,
  createDependencyAnalysisRuleRegistry,
  createRuleEngine,
  dependencyAnalysisRules,
} from "../src/rules/index.js";

// ─── Harness ─────────────────────────────────────────────────────────────────

const TMP_ROOT = join(tmpdir(), `cg-dependency-analysis-${process.pid}-${Date.now()}`);
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

const contextOf = (model, intelligence) =>
  buildAnalysisContext({
    repository: model,
    options: intelligence === undefined ? {} : { dependencyIntelligence: intelligence },
  });

async function runAnalyzer(model, intelligence) {
  const engine = createAnalyzerEngine({
    registry: createAnalyzerRegistry([createDependencyAnalysisAnalyzer()]),
  });
  return engine.runAll(contextOf(model, intelligence));
}

async function runRules(model, intelligence) {
  const engine = createRuleEngine({
    registry: createDependencyAnalysisRuleRegistry({ rules: dependencyAnalysisRules }),
  });
  return engine.runAll(contextOf(model, intelligence));
}

const summaryOf = (result) =>
  result.analyzers.find((entry) => entry.analyzer.id === DEPENDENCY_ANALYSIS_ANALYZER_ID).metadata
    .dependencySummary;
const statusOf = (run, ruleId) => run.rules.find((entry) => entry.rule.id === ruleId)?.status;
const findingsOf = (result, ruleId) => result.findings.filter((finding) => finding.ruleId === ruleId);

// ─── Lockfile builders ───────────────────────────────────────────────────────

function npmLock(packages) {
  return `${JSON.stringify({ name: "demo", version: "1.0.0", lockfileVersion: 3, packages }, null, 2)}\n`;
}

const LOCK_1 = npmLock({
  "": { name: "demo", version: "1.0.0", dependencies: { lodash: "^1.0.0" } },
  "node_modules/lodash": { version: "1.0.0" },
});

const PACKAGE_JSON_LODASH = `${JSON.stringify({ name: "demo", version: "1.0.0", dependencies: { lodash: "^1.0.0" } })}\n`;

// ─── External intelligence builders ──────────────────────────────────────────

function intelligence({ revision = "2026-10-01T00:00:00Z", advisories = [], releases = [] } = {}) {
  return { sources: [{ id: "test-feed", revision, kind: "test" }], advisories, releases };
}

const LODASH_ADVISORY = {
  id: "CVE-2020-0001",
  sourceId: "test-feed",
  ecosystem: "node",
  package: "lodash",
  affectedRange: "<2.0.0",
  severity: "high",
};
const LODASH_RELEASE = { sourceId: "test-feed", ecosystem: "node", package: "lodash", latest: "4.17.21" };

const LODASH_FILES = { "package.json": PACKAGE_JSON_LODASH, "package-lock.json": LOCK_1, "src/a.js": "export const a = 1;\n" };

// ─── Fixtures per the handoff ────────────────────────────────────────────────

// A — current dependency.
const FIXTURE_A = LODASH_FILES;
const INTEL_A = intelligence({ releases: [{ ...LODASH_RELEASE, latest: "1.0.0" }] });
// B — outdated dependency.
const FIXTURE_B = LODASH_FILES;
const INTEL_B = intelligence({ releases: [LODASH_RELEASE] });
// C — known vulnerability.
const FIXTURE_C = LODASH_FILES;
const INTEL_C = intelligence({ advisories: [LODASH_ADVISORY], releases: [] });
// D — vulnerability unknown (no dataset).
const FIXTURE_D = LODASH_FILES;
// E — unused dependency.
const FIXTURE_E = {
  "package.json": `${JSON.stringify({ name: "demo", version: "1.0.0", dependencies: { "unused-pkg": "^1.0.0" } })}\n`,
  "src/a.js": "export const a = 1;\n",
};
// F — incomplete usage coverage (a TSX-only repository: the import graph is unsupported).
const FIXTURE_F = {
  "package.json": `${JSON.stringify({ name: "demo", version: "1.0.0", dependencies: { x: "^1.0.0" } })}\n`,
  "src/a.tsx": "export const A = () => null;\n",
};
// G — duplicate resolved versions (two lockfiles disagree).
const FIXTURE_G = {
  "packages/a/package.json": `${JSON.stringify({ name: "a", version: "1.0.0", dependencies: { lodash: "^1.0.0" } })}\n`,
  "packages/a/package-lock.json": npmLock({
    "": { name: "a", version: "1.0.0", dependencies: { lodash: "^1.0.0" } },
    "node_modules/lodash": { version: "1.0.0" },
  }),
  "packages/b/package.json": `${JSON.stringify({ name: "b", version: "1.0.0", dependencies: { lodash: "^2.0.0" } })}\n`,
  "packages/b/package-lock.json": npmLock({
    "": { name: "b", version: "1.0.0", dependencies: { lodash: "^2.0.0" } },
    "node_modules/lodash": { version: "2.0.0" },
  }),
};
// H — concentrated dependency graph.
function concentrationFiles(count) {
  const rootDeps = Object.fromEntries(Array.from({ length: count }, (_, i) => [`p${i}`, "^1.0.0"]));
  const packages = { "": { name: "demo", version: "1.0.0", dependencies: rootDeps }, "node_modules/dep": { version: "1.0.0" } };
  for (let i = 0; i < count; i += 1) {
    packages[`node_modules/p${i}`] = { version: "1.0.0", dependencies: { dep: "^1.0.0" } };
  }
  return {
    "package.json": `${JSON.stringify({ name: "demo", version: "1.0.0", dependencies: rootDeps })}\n`,
    "package-lock.json": npmLock(packages),
  };
}
const FIXTURE_H = concentrationFiles(10);
// I — lockfile inconsistency (declared dependency has no resolution).
const FIXTURE_I = {
  "package.json": `${JSON.stringify({ name: "demo", version: "1.0.0", dependencies: { "left-pad": "^1.0.0" } })}\n`,
  "package-lock.json": LOCK_1,
};
// J — package-manager inconsistency.
const FIXTURE_J = {
  ...LODASH_FILES,
  "yarn.lock": "# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.\n",
};
// K — supply-chain indicator.
const FIXTURE_K = {
  "package.json": `${JSON.stringify({
    name: "demo",
    version: "1.0.0",
    dependencies: { evil: "git+https://github.com/x/y.git", aliasdep: "npm:other@^1.0.0" },
  })}\n`,
  "src/a.js": "export const a = 1;\n",
};
// L — clean dependency repository.
const FIXTURE_L = {
  "package.json": PACKAGE_JSON_LODASH,
  "package-lock.json": LOCK_1,
  "src/a.js": "import 'lodash';\nexport const a = 1;\n",
};
const INTEL_L = intelligence({ releases: [{ ...LODASH_RELEASE, latest: "1.0.0" }] });
// M — deterministic repeat.
const FIXTURE_M = { ...LODASH_FILES, "extra.js": "export const e = 1;\n" };

// ─── Analyzer contract ───────────────────────────────────────────────────────

describe("dependency analysis analyzer: contract", () => {
  it("is an ordinary Analyzer the shared registry runs", async () => {
    const analyzer = createDependencyAnalysisAnalyzer();
    assert.equal(analyzer.id, DEPENDENCY_ANALYSIS_ANALYZER_ID);
    assert.equal(analyzer.scope, "dependency-analysis");

    const { model } = await scanModel(FIXTURE_A);
    const result = await runAnalyzer(model, INTEL_A);
    assert.equal(result.analyzers.length, 1);
    assert.ok(summaryOf(result) !== undefined);
  });

  it("covers every one of the eight official domains with one rule id each", () => {
    const ids = Object.values(DEPENDENCY_ANALYSIS_RULE_IDS).sort();
    assert.equal(ids.length, 8);
    assert.deepEqual(architectureIds(), ids);

    function architectureIds() {
      return dependencyAnalysisRules.map((rule) => rule.id).sort();
    }
  });
});

// ─── Golden fixtures A–M ─────────────────────────────────────────────────────

describe("dependency analysis analyzer: golden fixtures", () => {
  it("A: a current dependency produces no outdated finding", async () => {
    const { model } = await scanModel(FIXTURE_A);
    const result = await runAnalyzer(model, INTEL_A);
    assert.equal(findingsOf(result, DEPENDENCY_ANALYSIS_RULE_IDS.OUTDATED).length, 0);
    assert.equal(summaryOf(result).outdated.state, DEPENDENCY_ANALYSIS_STATES.ESTABLISHED);
  });

  it("B: an outdated dependency is reported with its version instance and the newer release", async () => {
    const { model } = await scanModel(FIXTURE_B);
    const result = await runAnalyzer(model, INTEL_B);
    const outdated = findingsOf(result, DEPENDENCY_ANALYSIS_RULE_IDS.OUTDATED);
    assert.equal(outdated.length, 1);
    assert.equal(outdated[0].metadata.package, "lodash");
    assert.equal(outdated[0].metadata.current, "1.0.0");
    assert.equal(outdated[0].metadata.latest, "4.17.21");
    assert.equal(outdated[0].metadata.instanceBasis, "lockfile-resolution");
  });

  it("C: a known vulnerability is reported with its advisory and source revision", async () => {
    const { model } = await scanModel(FIXTURE_C);
    const result = await runAnalyzer(model, INTEL_C);
    const vulnerabilities = findingsOf(result, DEPENDENCY_ANALYSIS_RULE_IDS.VULNERABILITY);
    assert.equal(vulnerabilities.length, 1);
    assert.equal(vulnerabilities[0].severity, "high");
    assert.equal(vulnerabilities[0].metadata.advisoryId, "CVE-2020-0001");
    assert.equal(vulnerabilities[0].metadata.affectedRange, "<2.0.0");
    assert.equal(vulnerabilities[0].metadata.sourceRevision, "2026-10-01T00:00:00Z");
  });

  it("D: vulnerability is `unknown`, never clean, when no advisory dataset exists", async () => {
    const { model } = await scanModel(FIXTURE_D);
    const run = await runRules(model);
    assert.equal(statusOf(run, DEPENDENCY_ANALYSIS_RULE_IDS.VULNERABILITY), "unknown");
    assert.equal(statusOf(run, DEPENDENCY_ANALYSIS_RULE_IDS.OUTDATED), "unknown");
    const summary = summaryOf(await runAnalyzer(model));
    assert.equal(summary.vulnerabilities.state, DEPENDENCY_ANALYSIS_STATES.UNKNOWN);
    assert.equal(summary.vulnerabilities.dataState, "absent");
  });

  it("E: an unused dependency is reported as an indicator", async () => {
    const { model } = await scanModel(FIXTURE_E);
    const result = await runAnalyzer(model);
    const unused = findingsOf(result, DEPENDENCY_ANALYSIS_RULE_IDS.UNUSED);
    assert.equal(unused.length, 1);
    assert.equal(unused[0].metadata.package, "unused-pkg");
    assert.match(unused[0].description, /indicator/i);
  });

  it("F: incomplete usage coverage is `unknown`, not an unused finding", async () => {
    const { model } = await scanModel(FIXTURE_F);
    const run = await runRules(model);
    assert.equal(statusOf(run, DEPENDENCY_ANALYSIS_RULE_IDS.UNUSED), "unknown");
    assert.equal(findingsOf(await runAnalyzer(model), DEPENDENCY_ANALYSIS_RULE_IDS.UNUSED).length, 0);
  });

  it("G: duplicate resolved versions are reported from lockfile resolutions", async () => {
    const { model } = await scanModel(FIXTURE_G);
    const result = await runAnalyzer(model);
    const duplicates = findingsOf(result, DEPENDENCY_ANALYSIS_RULE_IDS.DUPLICATE_VERSIONS);
    assert.equal(duplicates.length, 1);
    assert.deepEqual(duplicates[0].metadata.versions, ["1.0.0", "2.0.0"]);
  });

  it("H: a concentrated dependency graph is reported as a measurement", async () => {
    const { model } = await scanModel(FIXTURE_H);
    const result = await runAnalyzer(model);
    const concentration = findingsOf(result, DEPENDENCY_ANALYSIS_RULE_IDS.CONCENTRATION);
    assert.equal(concentration.length, 1);
    assert.equal(concentration[0].metadata.package, "dep");
    assert.equal(concentration[0].metadata.dependents, 10);
    assert.match(concentration[0].description, /measured/i);
  });

  it("I: a declared dependency with no resolution is a lockfile-integrity finding", async () => {
    const { model } = await scanModel(FIXTURE_I);
    const result = await runAnalyzer(model);
    const integrity = findingsOf(result, DEPENDENCY_ANALYSIS_RULE_IDS.LOCKFILE_INTEGRITY);
    assert.equal(integrity.length, 1);
    assert.equal(integrity[0].metadata.condition, "declaration-unresolved");
  });

  it("J: competing package managers for one ecosystem are reported", async () => {
    const { model } = await scanModel(FIXTURE_J);
    const result = await runAnalyzer(model);
    const manager = findingsOf(result, DEPENDENCY_ANALYSIS_RULE_IDS.MANAGER_CONSISTENCY);
    assert.equal(manager.length, 1);
    assert.equal(manager[0].metadata.ecosystem, "node");
    assert.deepEqual(manager[0].metadata.managers, ["npm", "yarn"]);
  });

  it("K: out-of-registry dependency sources are supply-chain indicators", async () => {
    const { model } = await scanModel(FIXTURE_K);
    const result = await runAnalyzer(model);
    const supplyChain = findingsOf(result, DEPENDENCY_ANALYSIS_RULE_IDS.SUPPLY_CHAIN);
    assert.deepEqual(supplyChain.map((finding) => finding.metadata.specKind).sort(), ["alias", "git"]);
    for (const finding of supplyChain) assert.match(finding.description, /indicator/i);
  });

  it("L: a complete, current, fully-used repository is clean", async () => {
    const { model } = await scanModel(FIXTURE_L);
    const result = await runAnalyzer(model, INTEL_L);
    assert.equal(result.findings.length, 0);
    const summary = summaryOf(result);
    assert.equal(summary.outdated.state, DEPENDENCY_ANALYSIS_STATES.ESTABLISHED);
    assert.equal(summary.vulnerabilities.state, DEPENDENCY_ANALYSIS_STATES.ESTABLISHED);
    assert.equal(summary.unused.state, DEPENDENCY_ANALYSIS_STATES.ESTABLISHED);
    assert.equal(summary.supplyChain.state, DEPENDENCY_ANALYSIS_STATES.ESTABLISHED);
  });

  it("M: the same model and dataset twice give identical findings and fingerprints", async () => {
    const { model } = await scanModel(FIXTURE_M);
    const first = await runAnalyzer(model, intelligence({ advisories: [LODASH_ADVISORY], releases: [LODASH_RELEASE] }));
    const second = await runAnalyzer(model, intelligence({ advisories: [LODASH_ADVISORY], releases: [LODASH_RELEASE] }));
    assert.deepEqual(
      first.findings.map((finding) => finding.fingerprint),
      second.findings.map((finding) => finding.fingerprint),
    );
    assert.deepEqual(stableAnalysisView(first), stableAnalysisView(second));
    assert.deepEqual(summaryOf(first), summaryOf(second));
  });
});

// ─── Time-versioned vulnerability data ───────────────────────────────────────

describe("dependency analysis analyzer: versioned advisory provenance", () => {
  it("distinguishes which advisory source revision produced a finding", async () => {
    const { model } = await scanModel(FIXTURE_C);

    const first = await runAnalyzer(
      model,
      intelligence({ revision: "revision-A", advisories: [LODASH_ADVISORY], releases: [] }),
    );
    const second = await runAnalyzer(
      model,
      intelligence({
        revision: "revision-B",
        advisories: [
          LODASH_ADVISORY,
          { ...LODASH_ADVISORY, id: "CVE-2021-0002", affectedRange: "<3.0.0" },
        ],
        releases: [],
      }),
    );

    const firstFinding = findingsOf(first, DEPENDENCY_ANALYSIS_RULE_IDS.VULNERABILITY)[0];
    const secondFindings = findingsOf(second, DEPENDENCY_ANALYSIS_RULE_IDS.VULNERABILITY);
    assert.equal(firstFinding.metadata.sourceRevision, "revision-A");
    assert.equal(secondFindings.length, 2);
    assert.ok(secondFindings.every((finding) => finding.metadata.sourceRevision === "revision-B"));
    // The same model with a newer dataset yields a strictly richer result — the source revision
    // is part of every finding, so the difference is attributable.
    assert.notDeepEqual(
      firstFindingsKeys(first),
      firstFindingsKeys(second),
    );

    function firstFindingsKeys(result) {
      return findingsOf(result, DEPENDENCY_ANALYSIS_RULE_IDS.VULNERABILITY)
        .map((finding) => finding.metadata.advisoryId)
        .sort();
    }
  });
});

// ─── Negative fixtures ───────────────────────────────────────────────────────

describe("dependency analysis analyzer: negative fixtures", () => {
  it("does not infer a problem from a package name in documentation or a comment", async () => {
    const { model } = await scanModel({
      "package.json": `${JSON.stringify({ name: "demo", version: "1.0.0" })}\n`,
      "README.md": "`lodash` is vulnerable according to CVE-2020-0001\n",
      "src/a.js": "// lodash is vulnerable\nexport const a = 1;\n",
    });
    const result = await runAnalyzer(
      model,
      intelligence({ advisories: [LODASH_ADVISORY], releases: [LODASH_RELEASE] }),
    );
    assert.equal(findingsOf(result, DEPENDENCY_ANALYSIS_RULE_IDS.VULNERABILITY).length, 0);
    assert.equal(findingsOf(result, DEPENDENCY_ANALYSIS_RULE_IDS.OUTDATED).length, 0);
  });

  it("does not report an ordinary registry dependency as a supply-chain indicator", async () => {
    const { model } = await scanModel(LODASH_FILES);
    const result = await runAnalyzer(model, INTEL_L);
    assert.equal(findingsOf(result, DEPENDENCY_ANALYSIS_RULE_IDS.SUPPLY_CHAIN).length, 0);
  });

  it("does not create a finding from a directory or file name alone", async () => {
    const { model } = await scanModel({
      "package.json": `${JSON.stringify({ name: "demo", version: "1.0.0" })}\n`,
      "node_modules/vulnerable/package.json": `${JSON.stringify({ name: "vulnerable", version: "1.0.0" })}\n`,
    });
    const result = await runAnalyzer(model, intelligence({ advisories: [LODASH_ADVISORY], releases: [LODASH_RELEASE] }));
    assert.equal(result.findings.length, 0);
  });

  it("treats an unsupported ecosystem as `unknown`, not vulnerable", async () => {
    const { model } = await scanModel({
      "requirements.txt": "foo==1.0.0\n",
      "src/app.py": "def f():\n    return 1\n",
    });
    const run = await runRules(
      model,
      intelligence({
        advisories: [
          { id: "PY-1", sourceId: "test-feed", ecosystem: "python", package: "foo", affectedRange: "<2.0.0" },
        ],
        releases: [],
      }),
    );
    assert.equal(statusOf(run, DEPENDENCY_ANALYSIS_RULE_IDS.VULNERABILITY), "unknown");
    const mean = await runRules(model);
    assert.equal(statusOf(mean, DEPENDENCY_ANALYSIS_RULE_IDS.OUTDATED), "unknown");
  });

  it("treats a partial/partial lockfile as `unknown`, not clean", async () => {
    const { model } = await scanModel({
      "package.json": PACKAGE_JSON_LODASH,
      "package-lock.json": "{ not json",
      "src/a.js": "export const a = 1;\n",
    });
    const run = await runRules(model);
    assert.equal(statusOf(run, DEPENDENCY_ANALYSIS_RULE_IDS.DUPLICATE_VERSIONS), "unknown");
    assert.equal(statusOf(run, DEPENDENCY_ANALYSIS_RULE_IDS.LOCKFILE_INTEGRITY), "unknown");
  });

  it("treats an unavailable (malformed) advisory source as `unknown`, not clean", async () => {
    const { model } = await scanModel(FIXTURE_C);
    const invalid = { sources: [{ id: "feed" }], advisories: [LODASH_ADVISORY], releases: [] };
    const run = await runRules(model, invalid);
    assert.equal(statusOf(run, DEPENDENCY_ANALYSIS_RULE_IDS.VULNERABILITY), "unknown");
    assert.equal(findingsOf(await runAnalyzer(model, invalid), DEPENDENCY_ANALYSIS_RULE_IDS.VULNERABILITY).length, 0);
    assert.equal(summaryOf(await runAnalyzer(model, invalid)).vulnerabilities.dataState, "invalid");
  });
});

// ─── Evidence and fingerprints ───────────────────────────────────────────────

describe("dependency analysis analyzer: evidence", () => {
  it("cites only model evidence, and every cited id resolves", async () => {
    const { model } = await scanModel({ ...FIXTURE_C, ...FIXTURE_G, ...FIXTURE_K, ...FIXTURE_J });
    const result = await runAnalyzer(model, intelligence({ advisories: [LODASH_ADVISORY], releases: [LODASH_RELEASE] }));
    assert.ok(result.findings.length > 0);
    const evidenceById = model.indexes.evidenceById;
    for (const finding of result.findings) {
      assert.ok(Array.isArray(finding.evidence) && finding.evidence.length > 0, finding.ruleId);
      for (const id of finding.evidence) {
        assert.ok(evidenceById[id] !== undefined, `${finding.ruleId} cites ${id}`);
      }
    }
  });

  it("gives every finding a distinct canonical fingerprint", async () => {
    const { model } = await scanModel(FIXTURE_H);
    const result = await runAnalyzer(model);
    assert.equal(new Set(result.findings.map((finding) => finding.fingerprint)).size, result.findings.length);
    for (const finding of result.findings) assert.match(finding.fingerprint, /^cg-fp1-[0-9a-f]{32}$/);
  });
});

// ─── Performance measurement ─────────────────────────────────────────────────

describe("dependency analysis analyzer: performance", () => {
  it("analyzes a representative dependency set within a sane budget", async () => {
    const count = 200;
    const rootDeps = Object.fromEntries(Array.from({ length: count }, (_, i) => [`p${i}`, "^1.0.0"]));
    const packages = { "": { name: "demo", version: "1.0.0", dependencies: rootDeps }, "node_modules/dep": { version: "1.0.0" } };
    for (let i = 0; i < count; i += 1) packages[`node_modules/p${i}`] = { version: "1.0.0", dependencies: { dep: "^1.0.0" } };

    const { model } = await scanModel({
      "package.json": `${JSON.stringify({ name: "demo", version: "1.0.0", dependencies: rootDeps })}\n`,
      "package-lock.json": npmLock(packages),
      "src/a.js": "import 'dep';\nexport const a = 1;\n",
    });

    const releases = Array.from({ length: count }, (_, i) => ({
      sourceId: "test-feed",
      ecosystem: "node",
      package: `p${i}`,
      latest: "1.0.0",
    }));
    const dataset = intelligence({ releases: [...releases, { ...LODASH_RELEASE, package: "dep", latest: "1.0.0" }] });

    const start = process.hrtime.bigint();
    const first = await runAnalyzer(model, dataset);
    const second = await runAnalyzer(model, dataset);
    const elapsedMs = Number(process.hrtime.bigint() - start) / 1e6;

    assert.ok(elapsedMs < 8000, `analyzer took ${elapsedMs.toFixed(1)}ms`);
    assert.deepEqual(
      first.findings.map((finding) => finding.fingerprint),
      second.findings.map((finding) => finding.fingerprint),
    );
    // eslint-disable-next-line no-console
    console.log(`[phase-15] two analyzer passes over ${count} packages: ${elapsedMs.toFixed(1)}ms`);
  });
});

// ─── Architectural boundary ──────────────────────────────────────────────────

describe("dependency analysis analyzer: boundaries", () => {
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
    const packDir = join(process.cwd(), "src", "rules", "dependency-analysis");
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

  it("performs no network access and consults no clock or random source", () => {
    const packDir = join(process.cwd(), "src", "rules", "dependency-analysis");
    for (const file of sourceFiles(packDir)) {
      const text = readFileSync(file, "utf8");
      assert.doesNotMatch(text, /Date\.now\(\)|Math\.random\(\)|process\.env/);
      assert.doesNotMatch(text, /\bfetch\s*\(/);
    }
  });
});
