/**
 * Code Guardian — Architecture Analysis Rule Pack Tests (official roadmap Phase 14)
 *
 * The rule-layer proof for the Architecture Analysis pack: the pack contract (namespaced ids,
 * the nine declared rules present), the registry's fail-closed behaviour, the abstention
 * (`unknown`) shapes, and the bounded-output cap. These are unit-level checks over the real
 * scanner/model pipeline, complementing the end-to-end suite in `architecture-analyzer.test.js`.
 *
 * Run with: node --test tests/architecture-rules.test.js
 */

import { after, describe, it } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

import { scanRepository } from "../src/repository/scanner/index.js";
import { buildRepositoryModel } from "../src/repository/model/index.js";

import { buildAnalysisContext } from "../src/analysis/index.js";

import {
  ARCHITECTURE_ANALYSIS_RULE_ID_PREFIX,
  ARCHITECTURE_ANALYSIS_RULE_IDS,
  ARCHITECTURE_ANALYSIS_LIMITS,
  architectureAnalysisRuleSetIssues,
  architectureAnalysisRules,
  createArchitectureAnalysisRuleRegistry,
  createRuleEngine,
} from "../src/rules/index.js";

const TMP_ROOT = join(tmpdir(), `cg-arch-rules-${process.pid}-${Date.now()}`);
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

async function scanModel(files) {
  const root = makeRepo(files);
  const scan = await scanRepository(root);
  return buildRepositoryModel(scan);
}

const contextOf = (model) => buildAnalysisContext({ repository: model });

async function runRules(model) {
  const engine = createRuleEngine({
    registry: createArchitectureAnalysisRuleRegistry({ rules: architectureAnalysisRules }),
  });
  return engine.runAll(contextOf(model));
}

after(() => {
  rmSync(TMP_ROOT, { recursive: true, force: true });
});

const entryOf = (run, ruleId) => run.rules.find((entry) => entry.rule.id === ruleId);

describe("architecture analysis rules: pack contract", () => {
  it("declares each of the nine rules in the architecture namespace", () => {
    assert.deepEqual(architectureAnalysisRuleSetIssues(architectureAnalysisRules), []);
    for (const id of Object.values(ARCHITECTURE_ANALYSIS_RULE_IDS)) {
      assert.equal(id.startsWith(ARCHITECTURE_ANALYSIS_RULE_ID_PREFIX), true, id);
    }
    assert.equal(Object.keys(ARCHITECTURE_ANALYSIS_RULE_IDS).length, 9);
  });

  it("registers exactly the shipped rules, sorted by id", () => {
    const registry = createArchitectureAnalysisRuleRegistry({ rules: architectureAnalysisRules });
    assert.equal(registry.size, 9);
    const ids = architectureAnalysisRules.map((rule) => rule.id);
    assert.deepEqual(ids, [...ids].sort());
  });

  it("rejects a rule outside the namespace, or a missing declared rule", () => {
    assert.throws(
      () =>
        createArchitectureAnalysisRuleRegistry({
          rules: [{ ...architectureAnalysisRules[0], id: "security.x" }],
        }),
      (error) => (error.details?.issues ?? []).join(" ").includes("namespace"),
    );
    assert.throws(
      () => createArchitectureAnalysisRuleRegistry({ rules: [] }),
      (error) => (error.details?.issues ?? []).join(" ").includes("missing from the pack"),
    );
  });
});

describe("architecture analysis rules: abstention", () => {
  it("answers `unknown` with a reason when the repository declares no layer model", async () => {
    const model = await scanModel({ "src/a/a.js": "export const a = 1;\n" });
    const run = await runRules(model);
    const entry = entryOf(run, ARCHITECTURE_ANALYSIS_RULE_IDS.LAYER_VIOLATION);
    assert.equal(entry.status, "unknown");
    assert.match(entry.applicability.reason, /no layer model/i);
  });

  it("answers `unknown` for an unsupported language rather than a clean pass", async () => {
    const model = await scanModel({ "src/app.py": "def f():\n    return 1\n" });
    const run = await runRules(model);
    for (const id of [
      ARCHITECTURE_ANALYSIS_RULE_IDS.MODULE_BOUNDARY,
      ARCHITECTURE_ANALYSIS_RULE_IDS.DEPENDENCY_CYCLE,
      ARCHITECTURE_ANALYSIS_RULE_IDS.COUPLING_MEASURED,
    ]) {
      assert.equal(entryOf(run, id).status, "unknown", id);
    }
    assert.equal(run.complete, false);
  });

  it("reports no subject (not `unknown`) over an established empty graph", async () => {
    const model = await scanModel({ "README.md": "# docs only\n" });
    const run = await runRules(model);
    const entry = entryOf(run, ARCHITECTURE_ANALYSIS_RULE_IDS.MODULE_BOUNDARY);
    // No module source over a complete scan: the rule genuinely has no subject.
    assert.equal(entry.status, "pass");
    assert.equal(entry.metadata.state, "not_applicable");
  });
});

describe("architecture analysis rules: bounded output", () => {
  it("caps a large module inventory and says that it did", async () => {
    const files = {};
    const total = ARCHITECTURE_ANALYSIS_LIMITS.MAX_FINDINGS + 5;
    for (let index = 0; index < total; index += 1) {
      files[`src/m${String(index).padStart(3, "0")}/x.js`] = "export const v = 0;\n";
    }
    const model = await scanModel(files);
    const run = await runRules(model);
    const entry = entryOf(run, ARCHITECTURE_ANALYSIS_RULE_IDS.MODULE_BOUNDARY);
    assert.equal(entry.findings.length, ARCHITECTURE_ANALYSIS_LIMITS.MAX_FINDINGS);
    assert.equal(entry.metadata.truncated, true);
  });
});

describe("architecture analysis rules: determinism", () => {
  it("produces the same rule outcome order and fingerprints on a repeat run", async () => {
    const model = await scanModel({
      "src/a/a.js": "import '../b/b.js';\nexport const a = 1;\n",
      "src/b/b.js": "export const b = 1;\n",
    });
    const first = await runRules(model);
    const second = await runRules(model);
    assert.deepEqual(
      first.rules.map((entry) => entry.rule.id),
      second.rules.map((entry) => entry.rule.id),
    );
    assert.deepEqual(
      first.rules.flatMap((entry) => entry.findings.map((finding) => finding.fingerprint)),
      second.rules.flatMap((entry) => entry.findings.map((finding) => finding.fingerprint)),
    );
  });
});
