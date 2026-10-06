/**
 * Code Guardian — Guardian Engine Tests (official roadmap Phase 19)
 *
 * The dedicated proof of the canonical analysis engine. It exercises the real
 * pipeline end to end:
 *
 *   repository → RepositoryModel → GuardianEngine.audit → analyzers
 *              → evidence → findings → risk → canonical result
 *
 * and pins the phase's acceptance criteria: a stable `guardian.audit(...)` API,
 * explicit configuration, deterministic analyzer selection, the accepted
 * applicability/execution/evidence/finding semantics reused rather than
 * duplicated, a documented deterministic risk profile that never turns an
 * incomplete analysis into a clean one, a versioned validated canonical result
 * independent of any transport, and the dependency direction
 * `interface → Guardian Core → analysis/rules`.
 *
 * Run with: node --test tests/guardian-engine.test.js
 */

import { after, describe, it } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

import {
  createAnalysisResult,
  createAnalyzer,
  createApplicability,
  createEvidence,
} from "../src/core/index.js";

import { createAnalyzerRegistry } from "../src/analysis/index.js";

import { buildRepositoryModel } from "../src/repository/model/index.js";
import { createScanResult } from "../src/repository/scanner/index.js";

import {
  AUDIT_OPTION_KEYS,
  GUARDIAN_ENGINE_VERSION,
  GUARDIAN_FAILURE_CODES,
  GUARDIAN_RESULT_SCHEMA_VERSION,
  GUARDIAN_SELECTION_ALL,
  RISK_CONTRACT_VERSION,
  RISK_LIMITATION_KINDS,
  calculateRisk,
  createGuardianEngine,
  createGuardianResult,
  isRepositoryModel,
  isScanResult,
  resolveAuditOptions,
  selectAnalyzers,
  stableGuardianView,
  validateGuardianResult,
} from "../src/guardian/index.js";

// ─── Fixtures: a real RepositoryModel ────────────────────────────────────────

const ISO = "2026-01-01T00:00:00.000Z";
const byPath = (a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0);

function toEntry(path, isDirectory = false) {
  const name = path.split("/").pop();
  const dot = name.lastIndexOf(".");
  return {
    path,
    name,
    isDirectory,
    extension: isDirectory || dot <= 0 ? "" : name.slice(dot).toLowerCase(),
    depth: path.split("/").length,
  };
}

const filesOf = (...paths) => paths.map((path) => toEntry(path)).sort(byPath);
const dirsOf = (...paths) => paths.map((path) => toEntry(path, true)).sort(byPath);
const signal = (path, signalId, extra = {}) => ({ path, signal: signalId, ...extra });

function buildModel(overrides = {}) {
  return buildRepositoryModel(
    createScanResult({
      root: "/scan-root",
      scannedAt: ISO,
      files: filesOf("package.json", "src/app.js", "src/util.js", "tests/app.test.js"),
      directories: dirsOf("src", "tests"),
      languages: [
        {
          id: "javascript",
          fileCount: 3,
          extensions: [".js"],
          evidence: [
            signal("src/app.js", "source-extension"),
            signal("src/util.js", "source-extension"),
          ],
          evidenceTruncated: false,
        },
      ],
      manifests: [
        {
          path: "package.json",
          name: "package.json",
          directory: ".",
          ecosystem: "node",
          kind: "manifest",
          languages: ["javascript"],
          parse: { status: "parsed", format: "json", bytes: 12 },
        },
      ],
      tests: {
        detected: true,
        frameworks: ["node-test"],
        evidence: [
          signal("tests", "test-directory", { kind: "directory", framework: null }),
          signal("tests/app.test.js", "test-file", { kind: "file", framework: "node-test" }),
        ],
        evidenceTruncated: false,
      },
      statistics: {
        filesScanned: 4,
        directoriesScanned: 2,
        symlinksScanned: 0,
        ignored: 0,
        unreadable: 0,
        truncatedBy: [],
      },
      scan: { complete: true, truncated: false, limits: { maxFiles: 10000, maxDepth: 20 }, errors: [] },
      ...overrides,
    }),
  );
}

const MODEL = buildModel();
const TRUNCATED_MODEL = buildModel({
  scan: {
    complete: false,
    truncated: true,
    limits: { maxFiles: 2, maxDepth: 20 },
    errors: [],
  },
  statistics: {
    filesScanned: 4,
    directoriesScanned: 2,
    symlinksScanned: 0,
    ignored: 0,
    unreadable: 0,
    truncatedBy: ["maxFiles"],
  },
});

// ─── Real repository fixtures (for the path → scanner → builder path) ─────────

const TMP_ROOT = join(tmpdir(), `cg-guardian-${process.pid}-${Date.now()}`);
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

after(() => {
  rmSync(TMP_ROOT, { recursive: true, force: true });
});

const pkg = (extra = {}) => JSON.stringify({ name: "demo", version: "1.0.0", ...extra });
const SOURCE = "export const a = 1;\n";
const BASIC_REPO = {
  "package.json": pkg(),
  "src/app.js": SOURCE,
  "tests/app.test.js": "test('x', () => {});\n",
};

// ─── Fixtures: analyzers ─────────────────────────────────────────────────────

function evidenceOf(id, { path = "src/app.js", analyzer = "test.alpha" } = {}) {
  return createEvidence({
    id,
    type: "file",
    location: { path },
    source: { analyzer, method: "fixture" },
    data: {},
    provenance: { deterministic: true, collector: analyzer },
  });
}

function findingOf({
  ruleId = "test.rule",
  category = "testing",
  severity = "medium",
  confidence = 0.5,
  title = "fixture finding",
  evidence = [],
} = {}) {
  return { ruleId, category, severity, confidence, title, evidence };
}

function analyzerOf({
  id,
  name = id,
  scope = "test",
  version = "1.0.0",
  canAnalyze = () => createApplicability({ applicable: true }),
  analyze,
}) {
  return createAnalyzer({ id, name, version, scope, canAnalyze, analyze });
}

/** An analyzer that always completes with the given findings/evidence. */
function analyzerReturning(id, { findings = [], evidence = [] } = {}) {
  return analyzerOf({
    id,
    analyze: () => createAnalysisResult({ findings, evidence }),
  });
}

function engineWith(analyzers, options = {}) {
  return createGuardianEngine({ registry: createAnalyzerRegistry(analyzers), ...options });
}

// ─── Configuration ───────────────────────────────────────────────────────────

describe("guardian: configuration", () => {
  it("resolves a canonical default configuration", () => {
    const config = resolveAuditOptions();
    assert.equal(config.analyzers, GUARDIAN_SELECTION_ALL);
    assert.deepEqual(config.rules, []);
    assert.deepEqual(config.evidence, []);
    assert.deepEqual(config.configuration, {});
    assert.deepEqual(config.execution, {});
    assert.deepEqual(config.analysis, {});
    assert.equal(config.failFast, undefined);
    assert.deepEqual(config.scan, {});
    assert.equal(config.clock, null);
    assert.ok(Object.isFrozen(config));
  });

  it("exposes exactly the documented option keys", () => {
    assert.deepEqual([...AUDIT_OPTION_KEYS].sort(), [
      "analysis",
      "analyzers",
      "clock",
      "configuration",
      "evidence",
      "execution",
      "failFast",
      "rules",
      "scan",
    ]);
  });

  it("is order-independent for an explicit analyzer selection", () => {
    const a = resolveAuditOptions({ analyzers: ["test.beta", "test.alpha", "test.beta"] });
    const b = resolveAuditOptions({ analyzers: ["test.alpha", "test.beta"] });
    assert.deepEqual(a.analyzers, b.analyzers);
    assert.deepEqual(a.analyzers, ["test.alpha", "test.beta"]);
  });

  it("rejects an unknown option key", () => {
    assert.throws(
      () => resolveAuditOptions({ bogus: true }),
      (error) => error.code === GUARDIAN_FAILURE_CODES.invalidConfiguration,
    );
  });

  it("rejects a non-boolean failFast and a non-array analyzers", () => {
    assert.throws(() => resolveAuditOptions({ failFast: "yes" }), /failFast/);
    assert.throws(() => resolveAuditOptions({ analyzers: "test.alpha" }), /analyzers/);
  });

  it("rejects non-declarative configuration data", () => {
    assert.throws(
      () => resolveAuditOptions({ configuration: { fn: () => {} } }),
      /declarative/,
    );
    assert.throws(() => resolveAuditOptions({ analysis: { fn: () => {} } }), /declarative/);
  });

  it("rejects an unknown scanner option", () => {
    assert.throws(() => resolveAuditOptions({ scan: { bogus: 1 } }), /scan\.bogus/);
  });

  it("rejects a non-function clock", () => {
    assert.throws(() => resolveAuditOptions({ clock: 5 }), /clock/);
  });
});

// ─── RepositoryModel ─────────────────────────────────────────────────────────

describe("guardian: repository model", () => {
  it("scans a repository root through the existing pipeline", async () => {
    const root = makeRepo(BASIC_REPO);
    const guardian = engineWith([analyzerReturning("test.alpha", {})]);
    const result = await guardian.audit(root, { clock: () => 0 });
    assert.equal(typeof result.repository.root, "string");
    assert.ok(result.repository.root.length > 0);
    assert.ok(result.repository.modelVersion);
    assert.ok(result.repository.fileCount >= 2);
    assert.equal(result.analyzers.length, 1);
  });

  it("accepts a prebuilt RepositoryModel", async () => {
    assert.equal(isRepositoryModel(MODEL), true);
    const guardian = engineWith([analyzerReturning("test.alpha", {})]);
    const result = await guardian.audit(MODEL, { clock: () => 0 });
    assert.equal(result.repository.repositoryId, MODEL.identity.repositoryId);
    assert.equal(result.scan.guarantee, "complete");
  });

  it("accepts a ScanResult", async () => {
    const scan = createScanResult({
      root: "/scan-root",
      scannedAt: ISO,
      files: filesOf("package.json"),
      directories: [],
      statistics: {
        filesScanned: 1,
        directoriesScanned: 0,
        symlinksScanned: 0,
        ignored: 0,
        unreadable: 0,
        truncatedBy: [],
      },
      scan: { complete: true, truncated: false, limits: { maxFiles: 100, maxDepth: 20 }, errors: [] },
    });
    assert.equal(isScanResult(scan), true);
    const guardian = engineWith([analyzerReturning("test.alpha", {})]);
    const result = await guardian.audit(scan, { clock: () => 0 });
    assert.ok(result.repository.repositoryId);
  });

  it("rejects an invalid repository model", async () => {
    const guardian = engineWith([analyzerReturning("test.alpha", {})]);
    await assert.rejects(() => guardian.audit({ identity: {}, scan: {} }));
  });

  it("rejects a repository input that is none of the accepted forms", async () => {
    const guardian = engineWith([analyzerReturning("test.alpha", {})]);
    await assert.rejects(
      () => guardian.audit(42),
      (error) => error.code === GUARDIAN_FAILURE_CODES.invalidRepository,
    );
  });

  it("keeps an incomplete scan visible in the result", async () => {
    const guardian = engineWith([analyzerReturning("test.alpha", {})]);
    const result = await guardian.audit(TRUNCATED_MODEL, { clock: () => 0 });
    assert.equal(result.scan.complete, false);
    assert.equal(result.scan.truncated, true);
    assert.equal(result.scan.guarantee, "partial");
    assert.equal(result.repository.coverage.complete, false);
    assert.equal(result.risk.complete, false);
  });
});

// ─── Analyzer selection ──────────────────────────────────────────────────────

describe("guardian: analyzer selection", () => {
  it("selects every registered analyzer by default, id-sorted", async () => {
    const guardian = engineWith([
      analyzerReturning("test.beta", {}),
      analyzerReturning("test.alpha", {}),
    ]);
    const result = await guardian.audit(MODEL, { clock: () => 0 });
    assert.deepEqual(result.analysis.selectedAnalyzers, ["test.alpha", "test.beta"]);
  });

  it("selects an explicit subset", async () => {
    const guardian = engineWith([
      analyzerReturning("test.alpha", {}),
      analyzerReturning("test.beta", {}),
    ]);
    const result = await guardian.audit(MODEL, { analyzers: ["test.beta"], clock: () => 0 });
    assert.deepEqual(result.analysis.selectedAnalyzers, ["test.beta"]);
  });

  it("rejects an unknown explicitly requested analyzer", async () => {
    const guardian = engineWith([analyzerReturning("test.alpha", {})]);
    await assert.rejects(
      () => guardian.audit(MODEL, { analyzers: ["test.nope"] }),
      (error) => error.code === "CG_ANALYZER_UNKNOWN",
    );
  });

  it("rejects an empty selection instead of producing an empty audit", async () => {
    const guardian = engineWith([analyzerReturning("test.alpha", {})]);
    await assert.rejects(
      () => guardian.audit(MODEL, { analyzers: [] }),
      (error) => error.code === GUARDIAN_FAILURE_CODES.emptySelection,
    );
  });

  it("does not execute a duplicated selection twice", async () => {
    let runs = 0;
    const guardian = engineWith([
      analyzerOf({
        id: "test.alpha",
        analyze: () => {
          runs += 1;
          return createAnalysisResult({});
        },
      }),
    ]);
    const result = await guardian.audit(MODEL, {
      analyzers: ["test.alpha", "test.alpha", "test.alpha"],
      clock: () => 0,
    });
    assert.equal(runs, 1);
    assert.equal(result.analyzers.length, 1);
  });

  it("selectAnalyzers delegates to the registry (single authority)", () => {
    const registry = createAnalyzerRegistry([analyzerReturning("test.alpha", {})]);
    const selected = selectAnalyzers(registry, ["test.alpha"]);
    assert.equal(selected.length, 1);
    assert.equal(selected[0].id, "test.alpha");
    assert.throws(() => selectAnalyzers(registry, ["test.nope"]));
  });
});

// ─── Applicability ───────────────────────────────────────────────────────────

describe("guardian: applicability", () => {
  it("keeps a not-applicable analyzer distinguishable and does not fail the run", async () => {
    const guardian = engineWith([
      analyzerReturning("test.alpha", {}),
      analyzerOf({
        id: "test.beta",
        canAnalyze: () => createApplicability({ applicable: false, reason: "not a Go repository" }),
        analyze: () => {
          throw new Error("must not run");
        },
      }),
    ]);
    const result = await guardian.audit(MODEL, { clock: () => 0 });
    const beta = result.analyzers.find((entry) => entry.id === "test.beta");
    assert.equal(beta.status, "not-applicable");
    assert.equal(beta.applicability.applicable, false);
    // not-applicable is a normal outcome: it does not make the run incomplete.
    assert.equal(result.analysis.complete, true);
    assert.equal(result.risk.complete, true);
    assert.deepEqual(result.risk.limitations, []);
  });

  it("reuses the accepted applicability evaluator rather than a second implementation", async () => {
    // A malformed applicability is reported by the accepted Analyzer Engine with its
    // own failure kind; the Core does not reinterpret it.
    const guardian = engineWith([
      analyzerOf({ id: "test.alpha", canAnalyze: () => true, analyze: () => createAnalysisResult({}) }),
    ]);
    const result = await guardian.audit(MODEL, { clock: () => 0 });
    assert.equal(result.analyzers[0].status, "failed");
    assert.equal(result.analyzers[0].errors[0].kind, "invalid-applicability");
    assert.equal(result.risk.complete, false);
  });
});

// ─── Execution ───────────────────────────────────────────────────────────────

describe("guardian: execution", () => {
  it("isolates one analyzer failure from unrelated analyzers", async () => {
    const guardian = engineWith([
      analyzerOf({
        id: "test.alpha",
        analyze: () => {
          throw new Error("boom");
        },
      }),
      analyzerReturning("test.beta", { findings: [findingOf({ title: "beta finding" })] }),
    ]);
    const result = await guardian.audit(MODEL, { clock: () => 0 });
    const alpha = result.analyzers.find((entry) => entry.id === "test.alpha");
    const beta = result.analyzers.find((entry) => entry.id === "test.beta");
    assert.equal(alpha.status, "failed");
    assert.equal(alpha.errors[0].kind, "analyzer-failure");
    assert.equal(beta.status, "completed");
    assert.equal(result.findings.length, 1);
    assert.equal(result.findings[0].title, "beta finding");
  });

  it("records fail-fast skips visibly", async () => {
    const guardian = engineWith([
      analyzerOf({
        id: "test.alpha",
        analyze: () => {
          throw new Error("boom");
        },
      }),
      analyzerReturning("test.beta", {}),
    ]);
    const result = await guardian.audit(MODEL, { failFast: true, clock: () => 0 });
    assert.equal(result.analysis.failFast, true);
    assert.equal(result.analyzers.find((entry) => entry.id === "test.alpha").status, "failed");
    assert.equal(result.analyzers.find((entry) => entry.id === "test.beta").status, "skipped");
    assert.equal(result.analysis.complete, false);
    assert.deepEqual(result.metrics.analyzers, {
      selected: 2,
      completed: 0,
      notApplicable: 0,
      failed: 1,
      skipped: 1,
    });
  });

  it("keeps analyzer results attributable", async () => {
    const guardian = engineWith([
      analyzerReturning("test.alpha", { findings: [findingOf({ title: "from alpha" })] }),
      analyzerReturning("test.beta", { findings: [findingOf({ title: "from beta", severity: "high" })] }),
    ]);
    const result = await guardian.audit(MODEL, { clock: () => 0 });
    for (const finding of result.findings) {
      assert.ok(finding.metadata.analyzer.id.startsWith("test."));
    }
    const alphaSummary = result.analyzers.find((entry) => entry.id === "test.alpha");
    assert.equal(alphaSummary.findings.length, 1);
  });
});

// ─── Evidence ────────────────────────────────────────────────────────────────

describe("guardian: evidence", () => {
  it("preserves model evidence cited by a finding", async () => {
    const guardian = engineWith([
      analyzerOf({
        id: "test.alpha",
        analyze: (context) => {
          const modelEvidence = context.repository.evidence[0];
          return createAnalysisResult({
            findings: [findingOf({ evidence: [modelEvidence.id] })],
          });
        },
      }),
    ]);
    const result = await guardian.audit(MODEL, { clock: () => 0 });
    assert.equal(result.analyzers[0].status, "completed");
    assert.deepEqual(result.findings[0].evidence, [MODEL.evidence[0].id]);
    assert.ok(result.evidence.some((record) => record.id === MODEL.evidence[0].id));
  });

  it("preserves analyzer-derived evidence", async () => {
    const guardian = engineWith([
      analyzerOf({
        id: "test.alpha",
        analyze: () =>
          createAnalysisResult({
            evidence: [evidenceOf("evidence:test:derived", { analyzer: "test.alpha" })],
            findings: [findingOf({ evidence: ["evidence:test:derived"] })],
          }),
      }),
    ]);
    const result = await guardian.audit(MODEL, { clock: () => 0 });
    assert.deepEqual(result.findings[0].evidence, ["evidence:test:derived"]);
    assert.ok(result.evidence.some((record) => record.id === "evidence:test:derived"));
  });

  it("refuses to let an analyzer forge an existing evidence id", async () => {
    // Reusing a model evidence id would replace provenance another component
    // relies on; the accepted engine fails the analyzer, and the Core keeps the
    // failure visible.
    const guardian = engineWith([
      analyzerOf({
        id: "test.alpha",
        analyze: (context) =>
          createAnalysisResult({
            evidence: [evidenceOf(context.repository.evidence[0].id, { analyzer: "test.alpha" })],
          }),
      }),
    ]);
    const result = await guardian.audit(MODEL, { clock: () => 0 });
    assert.equal(result.analyzers[0].status, "failed");
    assert.equal(result.analyzers[0].errors[0].kind, "duplicate-evidence-id");
    assert.ok(
      result.risk.limitations.includes(`${RISK_LIMITATION_KINDS.ANALYZER_FAILED}:test.alpha`),
    );
  });

  it("resolves every finding reference in the canonical result", async () => {
    const guardian = engineWith([
      analyzerOf({
        id: "test.alpha",
        analyze: (context) =>
          createAnalysisResult({
            evidence: [evidenceOf("evidence:test:derived", { analyzer: "test.alpha" })],
            findings: [
              findingOf({ evidence: [context.repository.evidence[0].id, "evidence:test:derived"] }),
            ],
          }),
      }),
    ]);
    const result = await guardian.audit(MODEL, { clock: () => 0 });
    const ids = new Set(result.evidence.map((record) => record.id));
    for (const finding of result.findings) {
      for (const reference of finding.evidence) assert.ok(ids.has(reference));
    }
  });
});

// ─── Findings ────────────────────────────────────────────────────────────────

describe("guardian: findings", () => {
  it("produces canonical findings with stable fingerprints", async () => {
    const build = () =>
      engineWith([
        analyzerReturning("test.alpha", { findings: [findingOf({ title: "stable", confidence: 0.7 })] }),
      ]);
    const first = await build().audit(MODEL, { clock: () => 0 });
    const second = await build().audit(MODEL, { clock: () => 0 });
    assert.ok(first.findings[0].fingerprint);
    assert.equal(first.findings[0].fingerprint, second.findings[0].fingerprint);
    assert.equal(first.findings[0].id, `finding:${first.findings[0].fingerprint}`);
  });

  it("deduplicates identical findings by fingerprint", async () => {
    const shared = findingOf({ title: "duplicate" });
    const guardian = engineWith([
      analyzerReturning("test.alpha", { findings: [shared] }),
      analyzerReturning("test.beta", { findings: [{ ...shared }] }),
    ]);
    const result = await guardian.audit(MODEL, { clock: () => 0 });
    assert.equal(result.findings.length, 1);
    assert.equal(result.metrics.findings.duplicates, 1);
  });

  it("orders findings deterministically", async () => {
    const guardian = engineWith([
      analyzerReturning("test.alpha", {
        findings: [
          findingOf({ title: "b", ruleId: "test.rule.b" }),
          findingOf({ title: "a", ruleId: "test.rule.a" }),
        ],
      }),
    ]);
    const result = await guardian.audit(MODEL, { clock: () => 0 });
    const fingerprints = result.findings.map((finding) => finding.fingerprint);
    assert.deepEqual(fingerprints, [...fingerprints].sort());
  });
});

// ─── Risk ────────────────────────────────────────────────────────────────────

describe("guardian: risk", () => {
  it("records the risk contract version", async () => {
    const guardian = engineWith([analyzerReturning("test.alpha", {})]);
    const result = await guardian.audit(MODEL, { clock: () => 0 });
    assert.equal(result.risk.version, RISK_CONTRACT_VERSION);
  });

  it("is deterministic", async () => {
    const guardian = engineWith([
      analyzerReturning("test.alpha", { findings: [findingOf({ severity: "high" })] }),
    ]);
    const first = await guardian.audit(MODEL, { clock: () => 0 });
    const second = await guardian.audit(MODEL, { clock: () => 0 });
    assert.deepEqual(first.risk, second.risk);
  });

  it("keeps severity and confidence independent", async () => {
    const guardian = engineWith([
      analyzerReturning("test.alpha", {
        findings: [
          findingOf({ severity: "high", confidence: 0.4, ruleId: "test.rule.high" }),
          findingOf({ severity: "low", confidence: 0.95, ruleId: "test.rule.low" }),
        ],
      }),
    ]);
    const result = await guardian.audit(MODEL, { clock: () => 0 });
    assert.equal(result.risk.highestSeverity, "high");
    assert.equal(result.risk.counts.high, 1);
    assert.equal(result.risk.counts.low, 1);
    // Confidence is not folded into the risk profile: it stays on each finding.
    assert.equal("confidence" in result.risk, false);
    const bySeverity = new Map(result.findings.map((finding) => [finding.severity, finding.confidence]));
    assert.equal(bySeverity.get("high"), 0.4);
    assert.equal(bySeverity.get("low"), 0.95);
  });

  it("reflects an analyzer failure as a limitation", async () => {
    const guardian = engineWith([
      analyzerOf({ id: "test.alpha", analyze: () => { throw new Error("boom"); } }),
    ]);
    const result = await guardian.audit(MODEL, { clock: () => 0 });
    assert.equal(result.risk.complete, false);
    assert.deepEqual(result.risk.limitations, [
      `${RISK_LIMITATION_KINDS.ANALYZER_FAILED}:test.alpha`,
    ]);
  });

  it("never turns an incomplete repository scan into a clean profile", async () => {
    const guardian = engineWith([analyzerReturning("test.alpha", {})]);
    const result = await guardian.audit(TRUNCATED_MODEL, { clock: () => 0 });
    assert.equal(result.risk.highestSeverity, null);
    assert.equal(result.risk.counts.total, 0);
    assert.equal(result.risk.complete, false);
    assert.deepEqual(result.risk.limitations, [
      RISK_LIMITATION_KINDS.REPOSITORY_INCOMPLETE,
      RISK_LIMITATION_KINDS.REPOSITORY_TRUNCATED,
    ]);
  });

  it("calculates a profile directly from a run, without a clock or I/O", () => {
    const risk = calculateRisk({
      repository: MODEL,
      analysisRun: {
        analyzers: [{ analyzer: { id: "test.alpha" }, status: "completed" }],
        findings: [{ severity: "critical" }, { severity: "info" }, { severity: "critical" }],
      },
    });
    assert.equal(risk.highestSeverity, "critical");
    assert.deepEqual(risk.counts, { total: 3, info: 1, low: 0, medium: 0, high: 0, critical: 2 });
    assert.equal(risk.complete, true);
  });
});

// ─── Canonical result ────────────────────────────────────────────────────────

describe("guardian: canonical result", () => {
  it("is versioned and validated", async () => {
    const guardian = engineWith([analyzerReturning("test.alpha", {})]);
    const result = await guardian.audit(MODEL, { clock: () => 0 });
    assert.equal(result.schemaVersion, GUARDIAN_RESULT_SCHEMA_VERSION);
    assert.equal(result.engine.version, GUARDIAN_ENGINE_VERSION);
    assert.doesNotThrow(() => validateGuardianResult(result));
  });

  it("is deeply frozen", async () => {
    const guardian = engineWith([analyzerReturning("test.alpha", {})]);
    const result = await guardian.audit(MODEL, { clock: () => 0 });
    assert.ok(Object.isFrozen(result));
    assert.ok(Object.isFrozen(result.analyzers));
    assert.ok(Object.isFrozen(result.risk));
    assert.ok(Object.isFrozen(result.risk.coverage));
  });

  it("carries every required section", async () => {
    const guardian = engineWith([analyzerReturning("test.alpha", {})]);
    const result = await guardian.audit(MODEL, { clock: () => 0 });
    for (const field of [
      "schemaVersion",
      "engine",
      "repository",
      "analysis",
      "analyzers",
      "findings",
      "evidence",
      "metrics",
      "risk",
      "scan",
    ]) {
      assert.ok(field in result, `missing ${field}`);
    }
    assert.equal(Array.isArray(result.analyzers), true);
    assert.equal(Array.isArray(result.findings), true);
    assert.equal(Array.isArray(result.evidence), true);
  });

  it("is deterministic apart from the documented duration metadata", async () => {
    let fast = 0;
    let slow = 0;
    const guardian = engineWith([analyzerReturning("test.alpha", {})]);
    const first = await guardian.audit(MODEL, { clock: () => (fast += 5) });
    const second = await guardian.audit(MODEL, { clock: () => (slow += 17) });
    assert.notEqual(first.analysis.durationMs, second.analysis.durationMs);
    assert.equal(
      JSON.stringify(stableGuardianView(first)),
      JSON.stringify(stableGuardianView(second)),
    );
    assert.equal("durationMs" in stableGuardianView(first).analysis, false);
  });

  it("rejects a result carrying a collapsed judgment key", () => {
    const draft = createGuardianResult({
      repository: { repositoryId: "r", root: "/r", modelVersion: "1", coverage: {} },
      scan: { complete: true, truncated: false, guarantee: "complete" },
      engine: { name: "code-guardian", version: "1.0.0", fingerprintAlgorithm: "cg-fp1" },
      analysis: {
        complete: true,
        selectedAnalyzers: [],
        analyzers: { selected: 0, completed: 0, notApplicable: 0, failed: 0, skipped: 0 },
        failFast: false,
        durationMs: 0,
      },
      risk: {
        version: "1.0.0",
        highestSeverity: null,
        counts: { total: 0, info: 0, low: 0, medium: 0, high: 0, critical: 0 },
        complete: true,
        coverage: { repository: {}, analysis: {} },
        limitations: [],
      },
    });
    draft.score = 87;
    assert.throws(
      () => validateGuardianResult(draft),
      (error) => error.details.issues.some((issue) => issue.includes("score")),
    );
  });

  it("is independent of any transport", () => {
    // Structural proof: no key or value in a result names a transport.
    const forbidden = ["mcp", "stdio", "http", "cli", "jsonrpc"];
    const result = createGuardianResult({});
    const serialize = JSON.stringify(result).toLowerCase();
    for (const needle of forbidden) assert.equal(serialize.includes(needle), false);
  });
});

// ─── Architectural boundary ──────────────────────────────────────────────────

describe("guardian: architectural boundary", () => {
  const GUARDIAN_DIR = join(process.cwd(), "src", "guardian");
  const FILES = readdirSync(GUARDIAN_DIR).filter((name) => name.endsWith(".js"));
  const SOURCES = FILES.map((name) => ({
    name,
    text: readFileSync(join(GUARDIAN_DIR, name), "utf8"),
  }));

  const ALLOWED_SPECIFIERS = [
    "../core/index.js",
    "../repository/model/index.js",
    "../repository/scanner/index.js",
    "../analysis/index.js",
    "../rules/index.js",
  ];
  const FORBIDDEN = [
    "node:fs",
    "node:fs/promises",
    "child_process",
    "node:child_process",
    "node:net",
    "node:http",
    "node:https",
    "node:dns",
    "node:worker_threads",
    "../repository/filesystem",
    "../../repository/filesystem",
    "../execution",
    "../../execution",
    "tools.js",
    "tool-registry",
    "stdio-server",
    "http-server",
  ];

  const withoutComments = (text) =>
    text.replace(/\/\*[\s\S]*?\*\//g, "").replace(/^\s*\/\/.*$/gm, "");

  it("imports only the Core, the model/scanner boundaries, the analysis framework and the rule layer", () => {
    assert.ok(SOURCES.length >= 8);
    for (const { name, text } of SOURCES) {
      const code = withoutComments(text);
      for (const match of code.matchAll(/from\s+"([^"]+)"/g)) {
        const specifier = match[1];
        assert.ok(
          specifier.startsWith("./") || ALLOWED_SPECIFIERS.includes(specifier),
          `${name} imports disallowed module "${specifier}"`,
        );
      }
      assert.ok(!/import\s*\(/.test(code), `${name} must not use a dynamic import`);
      assert.ok(!/\brequire\s*\(/.test(code), `${name} must not use require`);
    }
  });

  it("has no filesystem, process, network, transport or worker access", () => {
    for (const { name, text } of SOURCES) {
      const code = withoutComments(text);
      for (const forbidden of FORBIDDEN) {
        assert.ok(!code.includes(`"${forbidden}"`), `${name} references "${forbidden}"`);
      }
      assert.ok(!/\bnew Date\b/.test(code), `${name} must not construct a Date`);
      assert.ok(!/\bMath\.random\b/.test(code), `${name} must not use randomness`);
      assert.ok(!/\bprocess\.env\b/.test(code), `${name} must not read the environment`);
      assert.ok(!/\beval\s*\(/.test(code), `${name} must not evaluate code`);
    }
  });

  it("does not depend on MCP, the legacy tools or the CLI", () => {
    for (const { name, text } of SOURCES) {
      const code = withoutComments(text).toLowerCase();
      for (const needle of ["tools.js", "tool-registry", "mcp", "stdio", "cli"]) {
        assert.ok(!code.includes(needle), `${name} references "${needle}"`);
      }
    }
  });

  it("analyzers do not call back into the Guardian Core", () => {
    for (const dir of [join(process.cwd(), "src", "analysis"), join(process.cwd(), "src", "rules")]) {
      for (const name of readdirSync(dir).filter((entry) => entry.endsWith(".js"))) {
        const source = readFileSync(join(dir, name), "utf8");
        assert.ok(!source.includes("/guardian"), `${name} must not depend on the Guardian Core`);
      }
    }
  });
});
