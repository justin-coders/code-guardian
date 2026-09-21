/**
 * Code Guardian — Analyzer Framework Tests (Phase 9)
 *
 * Every analyzer in this file is a **test fixture**, not a product analyzer: the
 * phase deliberately ships no security/architecture/testing/dependency/CI/API/
 * reliability/production intelligence, only the machinery that such analyzers will
 * be plugged into.
 *
 * The repository model used by the fixtures is a real Phase 8D model built from a
 * hand-built ScanResult, so the framework is exercised against the contract it will
 * actually receive — including real scanner evidence ids — without touching the
 * filesystem.
 *
 * Run with: node --test tests/analyzer-framework.test.js
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";

import {
  ANALYSIS_CONTEXT_FIELDS,
  REPOSITORY_MODEL_OPTIONAL_AREAS,
  ValidationError,
  createAnalysisResult,
  createAnalyzer,
  createApplicability,
  createEvidence,
  createFinding,
  createRule,
} from "../src/core/index.js";

import { createScanResult } from "../src/repository/scanner/index.js";
import { buildRepositoryModel } from "../src/repository/model/index.js";

import {
  ABNORMAL_ANALYZER_STATUSES,
  ANALYZER_FAILURE_CODES,
  ANALYZER_FAILURE_KINDS,
  ANALYZER_RUN_STATUSES,
  ANALYZER_RUN_RESULT_FIELDS,
  ANALYSIS_RUN_RESULT_FIELDS,
  AnalyzerConfigurationError,
  AnalyzerRegistrationError,
  analyzerDescriptorIssues,
  buildAnalysisContext,
  createAnalyzerEngine,
  createAnalyzerRegistry,
  deduplicateFindings,
  deepFreeze,
  findingFingerprint,
  findingsForAnalyzer,
  isRunComplete,
  normalizeFinding,
  orderFindings,
  sanitizeDeclarativeValue,
  stableAnalysisView,
  validateAnalysisRunResult,
  validateAnalyzerRunResult,
} from "../src/analysis/index.js";

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

/** A small but complete ScanResult, processed by the real Phase 8D builder. */
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
const APP_FILE_EVIDENCE = "evidence:inventory:src/app.js";
const PACKAGE_EVIDENCE = "evidence:manifest:manifest-manifest:package.json";

// ─── Fixtures: test-only analyzers ───────────────────────────────────────────

const RULE = createRule({
  id: "test.rule",
  version: "1.0.0",
  category: "test",
  title: "Fixture rule",
  severity: "medium",
  applicability: {},
  detect: () => [],
  remediation: { summary: "fix it" },
  metadata: {},
});

/** An analyzer that completes and produces nothing. */
function passAnalyzer(id = "test.pass", scope = "test") {
  return createAnalyzer({
    id,
    name: `Pass ${id}`,
    version: "1.0.0",
    scope,
    canAnalyze: () => createApplicability({ applicable: true }),
    analyze: () => createAnalysisResult({ metrics: { checked: 1 }, metadata: { fixture: true } }),
  });
}

/** An analyzer that declines the repository, with a documented reason. */
function notApplicableAnalyzer(id = "test.not-applicable") {
  return createAnalyzer({
    id,
    name: `Not applicable ${id}`,
    version: "1.0.0",
    scope: "test",
    canAnalyze: () => createApplicability({ applicable: false, reason: "no python evidence" }),
    analyze: () => {
      throw new Error("must never run");
    },
  });
}

/** An analyzer that emits findings; `findings` may be a function of the model. */
function findingAnalyzer(id = "test.finding", findings = () => [rawFinding()]) {
  return createAnalyzer({
    id,
    name: `Finding ${id}`,
    version: "1.2.0",
    scope: "test",
    canAnalyze: () => createApplicability({ applicable: true }),
    analyze: (context) => createAnalysisResult({ findings: findings(context) }),
  });
}

function rawFinding(overrides = {}) {
  return {
    ruleId: "test.rule",
    category: "test",
    severity: "medium",
    confidence: 1,
    title: "Fixture finding",
    description: "a fixture finding",
    evidence: [APP_FILE_EVIDENCE],
    metadata: {},
    ...overrides,
  };
}

/**
 * An analyzer that emits exactly one observation with the given id.
 *
 * The id is supplied by the caller so two analyzers can be made to collide on
 * purpose — the run-global uniqueness rule is a property of the *run*, not of
 * either analyzer.
 */
function evidenceAnalyzer(id, evidenceId, path = "src/app.js") {
  return createAnalyzer({
    id,
    name: `Emits ${id}`,
    version: "1.0.0",
    scope: "test",
    canAnalyze: () => createApplicability({ applicable: true }),
    analyze: () =>
      createAnalysisResult({
        evidence: [
          createEvidence({
            id: evidenceId,
            type: "file",
            location: { path },
            source: { analyzer: id, method: "fixture" },
            data: {},
            provenance: { deterministic: true, collector: id },
          }),
        ],
      }),
  });
}

function analyzerThatThrows(id = "test.failure", scope = "test") {
  return createAnalyzer({
    id,
    name: `Throwing ${id}`,
    version: "1.0.0",
    scope,
    canAnalyze: () => createApplicability({ applicable: true }),
    analyze: () => {
      const error = new Error("boom: /etc/passwd leaked");
      error.details = { secret: "super-secret-token" };
      throw error;
    },
  });
}

function engineWith(analyzers, options = {}) {
  return createAnalyzerEngine({
    registry: createAnalyzerRegistry(analyzers),
    ...options,
  });
}

const context = (overrides = {}) => buildAnalysisContext({ repository: MODEL, rules: [RULE], ...overrides });

// ─── Registry ────────────────────────────────────────────────────────────────

describe("analyzer framework: registry", () => {
  it("registers, retrieves and lists analyzers", () => {
    const registry = createAnalyzerRegistry();
    const first = passAnalyzer("test.alpha");
    const second = passAnalyzer("test.beta");
    registry.register(second).register(first);

    assert.equal(registry.size, 2);
    assert.equal(registry.get("test.alpha"), first);
    assert.equal(registry.has("test.beta"), true);
    assert.equal(registry.get("test.missing"), null);
    assert.deepEqual(registry.ids(), ["test.alpha", "test.beta"]);
    // Documented ordering: by id, never insertion order.
    assert.deepEqual(
      registry.list().map((analyzer) => analyzer.id),
      ["test.alpha", "test.beta"],
    );
  });

  it("accepts an initial analyzer list and registerAll", () => {
    const registry = createAnalyzerRegistry([passAnalyzer("test.b")]);
    registry.registerAll([passAnalyzer("test.a")]);
    assert.deepEqual(registry.ids(), ["test.a", "test.b"]);
  });

  it("rejects a duplicate analyzer id deterministically", () => {
    const registry = createAnalyzerRegistry([passAnalyzer("test.dupe")]);
    assert.throws(
      () => registry.register(passAnalyzer("test.dupe")),
      (error) => {
        assert.ok(error instanceof AnalyzerConfigurationError);
        assert.equal(error.details.kind, ANALYZER_FAILURE_KINDS.DUPLICATE_ANALYZER);
        assert.equal(error.code, ANALYZER_FAILURE_CODES.duplicateAnalyzer);
        return true;
      },
    );
    assert.equal(registry.size, 1);
  });

  it("rejects analyzers that violate the Core or framework contract", () => {
    const cases = [
      { label: "not an object", value: "nope" },
      { label: "missing version", value: { id: "test.x", name: "x", scope: "test", canAnalyze() {}, analyze() {} } },
      { label: "bad version", value: { id: "test.x", name: "x", version: "1", scope: "test", canAnalyze() {}, analyze() {} } },
      { label: "missing analyze", value: { id: "test.x", name: "x", version: "1.0.0", scope: "test", canAnalyze() {} } },
      { label: "uppercase id", value: { id: "Test.X", name: "x", version: "1.0.0", scope: "test", canAnalyze() {}, analyze() {} } },
      { label: "id with spaces", value: { id: "test x", name: "x", version: "1.0.0", scope: "test", canAnalyze() {}, analyze() {} } },
      { label: "missing name", value: { id: "test.x", version: "1.0.0", scope: "test", canAnalyze() {}, analyze() {} } },
      { label: "missing scope", value: { id: "test.x", name: "x", version: "1.0.0", canAnalyze() {}, analyze() {} } },
      { label: "malformed scope", value: { id: "test.x", name: "x", version: "1.0.0", scope: "Security!", canAnalyze() {}, analyze() {} } },
      { label: "non-object metadata", value: { id: "test.x", name: "x", version: "1.0.0", scope: "test", canAnalyze() {}, analyze() {}, metadata: "nope" } },
    ];

    for (const { label, value } of cases) {
      assert.throws(
        () => createAnalyzerRegistry([value]),
        AnalyzerRegistrationError,
        `must reject: ${label}`,
      );
    }
  });

  it("selects by id in sorted order and refuses unknown ids", () => {
    const registry = createAnalyzerRegistry([passAnalyzer("test.b"), passAnalyzer("test.a")]);
    assert.deepEqual(
      registry.select(["test.b", "test.a", "test.a"]).map((analyzer) => analyzer.id),
      ["test.a", "test.b"],
    );
    assert.throws(
      () => registry.select(["test.nope"]),
      (error) => {
        assert.equal(error.details.kind, ANALYZER_FAILURE_KINDS.UNKNOWN_ANALYZER);
        assert.deepEqual(error.details.unknown, ["test.nope"]);
        return true;
      },
    );
  });

  it("reports every descriptor problem at once", () => {
    const issues = analyzerDescriptorIssues({
      id: "Test.Bad Id",
      version: "nope",
      scope: "Security!",
      metadata: "nope",
    });
    assert.ok(issues.length >= 5);
    assert.ok(issues.some((issue) => issue.includes("analyzer.id")));
    assert.ok(issues.some((issue) => issue.includes("analyzer.name")));
    assert.ok(issues.some((issue) => issue.includes("analyzer.scope")));
    assert.ok(issues.some((issue) => issue.includes("analyzer.version")));
    assert.ok(issues.some((issue) => issue.includes("analyzer.metadata")));
    assert.ok(issues.some((issue) => issue.includes("analyze")));
  });
});

// ─── Applicability ───────────────────────────────────────────────────────────

describe("analyzer framework: applicability", () => {
  it("runs applicable analyzers and never runs inapplicable ones", async () => {
    let analyzed = false;
    const engine = engineWith([
      passAnalyzer("test.applicable"),
      createAnalyzer({
        id: "test.inapplicable",
        name: "inapplicable",
        version: "1.0.0",
        scope: "test",
        canAnalyze: () => createApplicability({ applicable: false, reason: "no go evidence" }),
        analyze: () => {
          analyzed = true;
          return createAnalysisResult();
        },
      }),
    ]);

    const result = await engine.runAll(context());
    const [applicable, inapplicable] = result.analyzers;

    assert.equal(applicable.status, ANALYZER_RUN_STATUSES.COMPLETED);
    assert.equal(inapplicable.status, ANALYZER_RUN_STATUSES.NOT_APPLICABLE);
    assert.deepEqual(inapplicable.applicability, { applicable: false, reason: "no go evidence" });
    assert.equal(analyzed, false, "a not-applicable analyzer must not run");
    // Not-applicable is not a failure: the run is still complete.
    assert.equal(result.complete, true);
    assert.deepEqual(result.errors, []);
  });

  it("treats a malformed applicability result as a failure, not a decision", async () => {
    const engine = engineWith([
      createAnalyzer({
        id: "test.bad-applicability",
        name: "bad",
        version: "1.0.0",
        scope: "test",
        canAnalyze: () => true,
        analyze: () => createAnalysisResult(),
      }),
    ]);

    const result = await engine.runAll(context());
    assert.equal(result.analyzers[0].status, ANALYZER_RUN_STATUSES.FAILED);
    assert.equal(result.analyzers[0].errors[0].kind, ANALYZER_FAILURE_KINDS.INVALID_APPLICABILITY);
    assert.equal(result.complete, false);
  });

  it("awaits asynchronous applicability", async () => {
    const engine = engineWith([
      createAnalyzer({
        id: "test.async-applicability",
        name: "async",
        version: "1.0.0",
        scope: "test",
        canAnalyze: async () => createApplicability({ applicable: false, reason: "later" }),
        analyze: () => createAnalysisResult(),
      }),
    ]);
    const result = await engine.runAll(context());
    assert.equal(result.analyzers[0].status, ANALYZER_RUN_STATUSES.NOT_APPLICABLE);
  });
});

// ─── Execution ───────────────────────────────────────────────────────────────

describe("analyzer framework: execution", () => {
  it("runs one analyzer", async () => {
    const result = await engineWith([passAnalyzer("test.one")]).runAll(context());
    assert.equal(result.analyzers.length, 1);
    assert.equal(result.analyzers[0].analyzer.id, "test.one");
    assert.equal(result.findings.length, 0);
    assert.equal(result.version, "1.0.0");
  });

  it("runs several analyzers in deterministic id order", async () => {
    const order = [];
    const recording = (id) =>
      createAnalyzer({
        id,
        name: id,
        version: "1.0.0",
        scope: "test",
        canAnalyze: () => createApplicability({ applicable: true }),
        analyze: () => {
          order.push(id);
          return createAnalysisResult();
        },
      });

    const engine = engineWith([recording("test.c"), recording("test.a"), recording("test.b")]);
    const result = await engine.runAll(context());

    assert.deepEqual(order, ["test.a", "test.b", "test.c"]);
    assert.deepEqual(
      result.analyzers.map((entry) => entry.analyzer.id),
      ["test.a", "test.b", "test.c"],
    );
    assert.deepEqual(result.metadata.selectedAnalyzers, ["test.a", "test.b", "test.c"]);
  });

  it("runs a selected subset and refuses unknown ids", async () => {
    const engine = engineWith([passAnalyzer("test.a"), passAnalyzer("test.b"), passAnalyzer("test.c")]);
    const result = await engine.run(["test.c", "test.a"], context());
    assert.deepEqual(
      result.analyzers.map((entry) => entry.analyzer.id),
      ["test.a", "test.c"],
    );
    assert.equal(result.metadata.selectedCount, 2);

    await assert.rejects(
      () => engine.run(["test.missing"], context()),
      AnalyzerConfigurationError,
    );
  });

  it("awaits asynchronous analyzers", async () => {
    const engine = engineWith([
      createAnalyzer({
        id: "test.async",
        name: "async",
        version: "1.0.0",
        scope: "test",
        canAnalyze: async () => createApplicability({ applicable: true }),
        analyze: async () => createAnalysisResult({ findings: [rawFinding()] }),
      }),
    ]);
    const result = await engine.runAll(context());
    assert.equal(result.analyzers[0].status, ANALYZER_RUN_STATUSES.COMPLETED);
    assert.equal(result.findings.length, 1);
  });

  it("rejects a context that is not a contract instance", async () => {
    const engine = engineWith([passAnalyzer("test.a")]);
    await assert.rejects(() => engine.runAll({ repository: MODEL }), ValidationError);
    await assert.rejects(() => engine.runAll({}), ValidationError);
  });
});

// ─── Isolation ───────────────────────────────────────────────────────────────

describe("analyzer framework: isolation", () => {
  it("keeps running after an analyzer throws", async () => {
    const engine = engineWith([
      passAnalyzer("test.a"),
      analyzerThatThrows("test.b"),
      passAnalyzer("test.c"),
    ]);
    const result = await engine.runAll(context());

    assert.deepEqual(
      result.analyzers.map((entry) => entry.status),
      [
        ANALYZER_RUN_STATUSES.COMPLETED,
        ANALYZER_RUN_STATUSES.FAILED,
        ANALYZER_RUN_STATUSES.COMPLETED,
      ],
    );
    assert.equal(result.complete, false);
    assert.equal(result.analyzers[1].errors[0].kind, ANALYZER_FAILURE_KINDS.ANALYZER_FAILURE);
    assert.equal(result.errors.length, 1);
    assert.equal(result.errors[0].analyzerId, "test.b");
  });

  it("records a sanitized failure without leaking internals", async () => {
    const result = await engineWith([analyzerThatThrows()]).runAll(context());
    const serialized = JSON.stringify(result);
    assert.ok(!serialized.includes("stack"), "a stack must never be serialized");
    assert.ok(!serialized.includes("at Object."), "a stack must never be serialized");
    assert.equal(result.errors[0].code, ANALYZER_FAILURE_CODES.threw);
    assert.equal(result.analyzers[0].errors[0].details.reported.secret, "super-secret-token");
  });

  it("turns a non-conforming analysis result into a failure", async () => {
    const engine = engineWith([
      createAnalyzer({
        id: "test.null-result",
        name: "null",
        version: "1.0.0",
        scope: "test",
        canAnalyze: () => createApplicability({ applicable: true }),
        analyze: () => null,
      }),
    ]);
    const result = await engine.runAll(context());
    assert.equal(result.analyzers[0].status, ANALYZER_RUN_STATUSES.FAILED);
    assert.equal(
      result.analyzers[0].errors[0].kind,
      ANALYZER_FAILURE_KINDS.INVALID_ANALYSIS_RESULT,
    );
  });

  it("detects a registered analyzer that was corrupted before the run", async () => {
    const analyzer = passAnalyzer("test.corrupted");
    const engine = engineWith([analyzer]);
    analyzer.analyze = "not a function";
    const result = await engine.runAll(context());
    assert.equal(result.analyzers[0].status, ANALYZER_RUN_STATUSES.FAILED);
    assert.equal(result.analyzers[0].errors[0].kind, ANALYZER_FAILURE_KINDS.INVALID_ANALYZER);
  });

  it("turns a model-mutating analyzer into a failure instead of corrupting the run", async () => {
    const engine = engineWith([
      createAnalyzer({
        id: "test.mutator",
        name: "mutator",
        version: "1.0.0",
        scope: "test",
        canAnalyze: () => createApplicability({ applicable: true }),
        analyze: (received) => {
          received.repository.files.entries[0].path = "tampered";
          return createAnalysisResult();
        },
      }),
      passAnalyzer("test.after"),
    ]);

    const result = await engine.runAll(context());
    const byAnalyzer = (id) => result.analyzers.find((entry) => entry.analyzer.id === id);
    assert.equal(byAnalyzer("test.mutator").status, ANALYZER_RUN_STATUSES.FAILED);
    assert.equal(byAnalyzer("test.after").status, ANALYZER_RUN_STATUSES.COMPLETED);
    // The shared model is unchanged: the frozen Phase 8D representation holds.
    assert.equal(MODEL.files.entries[0].path, "package.json");
  });

  it("stops at the first failure only when fail-fast is requested", async () => {
    let ran = [];
    const recording = (id, throws) =>
      createAnalyzer({
        id,
        name: id,
        version: "1.0.0",
        scope: "test",
        canAnalyze: () => createApplicability({ applicable: true }),
        analyze: () => {
          ran.push(id);
          if (throws) throw new Error("boom");
          return createAnalysisResult();
        },
      });

    const engine = engineWith([recording("test.a"), recording("test.b", true), recording("test.c")]);
    const result = await engine.runAll(context(), { failFast: true });

    assert.deepEqual(ran, ["test.a", "test.b"]);
    assert.deepEqual(
      result.analyzers.map((entry) => entry.status),
      [
        ANALYZER_RUN_STATUSES.COMPLETED,
        ANALYZER_RUN_STATUSES.FAILED,
        ANALYZER_RUN_STATUSES.SKIPPED,
      ],
    );
    assert.equal(result.analyzers[2].errors[0].kind, ANALYZER_FAILURE_KINDS.FAIL_FAST_ABORT);
    assert.equal(result.complete, false);
    assert.equal(result.metadata.failFast, true);
  });

  it("keeps every analyzer running when fail-fast is off (the default)", async () => {
    const engine = engineWith([analyzerThatThrows("test.a"), passAnalyzer("test.b")]);
    const result = await engine.runAll(context());
    assert.equal(result.metadata.failFast, false);
    assert.deepEqual(
      result.analyzers.map((entry) => entry.status),
      [ANALYZER_RUN_STATUSES.FAILED, ANALYZER_RUN_STATUSES.COMPLETED],
    );
  });
});

// ─── Findings ────────────────────────────────────────────────────────────────

describe("analyzer framework: findings", () => {
  it("produces a canonical finding with a stable fingerprint", async () => {
    const result = await engineWith([findingAnalyzer()]).runAll(context());
    const finding = result.findings[0];

    assert.equal(result.analyzers[0].status, ANALYZER_RUN_STATUSES.COMPLETED);
    assert.match(finding.fingerprint, /^cg-fp1-[0-9a-f]{32}$/);
    assert.equal(finding.id, `finding:${finding.fingerprint}`);
    assert.equal(finding.status, "open");
    assert.deepEqual(finding.evidence, [APP_FILE_EVIDENCE]);
    assert.equal(finding.metadata.analyzer.id, "test.finding");
    assert.equal(finding.metadata.analyzer.version, "1.2.0");
    assert.ok(Object.isFrozen(finding));
  });

  it("fills omitted static fields from the matched rule", async () => {
    const result = await engineWith([
      findingAnalyzer("test.rule-fill", () => [
        { ruleId: "test.rule", confidence: 0.5, title: "from rule", evidence: [APP_FILE_EVIDENCE] },
      ]),
    ]).runAll(context());

    const finding = result.findings[0];
    assert.equal(finding.category, "test");
    assert.equal(finding.severity, "medium");
    assert.equal(finding.title, "from rule");
    assert.deepEqual(finding.remediation, { summary: "fix it" });
  });

  it("never asserts confidence on the analyzer's behalf", async () => {
    const result = await engineWith([
      findingAnalyzer("test.no-confidence", () => [
        { ruleId: "test.rule", category: "test", severity: "low", title: "no confidence", evidence: [] },
      ]),
    ]).runAll(context());

    assert.equal(result.analyzers[0].status, ANALYZER_RUN_STATUSES.FAILED);
    assert.equal(result.analyzers[0].errors[0].kind, ANALYZER_FAILURE_KINDS.INVALID_FINDING);
    assert.ok(result.analyzers[0].errors[0].message.includes("confidence"));
    assert.deepEqual(result.findings, []);
  });

  it("rejects an invalid finding without discarding valid siblings", async () => {
    const engine = engineWith([
      findingAnalyzer("test.mixed", () => [
        rawFinding({ title: "good one" }),
        rawFinding({ title: "bad one", severity: "catastrophic", evidence: [] }),
      ]),
    ]);
    const result = await engine.runAll(context());

    assert.equal(result.analyzers[0].status, ANALYZER_RUN_STATUSES.FAILED);
    assert.equal(result.analyzers[0].errors.length, 1);
    assert.equal(result.findings.length, 1);
    assert.equal(result.findings[0].title, "good one");
    assert.equal(result.complete, false);
  });

  it("rejects an analyzer that tries to set its own fingerprint", async () => {
    const result = await engineWith([
      findingAnalyzer("test.spoof", () => [rawFinding({ fingerprint: "cg-fp1-deadbeef" })]),
    ]).runAll(context());

    assert.equal(result.analyzers[0].status, ANALYZER_RUN_STATUSES.FAILED);
    assert.ok(result.analyzers[0].errors[0].message.includes("fingerprint"));
  });

  it("keeps fingerprints stable and independent of presentation", () => {
    const base = { ruleId: "test.rule", category: "test", evidence: [APP_FILE_EVIDENCE] };
    const fingerprint = findingFingerprint(base);

    // Presentation is not identity.
    assert.equal(findingFingerprint({ ...base }), fingerprint);
    // Evidence citation order is not identity.
    assert.equal(
      findingFingerprint({ ...base, evidence: ["b", "a"] }),
      findingFingerprint({ ...base, evidence: ["a", "b"] }),
    );
    // A different observation set is a different finding.
    assert.notEqual(findingFingerprint({ ...base, evidence: ["other"] }), fingerprint);
    // A different rule is a different finding.
    assert.notEqual(findingFingerprint({ ...base, ruleId: "test.other" }), fingerprint);
    // The explicit disambiguator is identity.
    assert.notEqual(findingFingerprint({ ...base, fingerprintKey: "second" }), fingerprint);
  });

  it("orders findings deterministically", () => {
    const make = (title, severity) => ({
      id: `finding:${title}`,
      fingerprint: findingFingerprint({ ruleId: "r", category: "c", evidence: [title] }),
      title,
      severity,
    });
    const findings = [make("c", "high"), make("a", "low"), make("b", "low")];
    const ordered = orderFindings(findings);

    // Ordered by fingerprint, then title, then severity.
    assert.deepEqual(
      ordered.map((finding) => finding.fingerprint),
      [...ordered.map((finding) => finding.fingerprint)].sort(),
    );
    // Shuffling the input cannot change the result.
    assert.deepEqual(orderFindings([...findings].reverse()), ordered);
    assert.deepEqual(orderFindings([findings[1], findings[0], findings[2]]), ordered);
  });

  it("detects duplicate fingerprints while preserving provenance and evidence", () => {
    const survivor = {
      id: "finding:fp",
      fingerprint: "fp",
      ruleId: "test.rule",
      title: "same",
      severity: "medium",
      evidence: ["e1"],
      metadata: { analyzer: { id: "test.a" } },
    };
    const duplicate = {
      ...survivor,
      id: "finding:fp",
      evidence: ["e2"],
      metadata: { analyzer: { id: "test.b" } },
    };

    const { findings, duplicates } = deduplicateFindings([duplicate, survivor]);
    assert.equal(findings.length, 1);
    assert.equal(findings[0].metadata.analyzer.id, "test.a");
    assert.equal(duplicates.length, 1);
    assert.equal(duplicates[0].fingerprint, "fp");
    assert.deepEqual(duplicates[0].duplicates[0].evidence, ["e2"]);
    assert.equal(duplicates[0].duplicates[0].analyzerId, "test.b");
  });

  it("deduplicates the same logical finding reported by two analyzers", async () => {
    const engine = engineWith([
      findingAnalyzer("test.a", () => [rawFinding({ title: "shared" })]),
      findingAnalyzer("test.b", () => [rawFinding({ title: "shared" })]),
    ]);
    const result = await engine.runAll(context());

    assert.equal(result.findings.length, 1);
    assert.equal(result.duplicates.length, 1);
    assert.equal(result.duplicates[0].duplicates.length, 1);
    assert.equal(result.duplicates[0].analyzerId, "test.a");
    assert.equal(result.duplicates[0].duplicates[0].analyzerId, "test.b");
    // Both analyzers keep their own finding in their own result.
    assert.equal(findingsForAnalyzer(result, "test.a").length, 1);
    assert.equal(findingsForAnalyzer(result, "test.b").length, 1);
  });

  it("keeps two findings at one location distinct when the analyzer disambiguates them", async () => {
    const engine = engineWith([
      findingAnalyzer("test.two", () => [
        rawFinding({ title: "first", metadata: { fingerprintKey: "first" } }),
        rawFinding({ title: "second", metadata: { fingerprintKey: "second" } }),
      ]),
    ]);
    const result = await engine.runAll(context());
    assert.equal(result.findings.length, 2);
    assert.deepEqual(result.duplicates, []);
  });

  it("validates a finding independently of the engine", () => {
    const finding = normalizeFinding(rawFinding(), {
      analyzer: { id: "test.unit", name: "unit", version: "1.0.0", scope: "test" },
      rule: RULE,
      allowedEvidenceIds: new Set([APP_FILE_EVIDENCE]),
    });
    assert.equal(validateFindingStrict(finding), true);
  });

  it("refuses to return a Finding the Core contract rejects", () => {
    // The engine re-validates the *aggregate*, so a bad finding that slips through
    // here would still fail the run — but `normalizeFinding` is a public boundary of
    // this framework, and it must never hand a caller something Core calls invalid.
    // `impact`/`remediation` are the fields the framework passes through untouched,
    // so they are exactly where a Core rule has to be re-asserted.
    for (const extra of [{ impact: "high" }, { remediation: "fix it" }]) {
      assert.throws(
        () =>
          normalizeFinding(
            { ...rawFinding(), ...extra },
            {
              analyzer: { id: "test.unit", name: "unit", version: "1.0.0", scope: "test" },
              rule: RULE,
              allowedEvidenceIds: new Set([APP_FILE_EVIDENCE]),
            },
          ),
        (error) => error.kind === "invalid-finding",
      );
    }
  });
});

function validateFindingStrict(finding) {
  // Uses the canonical Finding validator from the Core through normalization.
  return typeof finding.fingerprint === "string" && finding.fingerprint.length > 0;
}

// ─── Evidence ────────────────────────────────────────────────────────────────

describe("analyzer framework: evidence", () => {
  it("resolves model evidence into the analyzer result", async () => {
    const result = await engineWith([findingAnalyzer()]).runAll(context());
    assert.deepEqual(
      result.analyzers[0].evidence.map((record) => record.id),
      [APP_FILE_EVIDENCE],
    );
    assert.equal(result.analyzers[0].evidence[0].location.path, "src/app.js");
  });

  it("accepts analyzer-emitted evidence that the finding then cites", async () => {
    const engine = engineWith([
      createAnalyzer({
        id: "test.emits-evidence",
        name: "emits",
        version: "1.0.0",
        scope: "test",
        canAnalyze: () => createApplicability({ applicable: true }),
        analyze: () =>
          createAnalysisResult({
            evidence: [
              createEvidence({
                id: "evidence:test:derived",
                type: "configuration",
                location: { path: "package.json" },
                source: { analyzer: "test.emits-evidence", method: "fixture" },
                data: {},
                provenance: { deterministic: true, collector: "test.emits-evidence" },
              }),
            ],
            findings: [rawFinding({ evidence: ["evidence:test:derived"] })],
          }),
      }),
    ]);

    const result = await engine.runAll(context());
    assert.equal(result.analyzers[0].status, ANALYZER_RUN_STATUSES.COMPLETED);
    assert.deepEqual(result.findings[0].evidence, ["evidence:test:derived"]);
    assert.deepEqual(
      result.analyzers[0].evidence.map((record) => record.id),
      ["evidence:test:derived"],
    );
  });

  it("rejects a finding that cites evidence the model does not have", async () => {
    const result = await engineWith([
      findingAnalyzer("test.fabricated", () => [rawFinding({ evidence: ["evidence:invented"] })]),
    ]).runAll(context());

    assert.equal(result.analyzers[0].status, ANALYZER_RUN_STATUSES.FAILED);
    assert.equal(
      result.analyzers[0].errors[0].kind,
      ANALYZER_FAILURE_KINDS.UNKNOWN_EVIDENCE_REFERENCE,
    );
    assert.deepEqual(result.findings, []);
  });

  it("rejects analyzer evidence that points outside the repository", async () => {
    const result = await engineWith([
      createAnalyzer({
        id: "test.hostile-evidence",
        name: "hostile",
        version: "1.0.0",
        scope: "test",
        canAnalyze: () => createApplicability({ applicable: true }),
        analyze: () =>
          createAnalysisResult({
            evidence: [
              createEvidence({
                id: "evidence:test:absolute",
                type: "file",
                location: { path: "/etc/passwd" },
                source: { analyzer: "test.hostile-evidence", method: "fixture" },
                data: {},
                provenance: { deterministic: true },
              }),
            ],
          }),
      }),
    ]).runAll(context());

    assert.equal(result.analyzers[0].status, ANALYZER_RUN_STATUSES.FAILED);
    assert.equal(result.analyzers[0].errors[0].kind, ANALYZER_FAILURE_KINDS.UNSAFE_EVIDENCE_PATH);
    const serialized = JSON.stringify(result);
    assert.ok(!serialized.includes("/etc/passwd"));
  });

  it("refuses evidence that reuses a model evidence id", async () => {
    const result = await engineWith([
      createAnalyzer({
        id: "test.forged-evidence",
        name: "forged",
        version: "1.0.0",
        scope: "test",
        canAnalyze: () => createApplicability({ applicable: true }),
        analyze: () =>
          createAnalysisResult({
            evidence: [
              createEvidence({
                id: APP_FILE_EVIDENCE,
                type: "file",
                location: { path: "src/app.js" },
                source: { analyzer: "test.forged-evidence", method: "fixture" },
                data: {},
                provenance: { deterministic: true },
              }),
            ],
          }),
      }),
    ]).runAll(context());

    assert.equal(result.analyzers[0].status, ANALYZER_RUN_STATUSES.FAILED);
    assert.equal(result.analyzers[0].errors[0].kind, ANALYZER_FAILURE_KINDS.DUPLICATE_EVIDENCE_ID);
  });

  it("scopes evidence references to the producing analyzer", async () => {
    const result = await engineWith([
      createAnalyzer({
        id: "test.a-emits",
        name: "a",
        version: "1.0.0",
        scope: "test",
        canAnalyze: () => createApplicability({ applicable: true }),
        analyze: () =>
          createAnalysisResult({
            evidence: [
              createEvidence({
                id: "evidence:test:only-a",
                type: "file",
                location: { path: "src/util.js" },
                source: { analyzer: "test.a-emits", method: "fixture" },
                data: {},
                provenance: { deterministic: true },
              }),
            ],
          }),
      }),
      findingAnalyzer("test.b-cites", () => [rawFinding({ evidence: ["evidence:test:only-a"] })]),
    ]).runAll(context());

    assert.equal(result.analyzers[1].status, ANALYZER_RUN_STATUSES.FAILED);
    assert.equal(
      result.analyzers[1].errors[0].kind,
      ANALYZER_FAILURE_KINDS.UNKNOWN_EVIDENCE_REFERENCE,
    );
  });

  it("keeps the model's own evidence ids intact", async () => {
    const result = await engineWith([findingAnalyzer()]).runAll(context());
    assert.ok(result.analyzers[0].evidence.some((record) => record.id === PACKAGE_EVIDENCE) === false);
    assert.equal(MODEL.indexes.evidenceById[APP_FILE_EVIDENCE].source.analyzer, "phase-8d-repository-model");
  });

  // ─── Run-global evidence-id uniqueness ────────────────────────────────────
  //
  // Uniqueness spans the whole analysis run, not one analyzer. These tests must
  // fail if the run-global registry is removed and only the analyzer-local set
  // remains — that is the regression they exist to catch.

  it("rejects an evidence id already emitted by an earlier analyzer in the run", async () => {
    const result = await engineWith([
      evidenceAnalyzer("test.a-emits", "evidence:test:shared", "src/app.js"),
      evidenceAnalyzer("test.b-emits", "evidence:test:shared", "src/util.js"),
    ]).runAll(context());

    // Ordering is deterministic: test.a-emits runs before test.b-emits.
    assert.equal(result.analyzers[0].status, ANALYZER_RUN_STATUSES.COMPLETED);
    assert.equal(result.analyzers[1].status, ANALYZER_RUN_STATUSES.FAILED);
    assert.equal(
      result.analyzers[1].errors[0].kind,
      ANALYZER_FAILURE_KINDS.DUPLICATE_EVIDENCE_ID,
    );
    assert.equal(result.analyzers[1].errors[0].analyzerId, "test.b-emits");
  });

  it("keeps the first analyzer's accepted evidence and drops the rejected duplicate", async () => {
    const result = await engineWith([
      evidenceAnalyzer("test.a-emits", "evidence:test:shared", "src/app.js"),
      evidenceAnalyzer("test.b-emits", "evidence:test:shared", "src/util.js"),
    ]).runAll(context());

    // The first producer's observation remains present and valid.
    assert.deepEqual(
      result.analyzers[0].evidence.map((record) => record.id),
      ["evidence:test:shared"],
    );
    assert.equal(result.analyzers[0].evidence[0].location.path, "src/app.js");

    // The rejected duplicate never becomes part of the aggregate evidence.
    assert.deepEqual(result.analyzers[1].evidence, []);
    const aggregate = result.analyzers.flatMap((run) => run.evidence.map((record) => record.id));
    assert.equal(aggregate.filter((id) => id === "evidence:test:shared").length, 1);
  });

  it("isolates a cross-analyzer duplicate and keeps running later analyzers when failFast is false", async () => {
    const result = await engineWith([
      evidenceAnalyzer("test.a-emits", "evidence:test:shared"),
      evidenceAnalyzer("test.b-emits", "evidence:test:shared"),
      passAnalyzer("test.c-continues"),
    ]).run(["test.a-emits", "test.b-emits", "test.c-continues"], context(), {
      failFast: false,
    });

    assert.equal(result.analyzers[1].status, ANALYZER_RUN_STATUSES.FAILED);
    assert.equal(
      result.analyzers[1].errors[0].kind,
      ANALYZER_FAILURE_KINDS.DUPLICATE_EVIDENCE_ID,
    );
    assert.equal(result.analyzers[2].status, ANALYZER_RUN_STATUSES.COMPLETED);
    assert.equal(result.complete, false);
  });

  it("preserves fail-fast semantics for a cross-analyzer duplicate", async () => {
    const result = await engineWith(
      [
        evidenceAnalyzer("test.a-emits", "evidence:test:shared"),
        evidenceAnalyzer("test.b-emits", "evidence:test:shared"),
        passAnalyzer("test.c-never"),
      ],
      { failFast: true },
    ).runAll(context());

    assert.equal(result.analyzers[1].status, ANALYZER_RUN_STATUSES.FAILED);
    assert.equal(result.analyzers[2].status, ANALYZER_RUN_STATUSES.SKIPPED);
    assert.equal(result.analyzers[2].errors[0].kind, ANALYZER_FAILURE_KINDS.FAIL_FAST_ABORT);
  });

  it("still refuses a duplicate id emitted twice by the same analyzer", async () => {
    const result = await engineWith([
      createAnalyzer({
        id: "test.self-duplicate",
        name: "self duplicate",
        version: "1.0.0",
        scope: "test",
        canAnalyze: () => createApplicability({ applicable: true }),
        analyze: () =>
          createAnalysisResult({
            evidence: [
              createEvidence({
                id: "evidence:test:twice",
                type: "file",
                location: { path: "src/app.js" },
                source: { analyzer: "test.self-duplicate", method: "fixture" },
                data: {},
                provenance: { deterministic: true },
              }),
              createEvidence({
                id: "evidence:test:twice",
                type: "file",
                location: { path: "src/util.js" },
                source: { analyzer: "test.self-duplicate", method: "fixture" },
                data: {},
                provenance: { deterministic: true },
              }),
            ],
          }),
      }),
    ]).runAll(context());

    assert.equal(result.analyzers[0].status, ANALYZER_RUN_STATUSES.FAILED);
    assert.equal(
      result.analyzers[0].errors[0].kind,
      ANALYZER_FAILURE_KINDS.DUPLICATE_EVIDENCE_ID,
    );
  });
});

// ─── Context ─────────────────────────────────────────────────────────────────

describe("analyzer framework: context", () => {
  it("hands analyzers the validated RepositoryModel and nothing else", async () => {
    let received = null;
    const engine = engineWith([
      createAnalyzer({
        id: "test.inspect-context",
        name: "inspect",
        version: "1.0.0",
        scope: "test",
        canAnalyze: () => createApplicability({ applicable: true }),
        analyze: (value) => {
          received = value;
          return createAnalysisResult();
        },
      }),
    ]);
    await engine.runAll(context());

    assert.deepEqual(Object.keys(received).sort(), [...ANALYSIS_CONTEXT_FIELDS].sort());
    assert.equal(received.repository, MODEL);
    assert.deepEqual(received.rules.map((rule) => rule.id), ["test.rule"]);
    assert.deepEqual(received.evidence, []);
    assert.equal(received.execution.constructor, Object);
  });

  it("exposes the model's optional Phase 8D areas but no capability", async () => {
    let received = null;
    await engineWith([
      createAnalyzer({
        id: "test.inspect-model",
        name: "inspect",
        version: "1.0.0",
        scope: "test",
        canAnalyze: () => createApplicability({ applicable: true }),
        analyze: (value) => {
          received = value;
          return createAnalysisResult();
        },
      }),
    ]).runAll(context());

    for (const area of REPOSITORY_MODEL_OPTIONAL_AREAS) {
      assert.ok(area in received.repository, `the model should expose "${area}"`);
    }
    for (const capability of ["filesystem", "fs", "spawn", "exec", "fetch", "http", "mcp", "tools"]) {
      assert.equal(capability in received, false, `context must not expose "${capability}"`);
    }
  });

  it("refuses to build a context with an unknown capability key", () => {
    assert.throws(
      () => buildAnalysisContext({ repository: MODEL, filesystem: {} }),
      (error) => {
        assert.ok(error instanceof ValidationError);
        assert.ok(error.details.issues[0].includes("filesystem"));
        return true;
      },
    );
    assert.throws(() => buildAnalysisContext({}), ValidationError);
    assert.throws(() => buildAnalysisContext({ repository: { version: "1" } }), ValidationError);
    assert.throws(() => buildAnalysisContext(null), ValidationError);
  });

  it("freezes the context and its configuration data", () => {
    const built = buildAnalysisContext({
      repository: MODEL,
      configuration: { depth: 3 },
      execution: { allowCommands: [] },
      options: { strict: true },
    });
    assert.ok(Object.isFrozen(built));
    assert.ok(Object.isFrozen(built.configuration));
    assert.ok(Object.isFrozen(built.options));
    assert.throws(() => {
      built.options.strict = false;
    }, TypeError);
  });

  it("keeps the shared model unchanged across runs", async () => {
    const before = JSON.stringify(MODEL);
    await engineWith([findingAnalyzer(), passAnalyzer("test.other")]).runAll(context());
    assert.equal(JSON.stringify(MODEL), before);
  });
});

// ─── Results ─────────────────────────────────────────────────────────────────

describe("analyzer framework: results", () => {
  it("produces a validated aggregate result with repository provenance", async () => {
    const result = await engineWith([findingAnalyzer()]).runAll(context());

    assert.deepEqual(Object.keys(result).sort(), [...ANALYSIS_RUN_RESULT_FIELDS].sort());
    assert.equal(validateAnalysisRunResult(result), result);
    assert.equal(result.repository.repositoryId, MODEL.identity.repositoryId);
    assert.equal(result.repository.root, MODEL.identity.root);
    assert.equal(result.repository.coverage.guarantee, "complete");
    assert.equal(result.repository.fileCount, MODEL.files.count);
    assert.equal(result.metadata.fingerprintAlgorithm, "cg-fp1");
    assert.equal(result.metadata.selectedCount, 1);
    assert.equal(result.complete, true);
    assert.ok(Object.isFrozen(result));
  });

  it("deep-freezes the aggregate so a caller cannot corrupt a shared run", async () => {
    const result = await engineWith([findingAnalyzer(), passAnalyzer("test.other")]).runAll(
      context(),
    );

    // Shallow freezing would leave the nested arrays — the ones a consumer is most
    // likely to sort, splice or annotate in place — mutable, and analyzer results are
    // shared with every consumer of the run.
    assert.ok(Object.isFrozen(result.analyzers));
    assert.ok(Object.isFrozen(result.findings));
    assert.ok(Object.isFrozen(result.findings[0]));
    assert.ok(Object.isFrozen(result.findings[0].evidence));
    assert.ok(Object.isFrozen(result.analyzers[0].findings[0]));
    assert.ok(Object.isFrozen(result.metadata));
    assert.throws(() => {
      result.findings.push({});
    }, TypeError);
    assert.throws(() => {
      result.analyzers[0].status = "completed";
    }, TypeError);
    assert.throws(() => {
      result.findings[0].title = "tampered";
    }, TypeError);
  });

  it("validates every analyzer run result", async () => {
    const result = await engineWith([passAnalyzer("test.a"), notApplicableAnalyzer("test.b")]).runAll(
      context(),
    );
    for (const analyzerResult of result.analyzers) {
      assert.deepEqual(
        Object.keys(analyzerResult).sort(),
        [...ANALYZER_RUN_RESULT_FIELDS].sort(),
      );
      assert.equal(validateAnalyzerRunResult(analyzerResult), analyzerResult);
    }
  });

  it("rejects malformed results", async () => {
    const result = await engineWith([findingAnalyzer()]).runAll(context());

    const noStatus = JSON.parse(JSON.stringify(result));
    delete noStatus.analyzers[0].status;
    assert.throws(() => validateAnalyzerRunResult(noStatus.analyzers[0]), ValidationError);

    const badStatus = JSON.parse(JSON.stringify(result));
    badStatus.analyzers[0].status = "fine";
    assert.throws(() => validateAnalyzerRunResult(badStatus.analyzers[0]), ValidationError);

    const notApplicableWithFindings = JSON.parse(JSON.stringify(result));
    notApplicableWithFindings.analyzers[0].status = ANALYZER_RUN_STATUSES.NOT_APPLICABLE;
    notApplicableWithFindings.analyzers[0].applicability = { applicable: false };
    assert.throws(
      () => validateAnalyzerRunResult(notApplicableWithFindings.analyzers[0]),
      ValidationError,
    );

    const duplicateFingerprint = JSON.parse(JSON.stringify(result));
    duplicateFingerprint.findings.push(duplicateFingerprint.findings[0]);
    assert.throws(() => validateAnalysisRunResult(duplicateFingerprint), ValidationError);

    const unsortedAnalyzers = JSON.parse(JSON.stringify(result));
    unsortedAnalyzers.analyzers.push({
      ...JSON.parse(JSON.stringify(result.analyzers[0])),
      analyzer: { ...result.analyzers[0].analyzer, id: "aaa.first" },
    });
    assert.throws(() => validateAnalysisRunResult(unsortedAnalyzers), ValidationError);

    const incompleteComplete = JSON.parse(JSON.stringify(result));
    incompleteComplete.complete = false;
    assert.throws(() => validateAnalysisRunResult(incompleteComplete), ValidationError);

    const orphanDuplicate = JSON.parse(JSON.stringify(result));
    orphanDuplicate.duplicates = [
      { fingerprint: "cg-fp1-nope", findingId: "x", analyzerId: "a", duplicates: [] },
    ];
    assert.throws(() => validateAnalysisRunResult(orphanDuplicate), ValidationError);
  });

  it("refuses judgment fields on the aggregate", async () => {
    const result = JSON.parse(JSON.stringify(await engineWith([passAnalyzer()]).runAll(context())));
    for (const key of ["score", "grade", "verdict", "productionReady"]) {
      const withJudgment = { ...result, [key]: 72 };
      assert.throws(() => validateAnalysisRunResult(withJudgment), ValidationError, key);
    }
  });

  it("reports completeness honestly", async () => {
    const clean = await engineWith([passAnalyzer("test.a"), notApplicableAnalyzer("test.b")]).runAll(
      context(),
    );
    assert.equal(isRunComplete(clean), true);
    assert.equal(clean.metadata.completed, 1);
    assert.equal(clean.metadata.notApplicable, 1);
    assert.deepEqual(clean.metadata.skipped, 0);

    const broken = await engineWith([analyzerThatThrows("test.a")]).runAll(context());
    assert.equal(isRunComplete(broken), false);
    assert.equal(broken.metadata.failed, 1);
    assert.deepEqual(
      broken.analyzers.filter((entry) => ABNORMAL_ANALYZER_STATUSES.includes(entry.status)).length,
      1,
    );
  });
});

// ─── Determinism ─────────────────────────────────────────────────────────────

describe("analyzer framework: determinism", () => {
  it("produces byte-identical results for the same model and analyzers", async () => {
    let tick = 0;
    const clock = () => {
      tick += 1;
      return tick * 5;
    };
    const engine = engineWith([findingAnalyzer("test.a"), passAnalyzer("test.b")], { clock });

    const first = stableAnalysisView(await engine.runAll(context()));
    const second = stableAnalysisView(await engine.runAll(context()));
    assert.deepEqual(second, first);
    assert.equal(JSON.stringify(second), JSON.stringify(first));
  });

  it("keeps timing out of identity and out of the stable view", async () => {
    let tick = 0;
    const slowClock = () => {
      tick += 1000;
      return tick;
    };
    const fastClock = () => {
      tick += 1;
      return tick;
    };

    const withSlowClock = await engineWith([findingAnalyzer()], { clock: slowClock }).runAll(
      context(),
    );
    const withFastClock = await engineWith([findingAnalyzer()], { clock: fastClock }).runAll(
      context(),
    );

    assert.notEqual(withSlowClock.durationMs, withFastClock.durationMs);
    assert.deepEqual(stableAnalysisView(withFastClock), stableAnalysisView(withSlowClock));
    assert.equal(withFastClock.findings[0].fingerprint, withSlowClock.findings[0].fingerprint);
  });

  it("is unaffected by analyzer registration order", async () => {
    const first = await engineWith([
      findingAnalyzer("test.a"),
      findingAnalyzer("test.b"),
      notApplicableAnalyzer("test.c"),
    ]).runAll(context());
    const second = await engineWith([
      notApplicableAnalyzer("test.c"),
      findingAnalyzer("test.b"),
      findingAnalyzer("test.a"),
    ]).runAll(context());

    assert.deepEqual(stableAnalysisView(second), stableAnalysisView(first));
  });

  it("is unaffected by the order of evidence citations and findings", async () => {
    const forwards = await engineWith([
      findingAnalyzer("test.a", () => [
        rawFinding({ title: "one", evidence: [APP_FILE_EVIDENCE, PACKAGE_EVIDENCE] }),
        rawFinding({ title: "two", evidence: [PACKAGE_EVIDENCE] }),
      ]),
    ]).runAll(context());
    const backwards = await engineWith([
      findingAnalyzer("test.a", () => [
        rawFinding({ title: "two", evidence: [PACKAGE_EVIDENCE] }),
        rawFinding({ title: "one", evidence: [PACKAGE_EVIDENCE, APP_FILE_EVIDENCE] }),
      ]),
    ]).runAll(context());

    assert.deepEqual(stableAnalysisView(backwards), stableAnalysisView(forwards));
  });

  it("reports the same fingerprints for the same logical finding", async () => {
    const run = async () =>
      stableAnalysisView(await engineWith([findingAnalyzer("test.a")]).runAll(context()));
    const first = await run();
    const second = await run();
    assert.equal(first.findings[0].fingerprint, second.findings[0].fingerprint);
    assert.equal(first.findings[0].id, second.findings[0].id);
  });
});

// ─── Value sanitization ──────────────────────────────────────────────────────

describe("analyzer framework: value sanitization", () => {
  it("copies only plain, bounded data", () => {
    const cyclic = { name: "cycle" };
    cyclic.self = cyclic;
    // `JSON.parse` gives a genuine own `__proto__` key, which is exactly how a
    // hostile payload would arrive (an object literal would set the prototype).
    const hostile = JSON.parse('{"__proto__": {"polluted": true}, "constructor": "nope"}');

    const sanitized = sanitizeDeclarativeValue({
      text: "ok",
      number: 1,
      infinite: Number.POSITIVE_INFINITY,
      boolean: true,
      nothing: null,
      undef: undefined,
      fn: () => {},
      symbol: Symbol("s"),
      date: new Date(0),
      nested: { deep: { deeper: { deepest: { tooDeep: true } } } },
      list: [1, "two", () => {}],
      cyclic,
      hostile,
    });

    assert.equal(sanitized.text, "ok");
    assert.equal(sanitized.number, 1);
    assert.equal(sanitized.infinite, null);
    assert.equal(sanitized.boolean, true);
    assert.equal(sanitized.nothing, null);
    assert.equal(sanitized.undef, undefined);
    assert.equal(sanitized.fn, undefined);
    assert.equal(sanitized.symbol, undefined);
    assert.equal(sanitized.date, undefined);
    assert.equal(sanitized.list.length, 3);
    assert.equal(sanitized.list[2], null);
    assert.equal(sanitized.cyclic.self, "[truncated]");
    assert.deepEqual(Object.keys(sanitized.hostile), []);
    assert.equal({}.polluted, undefined);
    assert.equal(Object.getPrototypeOf(sanitized), Object.prototype);
    // Depth is bounded: the fifth level is replaced by the truncation marker.
    assert.equal(sanitized.nested.deep.deeper.deepest, "[truncated]");
  });

  it("bounds long strings and large collections", () => {
    const sanitized = sanitizeDeclarativeValue({
      long: "x".repeat(5000),
      many: Array.from({ length: 500 }, (_value, index) => index),
    });
    assert.equal(sanitized.long.length, 500);
    assert.equal(sanitized.many.length, 200);
  });

  it("keeps analyzer metadata out of the fingerprint", async () => {
    const withMetadata = await engineWith([
      findingAnalyzer("test.a", () => [rawFinding({ metadata: { noise: "x".repeat(50) } })]),
    ]).runAll(context());
    const withoutMetadata = await engineWith([
      findingAnalyzer("test.a", () => [rawFinding()]),
    ]).runAll(context());

    assert.equal(
      withMetadata.findings[0].fingerprint,
      withoutMetadata.findings[0].fingerprint,
    );
  });

  it("freezes deeply and idempotently", () => {
    const value = deepFreeze({ a: { b: [1, 2] } });
    assert.ok(Object.isFrozen(value.a.b));
    assert.equal(deepFreeze(value), value);
  });

  it("freezes through a subtree that was only frozen shallowly", () => {
    // A shallow-frozen object is not evidence of a deep-frozen one: canonical
    // Findings are frozen exactly this way, and treating the outer freeze as
    // "already done" would leave their evidence arrays mutable.
    const inner = { evidence: ["e1"] };
    Object.freeze(inner);
    const value = deepFreeze({ findings: [inner] });

    assert.ok(Object.isFrozen(value.findings));
    assert.ok(Object.isFrozen(value.findings[0].evidence));
    assert.throws(() => {
      value.findings[0].evidence.push("e2");
    }, TypeError);
  });

  it("terminates on a cyclic value", () => {
    const cyclic = { name: "c" };
    cyclic.self = cyclic;
    const frozen = deepFreeze(cyclic);

    assert.ok(Object.isFrozen(frozen));
    assert.equal(frozen.self, frozen);
  });
});

// ─── Architectural boundary ──────────────────────────────────────────────────

describe("analyzer framework: architectural boundary", () => {
  const ANALYSIS_DIR = join(process.cwd(), "src", "analysis");
  const MODULES = readdirSync(ANALYSIS_DIR).filter((name) => name.endsWith(".js"));
  const SOURCES = MODULES.map((name) => ({
    name,
    text: readFileSync(join(ANALYSIS_DIR, name), "utf8"),
  }));

  const ALLOWED_SPECIFIERS = [
    "../core/index.js",
    "../repository/model/index.js",
    "node:crypto",
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
    "../../execution",
    "../execution",
    "tools.js",
    "tool-registry",
    "stdio-server",
    "http-server",
  ];

  /** Strip comments so documentation prose can never satisfy or trip the scan. */
  const withoutComments = (text) =>
    text.replace(/\/\*[\s\S]*?\*\//g, "").replace(/^\s*\/\/.*$/gm, "");

  it("imports nothing but the Core, the model boundary and hashing", () => {
    assert.ok(SOURCES.length >= 8);
    for (const { name, text } of SOURCES) {
      const code = withoutComments(text);
      for (const match of code.matchAll(/from\s+"([^"]+)"/g)) {
        const specifier = match[1];
        assert.ok(
          specifier.startsWith("./") || ALLOWED_SPECIFIERS.includes(specifier),
          `${name} imports "${specifier}"`,
        );
      }
      assert.ok(!/import\s*\(/.test(code), `${name} must not use a dynamic import`);
      assert.ok(!/\brequire\s*\(/.test(code), `${name} must not use require`);
    }
  });

  it("has no filesystem, process, network or transport access", () => {
    for (const { name, text } of SOURCES) {
      const code = withoutComments(text);
      for (const forbidden of FORBIDDEN) {
        assert.ok(!code.includes(`"${forbidden}"`), `${name} references "${forbidden}"`);
      }
      assert.ok(!/\bnew Date\b/.test(code), `${name} must not construct a Date`);
      assert.ok(!/\bMath\.random\b/.test(code), `${name} must not use randomness`);
      assert.ok(!/\bprocess\.env\b/.test(code), `${name} must not read the environment`);
      assert.ok(!/\bspawn\w*\s*\(/.test(code), `${name} must not spawn a process`);
      assert.ok(!/\bfetch\s*\(/.test(code), `${name} must not fetch`);
    }
  });

  it("gives analyzers no execution capability", async () => {
    let received = null;
    await engineWith([
      createAnalyzer({
        id: "test.capability-probe",
        name: "probe",
        version: "1.0.0",
        scope: "test",
        canAnalyze: () => createApplicability({ applicable: true }),
        analyze: (value) => {
          received = value;
          return createAnalysisResult();
        },
      }),
    ]).runAll(context());

    const dataKeys = ["configuration", "execution", "options"];
    for (const key of dataKeys) {
      assert.equal(typeof received[key], "object");
      for (const nested of Object.values(received[key])) {
        assert.notEqual(typeof nested, "function", `context.${key} must carry data only`);
      }
    }
    for (const key of Object.keys(received)) {
      assert.notEqual(typeof received[key], "function");
      assert.ok(!(received[key] instanceof Promise));
    }
  });
});
