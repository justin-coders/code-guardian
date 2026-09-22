/**
 * Code Guardian — Rule Engine Tests (Phase 10)
 *
 * Every rule in this file is a **test fixture**, not a product rule: the phase
 * deliberately ships no security/architecture/testing/dependency/CI/API/
 * reliability/production rule, only the machinery such rules will be plugged into.
 *
 * The repository model used by the fixtures is a real Phase 8D model built from a
 * hand-built ScanResult, so the engine is exercised against the contract it will
 * actually receive — including real scanner evidence ids — without touching the
 * filesystem.
 *
 * Run with: node --test tests/rule-engine.test.js
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  ValidationError,
  createEvidence,
  createRule,
} from "../src/core/index.js";

import { createScanResult } from "../src/repository/scanner/index.js";
import { buildRepositoryModel } from "../src/repository/model/index.js";

import {
  buildAnalysisContext,
  createAnalyzerEngine,
  createAnalyzerRegistry,
  deepFreeze,
  findingFingerprint,
  normalizeFinding,
  stableAnalysisView,
} from "../src/analysis/index.js";

import {
  APPLICABILITY_COVERAGE,
  RULE_CAPABILITIES,
  RULE_FAILURE_CODES,
  RULE_FAILURE_KINDS,
  RULE_OUTCOME_STATUSES,
  RULE_SELECTOR_KEYS,
  RuleConfigurationError,
  RuleFrameworkError,
  RuleRegistrationError,
  createRuleAnalyzer,
  createRuleDetection,
  createRuleEngine,
  createRuleRegistry,
  evaluateRule,
  evaluateRuleApplicability,
  findingsForRule,
  isRuleRunComplete,
  ruleDescriptorIssues,
  validateRuleEvaluationResult,
  validateRuleRunResult,
} from "../src/rules/index.js";

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
  scan: { complete: false, truncated: true, limits: { maxFiles: 2, maxDepth: 20 }, errors: [] },
});
const APP_FILE_EVIDENCE = "evidence:inventory:src/app.js";

const context = (model = MODEL, overrides = {}) => buildAnalysisContext({ repository: model, ...overrides });

// ─── Fixtures: test-only rules ───────────────────────────────────────────────

/** A rule with sensible defaults; override any field. */
function ruleOf(overrides = {}) {
  return createRule({
    id: "testing.fixture-rule",
    version: "1.0.0",
    category: "testing",
    title: "Fixture rule",
    description: "a fixture rule",
    severity: "medium",
    applicability: {},
    detect: () => [],
    remediation: { summary: "fix it" },
    metadata: {},
    ...overrides,
  });
}

function engineWith(rules, options = {}) {
  return createRuleEngine({ registry: createRuleRegistry(rules), ...options });
}

/** Run one rule through a fresh engine and return its evaluation result. */
async function evaluate(rule, model = MODEL) {
  const run = await engineWith([rule]).runAll(context(model));
  return run;
}

// ─── Registry ────────────────────────────────────────────────────────────────

describe("rule engine: registry", () => {
  it("registers, retrieves and lists rules in deterministic id order", () => {
    const registry = createRuleRegistry();
    const b = ruleOf({ id: "testing.b" });
    const a = ruleOf({ id: "testing.a" });
    registry.register(b).register(a);

    assert.equal(registry.size, 2);
    assert.equal(registry.get("testing.a"), registry.get("testing.a"));
    assert.equal(registry.has("testing.b"), true);
    assert.equal(registry.get("testing.missing"), null);
    assert.deepEqual(registry.ids(), ["testing.a", "testing.b"]);
    // Documented ordering: by id, never insertion order.
    assert.deepEqual(registry.list().map((rule) => rule.id), ["testing.a", "testing.b"]);
  });

  it("rejects a duplicate rule id deterministically", () => {
    const registry = createRuleRegistry([ruleOf({ id: "testing.dupe" })]);
    assert.throws(
      () => registry.register(ruleOf({ id: "testing.dupe" })),
      (error) => {
        assert.ok(error instanceof RuleConfigurationError);
        assert.equal(error.details.kind, RULE_FAILURE_KINDS.DUPLICATE_RULE);
        assert.equal(error.code, RULE_FAILURE_CODES.duplicateRule);
        return true;
      },
    );
    assert.equal(registry.size, 1);
  });

  it("rejects rules that violate the Core or framework contract", () => {
    const cases = [
      { label: "not an object", value: "nope" },
      { label: "missing version", value: ruleOf({ version: undefined }) },
      { label: "bad version", value: ruleOf({ version: "1" }) },
      { label: "missing detect", value: ruleOf({ detect: undefined }) },
      { label: "missing severity", value: ruleOf({ severity: undefined }) },
      { label: "bad severity", value: ruleOf({ severity: "catastrophic" }) },
      { label: "uppercase id", value: ruleOf({ id: "Testing.X" }) },
      { label: "id with spaces", value: ruleOf({ id: "testing x" }) },
      { label: "metadata not object", value: ruleOf({ metadata: "nope" }) },
    ];

    for (const { label, value } of cases) {
      assert.throws(
        () => createRuleRegistry([value]),
        RuleRegistrationError,
        `must reject: ${label}`,
      );
    }
  });

  it("reports every descriptor problem at once", () => {
    const issues = ruleDescriptorIssues({
      id: "Testing.Bad Id",
      version: "nope",
      category: "testing",
      title: "t",
      severity: "catastrophic",
      applicability: { nope: ["x"] },
    });
    assert.ok(issues.length >= 4);
    assert.ok(issues.some((issue) => issue.includes("rule.id")));
    assert.ok(issues.some((issue) => issue.includes("rule.applicability.nope")));
  });

  it("selects by id in sorted order and refuses unknown ids", () => {
    const registry = createRuleRegistry([ruleOf({ id: "testing.b" }), ruleOf({ id: "testing.a" })]);
    assert.deepEqual(
      registry.select(["testing.b", "testing.a", "testing.a"]).map((rule) => rule.id),
      ["testing.a", "testing.b"],
    );
    assert.throws(
      () => registry.select(["testing.nope"]),
      (error) => {
        assert.equal(error.details.kind, RULE_FAILURE_KINDS.UNKNOWN_RULE);
        assert.deepEqual(error.details.unknown, ["testing.nope"]);
        return true;
      },
    );
  });

  it("freezes registered rules and does not let callers mutate registry state", () => {
    const source = ruleOf({ id: "testing.frozen", metadata: { a: 1 } });
    const registry = createRuleRegistry([source]);
    const stored = registry.get("testing.frozen");

    assert.ok(Object.isFrozen(stored));
    assert.throws(() => {
      stored.id = "testing.mutated";
    }, TypeError);
    // Mutating the caller's original object must not affect the registry's entry.
    source.id = "testing.mutated";
    assert.equal(registry.ids()[0], "testing.frozen");
    assert.equal(registry.get("testing.frozen").id, "testing.frozen");
  });

  it("rejects malformed applicability selectors at registration", () => {
    const cases = [
      { applicability: { nope: ["x"] } },
      { applicability: { languages: "typescript" } },
      { applicability: { languages: [""] } },
      { applicability: { files: ["/etc/passwd"] } },
      { applicability: { files: ["../secret"] } },
      { applicability: [] },
    ];
    for (const { applicability } of cases) {
      assert.throws(() => createRuleRegistry([ruleOf({ applicability })]), RuleRegistrationError);
    }
    assert.deepEqual([...RULE_SELECTOR_KEYS].sort(), ["capabilities", "files", "frameworks", "languages"]);
  });
});

// ─── Applicability ───────────────────────────────────────────────────────────

describe("rule engine: applicability", () => {
  it("treats an empty selector object as universally applicable", () => {
    const rule = ruleOf({ applicability: {} });
    assert.deepEqual(evaluateRuleApplicability(rule, context()), {
      applicable: true,
      reason: null,
      coverage: APPLICABILITY_COVERAGE.COMPLETE,
    });
  });

  it("applies a language selector only when the language was observed", () => {
    const applicable = ruleOf({ applicability: { languages: ["javascript"] } });
    const inapplicable = ruleOf({ applicability: { languages: ["python"] } });

    assert.equal(evaluateRuleApplicability(applicable, context()).applicable, true);
    const decision = evaluateRuleApplicability(inapplicable, context());
    assert.equal(decision.applicable, false);
    assert.equal(decision.coverage, APPLICABILITY_COVERAGE.COMPLETE);
    assert.match(decision.reason, /requires language: python/);
  });

  it("reports unknown coverage rather than not-applicable when the scan is incomplete", () => {
    const rule = ruleOf({ applicability: { languages: ["python"] } });
    const decision = evaluateRuleApplicability(rule, context(TRUNCATED_MODEL));
    assert.equal(decision.applicable, false);
    assert.equal(decision.coverage, APPLICABILITY_COVERAGE.UNKNOWN);
    assert.match(decision.reason, /coverage is incomplete/);
  });

  it("applies a framework selector from observed framework entities", () => {
    const applicable = ruleOf({ applicability: { frameworks: ["node-test"] } });
    const inapplicable = ruleOf({ applicability: { frameworks: ["react"] } });
    assert.equal(evaluateRuleApplicability(applicable, context()).applicable, true);
    assert.equal(evaluateRuleApplicability(inapplicable, context()).applicable, false);
  });

  it("classifies file selectors as observed, absent or uncovered", () => {
    const observed = ruleOf({ applicability: { files: ["src/app.js"] } });
    const absent = ruleOf({ applicability: { files: ["src/missing.js"] } });
    assert.equal(evaluateRuleApplicability(observed, context()).applicable, true);

    const absentDecision = evaluateRuleApplicability(absent, context());
    assert.equal(absentDecision.applicable, false);
    assert.equal(absentDecision.coverage, APPLICABILITY_COVERAGE.COMPLETE);

    const unknownDecision = evaluateRuleApplicability(absent, context(TRUNCATED_MODEL));
    assert.equal(unknownDecision.coverage, APPLICABILITY_COVERAGE.UNKNOWN);
  });

  it("derives the source-code capability from observed languages", () => {
    const rule = ruleOf({ applicability: { capabilities: [RULE_CAPABILITIES.SOURCE_CODE] } });
    assert.equal(evaluateRuleApplicability(rule, context()).applicable, true);
  });

  it("rejects a rule whose applicability is not a selector object", () => {
    const rule = ruleOf();
    rule.applicability = null;
    assert.throws(
      () => evaluateRuleApplicability(rule, context()),
      (error) => {
        assert.ok(error instanceof RuleFrameworkError);
        assert.equal(error.kind, RULE_FAILURE_KINDS.INVALID_APPLICABILITY);
        return true;
      },
    );
  });

  it("combines selector keys with AND and values with OR", () => {
    const and = ruleOf({ applicability: { languages: ["javascript"], frameworks: ["react"] } });
    const or = ruleOf({ applicability: { languages: ["python", "javascript"] } });
    assert.equal(evaluateRuleApplicability(and, context()).applicable, false);
    assert.equal(evaluateRuleApplicability(or, context()).applicable, true);
  });
});

// ─── Evaluation ──────────────────────────────────────────────────────────────

describe("rule engine: evaluation", () => {
  it("passes when an applicable rule produces no findings", async () => {
    const run = await evaluate(ruleOf({ detect: () => [] }));
    assert.equal(run.rules[0].status, RULE_OUTCOME_STATUSES.PASS);
    assert.deepEqual(run.findings, []);
    assert.equal(run.complete, true);
    assert.equal(isRuleRunComplete(run), true);
  });

  it("reports a violation when an applicable rule produces a finding", async () => {
    const run = await evaluate(
      ruleOf({
        detect: () => [{ confidence: 1, evidence: [APP_FILE_EVIDENCE], title: "bad" }],
      }),
    );
    assert.equal(run.rules[0].status, RULE_OUTCOME_STATUSES.VIOLATION);
    assert.equal(run.findings.length, 1);
    assert.equal(run.findings[0].ruleId, "testing.fixture-rule");
    assert.equal(run.findings[0].category, "testing");
    assert.equal(run.findings[0].severity, "medium");
  });

  it("reports not-applicable without running detect", async () => {
    let ran = false;
    const rule = ruleOf({
      applicability: { languages: ["python"] },
      detect: () => {
        ran = true;
        return [];
      },
    });
    const run = await evaluate(rule);
    assert.equal(run.rules[0].status, RULE_OUTCOME_STATUSES.NOT_APPLICABLE);
    assert.equal(ran, false);
    assert.equal(run.complete, true);
  });

  it("reports unknown when applicability cannot be decided", async () => {
    const rule = ruleOf({ applicability: { languages: ["python"] } });
    const run = await evaluate(rule, TRUNCATED_MODEL);
    assert.equal(run.rules[0].status, RULE_OUTCOME_STATUSES.UNKNOWN);
    assert.equal(run.complete, false, "an unevaluated rule must make the run incomplete");
  });

  it("isolates a rule that throws", async () => {
    const run = await evaluate(
      ruleOf({
        id: "testing.throws",
        detect: () => {
          const error = new Error("boom: /etc/passwd leaked");
          error.details = { secret: "super-secret-token" };
          throw error;
        },
      }),
    );
    assert.equal(run.rules[0].status, RULE_OUTCOME_STATUSES.FAILED);
    assert.equal(run.rules[0].errors[0].kind, RULE_FAILURE_KINDS.RULE_FAILURE);
    const serialized = JSON.stringify(run);
    assert.ok(!serialized.includes("stack"), "a stack must never be serialized");
    assert.ok(!serialized.includes("at Object."), "a stack must never be serialized");
    // The rule's own structured details are preserved (they are its authored
    // context), exactly as the Phase 9 framework does for an analyzer.
    assert.equal(run.rules[0].errors[0].details.reported.secret, "super-secret-token");
  });

  it("rejects an uninterpretable detection result", async () => {
    const run = await evaluate(ruleOf({ detect: () => "nope" }));
    assert.equal(run.rules[0].status, RULE_OUTCOME_STATUSES.FAILED);
    assert.equal(run.rules[0].errors[0].kind, RULE_FAILURE_KINDS.INVALID_RULE_RESULT);
  });

  it("rejects a finding that does not declare confidence", async () => {
    const run = await evaluate(ruleOf({ detect: () => [{ evidence: [APP_FILE_EVIDENCE] }] }));
    assert.equal(run.rules[0].status, RULE_OUTCOME_STATUSES.FAILED);
    assert.equal(run.rules[0].errors[0].kind, RULE_FAILURE_KINDS.INVALID_FINDING);
  });

  it("accepts a structured detection result with metrics and metadata", async () => {
    const run = await evaluate(
      ruleOf({
        detect: () => ({
          ...createRuleDetection({ findings: [{ confidence: 0.5, evidence: [APP_FILE_EVIDENCE] }] }),
          metrics: { checked: 3 },
          metadata: { fixture: true },
        }),
      }),
    );
    assert.equal(run.rules[0].status, RULE_OUTCOME_STATUSES.VIOLATION);
    assert.deepEqual(run.rules[0].metrics, { checked: 3 });
    assert.equal(run.rules[0].metadata.fixture, true);
  });

  it("produces a validated, frozen rule evaluation result", async () => {
    const run = await evaluate(ruleOf({ detect: () => [] }));
    assert.equal(validateRuleEvaluationResult(run.rules[0]), run.rules[0]);
    assert.equal(validateRuleRunResult(run), run);
    assert.ok(Object.isFrozen(run));
    assert.ok(Object.isFrozen(run.rules[0]));
  });
});

// ─── Evidence ────────────────────────────────────────────────────────────────

describe("rule engine: evidence", () => {
  it("resolves model evidence a finding cites", async () => {
    const run = await evaluate(
      ruleOf({ detect: () => [{ confidence: 1, evidence: [APP_FILE_EVIDENCE] }] }),
    );
    assert.deepEqual(
      run.rules[0].evidence.map((record) => record.id),
      [APP_FILE_EVIDENCE],
    );
    assert.equal(run.rules[0].evidence[0].location.path, "src/app.js");
  });

  it("rejects a finding that cites evidence the model does not have", async () => {
    const run = await evaluate(
      ruleOf({ detect: () => [{ confidence: 1, evidence: ["evidence:invented"] }] }),
    );
    assert.equal(run.rules[0].status, RULE_OUTCOME_STATUSES.FAILED);
    assert.equal(run.rules[0].errors[0].kind, RULE_FAILURE_KINDS.INVALID_FINDING);
  });

  it("accepts derived evidence emitted by the rule and cited by its finding", async () => {
    const run = await evaluate(
      ruleOf({
        detect: () => ({
          evidence: [
            createEvidence({
              id: "evidence:test:derived",
              type: "configuration",
              location: { path: "package.json" },
              source: { analyzer: "testing.fixture-rule", method: "fixture" },
              data: {},
              provenance: { deterministic: true, collector: "testing.fixture-rule" },
            }),
          ],
          findings: [{ confidence: 1, evidence: ["evidence:test:derived"] }],
        }),
      }),
    );
    assert.equal(run.rules[0].status, RULE_OUTCOME_STATUSES.VIOLATION);
    assert.deepEqual(
      run.rules[0].evidence.map((record) => record.id),
      ["evidence:test:derived"],
    );
  });

  it("rejects derived evidence that points outside the repository", async () => {
    const run = await evaluate(
      ruleOf({
        detect: () => ({
          evidence: [
            createEvidence({
              id: "evidence:test:absolute",
              type: "file",
              location: { path: "/etc/passwd" },
              source: { analyzer: "testing.fixture-rule", method: "fixture" },
              data: {},
              provenance: { deterministic: true },
            }),
          ],
        }),
      }),
    );
    assert.equal(run.rules[0].errors[0].kind, RULE_FAILURE_KINDS.UNSAFE_EVIDENCE_PATH);
    assert.ok(!JSON.stringify(run).includes("/etc/passwd"));
  });

  it("rejects derived evidence that is not a valid Evidence record", async () => {
    const run = await evaluate(
      ruleOf({
        detect: () => ({
          evidence: [
            {
              id: "evidence:test:malformed",
              type: "file",
              location: { path: "src/app.js" },
              source: {},
              data: {},
              provenance: {},
            },
          ],
        }),
      }),
    );
    assert.equal(run.rules[0].errors[0].kind, RULE_FAILURE_KINDS.INVALID_EVIDENCE);
  });

  it("rejects derived evidence that reuses a model evidence id", async () => {
    const run = await evaluate(
      ruleOf({
        detect: () => ({
          evidence: [
            createEvidence({
              id: APP_FILE_EVIDENCE,
              type: "file",
              location: { path: "src/app.js" },
              source: { analyzer: "testing.fixture-rule", method: "fixture" },
              data: {},
              provenance: { deterministic: true },
            }),
          ],
        }),
      }),
    );
    assert.equal(run.rules[0].errors[0].kind, RULE_FAILURE_KINDS.DUPLICATE_EVIDENCE_ID);
  });

  it("reserves a rule's emitted evidence id run-globally", async () => {
    const sharedEvidence = () =>
      createEvidence({
        id: "evidence:test:shared",
        type: "configuration",
        location: { path: "package.json" },
        source: { analyzer: "fixture", method: "fixture" },
        data: {},
        provenance: { deterministic: true },
      });
    const run = await engineWith([
      ruleOf({ id: "testing.a-emits", detect: () => ({ evidence: [sharedEvidence()] }) }),
      ruleOf({ id: "testing.b-emits", detect: () => ({ evidence: [sharedEvidence()] }) }),
    ]).runAll(context());

    assert.equal(run.rules[0].status, RULE_OUTCOME_STATUSES.PASS);
    assert.equal(run.rules[1].status, RULE_OUTCOME_STATUSES.FAILED);
    assert.equal(run.rules[1].errors[0].kind, RULE_FAILURE_KINDS.DUPLICATE_EVIDENCE_ID);
    assert.deepEqual(run.rules[1].evidence, []);
  });
});

// ─── Isolation ───────────────────────────────────────────────────────────────

describe("rule engine: isolation", () => {
  it("keeps evaluating after a rule fails", async () => {
    const run = await engineWith([
      ruleOf({ id: "testing.a-throws", detect: () => { throw new Error("boom"); } }),
      ruleOf({
        id: "testing.b-emits",
        detect: () => [{ confidence: 1, evidence: [APP_FILE_EVIDENCE] }],
      }),
    ]).runAll(context());

    assert.equal(run.rules[0].status, RULE_OUTCOME_STATUSES.FAILED);
    assert.equal(run.rules[1].status, RULE_OUTCOME_STATUSES.VIOLATION);
    assert.equal(run.complete, false);
    assert.equal(run.errors.length, 1);
    assert.equal(run.errors[0].ruleId, "testing.a-throws");
  });

  it("does not let one rule corrupt the registry or another rule's result", async () => {
    const registry = createRuleRegistry([
      ruleOf({ id: "testing.a", detect: () => [{ confidence: 1, evidence: [APP_FILE_EVIDENCE] }] }),
      ruleOf({ id: "testing.b", detect: () => { throw new Error("nope"); } }),
    ]);
    const before = registry.ids();
    const engine = createRuleEngine({ registry });
    const run = await engine.runAll(context());

    assert.deepEqual(registry.ids(), before);
    assert.equal(run.rules[0].status, RULE_OUTCOME_STATUSES.VIOLATION);
    assert.deepEqual(findingsForRule(run, "testing.a").length, 1);
  });

  it("skips the remaining rules when fail-fast is enabled", async () => {
    const run = await engineWith(
      [
        ruleOf({ id: "testing.a-throws", detect: () => { throw new Error("boom"); } }),
        ruleOf({ id: "testing.b", detect: () => [{ confidence: 1, evidence: [APP_FILE_EVIDENCE] }] }),
      ],
      { failFast: true },
    ).runAll(context());

    assert.equal(run.rules[0].status, RULE_OUTCOME_STATUSES.FAILED);
    assert.equal(run.rules[1].status, RULE_OUTCOME_STATUSES.SKIPPED);
    assert.equal(run.rules[1].errors[0].kind, RULE_FAILURE_KINDS.FAIL_FAST_ABORT);
  });
});

// ─── Finding Engine integration ──────────────────────────────────────────────

describe("rule engine: finding engine integration", () => {
  it("feeds raw rule findings through the Phase 9 Finding Engine", async () => {
    const rule = ruleOf({
      id: "testing.missing-test",
      detect: () => [{ confidence: 1, evidence: [APP_FILE_EVIDENCE], title: "no test" }],
    });
    const run = await evaluate(rule);
    const canonical = normalizeFinding(run.findings[0], {
      analyzer: { id: "testing.rules", name: "testing", version: "1.0.0", scope: "testing" },
      rule: createRuleRegistry([rule]).get("testing.missing-test"),
      allowedEvidenceIds: new Set(Object.keys(MODEL.indexes.evidenceById)),
    });

    assert.equal(
      canonical.fingerprint,
      findingFingerprint({
        ruleId: "testing.missing-test",
        category: "testing",
        evidence: [APP_FILE_EVIDENCE],
      }),
    );
    assert.ok(canonical.fingerprint.startsWith("cg-fp1-"));
  });

  it("drives the analyzer engine through a RuleAnalyzer adapter", async () => {
    const analyzer = createRuleAnalyzer({
      id: "testing.rules",
      name: "Testing rules",
      version: "1.0.0",
      scope: "testing",
      rules: [
        ruleOf({
          id: "testing.missing-test",
          detect: () => [{ confidence: 1, evidence: [APP_FILE_EVIDENCE], title: "no test" }],
        }),
      ],
    });
    const engine = createAnalyzerEngine({
      registry: createAnalyzerRegistry([analyzer]),
    });
    const result = await engine.runAll(context());

    assert.equal(result.analyzers[0].status, "completed");
    assert.equal(result.findings.length, 1);
    assert.ok(result.findings[0].fingerprint.startsWith("cg-fp1-"));
    assert.equal(result.findings[0].metadata.analyzer.id, "testing.rules");
  });

  it("surfaces rule failures through the adapter's metadata", async () => {
    const analyzer = createRuleAnalyzer({
      id: "testing.rules",
      name: "Testing rules",
      version: "1.0.0",
      scope: "testing",
      rules: [ruleOf({ id: "testing.boom", detect: () => { throw new Error("boom"); } })],
    });
    const engine = createAnalyzerEngine({ registry: createAnalyzerRegistry([analyzer]) });
    const result = await engine.runAll(context());

    assert.equal(result.analyzers[0].metadata.ruleFailures.length, 1);
    assert.equal(result.analyzers[0].metadata.ruleFailures[0].ruleId, "testing.boom");
  });

  it("deduplicates the same rule's finding reported by two analyzers", async () => {
    const rule = ruleOf({
      id: "testing.dup",
      detect: () => [{ confidence: 1, evidence: [APP_FILE_EVIDENCE], title: "same" }],
    });
    const makeAnalyzer = (id) =>
      createRuleAnalyzer({
        id,
        name: id,
        version: "1.0.0",
        scope: "testing",
        rules: [rule],
      });
    const engine = createAnalyzerEngine({
      registry: createAnalyzerRegistry([makeAnalyzer("testing.a"), makeAnalyzer("testing.b")]),
    });
    const result = await engine.runAll(context());

    // The same rule id + category + evidence identity gives the same fingerprint,
    // so the Finding Engine keeps one survivor and records the other as a duplicate.
    assert.equal(result.findings.length, 1);
    assert.equal(result.duplicates.length, 1);
    assert.equal(result.duplicates[0].duplicates.length, 1);
  });
});

// ─── Determinism ─────────────────────────────────────────────────────────────

describe("rule engine: determinism", () => {
  const rules = [
    ruleOf({ id: "testing.b", detect: () => [{ confidence: 1, evidence: [APP_FILE_EVIDENCE] }] }),
    ruleOf({ id: "testing.a", detect: () => [] }),
  ];

  it("produces identical stable output for identical input", async () => {
    const first = await engineWith(rules).runAll(context());
    const second = await engineWith(rules).runAll(context());
    assert.deepEqual(stableAnalysisView(first), stableAnalysisView(second));
  });

  it("is unaffected by registration order", async () => {
    const first = await engineWith(rules).runAll(context());
    const second = await engineWith([...rules].reverse()).runAll(context());
    assert.deepEqual(
      first.rules.map((result) => result.rule.id),
      ["testing.a", "testing.b"],
    );
    assert.deepEqual(stableAnalysisView(first), stableAnalysisView(second));
  });

  it("embeds no timestamp, uuid or content hash in the run result", async () => {
    const run = await engineWith(rules).runAll(context());
    const serialized = JSON.stringify(stableAnalysisView(run));
    assert.ok(!/\d{13}/.test(serialized), "must not embed a millisecond timestamp");
    assert.ok(!/[0-9a-f]{8}-[0-9a-f]{4}/.test(serialized), "must not embed a uuid");
    // Paths stay repository-relative; the only absolute path is the declared root
    // metadata, which the model contract allows to be absolute.
    for (const finding of run.findings) {
      for (const id of finding.evidence) {
        assert.ok(!id.includes("/scan-root"), "evidence ids stay repository-relative");
      }
    }
    assert.equal(run.repository.root, "/scan-root");
  });
});

// ─── Producer-declared detection coverage ────────────────────────────────────
//
// Phase 12 added exactly one thing to the `detect()` contract: a rule may declare
// `coverage: "unknown"` when its conclusion depends on repository coverage the
// scan did not establish. These tests pin the extension and the fact that it
// changes nothing for rules that do not use it.

describe("rule engine: producer-declared detection coverage", () => {
  it("leaves a rule that declares nothing exactly as it was", async () => {
    const pass = await evaluate(ruleOf({ detect: () => [] }));
    assert.equal(pass.rules[0].status, RULE_OUTCOME_STATUSES.PASS);
    assert.equal(pass.complete, true);

    const detection = await evaluate(ruleOf({ detect: () => ({ findings: [], evidence: [] }) }));
    assert.equal(detection.rules[0].status, RULE_OUTCOME_STATUSES.PASS);
    assert.equal(detection.complete, true);
  });

  it("turns a declared unknown coverage into an unknown outcome, not a pass", async () => {
    const rule = ruleOf({
      detect: () =>
        createRuleDetection({
          findings: [],
          coverage: APPLICABILITY_COVERAGE.UNKNOWN,
          reason: "the inventory is incomplete",
        }),
    });
    const run = await evaluate(rule);
    assert.equal(run.rules[0].status, RULE_OUTCOME_STATUSES.UNKNOWN);
    assert.equal(run.rules[0].applicability.coverage, APPLICABILITY_COVERAGE.UNKNOWN);
    assert.equal(run.rules[0].applicability.reason, "the inventory is incomplete");
    assert.deepEqual(run.rules[0].findings, []);
    // An abstention makes the run incomplete, exactly like an applicability-driven
    // unknown: a caller must not read the run as clean.
    assert.equal(run.complete, false);
    assert.equal(isRuleRunComplete(run), false);
    assert.equal(run.metadata.unknown, 1);
  });

  it("supplies a framework reason when a rule declares none", async () => {
    const run = await evaluate(
      ruleOf({ detect: () => ({ findings: [], coverage: APPLICABILITY_COVERAGE.UNKNOWN }) }),
    );
    assert.equal(run.rules[0].status, RULE_OUTCOME_STATUSES.UNKNOWN);
    assert.ok(run.rules[0].applicability.reason.length > 0);
  });

  it("never lets an abstention hide an observation", async () => {
    const rule = ruleOf({
      detect: () => ({
        findings: [{ confidence: 0.5, evidence: [APP_FILE_EVIDENCE] }],
        coverage: APPLICABILITY_COVERAGE.UNKNOWN,
      }),
    });
    const run = await evaluate(rule);
    assert.equal(run.rules[0].status, RULE_OUTCOME_STATUSES.VIOLATION);
    assert.equal(run.rules[0].findings.length, 1);
  });

  it("refuses a rule that claims the repository was covered", async () => {
    for (const coverage of ["complete", "partial", 42]) {
      const run = await evaluate(ruleOf({ detect: () => ({ findings: [], coverage }) }));
      assert.equal(run.rules[0].status, RULE_OUTCOME_STATUSES.FAILED);
      assert.equal(run.rules[0].errors[0].kind, RULE_FAILURE_KINDS.INVALID_RULE_RESULT);
    }
  });

  it("refuses a malformed coverage reason", async () => {
    const run = await evaluate(
      ruleOf({
        detect: () => ({ findings: [], coverage: APPLICABILITY_COVERAGE.UNKNOWN, reason: 7 }),
      }),
    );
    assert.equal(run.rules[0].status, RULE_OUTCOME_STATUSES.FAILED);
    assert.equal(run.rules[0].errors[0].kind, RULE_FAILURE_KINDS.INVALID_RULE_RESULT);
  });

  it("produces the same unknown shape as an unresolved applicability selector", async () => {
    const bySelector = await evaluate(
      ruleOf({ applicability: { languages: ["rust"] }, detect: () => [] }),
      TRUNCATED_MODEL,
    );
    const byDeclaration = await evaluate(
      ruleOf({ detect: () => ({ findings: [], coverage: APPLICABILITY_COVERAGE.UNKNOWN }) }),
      TRUNCATED_MODEL,
    );
    for (const run of [bySelector, byDeclaration]) {
      assert.equal(run.rules[0].status, RULE_OUTCOME_STATUSES.UNKNOWN);
      assert.equal(run.rules[0].applicability.coverage, APPLICABILITY_COVERAGE.UNKNOWN);
      assert.deepEqual(run.findings, []);
    }
  });
});

// ─── Architectural boundary ──────────────────────────────────────────────────

describe("rule engine: architectural boundary", () => {
  const RULE_DIR = join(dirname(fileURLToPath(import.meta.url)), "..", "src", "rules");
  const files = readdirSync(RULE_DIR).filter((name) => name.endsWith(".js"));

  it("imports nothing but the Core, the model, the analysis framework and hashing", () => {
    for (const file of files) {
      const source = readFileSync(join(RULE_DIR, file), "utf8");
      const imports = [...source.matchAll(/from\s+"([^"]+)"/g)].map((match) => match[1]);
      for (const specifier of imports) {
        assert.ok(
          specifier.startsWith(".") || specifier === "node:crypto",
          `${file} imports disallowed module "${specifier}"`,
        );
      }
    }
  });

  it("has no filesystem, process, network, transport or worker access", () => {
    const forbidden = [
      "node:fs",
      "node:fs/promises",
      "child_process",
      "node:child_process",
      "node:net",
      "node:http",
      "node:https",
      "node:dns",
      "node:worker_threads",
      "tools.js",
      "tool-registry",
    ];
    for (const file of files) {
      const source = readFileSync(join(RULE_DIR, file), "utf8");
      for (const needle of forbidden) {
        assert.ok(!source.includes(`"${needle}"`), `${file} must not reference "${needle}"`);
      }
    }
  });

  it("gives rules no execution capability through the context", async () => {
    let received = null;
    const rule = ruleOf({
      detect: (value) => {
        received = value;
        return [];
      },
    });
    await evaluate(rule);
    for (const capability of ["filesystem", "fs", "spawn", "exec", "fetch", "http", "mcp", "tools"]) {
      assert.equal(capability in received, false, `context must not expose "${capability}"`);
    }
  });
});

// ─── Errors ──────────────────────────────────────────────────────────────────

describe("rule engine: error surface", () => {
  it("keeps unknown and not-applicable distinct in the vocabulary", () => {
    assert.equal(RULE_OUTCOME_STATUSES.UNKNOWN, "unknown");
    assert.equal(RULE_OUTCOME_STATUSES.NOT_APPLICABLE, "not-applicable");
    assert.notEqual(RULE_OUTCOME_STATUSES.UNKNOWN, RULE_OUTCOME_STATUSES.NOT_APPLICABLE);
  });

  it("rejects a malformed hand-built context", async () => {
    await assert.rejects(
      () => engineWith([ruleOf()]).runAll({ repository: { version: "1" } }),
      ValidationError,
    );
  });

  it("validates the aggregate run result against its contract", async () => {
    const run = await engineWith([ruleOf()]).runAll(context());
    assert.equal(validateRuleRunResult(run), run);
    const broken = { ...stableAnalysisView(run), version: undefined };
    assert.throws(() => validateRuleRunResult(broken), ValidationError);
  });

  it("re-exports a frozen, deeply frozen aggregate", () => {
    assert.ok(typeof deepFreeze === "function");
  });
});
