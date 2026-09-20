/**
 * Code Guardian — Core Contract Tests (Phase 7)
 *
 * Focused tests for the Core contract layer introduced in `src/core`.
 * These tests are additive: they do not replace or alter the existing suite.
 *
 * Run with: node --test tests/core-contracts.test.js
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";

import {
  CORE_CONTRACT_VERSION,
  CONTRACT_FACTORY_SEMANTICS,
  REPOSITORY_MODEL_VERSION,
  REPOSITORY_MODEL_AREAS,
  REPOSITORY_MODEL_OPTIONAL_AREAS,
  REPOSITORY_MODEL_JUDGMENT_AREAS,
  SCAN_REQUIRED_FIELDS,
  createRepositoryModel,
  EVIDENCE_TYPES,
  createEvidence,
  FINDING_SEVERITIES,
  FINDING_STATUSES,
  FINDING_STAGES,
  CONFIDENCE_MIN,
  CONFIDENCE_MAX,
  isValidConfidence,
  hasFingerprint,
  createFinding,
  RULE_REQUIRED_FIELDS,
  createRule,
  ANALYZER_DESCRIPTIVE_FIELDS,
  ANALYZER_REQUIRED_FIELDS,
  createAnalyzer,
  ANALYSIS_RESULT_FIELDS,
  createAnalysisResult,
  createApplicability,
  ANALYSIS_CONTEXT_FIELDS,
  createAnalysisContext,
  EXECUTION_STATES,
  EXECUTION_REQUEST_FIELDS,
  EXECUTION_RESULT_FIELDS,
  DEFAULT_EXECUTION_TIMEOUT_MS,
  DEFAULT_MAX_OUTPUT_BYTES,
  EXECUTION_LIMIT_PRECEDENCE,
  EXECUTION_COMMAND_PRECEDENCE,
  createExecutionRequest,
  createExecutionResult,
  createExecutionPolicy,
  getExecutionState,
  CoreError,
  ValidationError,
  ConfigurationError,
  RepositoryError,
  ExecutionError,
  AnalysisError,
  ERROR_CATEGORIES,
  ERROR_CODES,
  isCoreError,
  validateRepositoryModel,
  validateEvidence,
  validateFinding,
  validateRawFinding,
  validateRule,
  validateAnalyzer,
  validateAnalyzerApplicability,
  validateAnalyzerResult,
  validateAnalysisContext,
  validateExecutionRequest,
  validateExecutionResult,
  validateExecutionPolicy,
  validateContract,
  KNOWN_CONTRACTS,
} from "../src/core/index.js";

// ─── Helpers ─────────────────────────────────────────────────────────────────

const CORE_DIR = fileURLToPath(new URL("../src/core", import.meta.url));

/** Run a validator and return the ValidationError it threw. */
function captureValidationError(fn) {
  try {
    fn();
  } catch (error) {
    return error;
  }
  assert.fail("expected the validator to throw a ValidationError");
}

/** Assert the call throws a structured ValidationError. */
function assertInvalid(fn) {
  const error = captureValidationError(fn);
  assert.ok(error instanceof ValidationError, "should throw a ValidationError");
  assert.equal(error.code, ERROR_CODES.VALIDATION);
  assert.equal(error.category, ERROR_CATEGORIES.VALIDATION);
  assert.ok(Array.isArray(error.details.issues), "should list issues");
  assert.ok(
    error.details.issues.length > 0,
    "should report at least one issue",
  );
  return error;
}

/** A valid RepositoryModel literal, matching the architecture example. */
function validRepository(overrides = {}) {
  return {
    version: REPOSITORY_MODEL_VERSION,
    identity: { root: "/repo", name: "my-project", packageManager: "npm" },
    files: { entries: [], count: 0, truncated: false },
    languages: [],
    frameworks: [],
    manifests: {},
    dependencies: {},
    scripts: {},
    configuration: {},
    git: {},
    tests: {},
    ci: {},
    architecture: {},
    scan: {
      complete: true,
      truncated: false,
      limits: { maxFiles: 10000, maxDepth: 20 },
      errors: [],
    },
    metadata: {},
    ...overrides,
  };
}

function validEvidence(overrides = {}) {
  return createEvidence({
    id: "evidence-1",
    type: "file",
    location: { path: "src/auth/login.js" },
    source: { analyzer: "security", method: "filesystem" },
    data: {},
    provenance: { deterministic: true },
    ...overrides,
  });
}

/** A raw Evidence literal, so required fields can be genuinely omitted. */
function rawEvidence(overrides = {}) {
  return {
    id: "evidence-1",
    type: "file",
    location: { path: "src/auth/login.js" },
    source: { analyzer: "security", method: "filesystem" },
    data: {},
    provenance: { deterministic: true },
    ...overrides,
  };
}

/** A raw ExecutionResult literal, used to exercise invalid value types. */
function rawExecutionResult(overrides = {}) {
  return {
    exitCode: 0,
    stdout: "ok",
    stderr: "",
    duration: 12,
    timedOut: false,
    killed: false,
    truncated: false,
    ...overrides,
  };
}

function validFinding(overrides = {}) {
  return createFinding({
    id: "finding-1",
    ruleId: "security.hardcoded-secret",
    category: "security",
    severity: "high",
    confidence: 0.7,
    title: "Potential hardcoded credential",
    description: "A credential-like value was observed in source.",
    evidence: ["evidence-1"],
    status: "open",
    fingerprint: "fp-1",
    metadata: {},
    ...overrides,
  });
}

/**
 * A raw (pre-canonical) Finding: no fingerprint is generated at this stage.
 * Built through the factory so the factory's semantics are exercised.
 */
function rawFinding(overrides = {}) {
  return createFinding({
    id: "finding-1",
    ruleId: "security.hardcoded-secret",
    category: "security",
    severity: "high",
    confidence: 0.7,
    title: "Potential hardcoded credential",
    description: "A credential-like value was observed in source.",
    evidence: ["evidence-1"],
    status: "open",
    metadata: {},
    ...overrides,
  });
}

function validRule(overrides = {}) {
  return createRule({
    id: "security.example",
    version: "1.0.0",
    category: "security",
    title: "Example rule",
    description: "Example description.",
    severity: "high",
    applicability: {},
    detect: async () => [],
    remediation: {},
    metadata: {},
    ...overrides,
  });
}

function validAnalyzer(overrides = {}) {
  return {
    id: "security",
    version: "1.0.0",
    canAnalyze: async () => createApplicability({ applicable: true }),
    analyze: async () => createAnalysisResult(),
    ...overrides,
  };
}

function validAnalysisContext(overrides = {}) {
  return createAnalysisContext({
    repository: validRepository(),
    ...overrides,
  });
}

function validExecutionRequest(overrides = {}) {
  return createExecutionRequest({
    command: "npm",
    args: ["audit"],
    cwd: "/repo",
    ...overrides,
  });
}

function validExecutionResult(overrides = {}) {
  return createExecutionResult({
    exitCode: 0,
    stdout: "ok",
    stderr: "",
    duration: 12,
    timedOut: false,
    killed: false,
    truncated: false,
    ...overrides,
  });
}

function collectCoreFiles(dir) {
  const files = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      files.push(...collectCoreFiles(full));
    } else if (entry.name.endsWith(".js")) {
      files.push(full);
    }
  }
  return files;
}

// ─── Core index boundary ─────────────────────────────────────────────────────

describe("core index boundary", () => {
  it("exposes a versioned contract surface", () => {
    assert.equal(CORE_CONTRACT_VERSION, "1");
    assert.equal(REPOSITORY_MODEL_VERSION, "1");
  });

  it("exports the full stable public API", () => {
    const exported = {
      createRepositoryModel,
      createEvidence,
      createFinding,
      createRule,
      createAnalysisResult,
      createApplicability,
      createAnalysisContext,
      createExecutionRequest,
      createExecutionResult,
      createExecutionPolicy,
      getExecutionState,
      hasFingerprint,
      CoreError,
      ValidationError,
      ConfigurationError,
      RepositoryError,
      ExecutionError,
      AnalysisError,
      isCoreError,
      validateRepositoryModel,
      validateEvidence,
      validateFinding,
      validateRawFinding,
      validateRule,
      validateAnalyzer,
      validateAnalyzerApplicability,
      validateAnalyzerResult,
      validateAnalysisContext,
      validateExecutionRequest,
      validateExecutionResult,
      validateExecutionPolicy,
      validateContract,
    };
    for (const [name, value] of Object.entries(exported)) {
      assert.ok(
        value !== undefined,
        `${name} should be exported from src/core`,
      );
      assert.ok(
        typeof value === "function",
        `${name} should be a function/class`,
      );
    }
  });

  it("exposes the contract vocabularies", () => {
    assert.ok(Array.isArray(REPOSITORY_MODEL_AREAS));
    assert.ok(Array.isArray(SCAN_REQUIRED_FIELDS));
    assert.ok(Array.isArray(EVIDENCE_TYPES));
    assert.ok(Array.isArray(FINDING_SEVERITIES));
    assert.ok(Array.isArray(FINDING_STATUSES));
    assert.ok(Array.isArray(RULE_REQUIRED_FIELDS));
    assert.ok(Array.isArray(ANALYZER_REQUIRED_FIELDS));
    assert.ok(Array.isArray(ANALYSIS_RESULT_FIELDS));
    assert.ok(Array.isArray(ANALYSIS_CONTEXT_FIELDS));
    assert.ok(Array.isArray(EXECUTION_REQUEST_FIELDS));
    assert.ok(Array.isArray(EXECUTION_RESULT_FIELDS));
    assert.deepEqual(FINDING_STAGES, { RAW: "raw", CANONICAL: "canonical" });
    assert.ok(KNOWN_CONTRACTS.length > 0);
    assert.ok(KNOWN_CONTRACTS.includes("rawFinding"));
  });
});

// ─── Core errors ─────────────────────────────────────────────────────────────

describe("core errors", () => {
  it("exposes the structured error hierarchy", () => {
    const error = new ValidationError("bad input", {
      details: { contract: "Finding", issues: ["finding.severity: bad"] },
    });
    assert.ok(error instanceof ValidationError);
    assert.ok(error instanceof CoreError);
    assert.ok(error instanceof Error);
    assert.equal(error.name, "ValidationError");
    assert.equal(error.code, "CG_VALIDATION_ERROR");
    assert.equal(error.category, "validation");
    assert.equal(error.details.contract, "Finding");
  });

  it("classifies each error category with a stable code", () => {
    const expected = [
      [ValidationError, "CG_VALIDATION_ERROR", "validation"],
      [ConfigurationError, "CG_CONFIGURATION_ERROR", "configuration"],
      [RepositoryError, "CG_REPOSITORY_ERROR", "repository"],
      [ExecutionError, "CG_EXECUTION_ERROR", "execution"],
      [AnalysisError, "CG_ANALYSIS_ERROR", "analysis"],
    ];
    for (const [ErrorClass, code, category] of expected) {
      const error = new ErrorClass("boom");
      assert.equal(error.code, code);
      assert.equal(error.category, category);
      assert.deepEqual(error.details, {});
    }
  });

  it("does not expose internal details by default", () => {
    assert.equal(new ValidationError("bad").expose, true);
    assert.equal(new ConfigurationError("bad").expose, true);
    assert.equal(new RepositoryError("bad").expose, false);
    assert.equal(new ExecutionError("bad").expose, false);
    assert.equal(new AnalysisError("bad").expose, false);
  });

  it("serializes without leaking stack traces or causes", () => {
    const cause = new Error("internal path /secret/repo");
    const error = new RepositoryError("scan failed", {
      details: { path: "vendor/private" },
      cause,
    });
    const json = error.toJSON();
    assert.equal(json.name, "RepositoryError");
    assert.equal(json.code, "CG_REPOSITORY_ERROR");
    assert.equal(json.category, "repository");
    assert.equal(json.message, "scan failed");
    assert.deepEqual(json.details, { path: "vendor/private" });
    assert.equal(json.expose, false);
    assert.ok(!("stack" in json), "toJSON must not leak a stack trace");
    assert.ok(!("cause" in json), "toJSON must not leak the cause chain");
    assert.ok(error.stack, "local callers can still access the stack");
    assert.equal(error.cause, cause);
  });

  it("supports code overrides and narrowing", () => {
    const error = new AnalysisError("analyzer crashed", {
      code: "CG_ANALYZER_1",
    });
    assert.equal(error.code, "CG_ANALYZER_1");
    assert.equal(isCoreError(error), true);
    assert.equal(isCoreError(new Error("plain")), false);
    assert.equal(isCoreError(null), false);
  });
});

// ─── RepositoryModel ─────────────────────────────────────────────────────────

describe("RepositoryModel contract", () => {
  it("accepts a valid, complete model", () => {
    const model = validRepository();
    assert.equal(validateRepositoryModel(model), model);
  });

  it("accepts a valid, truncated model", () => {
    const model = validRepository({
      scan: {
        complete: false,
        truncated: true,
        limits: { maxFiles: 5000, maxDepth: 20 },
        errors: [{ path: "vendor/private", code: "EACCES" }],
      },
    });
    assert.equal(validateRepositoryModel(model), model);
  });

  it("builds a skeleton whose scan is not reported as complete", () => {
    const model = createRepositoryModel();
    for (const area of REPOSITORY_MODEL_AREAS) {
      assert.ok(area in model, `factory should provide "${area}"`);
    }
    assert.equal(model.scan.complete, false);
    assert.equal(model.scan.truncated, false);
    assert.deepEqual(model.scan.errors, []);
    assert.ok(validateRepositoryModel(model));
  });

  it("rejects a model missing identity", () => {
    const model = validRepository();
    delete model.identity;
    const error = assertInvalid(() => validateRepositoryModel(model));
    assert.ok(error.details.issues.some((i) => i.includes("identity")));
  });

  it("rejects a model missing the contract version", () => {
    const model = validRepository();
    delete model.version;
    assertInvalid(() => validateRepositoryModel(model));
  });

  it("rejects invalid scan states", () => {
    assertInvalid(() =>
      validateRepositoryModel(
        validRepository({
          scan: { complete: "yes", truncated: false, limits: {}, errors: [] },
        }),
      ),
    );
    assertInvalid(() =>
      validateRepositoryModel(
        validRepository({
          scan: { complete: false, truncated: 1, limits: {}, errors: [] },
        }),
      ),
    );
    assertInvalid(() =>
      validateRepositoryModel(
        validRepository({
          scan: { complete: false, truncated: false, limits: [], errors: [] },
        }),
      ),
    );
    assertInvalid(() =>
      validateRepositoryModel(
        validRepository({
          scan: {
            complete: false,
            truncated: false,
            limits: {},
            errors: "nope",
          },
        }),
      ),
    );
    assertInvalid(() =>
      validateRepositoryModel(validRepository({ scan: { complete: false } })),
    );
  });

  it("never lets a truncated scan masquerade as complete", () => {
    assertInvalid(() =>
      validateRepositoryModel(
        validRepository({
          scan: { complete: true, truncated: true, limits: {}, errors: [] },
        }),
      ),
    );
  });

  it("requires scan error entries to be structured objects", () => {
    const error = assertInvalid(() =>
      validateRepositoryModel(
        validRepository({
          scan: {
            complete: false,
            truncated: true,
            limits: {},
            errors: ["EACCES"],
          },
        }),
      ),
    );
    assert.ok(error.details.issues.some((i) => i.includes("errors[0]")));
  });

  it("rejects an invalid file collection", () => {
    assertInvalid(() =>
      validateRepositoryModel(validRepository({ files: [] })),
    );
    assertInvalid(() =>
      validateRepositoryModel(
        validRepository({
          files: { entries: "nope", count: 0, truncated: false },
        }),
      ),
    );
    assertInvalid(() =>
      validateRepositoryModel(
        validRepository({
          files: { entries: [], count: -1, truncated: false },
        }),
      ),
    );
  });

  it("rejects wrong collection types for other areas", () => {
    assertInvalid(() =>
      validateRepositoryModel(validRepository({ languages: "javascript" })),
    );
    assertInvalid(() =>
      validateRepositoryModel(validRepository({ configuration: [] })),
    );
    assertInvalid(() =>
      validateRepositoryModel(validRepository({ dependencies: [] })),
    );
  });

  it("provides the optional areas as empty, valid defaults", () => {
    const model = createRepositoryModel();
    for (const area of REPOSITORY_MODEL_OPTIONAL_AREAS) {
      assert.ok(area in model, `factory should provide "${area}"`);
    }
    assert.deepEqual(model.relationships, []);
    assert.deepEqual(model.evidence, []);
    assert.deepEqual(model.indexes, {});
    assert.deepEqual(model.documentation, {});
    assert.ok(validateRepositoryModel(model));
  });

  it("validates the optional areas when a model carries them", () => {
    const base = validRepository();

    // A model without the optional areas stays valid: they are optional.
    assert.ok(validateRepositoryModel(base));
    assert.ok(
      validateRepositoryModel({
        ...base,
        relationships: [{ from: "repository:1", type: "contains", to: "file:a.js" }],
        evidence: [validEvidence()],
        indexes: { entitiesById: {} },
        documentation: { detected: true, entries: [] },
      }),
    );

    // Malformed graph structures are rejected, not ignored.
    assertInvalid(() =>
      validateRepositoryModel({ ...base, relationships: [{ from: "a", type: "contains" }] }),
    );
    assertInvalid(() => validateRepositoryModel({ ...base, relationships: ["contains"] }));
    assertInvalid(() => validateRepositoryModel({ ...base, evidence: [{ id: "e1" }] }));
    assertInvalid(() => validateRepositoryModel({ ...base, evidence: "none" }));
    assertInvalid(() => validateRepositoryModel({ ...base, indexes: [] }));
    assertInvalid(() => validateRepositoryModel({ ...base, documentation: [] }));
  });

  it("requires facts, not judgments", () => {
    // The model is valid with observed facts and no judgments at all.
    const model = validRepository({
      configuration: { envFiles: [{ path: ".env" }] },
      dependencies: { production: [{ name: "express", version: "4.0.0" }] },
    });
    assert.ok(validateRepositoryModel(model));

    // The contract does not name or require any judgment area.
    for (const judgment of REPOSITORY_MODEL_JUDGMENT_AREAS) {
      assert.ok(
        !REPOSITORY_MODEL_AREAS.includes(judgment),
        `"${judgment}" must not be a required RepositoryModel area`,
      );
    }
  });
});

// ─── Evidence ────────────────────────────────────────────────────────────────

describe("Evidence contract", () => {
  it("accepts valid file evidence", () => {
    const evidence = validEvidence();
    assert.equal(validateEvidence(evidence), evidence);
  });

  it("accepts line evidence with a location", () => {
    const evidence = validEvidence({
      id: "evidence-line",
      type: "line",
      location: { path: "src/auth/login.js", line: 42, column: 17 },
    });
    assert.ok(validateEvidence(evidence));
  });

  it("accepts AST evidence", () => {
    const evidence = validEvidence({
      id: "evidence-ast",
      type: "ast",
      data: { nodeType: "CallExpression", symbol: "authenticateUser" },
    });
    assert.ok(validateEvidence(evidence));
  });

  it("accepts every declared evidence type", () => {
    for (const type of EVIDENCE_TYPES) {
      assert.ok(validateEvidence(validEvidence({ type })), `type ${type}`);
    }
  });

  it("allows locations without path, line, or column", () => {
    assert.ok(validateEvidence(validEvidence({ location: {} })));
  });

  it("rejects a missing or empty id", () => {
    assertInvalid(() => validateEvidence(validEvidence({ id: undefined })));
    assertInvalid(() => validateEvidence(validEvidence({ id: "" })));
  });

  it("rejects an invalid or missing type", () => {
    assertInvalid(() => validateEvidence(validEvidence({ type: "banana" })));
    assertInvalid(() => validateEvidence(validEvidence({ type: undefined })));
  });

  it("rejects invalid locations", () => {
    assertInvalid(() =>
      validateEvidence(rawEvidence({ location: "src/auth/login.js" })),
    );
    assertInvalid(() =>
      validateEvidence(rawEvidence({ location: { path: "x.js", line: 0 } })),
    );
    assertInvalid(() =>
      validateEvidence(rawEvidence({ location: { path: "x.js", line: -3 } })),
    );
    assertInvalid(() =>
      validateEvidence(
        rawEvidence({ location: { path: "x.js", column: 1.5 } }),
      ),
    );
    assertInvalid(() =>
      validateEvidence(rawEvidence({ location: { path: "" } })),
    );
  });

  it("requires provenance", () => {
    const missing = rawEvidence();
    delete missing.provenance;
    assertInvalid(() => validateEvidence(missing));

    assertInvalid(() => validateEvidence(rawEvidence({ provenance: {} })));
    assertInvalid(() =>
      validateEvidence(rawEvidence({ provenance: { deterministic: "yes" } })),
    );
    assertInvalid(() =>
      validateEvidence(rawEvidence({ provenance: "deterministic" })),
    );
  });

  it("never fabricates deterministic provenance", () => {
    // The producer must state whether the observation is deterministic; the
    // factory must not assert it on the producer's behalf.
    const draft = createEvidence({
      id: "evidence-1",
      type: "file",
      location: { path: "src/auth/login.js" },
      source: { analyzer: "security", method: "filesystem" },
      data: {},
    });
    assert.deepEqual(draft.provenance, {});
    assert.ok(!("deterministic" in draft.provenance));
    assertInvalid(() => validateEvidence(draft));
  });

  it("accepts explicit deterministic provenance", () => {
    const deterministic = validEvidence({
      provenance: { deterministic: true },
    });
    assert.equal(deterministic.provenance.deterministic, true);
    assert.ok(validateEvidence(deterministic));
  });

  it("accepts explicit non-deterministic provenance", () => {
    const nonDeterministic = validEvidence({
      provenance: { deterministic: false, collector: "llm-assist" },
    });
    assert.equal(nonDeterministic.provenance.deterministic, false);
    assert.ok(validateEvidence(nonDeterministic));
  });

  it("rejects missing or invalid deterministic provenance", () => {
    // Missing the `deterministic` key entirely.
    assertInvalid(() => validateEvidence(rawEvidence({ provenance: {} })));
    // Present but not a boolean.
    assertInvalid(() =>
      validateEvidence(rawEvidence({ provenance: { deterministic: "yes" } })),
    );
    assertInvalid(() =>
      validateEvidence(rawEvidence({ provenance: { deterministic: 1 } })),
    );
    assertInvalid(() =>
      validateEvidence(rawEvidence({ provenance: { deterministic: null } })),
    );
  });

  it("requires source and data", () => {
    const missingSource = rawEvidence();
    delete missingSource.source;
    assertInvalid(() => validateEvidence(missingSource));

    const missingData = rawEvidence();
    delete missingData.data;
    assertInvalid(() => validateEvidence(missingData));

    assertInvalid(() => validateEvidence(rawEvidence({ data: [] })));
  });
});

// ─── Finding ─────────────────────────────────────────────────────────────────

describe("Finding contract", () => {
  it("accepts a valid finding", () => {
    const finding = validFinding();
    assert.equal(validateFinding(finding), finding);
  });

  it("rejects an invalid severity", () => {
    assertInvalid(() => validateFinding(validFinding({ severity: "severe" })));
    assertInvalid(() => validateFinding(validFinding({ severity: undefined })));
  });

  it("rejects confidence outside [0, 1]", () => {
    assertInvalid(() => validateFinding(validFinding({ confidence: -1 })));
    assertInvalid(() => validateFinding(validFinding({ confidence: 1.4 })));
    assertInvalid(() =>
      validateFinding(validFinding({ confidence: 0.01 - 0.02 })),
    );
  });

  it("rejects a non-numeric confidence", () => {
    assertInvalid(() => validateFinding(validFinding({ confidence: "high" })));
    assertInvalid(() => validateFinding(validFinding({ confidence: NaN })));
    assertInvalid(() =>
      validateFinding(validFinding({ confidence: Infinity })),
    );
    assertInvalid(() =>
      validateFinding(validFinding({ confidence: undefined })),
    );
  });

  it("accepts and reports confidence boundary values", () => {
    assert.equal(isValidConfidence(CONFIDENCE_MIN), true);
    assert.equal(isValidConfidence(CONFIDENCE_MAX), true);
    assert.equal(isValidConfidence(0.5), true);
    assert.equal(isValidConfidence(-0.01), false);
    assert.equal(isValidConfidence(1.01), false);
    assert.equal(isValidConfidence("1"), false);
    assert.ok(validateFinding(validFinding({ confidence: 0 })));
    assert.ok(validateFinding(validFinding({ confidence: 1 })));
  });

  it("keeps severity and confidence independent", () => {
    const lowConfidenceCritical = validFinding({
      severity: "critical",
      confidence: 0.2,
    });
    const highConfidenceLow = validFinding({
      severity: "low",
      confidence: 0.99,
    });
    assert.ok(validateFinding(lowConfidenceCritical));
    assert.ok(validateFinding(highConfidenceLow));
    assert.equal(lowConfidenceCritical.severity, "critical");
    assert.equal(lowConfidenceCritical.confidence, 0.2);
    assert.ok(FINDING_SEVERITIES.includes("critical"));
  });

  it("rejects a missing rule ID or title", () => {
    assertInvalid(() => validateFinding(validFinding({ ruleId: undefined })));
    assertInvalid(() => validateFinding(validFinding({ ruleId: "" })));
    assertInvalid(() => validateFinding(validFinding({ title: undefined })));
    assertInvalid(() => validateFinding(validFinding({ title: "" })));
  });

  it("uses evidence references instead of embedded evidence", () => {
    assert.ok(validateFinding(validFinding({ evidence: [] })));
    assert.ok(
      validateFinding(validFinding({ evidence: ["evidence-1", "evidence-2"] })),
    );
    assertInvalid(() =>
      validateFinding(validFinding({ evidence: [{ id: "evidence-1" }] })),
    );
    assertInvalid(() => validateFinding(validFinding({ evidence: [1] })));
    assertInvalid(() =>
      validateFinding(validFinding({ evidence: "evidence-1" })),
    );
  });

  it("requires a fingerprint on the canonical finding", () => {
    assertInvalid(() =>
      validateFinding(validFinding({ fingerprint: undefined })),
    );
    assertInvalid(() => validateFinding(validFinding({ fingerprint: "" })));
    assert.ok(validateFinding(validFinding({ fingerprint: "sha256:abc" })));
  });

  it("produces raw findings without inventing a fingerprint", () => {
    // Fingerprint generation is deferred to the future Finding Engine, so a
    // raw finding may legitimately exist before a fingerprint is assigned.
    const raw = rawFinding();
    assert.ok(
      !("fingerprint" in raw),
      "the factory must not fabricate a fingerprint",
    );
    assert.equal(hasFingerprint(raw), false);
    assert.equal(validateRawFinding(raw), raw);
    // The canonical validator still demands a fingerprint.
    assertInvalid(() => validateFinding(raw));
  });

  it("promotes a raw finding once a fingerprint exists", () => {
    const canonical = validFinding();
    assert.equal(canonical.fingerprint, "fp-1");
    assert.equal(hasFingerprint(canonical), true);
    assert.ok(validateFinding(canonical));
    // A canonical finding also satisfies the raw contract.
    assert.ok(validateRawFinding(canonical));
  });

  it("rejects a malformed fingerprint even on a raw finding", () => {
    // Absent is fine pre-canonically; malformed never is.
    assertInvalid(() => validateRawFinding(rawFinding({ fingerprint: "" })));
    assertInvalid(() => validateRawFinding(rawFinding({ fingerprint: 42 })));
    assertInvalid(() => validateRawFinding(rawFinding({ fingerprint: "  " })));
  });

  it("enforces the raw finding contract as strictly as the canonical one otherwise", () => {
    assertInvalid(() => validateRawFinding(rawFinding({ severity: "severe" })));
    assertInvalid(() => validateRawFinding(rawFinding({ confidence: 2 })));
    assertInvalid(() => validateRawFinding(rawFinding({ ruleId: "" })));
    assertInvalid(() => validateRawFinding(rawFinding({ evidence: [1] })));
    const draft = rawFinding();
    assert.equal(validateRawFinding(draft), draft);
  });

  it("reports the fingerprint discriminator from the contract", () => {
    assert.equal(hasFingerprint(null), false);
    assert.equal(hasFingerprint("finding"), false);
    assert.equal(hasFingerprint({}), false);
    assert.equal(hasFingerprint({ fingerprint: "  " }), false);
    assert.equal(hasFingerprint({ fingerprint: "fp-1" }), true);
  });

  it("requires a valid status and metadata", () => {
    for (const status of FINDING_STATUSES) {
      assert.ok(validateFinding(validFinding({ status })), `status ${status}`);
    }
    assertInvalid(() => validateFinding(validFinding({ status: "closed" })));
    assertInvalid(() => validateFinding(validFinding({ metadata: [] })));
  });

  it("permits optional impact and remediation", () => {
    const finding = validFinding({
      impact: { type: "security", description: "credential exposure" },
      remediation: { summary: "rotate the secret", steps: [] },
    });
    assert.ok(validateFinding(finding));
  });
});

// ─── Rule ────────────────────────────────────────────────────────────────────

describe("Rule contract", () => {
  it("accepts a valid rule", () => {
    const rule = validRule();
    assert.equal(validateRule(rule), rule);
    assert.equal(typeof rule.detect, "function");
  });

  it("separates metadata from executable behavior", () => {
    const rule = validRule();
    assert.deepEqual(RULE_REQUIRED_FIELDS, [
      "id",
      "version",
      "category",
      "title",
      "description",
      "severity",
      "applicability",
      "detect",
      "remediation",
      "metadata",
    ]);
    assert.equal(Object.keys(rule).length, RULE_REQUIRED_FIELDS.length);
  });

  it("rejects invalid versions", () => {
    assertInvalid(() => validateRule(validRule({ version: undefined })));
    assertInvalid(() => validateRule(validRule({ version: "1.0" })));
    assertInvalid(() => validateRule(validRule({ version: "v1" })));
    assertInvalid(() => validateRule(validRule({ version: 1 })));
    assert.ok(validateRule(validRule({ version: "1.2.0-beta.1" })));
  });

  it("rejects an invalid severity", () => {
    assertInvalid(() => validateRule(validRule({ severity: "severe" })));
  });

  it("requires detect behavior to be a function", () => {
    assertInvalid(() => validateRule(validRule({ detect: undefined })));
    assertInvalid(() => validateRule(validRule({ detect: {} })));
    assertInvalid(() => validateRule(validRule({ detect: [] })));
  });

  it("rejects a rule with a missing ID", () => {
    assertInvalid(() => validateRule(validRule({ id: undefined })));
    assertInvalid(() => validateRule(validRule({ id: "" })));
  });

  it("rejects a non-object rule and invalid applicability", () => {
    assertInvalid(() => validateRule(null));
    assertInvalid(() => validateRule([]));
    assertInvalid(() => validateRule(validRule({ applicability: [] })));
    assertInvalid(() => validateRule(validRule({ remediation: [] })));
    assertInvalid(() => validateRule(validRule({ metadata: [] })));
  });
});

// ─── Analyzer ────────────────────────────────────────────────────────────────

describe("Analyzer contract", () => {
  it("accepts a valid analyzer", () => {
    const analyzer = validAnalyzer();
    assert.equal(validateAnalyzer(analyzer), analyzer);
    assert.equal(typeof analyzer.canAnalyze, "function");
    assert.equal(typeof analyzer.analyze, "function");
  });

  it("builds an analyzer draft without inventing behavior or identity", () => {
    const draft = createAnalyzer({
      id: "test.fixture",
      name: "Fixture",
      version: "1.0.0",
      scope: "test",
      canAnalyze: () => createApplicability({ applicable: true }),
      analyze: () => createAnalysisResult(),
    });
    assert.equal(validateAnalyzer(draft), draft);
    assert.equal(draft.name, "Fixture");
    assert.equal(draft.scope, "test");
    assert.deepEqual([...ANALYZER_DESCRIPTIVE_FIELDS].sort(), [
      "description",
      "metadata",
      "name",
      "scope",
    ]);

    // The factory fills only semantically neutral defaults.
    const empty = createAnalyzer();
    assert.equal(empty.id, undefined);
    assert.equal(empty.name, undefined);
    assert.equal(empty.canAnalyze, undefined);
    assert.equal(empty.analyze, undefined);
    assert.equal(empty.description, "");
    assert.deepEqual(empty.metadata, {});
    assertInvalid(() => validateAnalyzer(empty));

    // Descriptive fields are optional to the contract: an executable analyzer
    // without them is still a valid Analyzer.
    const minimal = {
      id: "test.minimal",
      version: "1.0.0",
      canAnalyze: () => createApplicability({ applicable: false, reason: "n/a" }),
      analyze: () => createAnalysisResult(),
    };
    assert.equal(validateAnalyzer(minimal), minimal);
  });

  it("accepts a valid canAnalyze() result", () => {
    assert.ok(
      validateAnalyzerApplicability(createApplicability({ applicable: true })),
    );
    assert.ok(
      validateAnalyzerApplicability(
        createApplicability({
          applicable: false,
          reason: "No HTTP application detected",
        }),
      ),
    );
  });

  it("rejects an invalid canAnalyze() result", () => {
    assertInvalid(() => validateAnalyzerApplicability(null));
    assertInvalid(() => validateAnalyzerApplicability({}));
    assertInvalid(() => validateAnalyzerApplicability({ applicable: "yes" }));
    assertInvalid(() =>
      validateAnalyzerApplicability({ applicable: true, reason: 5 }),
    );
  });

  it("accepts a valid analyze() result", () => {
    const result = createAnalysisResult({
      findings: [validFinding()],
      evidence: [validEvidence()],
      metrics: { filesAnalyzed: 1 },
      metadata: { analyzer: "security" },
    });
    assert.equal(validateAnalyzerResult(result), result);
  });

  it("rejects malformed analyzer results", () => {
    assertInvalid(() => validateAnalyzerResult(null));
    assertInvalid(() => validateAnalyzerResult(undefined));
    assertInvalid(() => validateAnalyzerResult([]));
    assertInvalid(() => validateAnalyzerResult("result"));
  });

  it("rejects results missing required fields", () => {
    assertInvalid(() =>
      validateAnalyzerResult({ evidence: [], metrics: {}, metadata: {} }),
    );
    assertInvalid(() =>
      validateAnalyzerResult({ findings: [], metrics: {}, metadata: {} }),
    );
    assertInvalid(() =>
      validateAnalyzerResult({ findings: [], evidence: [], metadata: {} }),
    );
    assertInvalid(() =>
      validateAnalyzerResult({ findings: [], evidence: [], metrics: {} }),
    );
    assertInvalid(() =>
      validateAnalyzerResult({
        findings: "nope",
        evidence: [],
        metrics: {},
        metadata: {},
      }),
    );
  });

  it("validates findings and evidence nested in a result", () => {
    const withBadEvidence = createAnalysisResult({
      evidence: [validEvidence({ type: "banana" })],
    });
    assertInvalid(() => validateAnalyzerResult(withBadEvidence));

    const withBadFinding = createAnalysisResult({
      findings: [validFinding({ severity: "severe" })],
    });
    assertInvalid(() => validateAnalyzerResult(withBadFinding));
  });

  it("accepts raw analyzer findings before the Finding Engine runs", () => {
    // Analyzers run before fingerprint generation, so a result may carry raw
    // findings that have no fingerprint yet.
    const result = createAnalysisResult({ findings: [rawFinding()] });
    assert.equal(validateAnalyzerResult(result), result);
    assert.ok(!("fingerprint" in result.findings[0]));
  });

  it("still rejects malformed raw findings nested in a result", () => {
    assertInvalid(() =>
      validateAnalyzerResult(
        createAnalysisResult({ findings: [rawFinding({ confidence: 3 })] }),
      ),
    );
  });

  it("rejects analyzers missing identity or methods", () => {
    assertInvalid(() => validateAnalyzer(validAnalyzer({ id: "" })));
    assertInvalid(() =>
      validateAnalyzer(validAnalyzer({ version: undefined })),
    );
    assertInvalid(() =>
      validateAnalyzer(validAnalyzer({ analyze: undefined })),
    );
    assertInvalid(() => validateAnalyzer(validAnalyzer({ canAnalyze: "yes" })));
    assert.equal(ANALYZER_REQUIRED_FIELDS.length, 4);
    assert.equal(ANALYSIS_RESULT_FIELDS.length, 4);
  });
});

// ─── AnalysisContext ─────────────────────────────────────────────────────────

describe("AnalysisContext contract", () => {
  it("accepts a valid context", () => {
    const context = validAnalysisContext();
    assert.equal(validateAnalysisContext(context), context);
  });

  it("defaults optional members while requiring the repository", () => {
    const context = createAnalysisContext({ repository: validRepository() });
    assert.deepEqual(context.rules, []);
    assert.deepEqual(context.evidence, []);
    assert.deepEqual(context.options, {});
    assert.deepEqual(context.configuration, {});
    assert.deepEqual(context.execution, {});
    assert.equal(context.repository.version, REPOSITORY_MODEL_VERSION);
  });

  it("rejects a context missing the repository", () => {
    const context = validAnalysisContext();
    delete context.repository;
    const error = assertInvalid(() => validateAnalysisContext(context));
    assert.ok(error.details.issues.some((i) => i.includes("repository")));
  });

  it("rejects invalid member types", () => {
    assertInvalid(() =>
      validateAnalysisContext(validAnalysisContext({ rules: {} })),
    );
    assertInvalid(() =>
      validateAnalysisContext(validAnalysisContext({ evidence: "evidence-1" })),
    );
    assertInvalid(() =>
      validateAnalysisContext(validAnalysisContext({ options: [] })),
    );
    assertInvalid(() =>
      validateAnalysisContext(validAnalysisContext({ configuration: [] })),
    );
  });

  it("accepts well-formed nested rules and evidence", () => {
    const context = validAnalysisContext({
      rules: [validRule()],
      evidence: [validEvidence()],
    });
    assert.equal(validateAnalysisContext(context), context);
  });

  it("rejects a malformed nested RepositoryModel", () => {
    // A plain object that is not a RepositoryModel must be rejected, not merely
    // accepted because it happens to be an object.
    const context = createAnalysisContext({
      repository: { version: REPOSITORY_MODEL_VERSION },
    });
    const error = assertInvalid(() => validateAnalysisContext(context));
    assert.ok(
      error.details.issues.some((i) => i.includes("repository.identity")),
      "should report the missing nested RepositoryModel area",
    );
  });

  it("rejects a nested RepositoryModel with an invalid area", () => {
    const context = validAnalysisContext({
      repository: validRepository({ languages: "javascript" }),
    });
    const error = assertInvalid(() => validateAnalysisContext(context));
    assert.ok(
      error.details.issues.some((i) => i.includes("repository.languages")),
    );
  });

  it("rejects malformed nested rules", () => {
    // An object that is shape-adjacent to a Rule but missing required behavior.
    const notARule = validRule({ detect: undefined });
    const context = validAnalysisContext({ rules: [notARule] });
    const error = assertInvalid(() => validateAnalysisContext(context));
    assert.ok(
      error.details.issues.some((i) => i.includes("rules[0].detect")),
      "should validate each nested rule",
    );
  });

  it("rejects malformed nested evidence", () => {
    const notEvidence = validEvidence({ type: "banana" });
    const context = validAnalysisContext({ evidence: [notEvidence] });
    const error = assertInvalid(() => validateAnalysisContext(context));
    assert.ok(
      error.details.issues.some((i) => i.includes("evidence[0].type")),
      "should validate each nested evidence object",
    );
  });

  it("rejects nested evidence missing deterministic provenance", () => {
    const draft = createEvidence({
      id: "evidence-1",
      type: "file",
      location: { path: "src/auth/login.js" },
      source: { analyzer: "security", method: "filesystem" },
      data: {},
    });
    const context = validAnalysisContext({ evidence: [draft] });
    assertInvalid(() => validateAnalysisContext(context));
  });
});

// ─── Execution ───────────────────────────────────────────────────────────────

describe("Execution contracts", () => {
  it("accepts a valid request and applies safe defaults", () => {
    const request = validExecutionRequest();
    assert.equal(validateExecutionRequest(request), request);
    assert.deepEqual(request.args, ["audit"]);
    assert.equal(request.timeout, DEFAULT_EXECUTION_TIMEOUT_MS);
    assert.equal(request.limits.maxOutputBytes, DEFAULT_MAX_OUTPUT_BYTES);
    assert.equal(request.policy.network, "disabled");
    assert.deepEqual(request.environment, {});
  });

  it("rejects invalid requests", () => {
    assertInvalid(() =>
      validateExecutionRequest(validExecutionRequest({ command: "" })),
    );
    assertInvalid(() =>
      validateExecutionRequest(validExecutionRequest({ command: undefined })),
    );
    assertInvalid(() =>
      validateExecutionRequest(validExecutionRequest({ cwd: undefined })),
    );
    assertInvalid(() =>
      validateExecutionRequest(validExecutionRequest({ args: "audit" })),
    );
    assertInvalid(() =>
      validateExecutionRequest(validExecutionRequest({ args: ["audit", 1] })),
    );
    assertInvalid(() =>
      validateExecutionRequest(validExecutionRequest({ timeout: 0 })),
    );
    assertInvalid(() =>
      validateExecutionRequest(validExecutionRequest({ timeout: 1.5 })),
    );
  });

  it("rejects invalid limits and policies", () => {
    assertInvalid(() =>
      validateExecutionRequest(
        validExecutionRequest({ limits: { maxOutputBytes: -1 } }),
      ),
    );
    assertInvalid(() =>
      validateExecutionRequest({ ...validExecutionRequest(), policy: [] }),
    );
    assertInvalid(() =>
      validateExecutionRequest(
        validExecutionRequest({
          policy: createExecutionPolicy({ allowCommands: "npm" }),
        }),
      ),
    );
    assertInvalid(() =>
      validateExecutionRequest(
        validExecutionRequest({
          policy: createExecutionPolicy({ network: 5 }),
        }),
      ),
    );
    assert.ok(
      validateExecutionPolicy(
        createExecutionPolicy({ allowCommands: ["npm", "git"] }),
      ),
    );
  });

  it("separates authorization policy from per-invocation limits", () => {
    // The contract documents the distinction so a future Command Runner never
    // has to guess: policy is the trust boundary, limits are resource caps.
    assert.equal(EXECUTION_LIMIT_PRECEDENCE, "most-restrictive");
    assert.equal(EXECUTION_COMMAND_PRECEDENCE, "deny-overrides-allow");

    const request = validExecutionRequest();
    assert.ok(request.limits, "request carries per-invocation limits");
    assert.ok(request.policy, "request carries an authorization policy");

    // Empty lists are meaningful and must not be read as wildcards.
    const policy = createExecutionPolicy();
    assert.deepEqual(policy.allowCommands, []);
    assert.deepEqual(policy.denyCommands, []);
    assert.equal(policy.network, "disabled");
  });

  it("preserves allowedExecutableRoots through the policy factory", () => {
    // Executable *locations* are part of the authorization contract, so a
    // policy must not silently drop the executable roots a caller declared.
    const roots = ["/opt/toolchain/bin"];
    assert.deepEqual(createExecutionPolicy().allowedExecutableRoots, []);
    assert.deepEqual(
      createExecutionPolicy({ allowedExecutableRoots: roots })
        .allowedExecutableRoots,
      roots,
    );
    assert.ok(
      validateExecutionPolicy(
        createExecutionPolicy({ allowedExecutableRoots: roots }),
      ),
    );
    assert.deepEqual(
      createExecutionRequest({
        command: "node",
        cwd: "/repo",
        policy: { allowedExecutableRoots: roots },
      }).policy.allowedExecutableRoots,
      roots,
    );
    assertInvalid(() =>
      validateExecutionPolicy(
        createExecutionPolicy({ allowedExecutableRoots: "/opt/toolchain/bin" }),
      ),
    );
  });

  it("accepts a valid result", () => {
    const result = validExecutionResult();
    assert.equal(validateExecutionResult(result), result);
  });

  it("represents a timeout", () => {
    const result = validExecutionResult({
      exitCode: null,
      timedOut: true,
      duration: DEFAULT_EXECUTION_TIMEOUT_MS,
    });
    assert.ok(validateExecutionResult(result));
    assert.equal(getExecutionState(result), EXECUTION_STATES.TIMED_OUT);
  });

  it("represents a killed process", () => {
    const result = validExecutionResult({ exitCode: null, killed: true });
    assert.ok(validateExecutionResult(result));
    assert.equal(getExecutionState(result), EXECUTION_STATES.KILLED);
  });

  it("represents truncated output", () => {
    const result = validExecutionResult({ truncated: true });
    assert.ok(validateExecutionResult(result));
    assert.equal(result.truncated, true);
  });

  it("represents a non-zero exit code without treating it as an error", () => {
    const result = validExecutionResult({
      exitCode: 2,
      stdout: "",
      stderr: "failed",
    });
    assert.ok(validateExecutionResult(result));
    assert.equal(getExecutionState(result), EXECUTION_STATES.NON_ZERO_EXIT);
  });

  it("distinguishes not-started from other states", () => {
    const result = validExecutionResult({ exitCode: null });
    assert.equal(getExecutionState(result), EXECUTION_STATES.NOT_STARTED);
    assert.equal(
      getExecutionState(validExecutionResult({ exitCode: 0 })),
      EXECUTION_STATES.COMPLETED,
    );
  });

  it("rejects invalid results", () => {
    assertInvalid(() =>
      validateExecutionResult(rawExecutionResult({ exitCode: "0" })),
    );
    assertInvalid(() =>
      validateExecutionResult(rawExecutionResult({ exitCode: 1.5 })),
    );
    assertInvalid(() =>
      validateExecutionResult(rawExecutionResult({ duration: -1 })),
    );
    assertInvalid(() =>
      validateExecutionResult(rawExecutionResult({ timedOut: "yes" })),
    );
    assertInvalid(() =>
      validateExecutionResult(rawExecutionResult({ killed: 1 })),
    );
    assertInvalid(() =>
      validateExecutionResult(rawExecutionResult({ truncated: null })),
    );
    assertInvalid(() =>
      validateExecutionResult(rawExecutionResult({ stdout: 5 })),
    );
    assertInvalid(() => validateExecutionResult({ exitCode: 0 }));
    assertInvalid(() => validateExecutionResult(null));
  });

  it("describes execution without executing anything", async () => {
    // Building a request must not run the command or return a promise.
    const request = validExecutionRequest({
      command: "node",
      args: ["--version"],
    });
    assert.equal(typeof request.command, "string");
    assert.ok(!(request instanceof Promise));

    // The Core index must not expose command-execution helpers.
    const core = await import("../src/core/index.js");
    assert.equal(typeof core.run, "undefined");
    assert.equal(typeof core.spawn, "undefined");
    assert.equal(typeof core.exec, "undefined");
  });
});

// ─── Validation layer ────────────────────────────────────────────────────────

describe("contract validation", () => {
  it("validates by contract name", () => {
    assert.ok(validateContract("finding", validFinding()));
    assert.ok(validateContract("rawFinding", rawFinding()));
    assert.ok(validateContract("evidence", validEvidence()));
    assert.ok(validateContract("rule", validRule()));
    assertInvalid(() => validateContract("finding", { id: "x" }));
    // The raw contract is strict about everything except the fingerprint.
    assertInvalid(() => validateContract("rawFinding", { id: "x" }));
  });

  it("rejects unknown contract names", () => {
    assertInvalid(() => validateContract("nonsense", validFinding()));
  });

  it("reports every issue in a single structured error", () => {
    const error = assertInvalid(() => validateContract("finding", {}));
    assert.ok(error.details.issues.length > 1, "should aggregate issues");
    assert.equal(error.details.contract, "Finding");
  });

  it("does not mutate valid input", () => {
    const finding = validFinding();
    const snapshot = JSON.stringify(finding);
    validateFinding(finding);
    assert.equal(JSON.stringify(finding), snapshot);
  });
});

// ─── Factory semantics ───────────────────────────────────────────────────────

describe("factory semantics", () => {
  it("declares one uniform draft semantics for every Core factory", () => {
    assert.equal(CONTRACT_FACTORY_SEMANTICS, "draft");
  });

  it("is a draft factory, not a guaranteed-valid constructor", () => {
    // Insufficient input yields a shape-correct draft that fails validation.
    assertInvalid(() => validateRule(createRule()));
    assertInvalid(() => validateFinding(createFinding()));
    assertInvalid(() => validateEvidence(createEvidence()));
  });

  it("validates a draft as-is once the required facts are supplied", () => {
    assert.ok(validateRule(validRule()));
    assert.ok(validateRawFinding(rawFinding()));
    assert.ok(validateEvidence(validEvidence()));
    assert.ok(validateRepositoryModel(createRepositoryModel()));
  });
});

// ─── Architectural boundary ──────────────────────────────────────────────────

describe("core architectural boundary", () => {
  const coreFiles = collectCoreFiles(CORE_DIR);

  it("contains the Phase 7 boundary files", () => {
    const relativePaths = coreFiles.map((f) =>
      relative(CORE_DIR, f).split(sep).join("/"),
    );
    for (const expected of [
      "index.js",
      "contracts/repository-model.js",
      "contracts/evidence.js",
      "contracts/finding.js",
      "contracts/rule.js",
      "contracts/analyzer.js",
      "contracts/analysis-context.js",
      "contracts/execution.js",
      "errors/core-error.js",
      "validation/contract-validation.js",
    ]) {
      assert.ok(
        relativePaths.includes(expected),
        `expected src/core/${expected}`,
      );
    }
  });

  it("never imports transports, legacy tools, or child processes", () => {
    const forbidden = [
      ["node:child_process", /from\s+["']node:child_process["']/],
      [
        "child_process require",
        /require\(\s*["'](?:node:)?child_process["']\s*\)/,
      ],
      ["tools.js", /from\s+["'][^"']*tools\.js["']/],
      ["tool-registry.js", /from\s+["'][^"']*tool-registry[^"']*["']/],
      ["stdio-server.js", /from\s+["'][^"']*stdio-server[^"']*["']/],
      ["http-server.js", /from\s+["'][^"']*http-server[^"']*["']/],
    ];
    for (const file of coreFiles) {
      const source = readFileSync(file, "utf8");
      for (const [label, pattern] of forbidden) {
        assert.ok(!pattern.test(source), `${file} must not reference ${label}`);
      }
    }
  });

  it("never calls a process-spawning API", () => {
    for (const file of coreFiles) {
      const source = readFileSync(file, "utf8");
      assert.ok(
        !/\b(spawn|execFile|execSync)\s*\(/.test(source),
        `${file} must not spawn processes`,
      );
    }
  });
});
