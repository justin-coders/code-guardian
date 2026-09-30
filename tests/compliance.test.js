/**
 * Code Guardian — Policy & Compliance Engine Tests (Phase 22)
 *
 * Four fixture styles, chosen deliberately:
 *
 *   - **real repositories** written to a temporary directory and scanned through the accepted
 *     Phase 8A boundary, the Phase 8C scanner and the Phase 8D model builder, so acquisition, model,
 *     policy area, compliance report, query API and rule pack agree end to end. This is the only way
 *     to prove that what a repository literally declares is what the compliance report measures.
 *   - **hand-built documents** for the parsing contract: a policy is one JSON file with a closed
 *     schema, and every way it can be wrong produces a state and a reason rather than a finding.
 *   - **tampering inside the model's own areas**, because the point of the contract is that a
 *     malformed policy or a one-sided violation is a validation failure instead of an answer.
 *   - **the accepted engines**, because the pack must be an ordinary analyzer over the accepted
 *     framework and nothing else.
 *
 * The suite's central claims are the phase's central requirements: a violation is a statement with
 * **two** sides — the repository observation and the policy that requires the opposite — a domain
 * with no declared policy abstains instead of passing, a malformed policy never becomes a document,
 * every item's rationale is the sentence its own fields render, and there is no score, percentage,
 * grade or traffic light anywhere in the report or in the rules that consume it.
 *
 * No test starts a container, sends a request, spawns a process, contacts a network, installs a
 * package, reads a vulnerability database or writes to the repository under test.
 *
 * Run with: node --test tests/compliance.test.js
 */

import { after, describe, it } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { ValidationError } from "../src/core/index.js";

import {
  POLICY_DOCUMENT_PATH,
  POLICY_FAILURE_REASONS,
  POLICY_LIMITS,
  POLICY_SOURCE_STATUSES,
  POLICY_UNREAD_FORMATS,
  boundedPolicyToken,
  createScanResult,
  parsePolicyDocument,
  policySettingCount,
  scanRepository,
  validateScanResult,
} from "../src/repository/scanner/index.js";

import {
  COMPLIANCE_BUILDER,
  COMPLIANCE_CHECK_IDS,
  COMPLIANCE_LIMITS,
  COMPLIANCE_OBSERVED_VALUES,
  COMPLIANCE_SECTIONS,
  COMPLIANCE_SECTION_STATES,
  COMPLIANCE_SECTION_TITLES,
  COMPLIANCE_STATES,
  COMPLIANCE_STATES as COMPLIANCE_REPORT_STATES,
  COMPLIANCE_STATUSES,
  COMPLIANCE_UNKNOWN_REASONS,
  COMPLIANCE_VERSION,
  EVIDENCE_SUBJECTS,
  MAX_RELEASE_WORKFLOWS,
  POLICY_DOCUMENT_KEYS,
  POLICY_DOCUMENT_SCHEMA,
  POLICY_DOCUMENT_VERSION,
  POLICY_DOMAINS,
  POLICY_LIMITS as MODEL_POLICY_LIMITS,
  POLICY_READ_FAILURE_REASONS,
  POLICY_STATES,
  POLICY_UNKNOWN_REASONS,
  buildComplianceReport,
  buildPolicyArea,
  buildRepositoryModel,
  createRepositoryQuery,
  emptyPolicyArea,
  isEstablishedPolicyState,
  policyDocumentDomains,
  policyDocumentSettingCount,
  policyDocumentEvidenceId,
  renderComplianceRationale,
  unmeasuredPolicyKeys,
  unknownPolicyCheckKeys,
  validateRepositoryModelGraph,
} from "../src/repository/model/index.js";

import {
  buildAnalysisContext,
  createAnalyzerEngine,
  createAnalyzerRegistry,
} from "../src/analysis/index.js";

import {
  APPLICABILITY_COVERAGE,
  MAX_IDENTIFIER_LENGTH,
  RULE_OUTCOME_STATUSES,
  createRuleEngine,
} from "../src/rules/index.js";

import {
  COMPLIANCE_ABSTENTION_WORDING,
  COMPLIANCE_ANALYZER_ID,
  COMPLIANCE_ANALYZER_NAME,
  COMPLIANCE_ANALYZER_SCOPE,
  COMPLIANCE_BASIS,
  COMPLIANCE_CATEGORY,
  COMPLIANCE_CONFIDENCE,
  COMPLIANCE_DESCRIBED_ABSTENTIONS,
  COMPLIANCE_DESCRIBED_POLICY_STATES,
  COMPLIANCE_DESCRIBED_SECTIONS,
  COMPLIANCE_DESCRIBED_STATES,
  COMPLIANCE_DESCRIBED_STATUSES,
  COMPLIANCE_POLICY_STATE_WORDING,
  COMPLIANCE_RULE_ID_PREFIX,
  COMPLIANCE_RULE_IDS,
  COMPLIANCE_RULE_PACK_VERSION,
  COMPLIANCE_RULE_SEVERITIES,
  COMPLIANCE_SECTIONS as PACK_SECTIONS,
  COMPLIANCE_SECTION_WORDING,
  COMPLIANCE_SEVERITY_VALUES,
  COMPLIANCE_STATE_WORDING,
  COMPLIANCE_STATUS_WORDING,
  MAX_COMPLIANCE_FINDINGS,
  complianceAbsence,
  complianceCoverage,
  complianceDomainRules,
  compliancePolicy,
  complianceRuleSetIssues,
  complianceRules,
  complianceSection as complianceSectionSignal,
  complianceSections,
  createComplianceAnalyzer,
  createComplianceRuleRegistry,
  queryFor,
} from "../src/rules/compliance/index.js";

// ─── Fixtures ────────────────────────────────────────────────────────────────

const HERE = dirname(fileURLToPath(import.meta.url));
const TMP = mkdtempSync(join(tmpdir(), "cg-compliance-"));
after(() => rmSync(TMP, { recursive: true, force: true }));

let repositories = 0;

/**
 * Write a repository and scan it end to end.
 *
 * @param {Record<string, string>} files Repository-relative path → contents.
 * @returns {Promise<object>} The scan, model, areas, query handle, context and report.
 */
async function scanOf(files) {
  const root = join(TMP, `repo-${repositories}`);
  repositories += 1;
  mkdirSync(root, { recursive: true });
  for (const [relative, content] of Object.entries(files)) {
    const full = join(root, relative);
    mkdirSync(dirname(full), { recursive: true });
    writeFileSync(full, content);
  }
  const scan = await scanRepository(root);
  const model = buildRepositoryModel(scan);
  return {
    root,
    scan,
    model,
    policy: model.policy,
    compliance: model.compliance,
    report: model.compliance.report,
    query: createRepositoryQuery(model),
    context: buildAnalysisContext({ repository: model }),
  };
}

/** A minimal `package.json`. */
const pkg = (fields = {}) =>
  JSON.stringify({ name: "demo", version: "1.0.0", ...fields }, null, 2);

/** An npm v3 lockfile resolving the given `node_modules/<name>` entries. */
const npmLock = (entries = {}) =>
  JSON.stringify(
    { name: "demo", lockfileVersion: 3, packages: { "": { name: "demo" }, ...entries } },
    null,
    2,
  );

/** A GitHub Actions workflow body. Deliberately minimal: no workflow body is ever read. */
const workflow = (name) =>
  `name: ${name}\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ${name}\n`;

/** A Dockerfile with the given instructions. */
const dockerfile = (...instructions) => [...instructions, ""].join("\n");

/** A repository-relative policy document. */
const policyFile = (policy) => ({ [POLICY_DOCUMENT_PATH]: JSON.stringify(policy, null, 2) });

/** Merge a partial document over the full one, so one key can be stated without the rest. */
function documentOf(overrides = {}) {
  return {
    environment: { requireTemplate: true, allowMultipleTemplates: false },
    container: { requireHealthcheck: true },
    ci: { requireTestsForRelease: true, requireLintForRelease: true, maxReleaseWorkflows: 1 },
    api: { requireResolvedMiddleware: true },
    dependencies: { requireLockfile: true, allowMultipleManagers: false },
    architecture: { requireConnectedEntrypoints: true },
    ...overrides,
  };
}

/** Everything a policy document can declare, all of it binding. */
const FULL_POLICY = documentOf();

/** A hand-built, validated scan result over a list of file paths. */
function literalScan(
  paths,
  { complete = true, truncated = false, ignored = [], policy = null, errors = [] } = {},
) {
  // The scan contract requires its inventory ordered by path, so a hand-built scan sorts here
  // rather than making every caller remember to.
  const ordered = [...paths].sort();
  const directories = new Set();
  for (const path of ordered) {
    const parts = path.split("/");
    for (let index = 1; index < parts.length; index += 1) {
      directories.add(parts.slice(0, index).join("/"));
    }
  }
  return validateScanResult(
    createScanResult({
      root: "/repo",
      scannedAt: "2026-01-01T00:00:00.000Z",
      files: ordered.map((path) => ({
        path,
        name: path.slice(path.lastIndexOf("/") + 1),
        extension: path.includes(".") ? path.slice(path.lastIndexOf(".")) : "",
        depth: path.split("/").length,
      })),
      directories: [...directories].sort().map((path) => ({
        path,
        name: path.slice(path.lastIndexOf("/") + 1),
        depth: path.split("/").length,
      })),
      ignored,
      policy: policy ?? undefined,
      statistics: {
        filesScanned: ordered.length,
        directoriesScanned: directories.size,
        symlinksScanned: 0,
        ignored: ignored.length,
        unreadable: errors.length,
        truncatedBy: truncated ? ["file-limit"] : [],
      },
      scan: { complete, truncated, limits: { maxFiles: 10000, maxDepth: 20 }, errors },
    }),
  );
}

/** Every problem the graph contract reports, or `null` when the model is valid. */
function issuesOfValidate(model) {
  try {
    validateRepositoryModelGraph(model);
    return null;
  } catch (error) {
    if (error instanceof ValidationError) return error.details?.issues ?? [];
    throw error;
  }
}

const clone = (value) => JSON.parse(JSON.stringify(value));
const sectionOf = (report, name) => report.sections.find((entry) => entry.name === name);
const itemsOf = (report, name) => sectionOf(report, name).items;
const itemOf = (report, name, policyKey) =>
  itemsOf(report, name).find((entry) => entry.policyKey === policyKey) ?? null;
const statusesOf = (report, name) => itemsOf(report, name).map((entry) => `${entry.policyKey}=${entry.status}`);

/**
 * A synthetic ProductionReport whose api section carries a chosen number of protected routes.
 *
 * The compliance report's item bound (200 per section) sits at the same ceiling as the accepted
 * production report's observation bound, so a scan of a real repository always reaches the
 * production bound first — no repository can drive the compliance bound through acquisition alone.
 * The bound is therefore tested where it lives: over the report the layers above would have had to
 * produce for it to bite.
 */
function routesReport(count) {
  return {
    sections: COMPLIANCE_SECTIONS.map((name) => ({
      name,
      state: "complete",
      established: true,
      observations:
        name === "api"
          ? Array.from({ length: count }, (_, index) => ({
              kind: "api-route",
              key: `api-route:GET:/r${String(index).padStart(4, "0")}`,
              route: `GET:/r${String(index).padStart(4, "0")}`,
              protection: "protected",
              evidenceIds: [],
            }))
          : [],
    })),
  };
}

/** A policy and a repository in which every declared requirement is contradicted. */
const VIOLATING_REPO = {
  ...policyFile(FULL_POLICY),
  ...pkg({ dependencies: { express: "^4.18.0" } })
    .split("\n")
    .reduce((accumulator, _line, index, all) => {
      accumulator["package.json"] = all.join("\n");
      return accumulator;
    }, {}),
  Dockerfile: dockerfile("FROM node:20", 'CMD ["node", "main.js"]'),
  ".github/workflows/release.yml": workflow("release"),
  "main.js": 'console.log("hi");\n',
  ".env.production": "SECRET=1\n",
};

/** A repository in which every declared requirement is satisfied. */
const COMPLIANT_REPO = {
  ...policyFile(FULL_POLICY),
  "package.json": pkg({ dependencies: { express: "^4.18.0" } }),
  "package-lock.json": npmLock({ "node_modules/express": { version: "4.18.2" } }),
  Dockerfile: dockerfile(
    "FROM node:20",
    'HEALTHCHECK CMD node -e "process.exit(0)"',
    'CMD ["node", "main.js"]',
  ),
  ".github/workflows/release.yml": workflow("release"),
  ".github/workflows/test.yml": workflow("test"),
  ".github/workflows/lint.yml": workflow("lint"),
  ".env": "DEMO=1\n",
  ".env.example": "PORT=3000\n",
  "main.js": ['import express from "express";', 'import { requireAuth } from "./src/auth.js";', "const app = express();", "app.use(requireAuth);", 'app.get("/users", handler);', "export default app;", ""].join("\n"),
  "src/auth.js": "export function requireAuth(req, res, next) { next(); }\n",
};

const AUTH_MODULE = { "src/auth.js": "export function requireAuth(req, res, next) { next(); }\n" };

/** A real Express entrypoint declaring one route, with the given registrations above it. */
const expressApp = (...registrations) => ({
  ...policyFile(documentOf({ environment: undefined, ci: undefined, dependencies: undefined, architecture: undefined, container: undefined })),
  "package.json": pkg(),
  ...AUTH_MODULE,
  "main.js": [
    'import express from "express";',
    'import { requireAuth } from "./src/auth.js";',
    "const app = express();",
    ...registrations,
    'app.get("/users", handler);',
    "export default app;",
    "",
  ].join("\n"),
});

// ─── Policy parsing ──────────────────────────────────────────────────────────

describe("policy parsing", () => {
  it("reads a valid document and rebuilds it in canonical order", () => {
    const parsed = parsePolicyDocument(
      '{"ci":{"maxReleaseWorkflows":2},"container":{"requireHealthcheck":true}}',
    );
    assert.equal(parsed.ok, true);
    // Declared order, not the document's own order: two spellings of one policy must serialize
    // identically, or every downstream id would depend on how a file was typed.
    assert.deepEqual(Object.keys(parsed.document), ["container", "ci"]);
    assert.deepEqual(parsed.document, {
      container: { requireHealthcheck: true },
      ci: { maxReleaseWorkflows: 2 },
    });
  });

  it("reads a partial document, an empty document and an unknown-shape document", () => {
    assert.deepEqual(parsePolicyDocument('{"container":{"requireHealthcheck":false}}').document, {
      container: { requireHealthcheck: false },
    });
    assert.deepEqual(parsePolicyDocument("{}").document, {});
    // An empty domain is declared and states nothing: a valid document with no requirement.
    assert.deepEqual(parsePolicyDocument('{"api":{}}').document, { api: {} });
  });

  it("rebuilds one domain's settings in schema order", () => {
    // A document may state its settings in any order; the parsed document is rebuilt in the
    // schema's, so two spellings of one policy serialize identically and every downstream id
    // depends on the declaration rather than on how a file was typed.
    const parsed = parsePolicyDocument(
      '{"ci":{"maxReleaseWorkflows":2,"requireTestsForRelease":true,"requireLintForRelease":false}}',
    );
    assert.equal(parsed.ok, true);
    assert.deepEqual(Object.keys(parsed.document.ci), [
      "requireTestsForRelease",
      "requireLintForRelease",
      "maxReleaseWorkflows",
    ]);
    assert.deepEqual(parsed.document.ci, {
      requireTestsForRelease: true,
      requireLintForRelease: false,
      maxReleaseWorkflows: 2,
    });
  });

  it("counts the settings a document states, and only the declared ones", () => {
    assert.equal(policySettingCount({ container: { requireHealthcheck: true } }), 1);
    assert.equal(policySettingCount({ ci: { maxReleaseWorkflows: 1, requireLintForRelease: false } }), 2);
    assert.equal(policySettingCount(null), 0);
  });

  it("refuses malformed JSON without quoting the document", () => {
    const parsed = parsePolicyDocument('{ "container": ');
    assert.equal(parsed.ok, false);
    assert.equal(parsed.reason, POLICY_FAILURE_REASONS.INVALID_JSON);
    assert.equal(parsed.detail, null);
  });

  it("refuses a document that is not an object", () => {
    for (const text of ["[]", '"policy"', "3", "null", "true"]) {
      const parsed = parsePolicyDocument(text);
      assert.equal(parsed.ok, false, text);
      assert.equal(parsed.reason, POLICY_FAILURE_REASONS.NOT_AN_OBJECT, text);
    }
  });

  it("refuses an unknown domain, an unknown key and a wrong type", () => {
    const domain = parsePolicyDocument('{"secrets":{"requireRotation":true}}');
    assert.equal(domain.reason, POLICY_FAILURE_REASONS.UNKNOWN_DOMAIN);
    assert.equal(domain.detail, "secrets");

    const key = parsePolicyDocument('{"container":{"requireHealthchecks":true}}');
    assert.equal(key.reason, POLICY_FAILURE_REASONS.UNKNOWN_KEY);
    assert.equal(key.detail, "container.requireHealthchecks");

    const type = parsePolicyDocument('{"container":{"requireHealthcheck":"yes"}}');
    assert.equal(type.reason, POLICY_FAILURE_REASONS.WRONG_TYPE);
    assert.equal(type.detail, "container.requireHealthcheck");

    const shape = parsePolicyDocument('{"container":true}');
    assert.equal(shape.reason, POLICY_FAILURE_REASONS.WRONG_TYPE);
  });

  it("refuses a setting outside its declared bound and accepts both ends of it", () => {
    const outOfRange = parsePolicyDocument(`{"ci":{"maxReleaseWorkflows":${MAX_RELEASE_WORKFLOWS + 1}}}`);
    assert.equal(outOfRange.reason, POLICY_FAILURE_REASONS.OUT_OF_RANGE);
    const negative = parsePolicyDocument('{"ci":{"maxReleaseWorkflows":-1}}');
    assert.equal(negative.reason, POLICY_FAILURE_REASONS.OUT_OF_RANGE);
    const fractional = parsePolicyDocument('{"ci":{"maxReleaseWorkflows":1.5}}');
    assert.equal(fractional.reason, POLICY_FAILURE_REASONS.WRONG_TYPE);
    assert.equal(parsePolicyDocument('{"ci":{"maxReleaseWorkflows":0}}').ok, true);
    assert.equal(
      parsePolicyDocument(`{"ci":{"maxReleaseWorkflows":${MAX_RELEASE_WORKFLOWS}}}`).ok,
      true,
    );
  });

  it("refuses bytes that are not text", () => {
    const parsed = parsePolicyDocument('{"container":\u0000}');
    assert.equal(parsed.reason, POLICY_FAILURE_REASONS.NOT_TEXT);
  });

  it("bounds the identifier a refusal may name", () => {
    const long = "x".repeat(200);
    assert.equal(boundedPolicyToken(long).length, POLICY_LIMITS.maxDetailLength);
    assert.equal(boundedPolicyToken("a/b\\c"), "abc");
    assert.equal(boundedPolicyToken(""), null);
    assert.equal(boundedPolicyToken(7), null);
    const parsed = parsePolicyDocument(JSON.stringify({ [`bad key ${long}`]: {} }));
    assert.equal(parsed.reason, POLICY_FAILURE_REASONS.UNKNOWN_DOMAIN);
    assert.equal(parsed.detail.length <= POLICY_LIMITS.maxDetailLength, true);
  });

  it("acquires the document through the scan and records it once", async () => {
    const { scan } = await scanOf({ ...policyFile(FULL_POLICY), "package.json": pkg() });
    assert.equal(scan.policy.path, POLICY_DOCUMENT_PATH);
    assert.equal(scan.policy.detected, true);
    assert.equal(scan.policy.inspected, true);
    assert.equal(scan.policy.status, POLICY_SOURCE_STATUSES.PARSED);
    assert.deepEqual(Object.keys(scan.policy.document), POLICY_DOMAINS);
  });

  it("records an absent policy as absent, never as an empty one", async () => {
    const { scan, policy } = await scanOf({ "package.json": pkg() });
    assert.equal(scan.policy.status, POLICY_SOURCE_STATUSES.ABSENT);
    assert.equal(scan.policy.detected, false);
    assert.equal(policy.state, POLICY_STATES.ABSENT);
    assert.equal(policy.document, null);
    assert.equal(policy.established, true);
  });

  it("records a policy in an unread format as unsupported rather than absent", async () => {
    for (const { path, format } of POLICY_UNREAD_FORMATS) {
      const { policy, compliance } = await scanOf({ [path]: "container:\n  requireHealthcheck: true\n" });
      // Never "this repository declares no policy": that would be a fabricated fact.
      assert.equal(policy.state, POLICY_STATES.UNSUPPORTED, path);
      assert.equal(policy.coverage.reason, POLICY_UNKNOWN_REASONS.FORMAT_NOT_INTERPRETED, path);
      assert.equal(policy.coverage.detail, format, path);
      assert.equal(policy.established, false, path);
      assert.equal(compliance.report.state, COMPLIANCE_STATES.UNKNOWN, path);
    }
  });

  it("lets the contracted path decide when both formats exist", async () => {
    const { policy } = await scanOf({
      ...policyFile({ container: { requireHealthcheck: true } }),
      ".codeguardian/policy.yaml": "container:\n  requireHealthcheck: false\n",
    });
    assert.equal(policy.state, POLICY_STATES.ESTABLISHED);
    assert.deepEqual(policy.document, { container: { requireHealthcheck: true } });
  });

  it("refuses a document larger than the read bound", async () => {
    const huge = `{"container":{"requireHealthcheck":true},"padding":"${"x".repeat(
      POLICY_LIMITS.maxFileBytes,
    )}"}`;
    const { policy } = await scanOf({ [POLICY_DOCUMENT_PATH]: huge });
    assert.equal(policy.state, POLICY_STATES.UNKNOWN);
    assert.equal(policy.document, null);
  });

  it("never turns a malformed policy into a document", () => {
    for (const text of ['{ nope', '{"container":{"requireHealthcheck":"yes"}}', "[]", '{"a":1}']) {
      const parsed = parsePolicyDocument(text);
      assert.equal(parsed.ok, false, text);
      assert.equal(Object.hasOwn(parsed, "document"), false, text);
    }
  });
});

// ─── The model's policy area ─────────────────────────────────────────────────

describe("model: policy area", () => {
  it("publishes only the contracted fields, preserving validated values", async () => {
    const { policy } = await scanOf({ ...policyFile(FULL_POLICY), "package.json": pkg() });
    // Phase 23 adds three fields to the area and changes none of the five: `document` is still the
    // policy the model acts on, `declared` is what the repository wrote, `preset` is the built-in
    // preset that was applied, and `provenance` says where every effective value came from. A
    // document that names no preset resolves to exactly the domains it stated (plus the pinned
    // version on the declared side), so `preset` is null and every value is user-stated here.
    assert.deepEqual(Object.keys(policy).sort(), [
      "coverage",
      "declared",
      "detected",
      "document",
      "established",
      "preset",
      "provenance",
      "state",
    ]);
    assert.deepEqual(policy.document, FULL_POLICY);
    // The declared document is the same policy plus the version the model pins to it; no preset was
    // named, so nothing is inherited and every value is the repository's own.
    assert.equal(policy.declared.version, POLICY_DOCUMENT_VERSION);
    assert.equal(policy.preset, null);
    assert.equal(policy.provenance.preset, null);
    assert.deepEqual(policy.provenance.inherited, []);
    assert.deepEqual(policy.provenance.overridden, []);
    assert.deepEqual(
      Object.keys(policy.provenance.sources),
      Object.keys(policy.document)
        .flatMap((domain) => Object.keys(policy.document[domain]).map((key) => `${domain}.${key}`))
        .sort(),
    );
    assert.equal(policy.provenance.sources["ci.requireTestsForRelease"], "user");
    assert.equal(policy.state, POLICY_STATES.ESTABLISHED);
    assert.equal(policy.established, true);
    assert.equal(isEstablishedPolicyState(policy.state), true);
    assert.deepEqual(policy.coverage.domains, POLICY_DOMAINS);
    assert.equal(policy.coverage.settings, policyDocumentSettingCount(policy.document));
    assert.equal(policy.coverage.path, POLICY_DOCUMENT_PATH);
    assert.equal(policy.coverage.complete, true);
  });

  it("makes the document itself first-class evidence", async () => {
    const { model, policy } = await scanOf({ ...policyFile(FULL_POLICY), "package.json": pkg() });
    const id = policyDocumentEvidenceId(POLICY_DOCUMENT_PATH);
    assert.deepEqual(policy.coverage.evidenceIds, [id]);
    const record = model.evidence.find((entry) => entry.id === id);
    assert.notEqual(record, undefined);
    assert.equal(record.id.split(":")[1], EVIDENCE_SUBJECTS.POLICY);
    assert.equal(record.location.path, POLICY_DOCUMENT_PATH);
    assert.equal(record.data.signal, "policy-document");
    assert.equal(record.data.status, POLICY_SOURCE_STATUSES.PARSED);
    assert.deepEqual(record.data.domains, POLICY_DOMAINS);
    // Deterministic provenance, like every other observation the model carries.
    assert.equal(record.provenance.deterministic, true);
  });

  it("maps a refusal to a state and a bounded reason", async () => {
    const cases = [
      ['{ nope', POLICY_UNKNOWN_REASONS.DOCUMENT_NOT_INTERPRETED, "invalid-json"],
      ['{"container":{"requireHealthcheck":"yes"}}', POLICY_UNKNOWN_REASONS.DOCUMENT_NOT_INTERPRETED, "wrong-type"],
      ['{"secrets":{}}', POLICY_UNKNOWN_REASONS.DOCUMENT_NOT_INTERPRETED, "unknown-domain"],
    ];
    for (const [text, reason, detail] of cases) {
      const { policy, compliance } = await scanOf({ [POLICY_DOCUMENT_PATH]: text, "package.json": pkg() });
      assert.equal(policy.state, POLICY_STATES.UNKNOWN, detail);
      assert.equal(policy.coverage.reason, reason, detail);
      assert.equal(policy.coverage.detail, detail, detail);
      assert.equal(policy.document, null, detail);
      assert.equal(policy.established, false, detail);
      // A malformed policy is a *state*, never a finding.
      assert.equal(compliance.report.coverage.items, 0, detail);
      assert.equal(
        compliance.report.sections.every((section) => section.items.length === 0),
        true,
        detail,
      );
    }
  });

  it("names a failed read as an unreadable path", async () => {
    // A policy path the scan could not read at all: the read boundary classifies the failure, and
    // the model turns that classification into a bounded reason rather than carrying a message.
    const scan = literalScan(["package.json", POLICY_DOCUMENT_PATH], {
      policy: {
        path: POLICY_DOCUMENT_PATH,
        detected: true,
        inspected: false,
        status: POLICY_SOURCE_STATUSES.FAILED,
        reason: POLICY_FAILURE_REASONS.READ_FAILED,
        detail: "PERMISSION_DENIED",
        document: null,
      },
    });
    const model = buildRepositoryModel(scan);
    assert.equal(model.policy.state, POLICY_STATES.UNKNOWN);
    assert.equal(model.policy.coverage.reason, POLICY_UNKNOWN_REASONS.PATH_UNREADABLE);
    assert.equal(model.policy.coverage.detail, "read-failed");
  });

  it("records an unreadable policy path as unreadable rather than absent", () => {
    // A scan that observed the path and could not read it is not a repository that declares no
    // policy: the reading failed, and the area says which of the two happened.
    const scan = literalScan(["package.json", POLICY_DOCUMENT_PATH], {
      errors: [{ path: POLICY_DOCUMENT_PATH, reason: "permission-denied" }],
    });
    const model = buildRepositoryModel(scan);
    assert.equal(model.policy.state, POLICY_STATES.UNKNOWN);
    assert.equal(model.policy.coverage.reason, POLICY_UNKNOWN_REASONS.PATH_UNREADABLE);
    assert.equal(model.policy.established, false);
    assert.equal(model.policy.document, null);
  });

  it("withholds absence when the scan did not cover the repository", () => {
    const ignoredPath = { path: POLICY_DOCUMENT_PATH, name: "policy.json", isDirectory: false, policy: "gitignore" };
    const scan = literalScan(["package.json", POLICY_DOCUMENT_PATH], {
      complete: false,
      ignored: [ignoredPath],
    });
    const model = buildRepositoryModel(scan);
    assert.equal(model.policy.state, POLICY_STATES.UNKNOWN);
    assert.equal(model.policy.coverage.reason, POLICY_UNKNOWN_REASONS.PATH_IGNORED);
    assert.equal(model.policy.established, false);
  });

  it("reports a truncated scan as truncated rather than as an absent policy", () => {
    const truncated = buildRepositoryModel(literalScan(["package.json"], { complete: false, truncated: true }));
    assert.equal(truncated.policy.state, POLICY_STATES.TRUNCATED);
    assert.equal(truncated.policy.coverage.reason, POLICY_UNKNOWN_REASONS.SCAN_TRUNCATED);
    assert.equal(truncated.policy.coverage.truncated, true);

    const partial = buildRepositoryModel(literalScan(["package.json"], { complete: false }));
    assert.equal(partial.policy.state, POLICY_STATES.UNKNOWN);
    assert.equal(partial.policy.coverage.reason, POLICY_UNKNOWN_REASONS.COVERAGE_NOT_COMPLETE);
  });

  it("keeps a read document established even when the inventory was truncated", () => {
    // The document was read in full; a truncated *inventory* says nothing about it.
    const scan = literalScan(["package.json", POLICY_DOCUMENT_PATH], {
      complete: false,
      truncated: true,
      policy: {
        path: POLICY_DOCUMENT_PATH,
        detected: true,
        inspected: true,
        status: POLICY_SOURCE_STATUSES.PARSED,
        reason: null,
        detail: null,
        document: { container: { requireHealthcheck: true } },
      },
    });
    const model = buildRepositoryModel(scan);
    assert.equal(model.policy.state, POLICY_STATES.ESTABLISHED);
    assert.deepEqual(model.policy.document, { container: { requireHealthcheck: true } });
  });

  it("names the domains and settings a document declares, and only those", () => {
    const partial = { container: { requireHealthcheck: true }, api: { requireResolvedMiddleware: false } };
    assert.deepEqual(policyDocumentDomains(partial), ["container", "api"]);
    assert.equal(policyDocumentSettingCount(partial), 2);
    // Domain order is the schema's, and a declared domain with no setting states nothing.
    assert.deepEqual(policyDocumentDomains({ api: {}, container: {} }), ["container", "api"]);
    assert.equal(policyDocumentSettingCount({ ci: { requireTestsForRelease: true, maxReleaseWorkflows: 2 } }), 2);
    assert.equal(policyDocumentSettingCount({ api: {} }), 0);
    assert.deepEqual(policyDocumentDomains(null), []);
    assert.equal(policyDocumentSettingCount(null), 0);
  });

  it("builds the same area from an empty input as the contracted skeleton carries", () => {
    const empty = emptyPolicyArea();
    assert.equal(empty.state, POLICY_STATES.UNKNOWN);
    assert.equal(empty.document, null);
    assert.equal(empty.coverage.reason, POLICY_UNKNOWN_REASONS.COVERAGE_NOT_COMPLETE);
    assert.deepEqual(empty.coverage.domains, []);
    assert.deepEqual(policyDocumentDomains(null), []);
    assert.equal(buildPolicyArea({ policy: null, scan: { complete: true, truncated: false } }).state, POLICY_STATES.ABSENT);
  });

  it("states every re-declared vocabulary exactly as the acquisition layer does", () => {
    // The model restates the schema rather than importing the scanner (the model must not depend on
    // the acquisition layer), so the two lists are pinned here: a rename on either side fails.
    assert.deepEqual(POLICY_DOMAINS, Object.keys(POLICY_DOCUMENT_SCHEMA));
    for (const domain of POLICY_DOMAINS) {
      assert.deepEqual(POLICY_DOCUMENT_KEYS[domain], Object.keys(POLICY_DOCUMENT_SCHEMA[domain]));
    }
    assert.deepEqual(Object.keys(POLICY_DOCUMENT_SCHEMA), COMPLIANCE_SECTIONS);
    assert.equal(
      MODEL_POLICY_LIMITS.maxDetailLength,
      POLICY_LIMITS.maxDetailLength,
    );
    assert.equal(MODEL_POLICY_LIMITS.maxDomains, POLICY_LIMITS.maxDomains);
    assert.equal(MODEL_POLICY_LIMITS.maxKeysPerDomain, POLICY_LIMITS.maxKeysPerDomain);
    assert.equal(MAX_RELEASE_WORKFLOWS, POLICY_LIMITS.maxReleaseWorkflows);
    for (const reason of POLICY_READ_FAILURE_REASONS) {
      assert.equal(POLICY_FAILURE_REASONS[reason.replace(/-/g, "_").toUpperCase()], reason, reason);
    }
  });
});

// ─── Environment ─────────────────────────────────────────────────────────────

describe("compliance: environment", () => {
  it("violates a required template the environment reading observed none of", async () => {
    const { report } = await scanOf({
      ...policyFile({ environment: { requireTemplate: true } }),
      ".env.production": "SECRET=1\n",
    });
    const item = itemOf(report, "environment", "environment.requireTemplate");
    assert.equal(item.status, COMPLIANCE_STATUSES.VIOLATION);
    assert.equal(item.expected, true);
    assert.equal(item.observed, "template-not-observed");
    assert.equal(item.basis, "file-name");
    // Both sides, always.
    assert.equal(item.evidenceIds.length > 0, true);
    assert.equal(item.policyEvidenceIds.length, 1);
    assert.equal(sectionOf(report, "environment").state, COMPLIANCE_SECTION_STATES.VIOLATION);
  });

  it("satisfies the same requirement when a template was observed", async () => {
    const { report } = await scanOf({
      ...policyFile({ environment: { requireTemplate: true } }),
      ".env": "DEMO=1\n",
      ".env.example": "PORT=3000\n",
    });
    const item = itemOf(report, "environment", "environment.requireTemplate");
    assert.equal(item.status, COMPLIANCE_STATUSES.PASS);
    assert.equal(item.observed, "template-observed");
    assert.equal(sectionOf(report, "environment").state, COMPLIANCE_SECTION_STATES.PASS);
  });

  it("measures a two-template limit from the observed template names", async () => {
    const { report } = await scanOf({
      ...policyFile({ environment: { allowMultipleTemplates: false } }),
      ".env.example": "PORT=3000\n",
      ".env.template": "PORT=3001\n",
    });
    const item = itemOf(report, "environment", "environment.allowMultipleTemplates");
    assert.equal(item.expected, false);
    assert.equal(item.observed, "templates-multiple");
    assert.equal(item.status, COMPLIANCE_STATUSES.VIOLATION);
  });

  it("states no requirement when the policy allows multiple templates", async () => {
    const { report, compliance } = await scanOf({
      ...policyFile({ environment: { allowMultipleTemplates: true } }),
      ".env.example": "PORT=3000\n",
      ".env.template": "PORT=3001\n",
    });
    // A key that makes no requirement produces no item: there is nothing to measure, and a "pass"
    // for it would inflate the satisfied list with something nobody checked.
    assert.equal(itemOf(report, "environment", "environment.allowMultipleTemplates"), null);
    assert.deepEqual(itemsOf(report, "environment"), []);
    assert.equal(sectionOf(report, "environment").policyDeclared, true);
    assert.deepEqual(sectionOf(report, "environment").policyKeys, ["allowMultipleTemplates"]);
    assert.equal(
      sectionOf(report, "environment").unknown.some(
        (record) => record.reason === COMPLIANCE_UNKNOWN_REASONS.POLICY_REQUIREMENT_NOT_DECLARED,
      ),
      true,
    );
    assert.equal(compliance.state, COMPLIANCE_STATES.UNKNOWN);
  });

  it("abstains when the policy states nothing for the domain", async () => {
    const { report, compliance } = await scanOf({
      // A policy that declares a domain and makes no requirement in it, so that no domain in this
      // repository can be measured: the environment case is the one under test, and the declared
      // domain keeps a satisfied requirement from appearing elsewhere in the report.
      ...policyFile({ container: { requireHealthcheck: false } }),
      ".env.production": "SECRET=1\n",
    });
    const section = sectionOf(report, "environment");
    assert.deepEqual(section.items, []);
    assert.equal(section.state, COMPLIANCE_SECTION_STATES.UNKNOWN);
    assert.equal(section.established, false);
    assert.equal(section.policyDeclared, false);
    assert.deepEqual(
      section.unknown.map((record) => record.reason),
      [COMPLIANCE_UNKNOWN_REASONS.POLICY_DOMAIN_NOT_DECLARED],
    );
    // Never a pass, at any level.
    assert.equal(compliance.state, COMPLIANCE_STATES.UNKNOWN);
    assert.equal(compliance.report.violations.length, 0);
    assert.equal(compliance.report.passed.length, 0);
    // The coverage names exactly the domains the document declared, not the six the schema has.
    assert.deepEqual(report.coverage.policyDomains, ["container"]);
  });

  it("abstains over the whole report when no policy exists at all", async () => {
    const { compliance, report } = await scanOf({ ".env.production": "SECRET=1\n" });
    assert.equal(compliance.state, COMPLIANCE_STATES.UNKNOWN);
    assert.equal(compliance.established, false);
    assert.equal(compliance.coverage.items, 0);
    assert.equal(report.coverage.policyState, POLICY_STATES.ABSENT);
    for (const section of report.sections) {
      assert.deepEqual(
        section.unknown.map((record) => record.reason),
        [COMPLIANCE_UNKNOWN_REASONS.POLICY_DOMAIN_NOT_DECLARED],
        section.name,
      );
    }
  });

  it("abstains when no policy document could be established", async () => {
    const { compliance, report } = await scanOf({
      [POLICY_DOCUMENT_PATH]: "{ nope",
      ".env.production": "SECRET=1\n",
    });
    assert.equal(compliance.state, COMPLIANCE_STATES.UNKNOWN);
    assert.equal(report.coverage.policyEstablished, false);
    for (const section of report.sections) {
      assert.deepEqual(
        section.unknown.map((record) => record.reason),
        [COMPLIANCE_UNKNOWN_REASONS.POLICY_DOCUMENT_NOT_ESTABLISHED],
        section.name,
      );
    }
  });
});

// ─── Container ───────────────────────────────────────────────────────────────

describe("compliance: container", () => {
  it("violates a required healthcheck the Dockerfile does not declare", async () => {
    const { report } = await scanOf({
      ...policyFile({ container: { requireHealthcheck: true } }),
      Dockerfile: dockerfile("FROM node:20", 'CMD ["node", "main.js"]'),
    });
    const item = itemOf(report, "container", "container.requireHealthcheck");
    assert.equal(item.status, COMPLIANCE_STATUSES.VIOLATION);
    assert.equal(item.observed, "healthcheck-absent");
    assert.equal(item.subject, "Dockerfile");
    assert.equal(item.basis, "dockerfile-instructions");
    assert.equal(item.evidenceIds.length, 2);
    assert.equal(item.rationale.includes("declares none"), true);
  });

  it("distinguishes a disabled healthcheck from an absent one", async () => {
    const { report } = await scanOf({
      ...policyFile({ container: { requireHealthcheck: true } }),
      Dockerfile: dockerfile("FROM node:20", "HEALTHCHECK NONE"),
    });
    const item = itemOf(report, "container", "container.requireHealthcheck");
    assert.equal(item.observed, "healthcheck-disabled");
    assert.equal(item.status, COMPLIANCE_STATUSES.VIOLATION);
    assert.equal(item.rationale.includes("disables it"), true);
  });

  it("satisfies the requirement when the Dockerfile declares one", async () => {
    const { report } = await scanOf({
      ...policyFile({ container: { requireHealthcheck: true } }),
      Dockerfile: dockerfile("FROM node:20", "HEALTHCHECK CMD node -e 0"),
    });
    const item = itemOf(report, "container", "container.requireHealthcheck");
    assert.equal(item.status, COMPLIANCE_STATUSES.PASS);
    assert.equal(item.observed, "healthcheck-declared");
  });

  it("abstains, never passes, for a repository that declares no container definition", async () => {
    const { report, compliance } = await scanOf({
      ...policyFile({ container: { requireHealthcheck: true } }),
      "package.json": pkg(),
    });
    // The requirement is about the definitions the repository declares. With none it was never
    // compared against anything, so it is unmeasured — not satisfied, and not a finding either.
    const section = sectionOf(report, "container");
    assert.deepEqual(section.items, []);
    assert.equal(itemOf(report, "container", "container.requireHealthcheck"), null);
    assert.equal(section.state, COMPLIANCE_SECTION_STATES.UNKNOWN);
    assert.equal(section.established, false);
    assert.deepEqual(
      section.unknown.map((record) => record.reason),
      [COMPLIANCE_UNKNOWN_REASONS.NO_SUBJECT_TO_MEASURE],
    );
    assert.equal(compliance.state, COMPLIANCE_STATES.UNKNOWN);
  });

  it("abstains when the policy states the requirement is not made", async () => {
    const { report } = await scanOf({
      ...policyFile({ container: { requireHealthcheck: false } }),
      Dockerfile: dockerfile("FROM node:20"),
    });
    assert.equal(itemOf(report, "container", "container.requireHealthcheck"), null);
    assert.deepEqual(itemsOf(report, "container"), []);
  });

  it("abstains for a domain with no policy", async () => {
    const { report } = await scanOf({
      ...policyFile({ environment: { requireTemplate: true } }),
      Dockerfile: dockerfile("FROM node:20"),
    });
    assert.equal(sectionOf(report, "container").established, false);
    assert.deepEqual(
      sectionOf(report, "container").unknown.map((record) => record.reason),
      [COMPLIANCE_UNKNOWN_REASONS.POLICY_DOMAIN_NOT_DECLARED],
    );
  });
});

// ─── CI ──────────────────────────────────────────────────────────────────────

describe("compliance: ci", () => {
  it("violates a release workflow with no test workflow beside it", async () => {
    const { report } = await scanOf({
      ...policyFile({ ci: { requireTestsForRelease: true, requireLintForRelease: true } }),
      ".github/workflows/release.yml": workflow("release"),
    });
    const item = itemOf(report, "ci", "ci.requireTestsForRelease");
    assert.equal(item.status, COMPLIANCE_STATUSES.VIOLATION);
    assert.equal(item.observed, "test-workflow-not-observed");
    assert.equal(item.subject, ".github/workflows/release.yml");
    assert.equal(item.evidenceIds.length > 0, true);
    assert.equal(itemOf(report, "ci", "ci.requireLintForRelease").status, COMPLIANCE_STATUSES.VIOLATION);
  });

  it("satisfies the requirement when a test-shaped workflow exists", async () => {
    const { report } = await scanOf({
      ...policyFile({ ci: { requireTestsForRelease: true, requireLintForRelease: true } }),
      ".github/workflows/release.yml": workflow("release"),
      ".github/workflows/test.yml": workflow("test"),
      ".github/workflows/lint.yml": workflow("lint"),
    });
    assert.equal(itemOf(report, "ci", "ci.requireTestsForRelease").status, COMPLIANCE_STATUSES.PASS);
    assert.equal(itemOf(report, "ci", "ci.requireLintForRelease").status, COMPLIANCE_STATUSES.PASS);
    assert.equal(sectionOf(report, "ci").state, COMPLIANCE_SECTION_STATES.PASS);
  });

  it("abstains rather than accusing when a workflow name states no purpose", async () => {
    const { report } = await scanOf({
      ...policyFile({ ci: { requireTestsForRelease: true } }),
      ".github/workflows/release.yml": workflow("release"),
      ".github/workflows/ci.yml": workflow("ci"),
    });
    const item = itemOf(report, "ci", "ci.requireTestsForRelease");
    assert.equal(item.status, COMPLIANCE_STATUSES.UNKNOWN);
    assert.equal(item.observed, "workflow-purpose-not-established");
    assert.equal(sectionOf(report, "ci").state, COMPLIANCE_SECTION_STATES.UNKNOWN);
    assert.equal(
      sectionOf(report, "ci").unknown.some(
        (record) => record.reason === COMPLIANCE_UNKNOWN_REASONS.WORKFLOW_PURPOSE_NOT_ESTABLISHED,
      ),
      true,
    );
  });

  it("enforces a release-workflow limit from the names the reading established", async () => {
    const { report } = await scanOf({
      ...policyFile({ ci: { maxReleaseWorkflows: 1 } }),
      ".github/workflows/release.yml": workflow("release"),
      ".github/workflows/publish.yml": workflow("publish"),
    });
    const item = itemOf(report, "ci", "ci.maxReleaseWorkflows");
    assert.equal(item.observed, 2);
    assert.equal(item.expected, 1);
    assert.equal(item.status, COMPLIANCE_STATUSES.VIOLATION);
    assert.equal(item.rationale, "the policy allows at most 1 release workflows and the repository declares 2");
  });

  it("satisfies a limit the established count respects", async () => {
    const { report } = await scanOf({
      ...policyFile({ ci: { maxReleaseWorkflows: 2 } }),
      ".github/workflows/release.yml": workflow("release"),
      ".github/workflows/publish.yml": workflow("publish"),
    });
    const item = itemOf(report, "ci", "ci.maxReleaseWorkflows");
    assert.equal(item.observed, 2);
    assert.equal(item.status, COMPLIANCE_STATUSES.PASS);
  });

  it("proves a limit is exceeded even when another name states no purpose", async () => {
    // The release set is a lower bound, and a lower bound can prove an *exceeded* limit — but never
    // a respected one, which is why the count is withheld in the other direction.
    const exceeded = await scanOf({
      ...policyFile({ ci: { maxReleaseWorkflows: 1 } }),
      ".github/workflows/release.yml": workflow("release"),
      ".github/workflows/publish.yml": workflow("publish"),
      ".github/workflows/ci.yml": workflow("ci"),
    });
    assert.equal(itemOf(exceeded.report, "ci", "ci.maxReleaseWorkflows").status, COMPLIANCE_STATUSES.VIOLATION);

    const unproven = await scanOf({
      ...policyFile({ ci: { maxReleaseWorkflows: 3 } }),
      ".github/workflows/release.yml": workflow("release"),
      ".github/workflows/ci.yml": workflow("ci"),
    });
    const item = itemOf(unproven.report, "ci", "ci.maxReleaseWorkflows");
    assert.equal(item.observed, "count-not-established");
    assert.equal(item.status, COMPLIANCE_STATUSES.UNKNOWN);
  });

  it("abstains when the repository declares no release workflow to require tests of", async () => {
    const { report } = await scanOf({
      ...policyFile({ ci: { requireTestsForRelease: true } }),
      ".github/workflows/test.yml": workflow("test"),
    });
    // The requirement is about *each release path*; this repository declares none, so there was
    // nothing to require a test workflow of.
    const section = sectionOf(report, "ci");
    assert.deepEqual(section.items, []);
    assert.equal(section.state, COMPLIANCE_SECTION_STATES.UNKNOWN);
    assert.deepEqual(
      section.unknown.map((record) => record.reason),
      [COMPLIANCE_UNKNOWN_REASONS.NO_SUBJECT_TO_MEASURE],
    );
  });

  it("measures a release-workflow limit against the workflows the reading established", async () => {
    // A limit is a statement about the release workflows that exist, and "none exist" is a fact
    // the workflow inventory establishes — so this is a measurement with evidence, not an
    // unmeasured requirement beside it.
    const { report } = await scanOf({
      ...policyFile({ ci: { maxReleaseWorkflows: 2 } }),
      ".github/workflows/test.yml": workflow("test"),
    });
    const item = itemOf(report, "ci", "ci.maxReleaseWorkflows");
    assert.equal(item.observed, 0);
    assert.equal(item.status, COMPLIANCE_STATUSES.PASS);
    assert.equal(item.evidenceIds.length > 0, true);
    assert.equal(item.observed <= item.expected, true);
  });

  it("abstains when the repository declares no CI configuration at all", async () => {
    const { report, model } = await scanOf({
      ...policyFile({ ci: { requireTestsForRelease: true } }),
      "package.json": pkg(),
    });
    assert.equal(sectionOf(report, "ci").established, false);
    assert.equal(itemOf(report, "ci", "ci.requireTestsForRelease"), null);
    // The abstention is not this layer's opinion: the accepted production reading answered "this
    // repository declares no CI configuration", and the compliance report carries that answer.
    assert.equal(
      model.production.report.sections
        .find((section) => section.name === "ci")
        .unknown.some((record) => record.reason === "no-ci-configuration-observed"),
      true,
    );
  });
});

// ─── API ─────────────────────────────────────────────────────────────────────

describe("compliance: api", () => {
  it("violates a route whose middleware could not be resolved", async () => {
    const { report, model } = await scanOf(expressApp("app.use(auth.middleware);"));
    const item = itemOf(report, "api", "api.requireResolvedMiddleware");
    assert.equal(item.status, COMPLIANCE_STATUSES.VIOLATION);
    assert.equal(item.observed, "middleware-unresolved");
    assert.equal(item.subject, "route:GET:/users");
    assert.equal(item.basis, "middleware-graph-protection");
    // The premise is the accepted middleware graph's own protection word.
    const route = model.production.report.sections
      .find((entry) => entry.name === "api")
      .observations.find((entry) => entry.route === item.subject);
    assert.equal(route.protection, "unresolved");
    // It is a statement about a resolvable registration, never about the route's safety.
    assert.equal(/insecure|vulnerab|expos|attack/i.test(item.rationale), false);
  });

  it("satisfies the requirement for a route whose middleware resolved", async () => {
    const { report } = await scanOf(expressApp("app.use(requireAuth);"));
    const item = itemOf(report, "api", "api.requireResolvedMiddleware");
    assert.equal(item.status, COMPLIANCE_STATUSES.PASS);
    assert.equal(item.observed, "middleware-resolved");
  });

  it("treats an established \"no middleware\" answer as satisfying the requirement", async () => {
    const { report } = await scanOf({
      ...policyFile({ api: { requireResolvedMiddleware: true } }),
      "package.json": pkg(),
      "main.js": [
        'import express from "express";',
        "const app = express();",
        'app.get("/users", handler);',
        "export default app;",
        "",
      ].join("\n"),
    });
    const item = itemOf(report, "api", "api.requireResolvedMiddleware");
    // The requirement is that the middleware state be *established*, not that middleware exist.
    assert.equal(item.observed, "middleware-none-observed");
    assert.equal(item.status, COMPLIANCE_STATUSES.PASS);
  });

  it("abstains when there is no route to measure", async () => {
    const { report, compliance } = await scanOf({
      ...policyFile({ api: { requireResolvedMiddleware: true } }),
      "package.json": pkg(),
      "main.js": 'console.log("hi");\n',
    });
    // The requirement is about each route's middleware state. With no route there is nothing whose
    // middleware could be established, so the requirement is unmeasured rather than satisfied.
    const section = sectionOf(report, "api");
    assert.deepEqual(section.items, []);
    assert.equal(section.state, COMPLIANCE_SECTION_STATES.UNKNOWN);
    assert.deepEqual(
      section.unknown.map((record) => record.reason),
      [COMPLIANCE_UNKNOWN_REASONS.NO_SUBJECT_TO_MEASURE],
    );
    assert.equal(compliance.state, COMPLIANCE_STATES.UNKNOWN);
  });

  it("abstains over a domain the accepted report could not read", async () => {
    // The repository declares Python only, so the accepted production report answers `unsupported`
    // for the API domain: this build interprets no API source here. An unread domain yields no
    // measurement — not a pass, and not a claim about routes nobody read.
    const { report, model } = await scanOf({
      ...policyFile({ api: { requireResolvedMiddleware: true } }),
      "requirements.txt": "flask==2.0.0\n",
      "app.py": "print('x')\n",
    });
    const production = model.production.report.sections.find((section) => section.name === "api");
    assert.equal(production.state, "unsupported");
    const section = sectionOf(report, "api");
    assert.deepEqual(section.items, []);
    assert.equal(section.state, COMPLIANCE_SECTION_STATES.UNKNOWN);
    assert.equal(section.established, false);
    assert.deepEqual(
      section.unknown.map((record) => record.reason),
      [COMPLIANCE_UNKNOWN_REASONS.DOMAIN_NOT_ESTABLISHED],
    );
  });

  it("abstains with no policy", async () => {
    // The same express entrypoint, with no policy document beside it: nothing declares API
    // requirements, so the domain abstains instead of passing over an unstated requirement.
    const { report } = await scanOf({
      "package.json": pkg(),
      ...AUTH_MODULE,
      "main.js": [
        'import express from "express";',
        'import { requireAuth } from "./src/auth.js";',
        "const app = express();",
        "app.use(requireAuth);",
        'app.get("/users", handler);',
        "export default app;",
        "",
      ].join("\n"),
    });
    assert.equal(sectionOf(report, "api").established, false);
    assert.deepEqual(itemsOf(report, "api"), []);
    assert.deepEqual(
      sectionOf(report, "api").unknown.map((record) => record.reason),
      [COMPLIANCE_UNKNOWN_REASONS.POLICY_DOMAIN_NOT_DECLARED],
    );
  });
});

// ─── Dependencies ────────────────────────────────────────────────────────────

describe("compliance: dependencies", () => {
  it("violates a required lockfile the ecosystem does not have", async () => {
    const { report } = await scanOf({
      ...policyFile({ dependencies: { requireLockfile: true } }),
      "package.json": pkg({ dependencies: { express: "^4.18.0" } }),
    });
    const item = itemOf(report, "dependencies", "dependencies.requireLockfile");
    assert.equal(item.status, COMPLIANCE_STATUSES.VIOLATION);
    assert.equal(item.observed, "lockfile-not-observed");
    assert.equal(item.subject, "package.json");
    assert.equal(item.evidenceIds.length > 0, true);
    assert.equal(item.rationale.includes("none was observed"), true);
  });

  it("satisfies the requirement when the ecosystem is locked", async () => {
    const { report } = await scanOf({
      ...policyFile({ dependencies: { requireLockfile: true } }),
      "package.json": pkg({ dependencies: { express: "^4.18.0" } }),
      "package-lock.json": npmLock({ "node_modules/express": { version: "4.18.2" } }),
    });
    assert.equal(itemOf(report, "dependencies", "dependencies.requireLockfile").status, COMPLIANCE_STATUSES.PASS);
  });

  it("violates a single-manager policy when two ecosystems are declared", async () => {
    const { report } = await scanOf({
      ...policyFile({ dependencies: { allowMultipleManagers: false } }),
      "package.json": pkg({ dependencies: { express: "^4.18.0" } }),
      "requirements.txt": "flask==2.0.0\n",
    });
    const item = itemOf(report, "dependencies", "dependencies.allowMultipleManagers");
    assert.equal(item.observed, "ecosystems-multiple");
    assert.equal(item.status, COMPLIANCE_STATUSES.VIOLATION);
  });

  it("satisfies it when one ecosystem is declared", async () => {
    const { report } = await scanOf({
      ...policyFile({ dependencies: { allowMultipleManagers: false } }),
      "package.json": pkg({ dependencies: { express: "^4.18.0" } }),
    });
    assert.equal(itemOf(report, "dependencies", "dependencies.allowMultipleManagers").status, COMPLIANCE_STATUSES.PASS);
  });

  it("abstains with no policy and measures nothing with no manifest", async () => {
    const noPolicy = await scanOf({ "package.json": pkg() });
    assert.equal(sectionOf(noPolicy.report, "dependencies").established, false);

    const noManifest = await scanOf({
      ...policyFile({ dependencies: { requireLockfile: true, allowMultipleManagers: false } }),
      "README.md": "# demo\n",
    });
    const section = sectionOf(noManifest.report, "dependencies");
    assert.equal(itemOf(noManifest.report, "dependencies", "dependencies.requireLockfile"), null);
    assert.deepEqual(section.items, []);
    // Both requirements range over the manifests the repository declares. With none, neither was
    // measured — and a repository that declares no dependency at all cannot be said to have kept
    // to a single ecosystem by declaring it an `ecosystems-single`.
    assert.deepEqual(
      section.unknown.map((record) => record.reason),
      [
        COMPLIANCE_UNKNOWN_REASONS.NO_SUBJECT_TO_MEASURE,
        COMPLIANCE_UNKNOWN_REASONS.NO_SUBJECT_TO_MEASURE,
      ],
    );
  });
});

// ─── Architecture ────────────────────────────────────────────────────────────

describe("compliance: architecture", () => {
  it("violates an entrypoint no import edge relates", async () => {
    const { report } = await scanOf({
      ...policyFile({ architecture: { requireConnectedEntrypoints: true } }),
      "package.json": pkg(),
      "main.js": 'console.log("hi");\n',
    });
    const item = itemOf(report, "architecture", "architecture.requireConnectedEntrypoints");
    assert.equal(item.status, COMPLIANCE_STATUSES.VIOLATION);
    assert.equal(item.observed, "entrypoint-disconnected");
    assert.equal(item.subject, "main.js");
    assert.equal(item.basis, "import-graph-connectivity");
    assert.equal(item.evidenceIds.length > 0, true);
    assert.equal(/dead|unused|runtime/i.test(item.rationale), false);
  });

  it("satisfies the requirement when the entrypoint is related", async () => {
    const { report } = await scanOf({
      ...policyFile({ architecture: { requireConnectedEntrypoints: true } }),
      "package.json": pkg(),
      "main.js": 'import { helper } from "./src/helper.js";\nconsole.log(helper);\n',
      "src/helper.js": "export const helper = 1;\n",
    });
    assert.equal(
      itemOf(report, "architecture", "architecture.requireConnectedEntrypoints").status,
      COMPLIANCE_STATUSES.PASS,
    );
  });

  it("withholds an accusation it cannot cite", async () => {
    const { model } = await scanOf({
      ...policyFile({ environment: { requireTemplate: true } }),
      ".env.production": "SECRET=1\n",
    });
    // The same accepted facts, with the observation's own citation removed: the condition is
    // established and the policy contradicts it, but the item cannot cite the repository side.
    // A one-sided accusation is exactly what this phase forbids, so the item is withheld and the
    // section says why rather than publishing it.
    const uncited = {
      sections: model.production.report.sections.map((section) =>
        section.name === "environment"
          ? {
              ...section,
              observations: section.observations.map((entry) => ({ ...entry, evidenceIds: [] })),
            }
          : section,
      ),
    };
    const measured = buildComplianceReport({
      policy: model.policy,
      report: uncited,
      evidence: model.evidence,
    });
    const section = sectionOf(measured, "environment");
    assert.deepEqual(section.items, []);
    assert.deepEqual(measured.violations, []);
    assert.deepEqual(measured.passed, []);
    assert.equal(
      section.unknown.some(
        (record) => record.reason === COMPLIANCE_UNKNOWN_REASONS.EVIDENCE_NOT_ESTABLISHED,
      ),
      true,
    );
  });

  it("withholds the connectivity claim when the architecture reading was not complete", async () => {
    const { model, report } = await scanOf({
      ...policyFile({ architecture: { requireConnectedEntrypoints: true } }),
      "package.json": pkg(),
      "main.js": 'console.log("hi");\n',
    });
    // The accepted reading is complete here, so the same facts are re-measured against a reading
    // that did not finish. An entrypoint no import edge relates is only *isolated* if the graph
    // was whole, so an incomplete reading makes the requirement unmeasured rather than violated.
    const partial = {
      sections: model.production.report.sections.map((section) =>
        section.name === "architecture" ? { ...section, state: "partial" } : section,
      ),
    };
    const measured = buildComplianceReport({
      policy: model.policy,
      report: partial,
      evidence: model.evidence,
    });
    assert.equal(itemOf(report, "architecture", "architecture.requireConnectedEntrypoints").status, COMPLIANCE_STATUSES.VIOLATION);
    const item = itemOf(measured, "architecture", "architecture.requireConnectedEntrypoints");
    assert.equal(item.status, COMPLIANCE_STATUSES.UNKNOWN);
    assert.equal(item.observed, "not-established");
    assert.deepEqual(measured.violations, []);
    assert.equal(
      sectionOf(measured, "architecture").unknown.some(
        (record) => record.reason === COMPLIANCE_UNKNOWN_REASONS.READING_NOT_COMPLETE,
      ),
      true,
    );
  });

  it("abstains in a repository with no entrypoint", async () => {
    const { report } = await scanOf({
      ...policyFile({ architecture: { requireConnectedEntrypoints: true } }),
      "package.json": pkg(),
      "src/thing.js": "export const thing = 1;\n",
    });
    const section = sectionOf(report, "architecture");
    assert.deepEqual(section.items, []);
    assert.equal(section.state, COMPLIANCE_SECTION_STATES.UNKNOWN);
    assert.deepEqual(
      section.unknown.map((record) => record.reason),
      [COMPLIANCE_UNKNOWN_REASONS.NO_SUBJECT_TO_MEASURE],
    );
  });

  it("abstains with no policy", async () => {
    const { report } = await scanOf({ "main.js": 'console.log("hi");\n' });
    assert.equal(sectionOf(report, "architecture").established, false);
  });
});

// ─── Report shape, determinism and bounds ────────────────────────────────────

describe("compliance report", () => {
  it("carries the six domains in order, once each", async () => {
    const { report } = await scanOf({ ...policyFile(FULL_POLICY), "package.json": pkg() });
    assert.equal(report.version, COMPLIANCE_VERSION);
    assert.deepEqual(report.sections.map((section) => section.name), COMPLIANCE_SECTIONS);
    assert.equal(report.sections.length, COMPLIANCE_SECTIONS.length);
    for (const section of report.sections) {
      assert.equal(section.title, COMPLIANCE_SECTION_TITLES[section.name]);
    }
  });

  it("files every item under exactly one status list", async () => {
    const { report } = await scanOf(VIOLATING_REPO);
    const all = report.sections.flatMap((section) => section.items);
    assert.equal(report.violations.length + report.passed.length + report.unknown.length, all.length);
    assert.deepEqual(
      report.violations.map((item) => item.id),
      all.filter((item) => item.status === COMPLIANCE_STATUSES.VIOLATION).map((item) => item.id),
    );
    for (const section of report.sections) {
      const items = section.items;
      assert.equal(section.counts.items, items.length);
      assert.equal(section.counts.violations, items.filter((i) => i.status === "violation").length);
      assert.equal(section.counts.passed, items.filter((i) => i.status === "pass").length);
      assert.equal(section.counts.unknown, items.filter((i) => i.status === "unknown").length);
    }
  });

  it("renders every rationale from the item's own fields", async () => {
    const { report } = await scanOf(VIOLATING_REPO);
    for (const section of report.sections) {
      for (const item of section.items) {
        assert.equal(item.rationale, renderComplianceRationale(item), item.id);
        assert.equal(item.rationale.length <= COMPLIANCE_LIMITS.maxRationaleLength, true, item.id);
        assert.equal(item.rationale.length > 0, true, item.id);
      }
    }
  });

  it("orders items deterministically and identifies them by key and subject", async () => {
    const { report } = await scanOf(VIOLATING_REPO);
    for (const section of report.sections) {
      const keys = section.items.map((item) => `${item.key}\u0000${item.subject ?? ""}\u0000${item.id}`);
      assert.deepEqual(keys, [...keys].sort(), section.name);
      assert.equal(new Set(section.items.map((item) => item.id)).size, section.items.length, section.name);
      for (const item of section.items) {
        assert.equal(item.id.startsWith(item.policyKey), true, item.id);
        assert.equal(item.domain, section.name);
      }
    }
  });

  it("is byte-identical across two builds of one scan", async () => {
    const { model, report } = await scanOf(VIOLATING_REPO);
    const again = buildComplianceReport({
      policy: model.policy,
      report: model.production.report,
      evidence: model.evidence,
    });
    assert.equal(JSON.stringify(again), JSON.stringify(report));
  });

  it("carries no score, grade, percentage or traffic light", async () => {
    const { report } = await scanOf(VIOLATING_REPO);
    const flat = JSON.stringify(report);
    for (const word of ["score", "grade", "percentage", "percent", "trafficLight", "readiness", "compliant"]) {
      assert.equal(flat.toLowerCase().includes(word.toLowerCase()), false, word);
    }
  });

  it("sorts and bounds every evidence list it publishes", async () => {
    const { report } = await scanOf(VIOLATING_REPO);
    for (const section of report.sections) {
      const sorted = [...section.evidenceIds].sort();
      assert.deepEqual(section.evidenceIds, sorted, section.name);
      assert.deepEqual(section.evidenceIds, [...new Set(section.evidenceIds)], section.name);
      for (const item of section.items) {
        assert.deepEqual(item.evidenceIds, [...item.evidenceIds].sort(), item.id);
        assert.equal(item.evidenceIds.length <= COMPLIANCE_LIMITS.maxEvidencePerItem, true, item.id);
      }
    }
  });

  it("never answers pass for a policy the repository gives nothing to measure", async () => {
    // The failure this phase exists to prevent, stated as one test: five domains, each declaring a
    // real requirement, and a repository that declares nothing any of them range over. Nothing was
    // compared against a requirement, so nothing is satisfied — at any level.
    const { report, compliance } = await scanOf({
      ...policyFile({
        container: { requireHealthcheck: true },
        ci: { requireTestsForRelease: true, maxReleaseWorkflows: 1 },
        api: { requireResolvedMiddleware: true },
        dependencies: { requireLockfile: true, allowMultipleManagers: false },
        architecture: { requireConnectedEntrypoints: true },
      }),
      "README.md": "# demo\n",
    });
    assert.equal(report.state, COMPLIANCE_STATES.UNKNOWN);
    assert.equal(report.established, false);
    assert.deepEqual(report.passed, []);
    assert.deepEqual(report.violations, []);
    for (const section of report.sections) {
      assert.deepEqual(section.items, [], section.name);
      assert.equal(section.state, COMPLIANCE_SECTION_STATES.UNKNOWN, section.name);
      assert.equal(section.established, false, section.name);
    }
    assert.equal(compliance.state, COMPLIANCE_STATES.UNKNOWN);
    assert.equal(
      report.coverage.unknownReasons[COMPLIANCE_UNKNOWN_REASONS.NO_SUBJECT_TO_MEASURE] > 0,
      true,
    );
  });

  it("records a bound that bit rather than presenting it as the whole list", async () => {
    const { model } = await scanOf({
      ...policyFile({ api: { requireResolvedMiddleware: true } }),
      "package.json": pkg(),
    });
    const report = buildComplianceReport({
      policy: model.policy,
      report: routesReport(COMPLIANCE_LIMITS.maxItemsPerSection + 5),
      evidence: model.evidence,
    });
    const section = sectionOf(report, "api");
    assert.equal(section.items.length, COMPLIANCE_LIMITS.maxItemsPerSection);
    assert.equal(section.coverage.items, COMPLIANCE_LIMITS.maxItemsPerSection);
    // The bound is visible as a fact about the section, not silently applied.
    assert.equal(section.coverage.truncated, true);
    assert.equal(
      section.unknown.some((record) => record.reason === COMPLIANCE_UNKNOWN_REASONS.ITEMS_TRUNCATED),
      true,
    );
    assert.equal(report.state, COMPLIANCE_STATES.TRUNCATED);
    assert.equal(report.coverage.truncated, true);
    assert.equal(report.coverage.items, COMPLIANCE_LIMITS.maxItemsPerSection);
  });

  it("abstains when this model carries no production report", async () => {
    const { model } = await scanOf(VIOLATING_REPO);
    const report = buildComplianceReport({
      policy: model.policy,
      report: null,
      evidence: model.evidence,
    });
    assert.equal(report.state, COMPLIANCE_STATES.UNKNOWN);
    assert.equal(report.coverage.policyState, POLICY_STATES.ESTABLISHED);
    for (const section of report.sections) {
      assert.deepEqual(section.items, [], section.name);
      assert.equal(section.established, false, section.name);
    }
  });

  it("states what the policy and the domains established in its coverage", async () => {
    const { report } = await scanOf(VIOLATING_REPO);
    assert.equal(report.coverage.state, report.state);
    assert.equal(report.coverage.established, report.established);
    assert.equal(report.coverage.items, report.sections.flatMap((s) => s.items).length);
    assert.equal(report.coverage.sections, COMPLIANCE_SECTIONS.length);
    assert.equal(report.coverage.policyEstablished, true);
    assert.deepEqual(report.coverage.policyDomains, POLICY_DOMAINS);
    assert.equal(report.coverage.policySettings, policySettingCount(FULL_POLICY));
    assert.equal(report.coverage.limits.maxItemsPerSection, COMPLIANCE_LIMITS.maxItemsPerSection);
  });

  it("stores its builder identity and states the report version", async () => {
    const { report } = await scanOf(VIOLATING_REPO);
    assert.equal(COMPLIANCE_BUILDER, "phase-22-compliance-report");
    assert.equal(report.version, "1");
  });
});

// ─── The contract: a malformed policy or a one-sided violation is refused ────

describe("compliance contract", () => {
  it("pins the check table to the schema in both directions", () => {
    assert.deepEqual(unmeasuredPolicyKeys(), []);
    assert.deepEqual(unknownPolicyCheckKeys(), []);
    assert.equal(
      COMPLIANCE_CHECK_IDS.length,
      POLICY_DOMAINS.flatMap((domain) => POLICY_DOCUMENT_KEYS[domain]).length,
    );
    for (const id of COMPLIANCE_CHECK_IDS) {
      assert.equal(Object.hasOwn(COMPLIANCE_OBSERVED_VALUES, id), true, id);
    }
  });

  /** The full model and report used by the tampering cases. */
  const tampered = async (mutate) => {
    const { model } = await scanOf(VIOLATING_REPO);
    const copy = clone(model);
    mutate(copy);
    return issuesOfValidate(copy);
  };

  it("accepts the untouched model", async () => {
    assert.equal(await tampered(() => {}), null);
  });

  it("refuses a policy area whose state and document disagree", async () => {
    const issues = await tampered((model) => {
      model.policy.document = null;
    });
    assert.notEqual(issues, null);
    assert.equal(issues.some((issue) => issue.includes("policy.document")), true);

    const answered = await tampered((model) => {
      model.policy.state = POLICY_STATES.UNKNOWN;
      model.policy.document = null;
      model.policy.coverage.state = POLICY_STATES.UNKNOWN;
      model.policy.coverage.complete = false;
    });
    // `established` must follow the state, so a reading that answered nothing cannot claim one.
    assert.notEqual(answered, null);
    assert.equal(answered.some((issue) => issue.includes("policy.established")), true);
  });

  it("refuses a policy document the schema does not declare", async () => {
    const unknownKey = await tampered((model) => {
      model.policy.document.container.requireHealthchecks = true;
      model.policy.coverage.domains = policyDocumentDomains(model.policy.document);
      model.policy.coverage.settings = policyDocumentSettingCount(model.policy.document);
    });
    assert.notEqual(unknownKey, null);
    // The *schema* check is what this case pins: several downstream checks would also complain
    // about the same edit, and only naming the message keeps each one load-bearing.
    assert.equal(
      unknownKey.some((issue) => issue.includes("is not a setting this schema declares")),
      true,
    );

    const wrongType = await tampered((model) => {
      model.policy.document.container.requireHealthcheck = "yes";
    });
    assert.notEqual(wrongType, null);

    const outOfRange = await tampered((model) => {
      model.policy.document.ci.maxReleaseWorkflows = MAX_RELEASE_WORKFLOWS + 1;
    });
    assert.notEqual(outOfRange, null);

    const outOfOrder = await tampered((model) => {
      model.policy.document = { ci: model.policy.document.ci, container: model.policy.document.container };
    });
    assert.notEqual(outOfOrder, null);
    assert.equal(
      outOfOrder.some((issue) => issue.includes("must state its domains in the declared order")),
      true,
    );
  });

  it("refuses a policy area that cites an observation the model does not carry", async () => {
    const issues = await tampered((model) => {
      model.policy.coverage.evidenceIds = ["evidence:policy:policy-document:elsewhere"];
    });
    assert.notEqual(issues, null);
    assert.equal(issues.some((issue) => issue.includes("policy.coverage.evidenceIds")), true);
  });

  it("refuses a violation with only one side", async () => {
    const noPolicy = await tampered((model) => {
      const item = model.compliance.report.violations[0];
      item.policyEvidenceIds = [];
      const section = sectionOf(model.compliance.report, item.domain);
      section.evidenceIds = [...section.evidenceIds, "x"].filter((id) => id !== item.policyEvidenceIds[0]);
      const mirror = section.items.find((entry) => entry.id === item.id);
      mirror.policyEvidenceIds = [];
    });
    assert.notEqual(noPolicy, null);
    assert.equal(
      noPolicy.some((issue) => issue.includes("must cite the policy a violation contradicts")),
      true,
    );

    const noRepository = await tampered((model) => {
      const item = model.compliance.report.violations[0];
      item.evidenceIds = [];
      const section = sectionOf(model.compliance.report, item.domain);
      section.items.find((entry) => entry.id === item.id).evidenceIds = [];
    });
    assert.notEqual(noRepository, null);
    assert.equal(
      noRepository.some((issue) =>
        issue.includes("must cite the observation a violation rests on"),
      ),
      true,
    );
  });

  it("refuses an item whose requirement is not the policy's own", async () => {
    const issues = await tampered((model) => {
      const item = model.compliance.report.violations[0];
      item.expected = item.expected === true ? false : true;
      item.rationale = renderComplianceRationale(item);
      sectionOf(model.compliance.report, item.domain).items.find(
        (entry) => entry.id === item.id,
      ).expected = item.expected;
      sectionOf(model.compliance.report, item.domain).items.find(
        (entry) => entry.id === item.id,
      ).rationale = item.rationale;
    });
    assert.notEqual(issues, null);
    assert.equal(issues.some((issue) => issue.includes("expected")), true);
  });

  it("refuses a rationale that its own fields do not render", async () => {
    const issues = await tampered((model) => {
      const item = model.compliance.report.passed[0];
      item.rationale = "this repository is non-compliant";
      sectionOf(model.compliance.report, item.domain).items.find(
        (entry) => entry.id === item.id,
      ).rationale = item.rationale;
    });
    assert.notEqual(issues, null);
    assert.equal(issues.some((issue) => issue.includes("rationale")), true);
  });

  it("refuses an observation outside the vocabulary its key declares", async () => {
    const issues = await tampered((model) => {
      const item = model.compliance.report.violations[0];
      item.observed = "looks-fine";
      item.rationale = renderComplianceRationale(item);
      const mirror = sectionOf(model.compliance.report, item.domain).items.find(
        (entry) => entry.id === item.id,
      );
      mirror.observed = item.observed;
      mirror.rationale = item.rationale;
    });
    assert.notEqual(issues, null);
  });

  it("refuses a section state that does not follow from its items", async () => {
    const issues = await tampered((model) => {
      const section = sectionOf(model.compliance.report, "container");
      section.state = COMPLIANCE_SECTION_STATES.PASS;
      section.established = true;
      section.coverage.state = COMPLIANCE_SECTION_STATES.PASS;
    });
    assert.notEqual(issues, null);
    assert.equal(issues.some((issue) => issue.includes("must follow from the items")), true);
  });

  it("refuses a report whose state does not follow from its sections", async () => {
    const issues = await tampered((model) => {
      model.compliance.report.state = COMPLIANCE_STATES.PASS;
      model.compliance.state = COMPLIANCE_STATES.PASS;
      model.compliance.report.coverage.state = COMPLIANCE_STATES.PASS;
      model.compliance.report.coverage.complete = true;
      model.compliance.coverage.state = COMPLIANCE_STATES.PASS;
    });
    assert.notEqual(issues, null);
    assert.equal(issues.some((issue) => issue.includes("compliance.report.state")), true);
  });

  it("refuses an item list that disagrees with its sections", async () => {
    const issues = await tampered((model) => {
      model.compliance.report.violations = [];
    });
    assert.notEqual(issues, null);
    assert.equal(issues.some((issue) => issue.includes("compliance.report.violations")), true);
  });

  it("refuses a coverage statement that stops naming the bound it applied", async () => {
    const issues = await tampered((model) => {
      model.compliance.report.coverage.limits.maxItemsPerSection = 5000;
    });
    assert.notEqual(issues, null);
    assert.equal(
      issues.some((issue) =>
        issue.includes("compliance.report.coverage.limits.maxItemsPerSection"),
      ),
      true,
    );
  });

  it("refuses a duplicated or out-of-order domain", async () => {
    const issues = await tampered((model) => {
      const sections = model.compliance.report.sections;
      sections[0] = sections[1];
    });
    assert.notEqual(issues, null);
  });

  it("refuses an undefined abstention reason and an unmerged pair", async () => {
    const unknown = await tampered((model) => {
      const section = sectionOf(model.compliance.report, "api");
      section.unknown = [{ reason: "looks-bad", detail: null, count: 1 }];
      section.coverage.unknownReasons = 1;
      model.compliance.report.coverage.unknownReasons = { "looks-bad": 1 };
    });
    assert.notEqual(unknown, null);
    assert.equal(
      unknown.some((issue) => issue.includes("must name a documented reason")),
      true,
    );
  });

  it("refuses a policy-declared flag that contradicts the policy", async () => {
    const issues = await tampered((model) => {
      sectionOf(model.compliance.report, "api").policyDeclared = false;
    });
    assert.notEqual(issues, null);
    assert.equal(
      issues.some((issue) => issue.includes("must agree with the policy this model carries")),
      true,
    );
  });

  it("refuses a policyKeys list that is not what the document declares", async () => {
    const issues = await tampered((model) => {
      sectionOf(model.compliance.report, "container").policyKeys = [];
    });
    assert.notEqual(issues, null);
  });

  it("keeps the report reachable only through its own vocabulary", async () => {
    const { report } = await scanOf(VIOLATING_REPO);
    for (const section of report.sections) {
      assert.equal(COMPLIANCE_SECTION_STATES[section.state.toUpperCase()], section.state);
      for (const item of section.items) {
        assert.equal([COMPLIANCE_STATUSES.PASS, COMPLIANCE_STATUSES.VIOLATION, COMPLIANCE_STATUSES.UNKNOWN].includes(item.status), true);
        assert.equal(
          COMPLIANCE_OBSERVED_VALUES[item.policyKey].includes(item.observed) ||
            (typeof item.observed === "number" && item.policyKey === "ci.maxReleaseWorkflows"),
          true,
          item.id,
        );
      }
      for (const record of section.unknown) {
        assert.equal(Object.values(COMPLIANCE_UNKNOWN_REASONS).includes(record.reason), true, record.reason);
      }
    }
  });
});

// ─── Query API ───────────────────────────────────────────────────────────────

describe("compliance query API", () => {
  it("hands out the policy area, the report, one section and the coverage", async () => {
    const { query } = await scanOf(VIOLATING_REPO);
    assert.equal(query.policy().state, POLICY_STATES.ESTABLISHED);
    assert.equal(query.complianceReport().state, COMPLIANCE_STATES.VIOLATION);
    assert.equal(query.complianceSection("container").name, "container");
    assert.equal(query.complianceCoverage().items, query.complianceReport().coverage.items);
    assert.deepEqual(query.complianceCoverage().policyDomains, POLICY_DOMAINS);
  });

  it("rejects an unknown domain name instead of answering emptiness", async () => {
    const { query } = await scanOf(VIOLATING_REPO);
    // A typo must fail rather than answer an empty section a caller could read as "this
    // repository satisfies this policy".
    assert.throws(() => query.complianceSection("security"), /invalid query/);
    assert.throws(() => query.complianceSection(7), /invalid query/);
  });

  it("answers null for a model that carries no policy or compliance area", async () => {
    const { model } = await scanOf(VIOLATING_REPO);
    const bare = { ...clone(model), policy: {}, compliance: {} };
    const query = createRepositoryQuery(bare);
    assert.equal(query.policy(), null);
    assert.equal(query.complianceReport(), null);
    assert.equal(query.complianceSection("container"), null);
    assert.equal(query.complianceCoverage(), null);
  });

  it("returns frozen values that cannot be mutated through the handle", async () => {
    const { query } = await scanOf(VIOLATING_REPO);
    const report = query.complianceReport();
    assert.equal(Object.isFrozen(report), true);
    assert.equal(Object.isFrozen(report.sections[0].items[0]), true);
    const coverage = query.complianceCoverage();
    assert.equal(Object.isFrozen(coverage), true);
    assert.equal(Object.isFrozen(coverage.unknownReasons), true);
    // A copy, so mutating it cannot reach the model.
    assert.throws(() => {
      "use strict";
      coverage.items = 99;
    });
  });

  it("reads the same report through every method", async () => {
    const { query } = await scanOf(VIOLATING_REPO);
    const report = query.complianceReport();
    for (const name of COMPLIANCE_SECTIONS) {
      assert.equal(query.complianceSection(name), report.sections.find((s) => s.name === name));
    }
  });
});

// ─── The rule pack ───────────────────────────────────────────────────────────

describe("compliance rules", () => {
  it("ships exactly six rules, one per domain, in the declared namespace", () => {
    assert.equal(complianceRules.length, COMPLIANCE_SECTIONS.length);
    assert.deepEqual(
      complianceRules.map((rule) => rule.id),
      Object.values(COMPLIANCE_RULE_IDS),
    );
    for (const rule of complianceRules) {
      assert.equal(rule.id.startsWith(COMPLIANCE_RULE_ID_PREFIX), true, rule.id);
      assert.equal(COMPLIANCE_SEVERITY_VALUES.includes(rule.severity), true, rule.id);
      assert.equal(["high", "critical"].includes(rule.severity), false, rule.id);
      assert.equal(rule.category, COMPLIANCE_CATEGORY);
      assert.equal(rule.metadata.basis, COMPLIANCE_BASIS);
      assert.equal(rule.version, "1.0.0");
    }
    assert.equal(complianceDomainRules.length, complianceRules.length);
  });

  it("describes every vocabulary the model can produce", () => {
    assert.deepEqual([...COMPLIANCE_DESCRIBED_SECTIONS].sort(), [...COMPLIANCE_SECTIONS].sort());
    assert.deepEqual([...COMPLIANCE_DESCRIBED_STATES].sort(), Object.values(COMPLIANCE_SECTION_STATES).sort());
    assert.deepEqual([...COMPLIANCE_DESCRIBED_STATUSES].sort(), Object.values(COMPLIANCE_STATUSES).sort());
    assert.deepEqual([...COMPLIANCE_DESCRIBED_POLICY_STATES].sort(), Object.values(POLICY_STATES).sort());
    assert.deepEqual(
      [...COMPLIANCE_DESCRIBED_ABSTENTIONS].sort(),
      Object.values(COMPLIANCE_UNKNOWN_REASONS).sort(),
    );
    for (const rule of complianceRules) {
      assert.equal(COMPLIANCE_RULE_SEVERITIES[rule.id.split(".")[1]], rule.severity, rule.id);
    }
    assert.deepEqual(PACK_SECTIONS, COMPLIANCE_SECTIONS);
    assert.equal(COMPLIANCE_RULE_PACK_VERSION, "1.0.0");
    assert.equal(COMPLIANCE_CONFIDENCE.DECLARED_POLICY_VIOLATION > 0, true);
  });

  it("refuses a rule set that drops, duplicates or renames a declared rule", () => {
    assert.deepEqual(complianceRuleSetIssues(complianceRules), []);
    assert.equal(complianceRuleSetIssues(complianceRules.slice(1)).length, 1);
    assert.equal(complianceRuleSetIssues([...complianceRules, complianceRules[0]]).length, 1);
    assert.equal(complianceRuleSetIssues([{ id: "security.x" }]).length > 0, true);
    assert.equal(complianceRuleSetIssues("rules").length, 1);
    assert.throws(() => createComplianceRuleRegistry({ rules: [] }));
    assert.equal(typeof createComplianceRuleRegistry({ rules: complianceRules }).select, "function");
  });

  it("reports every measured violation, and only those", async () => {
    const { model, report, context } = await scanOf(VIOLATING_REPO);
    const engine = createRuleEngine({ registry: createComplianceRuleRegistry({ rules: complianceRules }) });
    const run = await engine.runAll(context);
    const findings = run.findings;
    assert.equal(findings.length, report.violations.length);
    assert.equal(findings.length, 6);
    for (const finding of findings) {
      assert.equal(finding.ruleId.startsWith(COMPLIANCE_RULE_ID_PREFIX), true);
      assert.equal(COMPLIANCE_SEVERITY_VALUES.includes(finding.severity), true);
      assert.equal(finding.severity, "medium");
      assert.equal(finding.evidence.length >= 2, true, finding.title);
      // Both sides: at least one repository observation and the policy document.
      const policyId = model.policy.coverage.evidenceIds[0];
      assert.equal(finding.evidence.includes(policyId), true, finding.title);
      assert.equal(finding.metadata.policyKey.startsWith(finding.ruleId.split(".")[1]), true);
      assert.equal(typeof finding.metadata.fingerprintKey, "string");
      assert.equal(typeof finding.metadata.rationale, "string");
      assert.equal(finding.title.length <= MAX_IDENTIFIER_LENGTH, true, finding.title);
    }
    // A raw draft has no canonical fingerprint yet — that is the Finding Engine's job — so the
    // pack's own disambiguator is what has to be unique across the run.
    assert.equal(
      new Set(findings.map((finding) => finding.metadata.fingerprintKey)).size,
      findings.length,
    );
  });

  it("abstains, never passes, for a domain with no policy", async () => {
    const { context, report } = await scanOf({ "main.js": 'console.log("hi");\n' });
    assert.equal(report.state, COMPLIANCE_STATES.UNKNOWN);
    const engine = createRuleEngine({ registry: createComplianceRuleRegistry({ rules: complianceRules }) });
    const run = await engine.runAll(context);
    assert.deepEqual(run.findings, []);
    // Every domain abstains with the report's own reason, and none of them passes.
    for (const result of run.rules) {
      assert.equal(result.status, RULE_OUTCOME_STATUSES.UNKNOWN, result.rule.id);
      assert.equal(result.applicability.applicable, true, result.rule.id);
      assert.equal(result.applicability.coverage, APPLICABILITY_COVERAGE.UNKNOWN, result.rule.id);
      assert.equal(typeof result.applicability.reason, "string", result.rule.id);
      assert.equal(result.applicability.reason.includes("policy"), true, result.rule.id);
    }
  });

  it("abstains, never passes, when a declared policy has nothing to measure", async () => {
    const { context, report } = await scanOf({
      ...policyFile({
        container: { requireHealthcheck: true },
        api: { requireResolvedMiddleware: true },
      }),
      "README.md": "# demo\n",
    });
    assert.equal(report.state, COMPLIANCE_STATES.UNKNOWN);
    const engine = createRuleEngine({ registry: createComplianceRuleRegistry({ rules: complianceRules }) });
    const run = await engine.runAll(context);
    assert.deepEqual(run.findings, []);
    for (const result of run.rules) {
      assert.equal(result.status, RULE_OUTCOME_STATUSES.UNKNOWN, result.rule.id);
    }
    // The declared domain abstains with the model's own reason, not with an opinion of its own.
    const container = run.rules.find((entry) => entry.rule.id === COMPLIANCE_RULE_IDS.CONTAINER);
    assert.equal(
      container.applicability.reason.includes("declares no subject this requirement ranges over"),
      true,
    );
  });

  it("reports nothing for a domain whose requirements were measured and satisfied", async () => {
    const { context, report } = await scanOf(COMPLIANT_REPO);
    assert.equal(report.state, COMPLIANCE_STATES.PASS);
    const engine = createRuleEngine({ registry: createComplianceRuleRegistry({ rules: complianceRules }) });
    const run = await engine.runAll(context);
    assert.deepEqual(run.findings, []);
    // Every requirement was measured and satisfied: an evaluated rule, not an abstention.
    for (const result of run.rules) {
      assert.equal(result.status, RULE_OUTCOME_STATUSES.PASS, result.rule.id);
      assert.equal(result.applicability.applicable, true, result.rule.id);
      assert.equal(
        result.applicability.coverage,
        APPLICABILITY_COVERAGE.COMPLETE,
        result.rule.id,
      );
    }
  });

  it("abstains over a domain that was measured and partly unmeasured", async () => {
    const { context, report } = await scanOf({
      ...policyFile({ ci: { requireTestsForRelease: true } }),
      ".github/workflows/release.yml": workflow("release"),
      ".github/workflows/ci.yml": workflow("ci"),
    });
    assert.equal(sectionOf(report, "ci").state, COMPLIANCE_SECTION_STATES.UNKNOWN);
    const engine = createRuleEngine({ registry: createComplianceRuleRegistry({ rules: complianceRules }) });
    const run = await engine.runAll(context);
    const result = run.rules.find((entry) => entry.rule.id === COMPLIANCE_RULE_IDS.CI);
    assert.equal(result.status, RULE_OUTCOME_STATUSES.UNKNOWN);
    assert.equal(result.applicability.coverage, APPLICABILITY_COVERAGE.UNKNOWN);
    assert.equal(
      result.applicability.reason.includes("workflow file name states no purpose"),
      true,
    );
  });

  it("abstains when this model carries no compliance report", async () => {
    const { model, context } = await scanOf(VIOLATING_REPO);
    const bare = { ...clone(model), compliance: {} };
    const bareContext = buildAnalysisContext({ repository: bare });
    const engine = createRuleEngine({ registry: createComplianceRuleRegistry({ rules: complianceRules }) });
    const run = await engine.runAll(bareContext);
    assert.deepEqual(run.findings, []);
    for (const result of run.rules) {
      assert.equal(result.applicability.coverage, APPLICABILITY_COVERAGE.UNKNOWN, result.rule.id);
    }
    assert.equal(context.repository.compliance.report !== null, true);
  });

  it("exposes the report through the pack's own signal readers", async () => {
    const { context, report } = await scanOf(VIOLATING_REPO);
    const query = queryFor(context);
    assert.equal(complianceSections(query).length, COMPLIANCE_SECTIONS.length);
    assert.equal(complianceCoverage(query).items, report.coverage.items);
    assert.equal(compliancePolicy(query).state, POLICY_STATES.ESTABLISHED);
    const section = complianceSectionSignal(query, "container");
    assert.equal(section.stateWording, COMPLIANCE_STATE_WORDING[section.state]);
    assert.equal(section.domainWording, COMPLIANCE_SECTION_WORDING.container);
    for (const item of section.items) {
      assert.equal(item.statusWording, COMPLIANCE_STATUS_WORDING[item.status]);
      assert.equal(typeof item.fingerprintKey, "string");
    }
    for (const record of section.unknown) {
      assert.equal(typeof record.wording, "string", record.reason);
    }
    const absence = complianceAbsence(query, "container");
    assert.equal(absence.established, true);
    assert.equal(absence.reason, null);
    // The other answer is an absence, and it carries the model's own reason rather than an
    // opinion of the pack's.
    const { context: policyLess } = await scanOf({ "package.json": pkg() });
    const absent = complianceAbsence(queryFor(policyLess), "container");
    assert.equal(absent.established, false);
    assert.equal(typeof absent.reason, "string");
    assert.equal(absent.reason.includes("policy"), true);
  });

  it("explains a partial section with the model's own abstention wording", async () => {
    const { context } = await scanOf({
      ...policyFile({ ci: { requireTestsForRelease: true } }),
      ".github/workflows/release.yml": workflow("release"),
      ".github/workflows/ci.yml": workflow("ci"),
    });
    const query = queryFor(context);
    const section = complianceSectionSignal(query, "ci");
    assert.equal(section.unknown[0].wording, COMPLIANCE_ABSTENTION_WORDING["workflow-purpose-not-established"]);
  });

  it("reports `capped` when a bound stopped the item list", async () => {
    const { model } = await scanOf({
      ...policyFile({ api: { requireResolvedMiddleware: true } }),
      "package.json": pkg(),
    });
    const report = buildComplianceReport({
      policy: model.policy,
      report: routesReport(COMPLIANCE_LIMITS.maxItemsPerSection + 2),
      evidence: model.evidence,
    });
    const bounded = {
      ...clone(model),
      compliance: {
        detected: true,
        state: report.state,
        established: report.established,
        report,
        coverage: { ...report.coverage },
      },
    };
    const context = buildAnalysisContext({ repository: bounded });
    const engine = createRuleEngine({ registry: createComplianceRuleRegistry({ rules: complianceRules }) });
    const run = await engine.runAll(context);
    const outcome = run.rules.find((entry) => entry.rule.id === COMPLIANCE_RULE_IDS.API);
    assert.equal(sectionOf(report, "api").coverage.truncated, true);
    assert.equal(outcome.metadata.capped, true);
    assert.equal(
      outcome.metadata.abstentions.some(
        (record) => record.reason === COMPLIANCE_UNKNOWN_REASONS.ITEMS_TRUNCATED,
      ),
      true,
    );
    // Capped is not silence: the rule abstains with the bound it hit.
    assert.equal(outcome.status, RULE_OUTCOME_STATUSES.UNKNOWN);
    assert.equal(outcome.applicability.coverage, APPLICABILITY_COVERAGE.UNKNOWN);
  });

  it("bounds the findings one rule run will report", async () => {
    assert.equal(MAX_COMPLIANCE_FINDINGS, 200);
    assert.equal(COMPLIANCE_RULE_SEVERITIES.environment, "medium");
    assert.equal(COMPLIANCE_LIMITS.maxItemsPerSection, 200);
  });

  it("leaves every other pack's answer untouched beside it", async () => {
    const { model, query } = await scanOf(VIOLATING_REPO);
    // The policy and compliance projections are separate answers over one model.
    assert.notEqual(query.complianceReport(), query.productionReport());
    assert.notEqual(query.complianceReport(), query.productionRiskReport());
    assert.equal(model.production.report.sections.length, COMPLIANCE_SECTIONS.length);
    assert.equal(query.policy().document !== null, true);
    // The inventory report still reports observations, and calls nothing a violation.
    assert.equal(JSON.stringify(query.productionReport()).includes("violation"), false);
  });

  it("refuses to read a file, a process or a clock", () => {
    // The pack's own architectural boundary: the model layer must not reach for the acquisition
    // layer, and the pack must import nothing but the model and its own modules.
    const packDir = join(HERE, "..", "src", "rules", "compliance");
    const sources = readdirSync(packDir)
      .filter((name) => name.endsWith(".js"))
      .map((name) => ({ name, text: readFileSync(join(packDir, name), "utf8") }));
    assert.equal(sources.length > 0, true);
    for (const { name, text } of sources) {
      for (const match of text.matchAll(/from\s+"([^"]+)"/g)) {
        const specifier = match[1];
        const allowed =
          specifier.startsWith("./") ||
          specifier.startsWith("../contracts.js") ||
          specifier.startsWith("../evaluation.js") ||
          specifier.startsWith("../registry.js") ||
          specifier.startsWith("../errors.js") ||
          specifier.startsWith("../analyzer.js") ||
          specifier.startsWith("../../../core/index.js") ||
          specifier.startsWith("../../repository/model/index.js");
        assert.equal(allowed, true, `${name} imports "${specifier}"`);
      }
      for (const forbidden of [
        "node:fs",
        "node:path",
        "child_process",
        "node:net",
        "node:http",
        "node:https",
        "node:dns",
        "node:worker_threads",
        "tools.js",
        "tool-registry",
        "scanner",
      ]) {
        assert.equal(text.includes(`"${forbidden}`), false, `${name} mentions \"${forbidden}\"`);
      }
      assert.equal(/import\s*\(\s*"/.test(text), false, `${name} uses a dynamic import`);
    }
  });
});

// ─── Integration with the accepted engines ───────────────────────────────────

describe("compliance integration", () => {
  it("runs as an ordinary analyzer over the accepted framework", async () => {
    const { model, context, report } = await scanOf(VIOLATING_REPO);
    const engine = createAnalyzerEngine({
      registry: createAnalyzerRegistry([createComplianceAnalyzer()]),
    });
    const result = await engine.runAll(context);
    assert.equal(result.analyzers.length, 1);
    assert.equal(result.analyzers[0].analyzer.id, COMPLIANCE_ANALYZER_ID);
    assert.equal(result.analyzers[0].analyzer.scope, COMPLIANCE_ANALYZER_SCOPE);
    assert.equal(COMPLIANCE_ANALYZER_NAME, "Project Policy Compliance");
    assert.equal(result.analyzers[0].metadata.ruleSet.length, COMPLIANCE_SECTIONS.length);
    assert.equal(result.findings.length, report.violations.length);
    assert.equal(model.compliance.report.state, COMPLIANCE_STATES.VIOLATION);
  });

  it("produces deterministic, uniquely fingerprinted findings", async () => {
    const { context } = await scanOf(VIOLATING_REPO);
    const engine = createAnalyzerEngine({
      registry: createAnalyzerRegistry([createComplianceAnalyzer()]),
    });
    const first = await engine.runAll(context);
    const second = await engine.runAll(context);
    assert.equal(new Set(first.findings.map((f) => f.fingerprint)).size, first.findings.length);
    assert.deepEqual(
      first.findings.map((f) => f.fingerprint),
      second.findings.map((f) => f.fingerprint),
    );
  });

  it("proves the whole path from a repository's own file to a finding", async () => {
    // One repository, one policy document, and one finding per requirement it contradicts — from
    // the bytes on disk to the fingerprint an engine produced, with no step skipped.
    const { scan, model, query, context, report } = await scanOf(VIOLATING_REPO);

    // 1. acquisition
    assert.equal(scan.policy.document.container.requireHealthcheck, true);
    // 2. model
    assert.equal(model.policy.document.ci.maxReleaseWorkflows, 1);
    // 3. compliance report
    assert.equal(report.violations.length, 6);
    // 4. query API
    assert.equal(query.complianceSection("ci").counts.violations, 2);
    assert.equal(query.complianceCoverage().violations, 6);
    // 5. rule engine
    const engine = createRuleEngine({ registry: createComplianceRuleRegistry({ rules: complianceRules }) });
    const run = await engine.runAll(context);
    assert.equal(run.findings.length, report.violations.length);
    // 6. analyzer engine
    const analyzers = createAnalyzerEngine({
      registry: createAnalyzerRegistry([createComplianceAnalyzer()]),
    });
    const result = await analyzers.runAll(context);
    // The two engines report the same statements. They are compared by the identity they share —
    // the item each finding measures — because only the analyzer canonicalizes a fingerprint.
    assert.equal(result.findings.length, run.findings.length);
    assert.deepEqual(
      result.findings.map((finding) => finding.title).sort(),
      run.findings.map((finding) => finding.title).sort(),
    );
    // Every finding names the declared key it measures and the document that declares it.
    for (const finding of result.findings) {
      const item = report.violations.find((entry) => entry.policyKey === finding.metadata.policyKey);
      assert.notEqual(item, undefined, finding.metadata.policyKey);
      assert.equal(item.status, COMPLIANCE_STATUSES.VIOLATION);
      assert.equal(finding.evidence.includes(model.policy.coverage.evidenceIds[0]), true);
    }
  });

  it("validates the model it publishes against the graph contract", async () => {
    const { model } = await scanOf(VIOLATING_REPO);
    assert.equal(validateRepositoryModelGraph(model), model);
    assert.equal(Object.isFrozen(model.policy), true);
    assert.equal(Object.isFrozen(model.compliance.report), true);
    // The area summaries agree with the report they summarise.
    assert.equal(model.compliance.state, model.compliance.report.state);
    assert.equal(model.compliance.coverage.items, model.compliance.report.coverage.items);
    assert.equal(model.policy.established, isEstablishedPolicyState(model.policy.state));
  });

  it("keeps a second pack's abstention out of this one's answers", async () => {
    // The compliance report reads the accepted inventory report, which is itself a projection over
    // the graphs, so no domain's answer is invented twice.
    const { model, report } = await scanOf(VIOLATING_REPO);
    for (const section of report.sections) {
      const inventory = model.production.report.sections.find((entry) => entry.name === section.name);
      assert.notEqual(inventory, undefined, section.name);
      if (inventory.established !== true) {
        assert.equal(section.established, false, section.name);
        assert.deepEqual(section.items, [], section.name);
      }
    }
  });
});
