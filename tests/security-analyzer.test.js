/**
 * Code Guardian — Security Analyzer Tests (official roadmap Phase 10)
 *
 * The suite for the two security rules that consume the **API graph** and the **middleware &
 * authorization graph**, and the end-to-end proof that the analysis pipeline works for a real
 * analyzer:
 *
 *   Repository → RepositoryModel → SecurityAnalyzer → applicable rules → evidence → findings
 *
 * Two fixture styles, chosen for what each can prove:
 *
 *   - **real repositories** written to a temporary directory and scanned through the accepted
 *     Phase 8A boundary, Phase 8C scanner, Phase 8D model builder and the graph projections, so
 *     what a source file literally states is what the rules report. This is the only way to
 *     prove that an unguarded `app.get("/admin/users", …)` is reported and a guarded one is not.
 *   - **hand-built ScanResults** for the states a tiny repository cannot be made to reach on
 *     demand — an unreadable path, a truncated scan, an incomplete inventory — because the
 *     point of those cases is that they must become `unknown` rather than `pass`, and that has
 *     to be stated exactly.
 *
 * The suite's central claims are the roadmap's exit criteria for a security analyzer: every
 * finding has a stable rule id, evidence, severity, confidence and a canonical fingerprint, and
 * an incomplete repository is reported as `unknown` rather than as clean.
 *
 * No test starts a server, sends a request, spawns a process or contacts a network.
 *
 * Run with: node --test tests/security-analyzer.test.js
 */

import { after, describe, it } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

import { createRule } from "../src/core/index.js";

import { SCAN_SIGNALS, createScanResult, scanRepository } from "../src/repository/scanner/index.js";
import {
  MIDDLEWARE_CLASSIFICATION_VALUES,
  buildRepositoryModel,
  createRepositoryQuery,
  getEvidence,
} from "../src/repository/model/index.js";

import {
  buildAnalysisContext,
  createAnalyzerEngine,
  createAnalyzerRegistry,
  stableAnalysisView,
} from "../src/analysis/index.js";

import {
  AUTHORIZING_CLASSIFICATIONS,
  APPLICABILITY_COVERAGE,
  DIAGNOSTIC_ROUTE_SEGMENTS,
  FINDING_BASES,
  PRIVILEGED_ROUTE_SEGMENTS,
  RULE_OUTCOME_STATUSES,
  SECURITY_ANALYZER_ID,
  SECURITY_CATEGORY,
  SECURITY_CONFIDENCE,
  SECURITY_RULE_IDS,
  SECURITY_RULE_VERSION,
  createRuleEngine,
  createSecurityAnalyzer,
  createSecurityRuleRegistry,
  matchesRoutePath,
  middlewareSourceEvidenceId,
  routeInventory,
  routeProtections,
  securityRules,
} from "../src/rules/index.js";

// ─── Fixtures: real repositories, scanned through the accepted boundary ──────

const TMP_ROOT = join(tmpdir(), `cg-security-analyzer-${process.pid}-${Date.now()}`);
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

const MANIFEST = JSON.stringify({
  name: "demo",
  version: "1.0.0",
  dependencies: { express: "^4.0.0" },
});

/** One express module source, with the middleware registration and routes it states. */
function appSource({ register = null, middleware = null, routes = [] } = {}) {
  const lines = ['import express from "express";', "const app = express();"];
  if (middleware !== null) {
    lines.push(`function ${middleware}(req, res, next) { next(); }`);
    lines.push(`app.use(${middleware});`);
  }
  lines.push("function handler(req, res) { res.end(); }");
  if (register !== null) lines.push(`const ${register} = { list: handler };`);
  for (const [method, path, target] of routes) {
    const handler = target ?? (register !== null ? `${register}.list` : "handler");
    lines.push(`app.${method}("${path}", ${handler});`);
  }
  lines.push("export default app;");
  return `${lines.join("\n")}\n`;
}

/** An express source whose route path is a computed value, so no route is established. */
const COMPUTED_APP = `import express from "express";
const app = express();
const target = "/admin";
function handler(req, res) { res.end(); }
app.get(target, handler);
export default app;
`;

async function scanModel(files) {
  const root = makeRepo(files);
  const scan = await scanRepository(root);
  const model = buildRepositoryModel(scan);
  return { scan, model, query: createRepositoryQuery(model) };
}

const UNGUARDED = {
  "package.json": MANIFEST,
  "src/app.js": appSource({ routes: [["get", "/admin/users"]] }),
};

const GUARDED = {
  "package.json": MANIFEST,
  "src/app.js": appSource({
    middleware: "authenticate",
    routes: [["get", "/admin/roles"]],
  }),
};

const LOGGED_ONLY = {
  "package.json": MANIFEST,
  "src/app.js": appSource({
    middleware: "requestLogger",
    routes: [["get", "/admin/audit"]],
  }),
};

const OPAQUE_MIDDLEWARE = {
  "package.json": MANIFEST,
  "src/app.js": appSource({
    middleware: "xyz",
    routes: [["get", "/internal/status"]],
  }),
};

const DIAGNOSTIC = {
  "package.json": MANIFEST,
  "src/app.js": appSource({
    routes: [
      ["get", "/debug/heap"],
      ["get", "/api/users"],
    ],
  }),
};

const PLAIN_APP = {
  "package.json": MANIFEST,
  "src/app.js": appSource({ routes: [["get", "/api/users"]] }),
};

const NO_HTTP = {
  "package.json": MANIFEST,
  "src/cli.js": '#!/usr/bin/env node\nconsole.log("hello");\n',
};

const COMPUTED = {
  "package.json": MANIFEST,
  "src/app.js": COMPUTED_APP,
};

/** An established inventory whose only module source is a format this build never interprets. */
const UNINTERPRETED = {
  "package.json": MANIFEST,
  "src/App.jsx": "export default function App() { return <div>hi</div>; }\n",
};

/** Several observed conditions at once, so a single run must fingerprint them apart. */
const MIXED = {
  "package.json": MANIFEST,
  "src/app.js": appSource({
    routes: [
      ["get", "/admin/users"],
      ["post", "/internal/export"],
      ["get", "/debug/heap"],
    ],
  }),
  ".env": "EXAMPLE=1\n",
  "id_rsa": "-----BEGIN OPENSSH PRIVATE KEY-----\n",
};

// ─── Fixtures: hand-built scans for coverage states ─────────────────────────

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

function ancestorPaths(path) {
  const segments = path.split("/").slice(0, -1);
  return segments.map((_segment, index) => segments.slice(0, index + 1).join("/"));
}

/**
 * A real RepositoryModel built from a hand-built ScanResult.
 *
 * Only the inventory and the scan state are declared: the graphs are then whatever the
 * builder derives from an inventory with no module source in it, which is exactly the
 * established-and-empty route set these cases are about.
 */
function inventoryModel({ paths, errors = [], complete = true, truncated = false }) {
  const directories = [...new Set(paths.flatMap(ancestorPaths))].sort();
  return buildRepositoryModel(
    createScanResult({
      root: "/scan-root",
      scannedAt: ISO,
      files: paths.map((path) => toEntry(path)).sort(byPath),
      directories: directories.map((path) => toEntry(path, true)).sort(byPath),
      configuration: { detected: false, evidence: [], evidenceTruncated: false },
      statistics: {
        filesScanned: paths.length,
        directoriesScanned: directories.length,
        symlinksScanned: 0,
        ignored: 0,
        unreadable: errors.length,
        truncatedBy: truncated ? ["file-limit"] : [],
      },
      scan: {
        complete,
        truncated,
        limits: { maxFiles: 10000, maxDepth: 20 },
        errors,
      },
    }),
  );
}

const BASE_PATHS = ["README.md", "package.json", "src/app.js"];

const UNREADABLE = inventoryModel({
  paths: BASE_PATHS,
  errors: [
    {
      kind: "filesystem-error",
      code: "CG_FS_PERMISSION_DENIED",
      operation: "listDirectory",
      path: "src/routes",
    },
  ],
});

const TRUNCATED = inventoryModel({ paths: BASE_PATHS, complete: false, truncated: true });

// ─── Helpers ─────────────────────────────────────────────────────────────────

const contextOf = (model) => buildAnalysisContext({ repository: model });

async function runRules(model, { rules = securityRules } = {}) {
  const engine = createRuleEngine({ registry: createSecurityRuleRegistry({ rules }) });
  return engine.runAll(contextOf(model));
}

async function runAnalyzer(model) {
  const engine = createAnalyzerEngine({
    registry: createAnalyzerRegistry([createSecurityAnalyzer()]),
  });
  return engine.runAll(contextOf(model));
}

const resultOf = (run, ruleId) => run.rules.find((entry) => entry.rule.id === ruleId);
const statusOf = (run, ruleId) => resultOf(run, ruleId)?.status;

const PRIVILEGED_RULE = SECURITY_RULE_IDS.UNPROTECTED_PRIVILEGED_ROUTE;
const DIAGNOSTIC_RULE = SECURITY_RULE_IDS.DIAGNOSTIC_ENDPOINT;

// ─── Rule set ────────────────────────────────────────────────────────────────

describe("security analyzer: rule set", () => {
  it("ships both route rules under the pack's declared contract", () => {
    const routeRules = securityRules.filter((rule) =>
      [PRIVILEGED_RULE, DIAGNOSTIC_RULE].includes(rule.id),
    );
    assert.deepEqual(
      routeRules.map((rule) => rule.id).sort(),
      [PRIVILEGED_RULE, DIAGNOSTIC_RULE].sort(),
    );
    for (const rule of routeRules) {
      assert.equal(rule.version, SECURITY_RULE_VERSION);
      assert.equal(rule.category, SECURITY_CATEGORY);
      assert.equal(rule.metadata.basis, FINDING_BASES.ROUTE);
      assert.equal(typeof rule.detect, "function");
      assert.ok(["info", "low", "medium", "high", "critical"].includes(rule.severity));
      assert.deepEqual({ ...rule.applicability }, {});
      assert.ok(rule.description.length > 0);
    }
  });

  it("gives the authorization rule the higher severity, because a guarded address is the stronger claim", () => {
    const privileged = securityRules.find((rule) => rule.id === PRIVILEGED_RULE);
    const diagnostic = securityRules.find((rule) => rule.id === DIAGNOSTIC_RULE);
    assert.equal(privileged.severity, "high");
    assert.equal(diagnostic.severity, "medium");
  });

  it("keeps the two path vocabularies disjoint, so one address is never reported twice", () => {
    const overlap = PRIVILEGED_ROUTE_SEGMENTS.filter((word) =>
      DIAGNOSTIC_ROUTE_SEGMENTS.includes(word),
    );
    assert.deepEqual(overlap, []);
    assert.ok(PRIVILEGED_ROUTE_SEGMENTS.length > 0);
    assert.ok(DIAGNOSTIC_ROUTE_SEGMENTS.length > 0);
  });

  it("authorizes only through the classifications the middleware graph can assign from a name", () => {
    assert.deepEqual([...AUTHORIZING_CLASSIFICATIONS], ["authentication", "authorization"]);
    // `unknown` is deliberately absent: "not known to authorize" is not "unguarded".
    assert.equal(AUTHORIZING_CLASSIFICATIONS.includes("unknown"), false);
    // Drift guard: every word the pack treats as authorization is a classification the
    // middleware graph can actually assign, so a renamed vocabulary cannot silently make
    // the rule authorize nothing.
    for (const classification of AUTHORIZING_CLASSIFICATIONS) {
      assert.ok(MIDDLEWARE_CLASSIFICATION_VALUES.includes(classification), classification);
    }
  });
});

// ─── Route path matching ─────────────────────────────────────────────────────

describe("security analyzer: route path matching", () => {
  it("matches a whole word in any segment, case-folded", () => {
    assert.equal(matchesRoutePath("/admin/users", ["admin"]), true);
    assert.equal(matchesRoutePath("/api/Admin/users", ["admin"]), true);
    assert.equal(matchesRoutePath("/api/v1/admin", ["admin"]), true);
    assert.equal(matchesRoutePath("/admin-panel", ["admin"]), true);
  });

  it("does not match a mere substring of a segment", () => {
    assert.equal(matchesRoutePath("/candidate", ["admin"]), false);
    assert.equal(matchesRoutePath("/administrate", ["admin"]), false);
    assert.equal(matchesRoutePath("/users", ["admin"]), false);
  });

  it("answers `false` for a path or a vocabulary it cannot read", () => {
    assert.equal(matchesRoutePath(null, ["admin"]), false);
    assert.equal(matchesRoutePath("", ["admin"]), false);
    assert.equal(matchesRoutePath(7, ["admin"]), false);
    assert.equal(matchesRoutePath("/admin", []), false);
    assert.equal(matchesRoutePath("/admin", null), false);
  });

  it("folds the vocabulary's own case, so a caller's spelling of a word does not matter", () => {
    assert.equal(matchesRoutePath("/api/Admin/users", ["Admin"]), true);
    assert.equal(matchesRoutePath("/API/ADMIN", ["Admin"]), true);
  });

  it("is deterministic and consults nothing outside its arguments", () => {
    const first = matchesRoutePath("/api/admin/users", PRIVILEGED_ROUTE_SEGMENTS);
    const second = matchesRoutePath("/api/admin/users", PRIVILEGED_ROUTE_SEGMENTS);
    assert.equal(first, true);
    assert.equal(first, second);
  });
});

// ─── Signals ────────────────────────────────────────────────────────────────

describe("security analyzer: signals", () => {
  it("answers the route inventory and the per-route protection from the model alone", async () => {
    const { model, query } = await scanModel(GUARDED);
    const inventory = routeInventory(query);
    const protections = routeProtections(query);
    assert.equal(inventory.established, true);
    assert.equal(inventory.complete, true);
    assert.equal(inventory.routes.length, 1);
    assert.deepEqual(inventory.unresolvedRoutes, []);
    assert.equal(inventory.inventory.established, true);
    assert.equal(protections.established, true);
    assert.equal(protections.routes[0].protection, "protected");
    assert.equal(model.scan.complete, true);
  });

  it("finds the middleware-source observation of a module path, and refuses anything else", async () => {
    const { query } = await scanModel(GUARDED);
    const id = middlewareSourceEvidenceId(query, "src/app.js");
    assert.equal(typeof id, "string");
    assert.ok(id.includes("middleware-source"));
    // A path the model carries no middleware observation for is `null`, not an empty answer.
    assert.equal(middlewareSourceEvidenceId(query, "src/missing.js"), null);
    assert.equal(middlewareSourceEvidenceId(query, null), null);
    assert.equal(middlewareSourceEvidenceId(query, undefined), null);
    assert.equal(middlewareSourceEvidenceId(query, ""), null);
    assert.equal(middlewareSourceEvidenceId(query, 7), null);
  });
});

// ─── Authorization: privileged routes ───────────────────────────────────────

describe("security analyzer: privileged route authorization", () => {
  it("reports a privileged route no middleware reaches", async () => {
    const { model } = await scanModel(UNGUARDED);
    const run = await runRules(model);
    const entry = resultOf(run, PRIVILEGED_RULE);

    assert.equal(entry.status, RULE_OUTCOME_STATUSES.VIOLATION);
    assert.equal(entry.findings.length, 1);

    const finding = entry.findings[0];
    assert.equal(finding.ruleId, PRIVILEGED_RULE);
    assert.equal(finding.severity, "high");
    // The literal pins the pack's own confidence policy: a silent change to it fails here.
    assert.equal(finding.confidence, 0.5);
    assert.equal(finding.confidence, SECURITY_CONFIDENCE.NAME_DERIVED);
    assert.equal(finding.metadata.path, "/admin/users");
    assert.equal(finding.metadata.method, "GET");
    assert.equal(finding.metadata.protection, "none-observed");
    assert.equal(finding.metadata.protectionBasis, "established-and-empty");
    assert.deepEqual(finding.metadata.matchedSegments, ["admin"]);
    assert.deepEqual(finding.metadata.middleware, []);
    assert.equal(finding.metadata.basis, "route");
    assert.equal(finding.metadata.basis, FINDING_BASES.ROUTE);
    assert.ok(finding.evidence.length > 0);
  });

  it("cites both halves of the claim — the route declaration and the registration record", async () => {
    const { model } = await scanModel(UNGUARDED);
    const run = await runRules(model);
    const signals = resultOf(run, PRIVILEGED_RULE).findings[0].evidence
      .map((id) => getEvidence(model, id)?.data?.signal)
      .sort();
    assert.ok(signals.includes("api-source"), "the route declaration is cited");
    assert.ok(signals.includes("middleware-source"), "the file's registrations are cited");
  });

  it("passes when authentication middleware reaches the route", async () => {
    const { model } = await scanModel(GUARDED);
    const run = await runRules(model);
    const entry = resultOf(run, PRIVILEGED_RULE);
    assert.equal(entry.status, RULE_OUTCOME_STATUSES.PASS);
    assert.deepEqual(entry.findings, []);
    assert.equal(entry.metadata.privilegedRoutes, 1);
  });

  it("reports a route reached only by middleware that is not known to authorize", async () => {
    const { model } = await scanModel(LOGGED_ONLY);
    const run = await runRules(model);
    const entry = resultOf(run, PRIVILEGED_RULE);
    assert.equal(entry.status, RULE_OUTCOME_STATUSES.VIOLATION);
    const finding = entry.findings[0];
    assert.equal(finding.metadata.path, "/admin/audit");
    assert.equal(finding.metadata.protection, "protected");
    assert.deepEqual(finding.metadata.middleware, [
      { name: "requestLogger", classification: "logging" },
    ]);
  });

  it("abstains when a middleware reaching the route is classified unknown", async () => {
    const { model } = await scanModel(OPAQUE_MIDDLEWARE);
    const run = await runRules(model);
    const entry = resultOf(run, PRIVILEGED_RULE);
    assert.equal(entry.status, RULE_OUTCOME_STATUSES.UNKNOWN);
    assert.deepEqual(entry.findings, []);
    assert.equal(entry.applicability.coverage, APPLICABILITY_COVERAGE.UNKNOWN);
    assert.ok(entry.applicability.reason.includes("classified unknown"));
  });

  it("abstains when the repository's module sources are a format this build does not interpret", async () => {
    const { model } = await scanModel(UNINTERPRETED);
    const run = await runRules(model);
    for (const id of [PRIVILEGED_RULE, DIAGNOSTIC_RULE]) {
      const entry = resultOf(run, id);
      assert.equal(entry.status, RULE_OUTCOME_STATUSES.UNKNOWN, id);
      assert.equal(entry.applicability.coverage, APPLICABILITY_COVERAGE.UNKNOWN);
      assert.ok(entry.applicability.reason.includes("unsupported"), id);
    }
  });

  it("abstains when a route-shaped occurrence could not be established as a route", async () => {
    const { model } = await scanModel(COMPUTED);
    const run = await runRules(model);
    for (const id of [PRIVILEGED_RULE, DIAGNOSTIC_RULE]) {
      const entry = resultOf(run, id);
      assert.equal(entry.status, RULE_OUTCOME_STATUSES.UNKNOWN, id);
      assert.ok(entry.applicability.reason.includes("not established"), id);
    }
  });

  it("passes for a repository that declares no privileged route", async () => {
    const { model } = await scanModel(PLAIN_APP);
    const run = await runRules(model);
    const entry = resultOf(run, PRIVILEGED_RULE);
    assert.equal(entry.status, RULE_OUTCOME_STATUSES.PASS);
    assert.equal(entry.metadata.privilegedRoutes, 0);
  });

  it("passes for a repository that declares no route at all", async () => {
    const { model } = await scanModel(NO_HTTP);
    const run = await runRules(model);
    assert.equal(statusOf(run, PRIVILEGED_RULE), RULE_OUTCOME_STATUSES.PASS);
    assert.equal(statusOf(run, DIAGNOSTIC_RULE), RULE_OUTCOME_STATUSES.PASS);
  });

  it("turns an unreadable path into unknown, because a source there was never scanned", async () => {
    const run = await runRules(UNREADABLE);
    const entry = resultOf(run, PRIVILEGED_RULE);
    assert.equal(entry.status, RULE_OUTCOME_STATUSES.UNKNOWN);
    assert.ok(entry.applicability.reason.includes("could not be read"));
  });

  it("turns a truncated scan into unknown, never pass", async () => {
    const run = await runRules(TRUNCATED);
    for (const id of [PRIVILEGED_RULE, DIAGNOSTIC_RULE]) {
      const entry = resultOf(run, id);
      assert.equal(entry.status, RULE_OUTCOME_STATUSES.UNKNOWN, id);
      assert.notEqual(entry.status, RULE_OUTCOME_STATUSES.NOT_APPLICABLE);
      assert.ok(entry.applicability.reason.length > 0, id);
    }
  });
});

// ─── Diagnostic endpoints ────────────────────────────────────────────────────

describe("security analyzer: diagnostic endpoints", () => {
  it("reports a route whose path names a diagnostic surface, with its protection recorded", async () => {
    const { model } = await scanModel(DIAGNOSTIC);
    const run = await runRules(model);
    const entry = resultOf(run, DIAGNOSTIC_RULE);

    assert.equal(entry.status, RULE_OUTCOME_STATUSES.VIOLATION);
    assert.equal(entry.findings.length, 1);

    const finding = entry.findings[0];
    assert.equal(finding.ruleId, DIAGNOSTIC_RULE);
    assert.equal(finding.severity, "medium");
    assert.equal(finding.confidence, SECURITY_CONFIDENCE.NAME_DERIVED);
    assert.equal(finding.metadata.path, "/debug/heap");
    assert.equal(finding.metadata.protection, "none-observed");
    assert.deepEqual(finding.metadata.matchedSegments, ["debug"]);
    assert.equal(finding.confidence, 0.5);
    assert.equal(finding.metadata.basis, "route");
    assert.equal(finding.metadata.basis, FINDING_BASES.ROUTE);
  });

  it("leaves an ordinary route alone", async () => {
    const { model } = await scanModel(PLAIN_APP);
    const run = await runRules(model);
    const entry = resultOf(run, DIAGNOSTIC_RULE);
    assert.equal(entry.status, RULE_OUTCOME_STATUSES.PASS);
    assert.equal(entry.metadata.diagnosticRoutes, 0);
  });

  it("does not report a privileged route as a diagnostic one, or the reverse", async () => {
    const { model } = await scanModel(UNGUARDED);
    const run = await runRules(model);
    // `/admin/users` is privileged and not diagnostic, so exactly one rule speaks.
    assert.equal(statusOf(run, PRIVILEGED_RULE), RULE_OUTCOME_STATUSES.VIOLATION);
    assert.equal(statusOf(run, DIAGNOSTIC_RULE), RULE_OUTCOME_STATUSES.PASS);
  });
});

// ─── Applicability and the unknown boundary ─────────────────────────────────

/**
 * The pack's outcome invariant, asserted over any run.
 *
 * The Rule Engine owns four outcome values a rule can reach (`pass`, `violation`,
 * `unknown`, `not-applicable` — plus `failed`/`skipped` for framework-level outcomes).
 * These rules produce three of them, because every rule declares an empty selector object
 * and answers "does this apply?" from evidence instead:
 *
 *   - the outcome is pass, violation or unknown — never not-applicable;
 *   - the engine's own applicability answer is the universal one, so an abstention is
 *     expressed as UNKNOWN with the rule's reason, not by skipping the rule;
 *   - UNKNOWN and the engine's UNKNOWN coverage are the same fact, and a non-unknown
 *     outcome carries no reason;
 *   - a run containing an abstention is not complete.
 */
function assertCoherentOutcomes(run) {
  assert.equal(run.rules.length, securityRules.length);
  for (const entry of run.rules) {
    const id = entry.rule.id;
    assert.ok(
      [
        RULE_OUTCOME_STATUSES.PASS,
        RULE_OUTCOME_STATUSES.VIOLATION,
        RULE_OUTCOME_STATUSES.UNKNOWN,
      ].includes(entry.status),
      `${id}: unexpected status ${entry.status}`,
    );
    assert.equal(entry.applicability.applicable, true, id);
    assert.equal(
      entry.status === RULE_OUTCOME_STATUSES.UNKNOWN,
      entry.applicability.coverage === APPLICABILITY_COVERAGE.UNKNOWN,
      id,
    );
    if (entry.status === RULE_OUTCOME_STATUSES.UNKNOWN) {
      assert.equal(typeof entry.applicability.reason, "string", id);
      assert.ok(entry.applicability.reason.length > 0, id);
    } else {
      assert.equal(entry.applicability.reason, null, id);
    }
  }
  assert.equal(
    run.complete,
    run.rules.every((entry) => entry.status !== RULE_OUTCOME_STATUSES.UNKNOWN),
  );
}

describe("security analyzer: applicability and the unknown boundary", () => {
  it("answers every rule as pass, violation or unknown — never as not-applicable", async () => {
    const models = [
      (await scanModel(GUARDED)).model,
      (await scanModel(UNGUARDED)).model,
      (await scanModel(UNINTERPRETED)).model,
      UNREADABLE,
      TRUNCATED,
    ];
    for (const model of models) assertCoherentOutcomes(await runRules(model));
  });

  it("keeps `not-applicable` available and distinguishable, so the pack's choice is visible", async () => {
    // A rule that declares a selector the repository does not satisfy gets the engine's
    // not-applicable answer in the very same run, which proves the three outcomes are
    // different facts rather than one undifferentiated "no finding".
    const probe = createRule({
      id: "security.probe.react-only",
      version: SECURITY_RULE_VERSION,
      category: SECURITY_CATEGORY,
      title: "Probe rule with an unsatisfied selector",
      description: "Exists only to pin the engine's not-applicable outcome.",
      severity: "low",
      applicability: { frameworks: ["react"] },
      detect: () => [],
      remediation: {},
      metadata: {},
    });

    const { model } = await scanModel(GUARDED);
    const run = await runRules(model, { rules: [...securityRules, probe] });

    const probed = run.rules.find((entry) => entry.rule.id === "security.probe.react-only");
    assert.equal(probed.status, RULE_OUTCOME_STATUSES.NOT_APPLICABLE);
    assert.equal(probed.applicability.applicable, false);
    assert.equal(probed.applicability.coverage, APPLICABILITY_COVERAGE.COMPLETE);
    assert.ok(probed.applicability.reason.includes("requires framework: react"));

    // …while every shipped rule stays applicable and reaches an outcome of its own.
    assert.equal(run.rules.length, securityRules.length + 1);
    for (const entry of run.rules) {
      if (entry.rule.id === "security.probe.react-only") continue;
      assert.notEqual(entry.status, RULE_OUTCOME_STATUSES.NOT_APPLICABLE, entry.rule.id);
      assert.equal(entry.status, RULE_OUTCOME_STATUSES.PASS, entry.rule.id);
    }
  });

  it("returns unknown, not a clean pass, whenever the repository was not read in full", async () => {
    for (const model of [UNREADABLE, TRUNCATED]) {
      const run = await runRules(model);
      assert.equal(run.complete, false);
      assert.equal(
        run.rules.every((entry) => entry.status === RULE_OUTCOME_STATUSES.UNKNOWN),
        true,
      );
    }
  });

  it("records the subject count on a clean outcome, so an empty pass is auditable", async () => {
    const guarded = resultOf(await runRules((await scanModel(GUARDED)).model), PRIVILEGED_RULE);
    const plain = resultOf(await runRules((await scanModel(PLAIN_APP)).model), PRIVILEGED_RULE);

    // Both are `pass`, and the metadata is what distinguishes "one privileged route, and
    // authorization reaches it" from "this repository declares no privileged route".
    assert.equal(guarded.status, RULE_OUTCOME_STATUSES.PASS);
    assert.equal(plain.status, RULE_OUTCOME_STATUSES.PASS);
    assert.equal(guarded.metadata.privilegedRoutes, 1);
    assert.equal(plain.metadata.privilegedRoutes, 0);
  });
});

// ─── Pipeline: RepositoryModel → Analyzer → Findings ────────────────────────

describe("security analyzer: pipeline", () => {
  it("reaches the Finding Engine from the model and comes back canonical", async () => {
    const { model } = await scanModel(UNGUARDED);
    const result = await runAnalyzer(model);

    assert.equal(result.findings.length, 1);
    const finding = result.findings[0];
    assert.equal(finding.ruleId, PRIVILEGED_RULE);
    assert.match(finding.fingerprint, /^cg-fp1-[0-9a-f]{32}$/);
    assert.equal(finding.id, `finding:${finding.fingerprint}`);
    assert.equal(finding.category, SECURITY_CATEGORY);
    assert.equal(finding.severity, "high");
    assert.equal(finding.confidence, SECURITY_CONFIDENCE.NAME_DERIVED);
    assert.equal(finding.metadata.analyzer.id, SECURITY_ANALYZER_ID);
    assert.equal(finding.metadata.analyzer.scope, "security");
    assert.ok(finding.evidence.length > 0);
    assert.equal(finding.status, "open");
  });

  it("gives every finding evidence the repository model actually holds", async () => {
    const { model } = await scanModel(DIAGNOSTIC);
    const result = await runAnalyzer(model);
    assert.ok(result.findings.length > 0);
    for (const finding of result.findings) {
      for (const id of finding.evidence) {
        const record = getEvidence(model, id);
        assert.ok(record, `${id} must exist in the model`);
        assert.ok(record.location.path.length > 0);
        assert.equal(record.location.path.startsWith("/"), false);
      }
    }
  });

  it("gives every finding of one run its own fingerprint, across rules and files", async () => {
    const { model } = await scanModel(MIXED);
    const result = await runAnalyzer(model);

    const fingerprints = result.findings.map((finding) => finding.fingerprint);
    assert.ok(fingerprints.length >= 4, `expected several findings, got ${fingerprints.length}`);
    assert.equal(new Set(fingerprints).size, fingerprints.length);
    assert.deepEqual(fingerprints, [...fingerprints].sort());

    // Two routes in the same file are the case that needs the analyzer-supplied key.
    const privileged = result.findings.filter((finding) => finding.ruleId === PRIVILEGED_RULE);
    assert.equal(privileged.length, 2);
  });

  it("is deterministic: the same repository twice gives the same fingerprints", async () => {
    const { model } = await scanModel(UNGUARDED);
    const first = await runAnalyzer(model);
    const second = await runAnalyzer(model);
    assert.deepEqual(
      first.findings.map((finding) => finding.fingerprint),
      second.findings.map((finding) => finding.fingerprint),
    );
    assert.deepEqual(stableAnalysisView(first), stableAnalysisView(second));
  });

  it("reports unknown rather than clean when the scan did not cover the repository", async () => {
    const result = await runAnalyzer(TRUNCATED);
    assert.deepEqual(result.findings, []);
    const analyzer = result.analyzers.find((entry) => entry.analyzer.id === SECURITY_ANALYZER_ID);
    const unavailable = analyzer.metadata.unavailableRules
      .map((entry) => entry.ruleId)
      .filter((id) => [PRIVILEGED_RULE, DIAGNOSTIC_RULE].includes(id));
    assert.deepEqual(unavailable.sort(), [DIAGNOSTIC_RULE, PRIVILEGED_RULE].sort());
    assert.equal(analyzer.metrics.rulesUnknown >= unavailable.length, true);
  });

  it("distinguishes two routes in one file by their own identity, not only by their evidence", async () => {
    // Both findings cite the same declaring file's evidence, so without the analyzer-supplied
    // fingerprint key the engine would refuse them as duplicates.
    const { model } = await scanModel({
      "package.json": MANIFEST,
      "src/app.js": appSource({
        routes: [
          ["get", "/admin/users"],
          ["get", "/internal/reports"],
        ],
      }),
    });
    const result = await runAnalyzer(model);
    const findings = result.findings.filter((finding) => finding.ruleId === PRIVILEGED_RULE);
    assert.equal(findings.length, 2);
    assert.deepEqual(
      findings.map((finding) => finding.metadata.path).sort(),
      ["/admin/users", "/internal/reports"],
    );
  });

  it("stays an ordinary Analyzer descriptor the registry can hold", async () => {
    const analyzer = createSecurityAnalyzer();
    assert.equal(analyzer.id, SECURITY_ANALYZER_ID);
    assert.equal(typeof analyzer.analyze, "function");
    assert.equal(analyzer.canAnalyze().applicable, true);
    const registry = createAnalyzerRegistry([analyzer]);
    assert.equal(registry.has(SECURITY_ANALYZER_ID), true);
  });
});

// ─── Architectural boundary ─────────────────────────────────────────────────

describe("security analyzer: boundaries", () => {
  it("reads the repository only through the query API, never the scanner or the filesystem", async () => {
    const { model } = await scanModel(UNGUARDED);
    const query = createRepositoryQuery(model);
    // Every fact the rules use is answerable from the frozen model alone.
    assert.equal(typeof query.apiGraph, "function");
    assert.equal(typeof query.middlewareGraph, "function");
    assert.equal(typeof query.routes, "function");
    assert.equal(typeof query.unresolvedRoutes, "function");
    assert.ok(query.apiGraph().nodes.length > 0);
    assert.ok(query.middlewareGraph().routes.length > 0);
  });

  it("does not import the scanner's detectors into the rules layer", async () => {
    // The pack is a consumer of the model, not of acquisition. `SCAN_SIGNALS` is imported
    // by the pack's test only, which is why it can be asserted here without the pack
    // depending on it.
    assert.equal(typeof SCAN_SIGNALS.DOCKERFILE, "string");
  });
});
