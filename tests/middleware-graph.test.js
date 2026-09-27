/**
 * Code Guardian — Middleware & Authorization Graph Tests (Phase 19)
 *
 * Three fixture styles, chosen deliberately:
 *
 *   - **real repositories** written to a temporary directory and scanned through the accepted
 *     Phase 8A boundary, Phase 8C scanner, Phase 8D model builder and Phase 19 projection, so
 *     acquisition, model and graph agree end to end. This is the only way to prove that what a
 *     source file literally states is what the graph exposes.
 *   - **hand-built middleware, API and semantic sources** for facts a tiny repository cannot
 *     reach on demand — a name with no module-scope binding, a shadowed name, a file with no
 *     semantic record, an unsupported format — and for tampering, so the fail-closed behaviour
 *     of the graph contract is stated exactly.
 *   - **mutation-style tampering** inside the model's own middleware area, because the point of
 *     the contract is that a malformed graph fails validation instead of becoming a finding.
 *
 * The suite's central claims are the phase's central requirements: a middleware node exists
 * only when its name is a Phase 17 symbol, a route whose middleware could not be established is
 * never reported as unprotected, and nothing here claims anything about execution, ordering
 * correctness or behavioural authorization.
 *
 * No test starts a server, sends a request, spawns a process, contacts a network, installs a
 * package or writes to the repository under test.
 *
 * Run with: node --test tests/middleware-graph.test.js
 */

import { after, describe, it } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { ValidationError } from "../src/core/index.js";

import {
  MIDDLEWARE_ACQUISITION_LIMITS,
  MIDDLEWARE_CALLABLE_FORMS,
  MIDDLEWARE_FRAMEWORKS as SCANNER_FRAMEWORKS,
  MIDDLEWARE_PROBLEMS,
  MIDDLEWARE_REGISTRATIONS as SCANNER_REGISTRATIONS,
  MIDDLEWARE_SCOPES as SCANNER_SCOPES,
  MIDDLEWARE_SOURCE_STATUSES as SCANNER_SOURCE_STATUSES,
  MIDDLEWARE_UNRESOLVED_REASONS as SCANNER_UNRESOLVED_REASONS,
  createScanResult,
  scanMiddleware,
  scanRepository,
  validateScanResult,
} from "../src/repository/scanner/index.js";

import {
  COVERAGE_GUARANTEES,
  MIDDLEWARE_CALLABLE_FORMS as MODEL_CALLABLE_FORMS,
  MIDDLEWARE_CLASSIFICATION_RULES,
  MIDDLEWARE_CLASSIFICATION_VALUES,
  MIDDLEWARE_CLASSIFICATIONS,
  MIDDLEWARE_EDGE_TYPES,
  MIDDLEWARE_EDGE_TYPE_VALUES,
  MIDDLEWARE_FRAMEWORKS,
  MIDDLEWARE_GRAPH_LIMITS,
  MIDDLEWARE_GRAPH_REGISTRATIONS,
  MIDDLEWARE_GRAPH_SCOPES,
  MIDDLEWARE_GRAPH_STATES,
  MIDDLEWARE_GRAPH_STATE_VALUES,
  MIDDLEWARE_GRAPH_VERSION,
  MIDDLEWARE_PROBLEM_REASONS,
  MIDDLEWARE_PROTECTION_STATES,
  MIDDLEWARE_REGISTRATIONS,
  MIDDLEWARE_PROTECTION_VALUES,
  MIDDLEWARE_ROUTE_SCOPE,
  MIDDLEWARE_SCOPES,
  MIDDLEWARE_SOURCE_REASONS,
  MIDDLEWARE_SOURCE_STATUSES,
  MIDDLEWARE_SOURCE_UNRESOLVED_REASONS,
  MIDDLEWARE_UNRESOLVED_KINDS,
  MIDDLEWARE_UNRESOLVED_REASONS,
  MIDDLEWARE_UNRESOLVED_REASON_VALUES,
  RepositoryQueryError,
  buildRepositoryModel,
  classifyMiddlewareName,
  createRepositoryQuery,
  isEstablishedMiddlewareState,
  isMiddlewareSourceEstablished,
  middlewareGraphState,
  middlewareNameWords,
  validateRepositoryModelGraph,
} from "../src/repository/model/index.js";

import {
  buildAnalysisContext,
  createAnalyzerEngine,
  createAnalyzerRegistry,
} from "../src/analysis/index.js";

import {
  MAX_MIDDLEWARE_FINDINGS,
  MIDDLEWARE_ANALYZER_ID,
  MIDDLEWARE_ANALYZER_SCOPE,
  MIDDLEWARE_BASIS,
  MIDDLEWARE_CLASSIFICATION_WORDING,
  MIDDLEWARE_CONFIDENCE,
  MIDDLEWARE_DESCRIBED_EDGE_TYPES,
  MIDDLEWARE_DESCRIBED_UNRESOLVED_REASONS,
  MIDDLEWARE_EDGE_TYPE_WORDING,
  MIDDLEWARE_PROTECTION_WORDING,
  MIDDLEWARE_RULE_IDS,
  MIDDLEWARE_UNRESOLVED_REASON_WORDING,
  RULE_OUTCOME_STATUSES,
  createMiddlewareAnalyzer,
  createMiddlewareRuleRegistry,
  createRuleEngine,
  middlewareAbsence,
  middlewareCoverage,
  middlewareNodes,
  middlewareRuleSetIssues,
  middlewareRules,
  middlewareUnresolved,
} from "../src/rules/index.js";

// ─── Fixtures ────────────────────────────────────────────────────────────────

const TMP_ROOT = join(tmpdir(), `cg-middleware-${process.pid}-${Date.now()}`);
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

async function scanModel(root) {
  const scan = await scanRepository(root);
  const model = buildRepositoryModel(scan);
  return { scan, model, query: createRepositoryQuery(model) };
}

const scanOf = (files) => scanModel(makeRepo(files));
const contextOf = (model) => buildAnalysisContext({ repository: model });
const packageJson = (fields = {}) => JSON.stringify({ name: "demo", version: "1.0.0", ...fields });

/** The language id a fixture path implies. */
const languageOf = (path) => (path.endsWith(".ts") || path.endsWith(".tsx") ? "typescript" : "javascript");

/**
 * A middleware source record for a hand-built ScanResult.
 *
 * Defaults to a fully established parsed source with nothing in it, so a test states only the
 * field it is actually about.
 */
function middlewareSource(path, options = {}) {
  const {
    status = "parsed",
    reason = null,
    detail = null,
    established = status === "parsed",
    frameworks = status === "parsed" ? ["express"] : [],
    unsupportedFrameworks = [],
    receivers = status === "parsed"
      ? [{ name: "app", framework: "express", supported: true, kind: "app" }]
      : [],
    registrations = [],
    mounts = [],
    problems = [],
    truncated = false,
    bytesInspected = 120,
    counts,
  } = options;
  return {
    path,
    extension: path.slice(path.lastIndexOf(".")),
    language: languageOf(path),
    status,
    reason,
    detail,
    bytesInspected,
    truncated,
    established,
    frameworks,
    unsupportedFrameworks,
    receivers,
    registrations,
    mounts,
    problems,
    counts:
      counts ?? {
        tokens: 20,
        registrations: registrations.length,
        mounts: mounts.length,
        middleware: registrations.reduce((total, entry) => total + entry.middleware.length, 0),
        unresolved: registrations.reduce((total, entry) => total + entry.unresolved.length, 0),
      },
  };
}

/** A registration record for a hand-built middleware source. */
function registration(options = {}) {
  return {
    receiver: "app",
    receiverKind: "app",
    framework: "express",
    registration: "use",
    scope: "app",
    path: null,
    hook: null,
    sequence: 0,
    conditional: false,
    middleware: [],
    unresolved: [],
    ...options,
  };
}

/** A route record for a hand-built API source. */
function route(method, path, extra = {}) {
  return {
    method,
    path,
    receiver: "app",
    framework: "express",
    receiverKind: "app",
    form: "direct",
    handler: null,
    middleware: [],
    ...extra,
  };
}

/** An API source record for a hand-built ScanResult. */
function apiSource(path, options = {}) {
  const {
    status = "parsed",
    reason = null,
    detail = null,
    established = status === "parsed",
    frameworks = status === "parsed" ? ["express"] : [],
    unsupportedFrameworks = [],
    receivers = status === "parsed"
      ? [{ name: "app", framework: "express", supported: true, kind: "app" }]
      : [],
    routes = [],
    shapes = [],
    problems = [],
    truncated = false,
    bytesInspected = 120,
    counts,
  } = options;
  return {
    path,
    extension: path.slice(path.lastIndexOf(".")),
    language: languageOf(path),
    status,
    reason,
    detail,
    bytesInspected,
    truncated,
    established,
    frameworks,
    unsupportedFrameworks,
    aliases: [],
    receivers,
    routes,
    shapes,
    problems,
    counts:
      counts ?? {
        tokens: 20,
        routes: routes.length,
        shapes: shapes.length,
        receivers: receivers.length,
      },
  };
}

/** A declaration record for a hand-built semantic source. */
function declaration(name, extra = {}) {
  return {
    name,
    kinds: ["function"],
    keywords: ["function"],
    exported: true,
    exportNames: [name],
    callable: true,
    constructable: true,
    shadowed: false,
    reassigned: false,
    binding: null,
    ...extra,
  };
}

/** A semantic source record for a hand-built ScanResult. */
function semanticsSource(path, names, { established } = {}) {
  return {
    path,
    extension: path.slice(path.lastIndexOf(".")),
    language: languageOf(path),
    status: "parsed",
    reason: null,
    detail: null,
    bytesInspected: 100,
    truncated: false,
    established: { declarations: true, resolution: true, exports: true, ...(established ?? {}) },
    counts: {
      declarations: names.length,
      exports: names.length,
      names: names.length,
      references: 0,
      calls: 0,
      constructs: 0,
      tokens: 40,
    },
    problems: [],
    declarations: names.map((entry) =>
      typeof entry === "string" ? declaration(entry) : declaration(entry.name, entry),
    ),
    exports: [],
    starExports: [],
    references: [],
  };
}

/**
 * A validated ScanResult literal carrying `middleware`, `api` and `semantics` sections.
 *
 * Every branch is optional, so a test states only the sections its claim needs.
 */
function scanLiteral({
  middlewareSources = [],
  apiSources = [],
  semantics = [],
  complete = false,
  truncated = false,
  scanComplete = true,
} = {}) {
  const sortedMiddleware = [...middlewareSources].sort((a, b) => (a.path < b.path ? -1 : 1));
  const sortedApi = [...apiSources].sort((a, b) => (a.path < b.path ? -1 : 1));
  const paths = [
    ...new Set([
      ...sortedMiddleware.map((source) => source.path),
      ...sortedApi.map((source) => source.path),
      ...semantics.map((source) => source.path),
    ]),
  ].sort();
  const files = paths.map((path) => ({
    path,
    name: path.slice(path.lastIndexOf("/") + 1),
    extension: path.slice(path.lastIndexOf(".")),
    depth: path.split("/").length,
  }));
  const directories = new Set();
  for (const file of files) {
    const parts = file.path.split("/");
    for (let index = 1; index < parts.length; index += 1) {
      directories.add(parts.slice(0, index).join("/"));
    }
  }
  return validateScanResult(
    createScanResult({
      root: "/repo",
      scannedAt: "2026-01-01T00:00:00.000Z",
      files,
      directories: [...directories]
        .sort()
        .map((path) => ({
          path,
          name: path.slice(path.lastIndexOf("/") + 1),
          depth: path.split("/").length,
        })),
      ...(files.length === 0
        ? {}
        : {
            languages: [
              {
                id: "javascript",
                fileCount: files.length,
                extensions: [".js"],
                evidence: files.map((file) => ({ path: file.path, signal: "source-extension" })),
                evidenceTruncated: false,
              },
            ],
          }),
      middleware: {
        inspected: sortedMiddleware.length > 0,
        complete,
        truncated,
        files: sortedMiddleware,
        limits: {},
      },
      api: { inspected: sortedApi.length > 0, complete: false, truncated: false, files: sortedApi, limits: {} },
      semantics: { inspected: semantics.length > 0, complete: false, truncated: false, files: semantics, limits: {} },
      scan: { complete: scanComplete, truncated },
    }),
  );
}

function modelOf(input) {
  const model = buildRepositoryModel(scanLiteral(input));
  return { model, query: createRepositoryQuery(model) };
}

const graphOf = (input) => modelOf(input).model.middleware.graph;
const clone = (value) => JSON.parse(JSON.stringify(value));
const routeOf = (graph, routeId) => graph.routes.find((entry) => entry.route === routeId);
const edgesOf = (graph, type) => graph.edges.filter((edge) => edge.type === type);
const nameOf = (id) => id.slice(id.indexOf("#") + 1);

function stringsIn(value) {
  const found = [];
  const walk = (node) => {
    if (typeof node === "string") {
      found.push(node);
      return;
    }
    if (node === null || typeof node !== "object") return;
    for (const key of Object.keys(node)) walk(node[key]);
  };
  walk(value);
  return found;
}

const repoFile = (relative) => fileURLToPath(new URL(`../${relative}`, import.meta.url));

/** The issues a model's middleware graph raises, or `null` when it validates. */
function issuesOfValidate(model) {
  try {
    validateRepositoryModelGraph(model);
    return null;
  } catch (error) {
    assert.equal(error instanceof ValidationError, true);
    return (error.details?.issues ?? []).join(" | ");
  }
}

/** Sort edges the way the projection does, so a rename alone is not a sorting violation. */
function sortEdges(edges) {
  edges.sort((a, b) => {
    const left = `${a.from}\u0000${a.to}\u0000${a.type}`;
    const right = `${b.from}\u0000${b.to}\u0000${b.type}`;
    return left < right ? -1 : left > right ? 1 : 0;
  });
  return edges;
}

// ─── Real-repository fixtures ────────────────────────────────────────────────

const fullRepo = () => ({
  "package.json": packageJson(),
  "src/middleware.js": [
    "export function requireAuth() {}",
    "export function requireAdmin() {}",
    "export function rateLimit() {}",
    "export function corsMiddleware() {}",
    "export function logger() {}",
    "export function validateBody() {}",
    "export function uploadParser() {}",
    "",
  ].join("\n"),
  "src/app.js": [
    'import express from "express";',
    'import { requireAuth, requireAdmin, corsMiddleware, logger, validateBody } from "./middleware.js";',
    "const app = express();",
    "const router = express.Router();",
    "const sub = express.Router();",
    "app.use(corsMiddleware);",
    "app.use(logger);",
    "router.use(requireAuth);",
    'router.use("/sub", sub);',
    'app.use("/api", router);',
    'router.get("/admin", requireAdmin, validateBody, adminHandler);',
    'router.post("/things", uploadParser, createThing);',
    'sub.get("/nested", nestedHandler);',
    'app.get("/open", openHandler);',
    "app.use([a, b]);",
    "app.use(...rest);",
    "app.use(getMiddleware());",
    "app.use(express.json());",
    'if (process.env.NODE_ENV !== "production") { app.use(debugLogger); }',
    'app.use("/legacy", require("./legacy"));',
    "function adminHandler() {}",
    "function createThing() {}",
    "function nestedHandler() {}",
    "function openHandler() {}",
    "function uploadParser() {}",
    "function debugLogger() {}",
    "export default app;",
    "",
  ].join("\n"),
  "src/fast.js": [
    'import fastify from "fastify";',
    'import { requireAuth, rateLimit } from "./middleware.js";',
    "const server = fastify({ logger: true });",
    'server.addHook("preHandler", requireAuth);',
    'server.addHook("onSend", rateLimit);',
    "server.register(healthPlugin);",
    'server.get("/status", statusHandler);',
    "function healthPlugin() {}",
    "function statusHandler() {}",
    "export default server;",
    "",
  ].join("\n"),
});

const unsupportedFrameworkRepo = () => ({
  "package.json": packageJson(),
  "src/koa.js": [
    'import Koa from "koa";',
    "const app = new Koa();",
    "app.use(koaAuth);",
    "function koaAuth() {}",
    "",
  ].join("\n"),
});

const tsxOnlyRepo = () => ({
  "package.json": packageJson(),
  "src/component.tsx": "export function Widget() { return 1; }\n",
});

// ─── Acquisition ─────────────────────────────────────────────────────────────

describe("middleware acquisition (real repositories)", () => {
  it("records app-level and router-level `use` registrations with their scope", async () => {
    const { model } = await scanOf(fullRepo());
    const byId = new Map(model.middleware.graph.nodes.map((node) => [node.id, node]));

    const cors = byId.get("symbol:src/app.js#corsMiddleware");
    assert.deepEqual(cors.scopes, ["app"]);
    assert.deepEqual(cors.registrations, ["use"]);
    assert.deepEqual(cors.receivers, ["app"]);
    assert.deepEqual(cors.frameworks, ["express"]);
    assert.equal(cors.classification, "cors");

    // Identity is per-file: the `requireAuth` the Express app registers and the `requireAuth`
    // the Fastify server hooks are two different module-scope bindings, so they are two
    // middleware nodes that never collapse into one.
    const auth = byId.get("symbol:src/app.js#requireAuth");
    assert.deepEqual(auth.scopes, ["router"]);
    assert.deepEqual(auth.registrations, ["use"]);
    assert.deepEqual(auth.receivers, ["router"]);
    assert.deepEqual(auth.frameworks, ["express"]);
    assert.notEqual(byId.get("symbol:src/fast.js#requireAuth"), undefined);
  });

  it("records route-level middleware as `protects` edges", async () => {
    const { model } = await scanOf(fullRepo());
    const protects = edgesOf(model.middleware.graph, MIDDLEWARE_EDGE_TYPES.PROTECTS).filter(
      (edge) => edge.to === "route:GET:/admin",
    );
    assert.deepEqual(protects.map((edge) => edge.from).sort(), [
      "symbol:src/app.js#requireAdmin",
      "symbol:src/app.js#validateBody",
    ]);
    assert.deepEqual(protects[0].names, ["requireAdmin"]);
    assert.equal(protects[0].evidenceIds.length > 0, true);
  });

  it("records every middleware a route is declared with, ordered by middleware identity", async () => {
    const { query } = await scanOf(fullRepo());
    const chain = query.authorizationChains({ route: "route:GET:/admin" }).chains[0];
    assert.deepEqual(
      chain.middleware.map((entry) => entry.name),
      ["corsMiddleware", "logger", "requireAdmin", "requireAuth", "validateBody"],
    );
    assert.deepEqual(
      chain.middleware.map((entry) => entry.classification),
      ["cors", "logging", "authorization", "authentication", "validation"],
    );
  });

  it("records a nested router mount and inherits every enclosing scope", async () => {
    const { model } = await scanOf(fullRepo());
    const entry = routeOf(model.middleware.graph, "route:GET:/nested");
    assert.deepEqual(
      entry.middleware.map((id) => nameOf(id)),
      ["corsMiddleware", "logger", "requireAuth"],
    );
    const appliesTo = edgesOf(model.middleware.graph, MIDDLEWARE_EDGE_TYPES.APPLIES_TO).filter(
      (edge) => edge.to === "route:GET:/nested",
    );
    assert.equal(appliesTo.some((edge) => edge.receivers.includes("app")), true);
    assert.equal(appliesTo.some((edge) => edge.receivers.includes("router")), true);
  });

  it("records Fastify hooks with their hook name and hook scope", async () => {
    const { model } = await scanOf(fullRepo());
    const auth = model.middleware.graph.nodes.find(
      (node) => node.id === "symbol:src/fast.js#requireAuth",
    );
    assert.deepEqual(auth.scopes, ["hook"]);
    assert.deepEqual(auth.hooks, ["preHandler"]);
    assert.deepEqual(auth.frameworks, ["fastify"]);
  });

  it("records a Fastify plugin registration as a registration", async () => {
    const { model } = await scanOf(fullRepo());
    const node = model.middleware.graph.nodes.find(
      (node) => node.id === "symbol:src/fast.js#healthPlugin",
    );
    assert.deepEqual(node.registrations, ["register"]);
    assert.deepEqual(node.receivers, ["server"]);
    assert.equal(node.classification, "unknown");
  });

  it("records an unsupported framework receiver as an observation, never a node", async () => {
    const { model } = await scanOf(unsupportedFrameworkRepo());
    assert.deepEqual(model.middleware.graph.nodes, []);
    const unresolved = model.middleware.graph.unresolved.filter(
      (record) => record.reason === MIDDLEWARE_UNRESOLVED_REASONS.FRAMEWORK_UNSUPPORTED,
    );
    assert.equal(unresolved.length, 1);
    assert.equal(unresolved[0].receiver, "app");
    assert.equal(unresolved[0].kind, "registration");
  });

  it("records computed arrays, spreads, runtime calls, member calls and conditionals", async () => {
    const { model } = await scanOf(fullRepo());
    const reasons = new Set(model.middleware.graph.unresolved.map((record) => record.reason));
    assert.equal(reasons.has(MIDDLEWARE_UNRESOLVED_REASONS.ARRAY_NOT_ESTABLISHED), true);
    assert.equal(reasons.has(MIDDLEWARE_UNRESOLVED_REASONS.SPREAD_NOT_ESTABLISHED), true);
    assert.equal(reasons.has(MIDDLEWARE_UNRESOLVED_REASONS.REGISTRATION_NOT_ESTABLISHED), true);
    assert.equal(reasons.has(MIDDLEWARE_UNRESOLVED_REASONS.CONDITIONAL_NOT_ESTABLISHED), true);
  });

  it("records an inline function as an observation rather than a node", async () => {
    const { model } = await scanOf({
      "package.json": packageJson(),
      "src/app.js": [
        'import express from "express";',
        "const app = express();",
        "app.use((req, res, next) => next());",
        'app.get("/x", (req, res) => res.end());',
        "export default app;",
        "",
      ].join("\n"),
    });
    assert.deepEqual(model.middleware.graph.nodes, []);
    assert.equal(
      model.middleware.graph.unresolved.some(
        (record) => record.reason === MIDDLEWARE_UNRESOLVED_REASONS.INLINE_MIDDLEWARE,
      ),
      true,
    );
  });

  it("ignores middleware-shaped text in comments and strings", () => {
    const scanned = scanMiddleware(
      [
        "// app.use(auth);",
        "/* app.use(secret); */",
        'const text = "app.use(quoted)";',
        'import express from "express";',
        "const app = express();",
        "app.use(real);",
        "",
      ].join("\n"),
    );
    assert.equal(scanned.registrations.length, 1);
    assert.deepEqual(scanned.registrations[0].middleware, [
      { form: "reference", name: "real", member: null },
    ]);
  });

  it("ignores `.use` on a receiver the module never bound to a framework", () => {
    const scanned = scanMiddleware(
      ["const cache = createCache();", 'cache.use("/key");', "cache.use(thing);", ""].join("\n"),
    );
    assert.deepEqual(scanned.registrations, []);
    assert.deepEqual(scanned.mounts, []);
  });

  it("refuses a hook whose name is not a literal string", () => {
    const scanned = scanMiddleware(
      [
        'import fastify from "fastify";',
        "const server = fastify();",
        "server.addHook(hookName, auth);",
        "",
      ].join("\n"),
    );
    assert.equal(scanned.registrations.length, 1);
    assert.equal(scanned.registrations[0].hook, null);
    assert.deepEqual(scanned.registrations[0].unresolved, [
      { reason: MIDDLEWARE_UNRESOLVED_REASONS.HOOK_NAME_NOT_ESTABLISHED, name: null, member: null, form: null },
    ]);
    assert.deepEqual(scanned.registrations[0].middleware, [
      { form: "reference", name: "auth", member: null },
    ]);
  });

  it("keeps the acquisition bounds explicit", () => {
    assert.equal(MIDDLEWARE_ACQUISITION_LIMITS.maxFiles > 0, true);
    assert.equal(MIDDLEWARE_ACQUISITION_LIMITS.maxFileBytes > 0, true);
    assert.equal(MIDDLEWARE_ACQUISITION_LIMITS.maxRegistrationsPerFile > 0, true);
    assert.equal(MIDDLEWARE_ACQUISITION_LIMITS.maxMountsPerFile > 0, true);
    assert.equal(MIDDLEWARE_ACQUISITION_LIMITS.maxObservationsPerFile > 0, true);
    assert.equal(MIDDLEWARE_GRAPH_LIMITS.MAX_MIDDLEWARE > 0, true);
    assert.equal(MIDDLEWARE_GRAPH_LIMITS.MAX_CHAIN_LENGTH > 0, true);
  });
});

// ─── Middleware identity ─────────────────────────────────────────────────────

describe("middleware identity", () => {
  it("resolves an unresolved middleware name without fabricating a node", () => {
    const graph = graphOf({
      middlewareSources: [
        middlewareSource("a.js", {
          registrations: [
            registration({ middleware: [{ form: "reference", name: "ghost", member: null }] }),
          ],
        }),
      ],
      semantics: [semanticsSource("a.js", ["other"])],
    });
    assert.deepEqual(graph.nodes, []);
    assert.equal(graph.unresolved[0].reason, MIDDLEWARE_UNRESOLVED_REASONS.MIDDLEWARE_NOT_ESTABLISHED);
    assert.equal(graph.unresolved[0].name, "ghost");
  });

  it("refuses a shadowed name", () => {
    const graph = graphOf({
      middlewareSources: [
        middlewareSource("a.js", {
          registrations: [
            registration({ middleware: [{ form: "reference", name: "auth", member: null }] }),
          ],
        }),
      ],
      semantics: [semanticsSource("a.js", [{ name: "auth", shadowed: true }])],
    });
    assert.deepEqual(graph.nodes, []);
    assert.equal(graph.unresolved[0].reason, MIDDLEWARE_UNRESOLVED_REASONS.MIDDLEWARE_NOT_UNIQUE);
  });

  it("says a resolution was not established when the file has no semantic record", () => {
    const graph = graphOf({
      middlewareSources: [
        middlewareSource("a.js", {
          registrations: [
            registration({ middleware: [{ form: "reference", name: "auth", member: null }] }),
          ],
        }),
      ],
    });
    assert.deepEqual(graph.nodes, []);
    assert.equal(
      graph.unresolved[0].reason,
      MIDDLEWARE_UNRESOLVED_REASONS.RESOLUTION_NOT_ESTABLISHED,
    );
  });

  it("records a member access as an observation rather than a node", () => {
    const graph = graphOf({
      middlewareSources: [
        middlewareSource("a.js", {
          registrations: [
            registration({ middleware: [{ form: "reference", name: "security", member: "auth" }] }),
          ],
        }),
      ],
    });
    assert.deepEqual(graph.nodes, []);
    assert.equal(graph.unresolved[0].reason, MIDDLEWARE_UNRESOLVED_REASONS.MEMBER_EXPRESSION);
    assert.equal(graph.unresolved[0].name, "security");
    assert.equal(graph.unresolved[0].member, "auth");
  });

  it("reuses the Phase 17 symbol identity rather than a second symbol table", async () => {
    const { model } = await scanOf(fullRepo());
    const symbolIds = new Set(model.symbols.graph.nodes.map((node) => node.id));
    assert.equal(model.middleware.graph.nodes.length > 0, true);
    for (const node of model.middleware.graph.nodes) {
      assert.equal(symbolIds.has(node.id), true);
      assert.equal(node.id, node.symbolId);
      assert.equal(node.id, `symbol:${node.path}#${node.name}`);
      assert.equal(node.fileId, `file:${node.path}`);
    }
    // The middleware graph contributes no symbol node of its own, so the symbol graph is
    // exactly as large as it would be without this phase.
    assert.equal(
      model.symbols.graph.nodes.length,
      new Set(model.symbols.graph.nodes.map((node) => node.id)).size,
    );
  });
});

// ─── Authorization classification ────────────────────────────────────────────

describe("authorization classification", () => {
  it("classifies from the middleware name alone, in a fixed precedence order", () => {
    const cases = [
      ["corsMiddleware", "cors"],
      ["crossOriginGuard", "cors"],
      ["rateLimit", "rate-limit"],
      ["rate_limiter", "rate-limit"],
      ["throttle", "rate-limit"],
      ["authorizeRole", "authorization"],
      ["requireAdmin", "authorization"],
      ["permissionGate", "authorization"],
      ["requireAuth", "authentication"],
      ["authenticate", "authentication"],
      ["jwtAuth", "authentication"],
      ["checkAuthToken", "authentication"],
      ["validateBody", "validation"],
      ["schemaGuard", "validation"],
      ["bodyParser", "parsing"],
      ["uploadParser", "parsing"],
      ["morganLogger", "logging"],
      ["requestLogger", "logging"],
      ["healthPlugin", "unknown"],
      ["helmet", "unknown"],
    ];
    for (const [name, expected] of cases) {
      assert.equal(classifyMiddlewareName(name), expected, `${name} should be ${expected}`);
    }
    assert.deepEqual(middlewareNameWords("requireAuth"), ["require", "auth"]);
    assert.deepEqual(middlewareNameWords("rate-limit"), ["rate", "limit"]);
    assert.equal(MIDDLEWARE_CLASSIFICATION_VALUES.includes("unknown"), true);
  });

  it("declares the classification vocabulary and its precedence order", () => {
    assert.deepEqual(
      [...new Set(MIDDLEWARE_CLASSIFICATION_RULES.map((rule) => rule.classification))],
      ["cors", "rate-limit", "authorization", "authentication", "validation", "parsing", "logging"],
    );
    assert.deepEqual(
      [...MIDDLEWARE_CLASSIFICATION_VALUES].sort(),
      [
        "authentication",
        "authorization",
        "cors",
        "logging",
        "parsing",
        "rate-limit",
        "unknown",
        "validation",
      ],
    );
    assert.deepEqual(MIDDLEWARE_CLASSIFICATIONS.UNKNOWN, "unknown");
  });

  it("reads a classification as name-shaped, never as a behaviour claim", () => {
    assert.equal(MIDDLEWARE_CLASSIFICATION_WORDING.authentication, "authentication-shaped");
    assert.equal(MIDDLEWARE_CLASSIFICATION_WORDING.authorization, "authorization-shaped");
    assert.equal(MIDDLEWARE_CLASSIFICATION_WORDING.unknown, "unclassified");
    assert.deepEqual(
      Object.keys(MIDDLEWARE_CLASSIFICATION_WORDING).sort(),
      [...MIDDLEWARE_CLASSIFICATION_VALUES].sort(),
    );
  });
});

// ─── Graph ───────────────────────────────────────────────────────────────────

describe("middleware graph", () => {
  it("declares exactly the documented edge vocabulary", () => {
    assert.deepEqual([...MIDDLEWARE_EDGE_TYPE_VALUES].sort(), [
      "applies-to",
      "precedes",
      "protects",
      "registered-on",
    ]);
    assert.deepEqual(Object.keys(MIDDLEWARE_EDGE_TYPES).sort(), [
      "APPLIES_TO",
      "PRECEDES",
      "PROTECTS",
      "REGISTERED_ON",
    ]);
    assert.deepEqual([...MIDDLEWARE_UNRESOLVED_KINDS].sort(), [
      "registration",
      "route-middleware",
    ]);
    assert.equal(MIDDLEWARE_GRAPH_VERSION, "1");
  });

  it("states each route's structural protection", async () => {
    const graph = (await scanOf(fullRepo())).model.middleware.graph;
    assert.equal(routeOf(graph, "route:GET:/admin").protection, MIDDLEWARE_PROTECTION_STATES.PROTECTED);
    assert.equal(routeOf(graph, "route:GET:/open").protection, MIDDLEWARE_PROTECTION_STATES.PROTECTED);
    assert.equal(routeOf(graph, "route:GET:/status").protection, MIDDLEWARE_PROTECTION_STATES.PROTECTED);
    assert.equal(routeOf(graph, "route:GET:/admin").protectionBasis, "established-registration");
  });

  it("orders middleware with `precedes` edges in the declared registration sequence", async () => {
    const graph = (await scanOf(fullRepo())).model.middleware.graph;
    const precedes = edgesOf(graph, MIDDLEWARE_EDGE_TYPES.PRECEDES);
    const pairs = precedes.map((edge) => [nameOf(edge.from), nameOf(edge.to)]);
    assert.equal(pairs.some(([from, to]) => from === "corsMiddleware" && to === "logger"), true);
    assert.equal(pairs.some(([from, to]) => from === "logger" && to === "requireAuth"), true);
    assert.equal(pairs.some(([from, to]) => from === "requireAuth" && to === "requireAdmin"), true);
    for (const edge of precedes) {
      assert.equal(edge.from.startsWith("symbol:"), true);
      assert.equal(edge.to.startsWith("symbol:"), true);
    }
  });

  it("joins a receiver registration to the file it was registered in", async () => {
    const graph = (await scanOf(fullRepo())).model.middleware.graph;
    const registeredOn = edgesOf(graph, MIDDLEWARE_EDGE_TYPES.REGISTERED_ON);
    assert.equal(registeredOn.length > 0, true);
    for (const edge of registeredOn) {
      assert.equal(edge.from.startsWith("symbol:"), true);
      assert.equal(edge.to.startsWith("file:"), true);
      assert.equal(edge.evidenceIds.length > 0, true);
      assert.equal(edge.receivers.length > 0, true);
    }
  });

  it("eliminates duplicate middleware from a route's chain", async () => {
    const { query } = await scanOf(fullRepo());
    const applied = query.middlewareForRoute("route:GET:/admin").applied.map((node) => node.id);
    assert.deepEqual(applied, [...new Set(applied)]);
    const chain = query.authorizationChains({ route: "route:GET:/admin" }).chains[0];
    const chainIds = chain.middleware.map((entry) => entry.id);
    assert.deepEqual(chainIds, [...new Set(chainIds)]);
  });

  it("never reports a route with unresolved middleware as unprotected", () => {
    const graph = graphOf({
      middlewareSources: [
        middlewareSource("a.js", {
          registrations: [
            registration({ middleware: [{ form: "reference", name: "ghost", member: null }] }),
          ],
        }),
      ],
      apiSources: [apiSource("a.js", { routes: [route("GET", "/x")] })],
    });
    const entry = routeOf(graph, "route:GET:/x");
    assert.equal(entry.protection, MIDDLEWARE_PROTECTION_STATES.UNRESOLVED);
    assert.equal(entry.middlewareCount, 0);
    assert.equal(entry.unresolvedCount > 0, true);
    assert.equal(entry.protectionBasis, "unresolved-registration");
  });

  it("reports a route with a route-scope unresolved middleware as unresolved too", () => {
    const graph = graphOf({
      apiSources: [
        apiSource("a.js", {
          routes: [
            route("GET", "/x", {
              middleware: [{ form: "reference", name: "ghost", member: null }],
            }),
          ],
        }),
      ],
    });
    const entry = routeOf(graph, "route:GET:/x");
    assert.equal(entry.protection, MIDDLEWARE_PROTECTION_STATES.UNRESOLVED);
    assert.equal(
      graph.unresolved.some((record) => record.kind === "route-middleware"),
      true,
    );
  });

  it("reports `none-observed` only for an established, empty, untruncated source", () => {
    const graph = graphOf({
      middlewareSources: [middlewareSource("a.js")],
      apiSources: [apiSource("a.js", { routes: [route("GET", "/x")] })],
    });
    assert.equal(
      routeOf(graph, "route:GET:/x").protection,
      MIDDLEWARE_PROTECTION_STATES.NONE_OBSERVED,
    );
  });

  it("reports `unknown` when the declaring file has no middleware record", () => {
    const graph = graphOf({
      apiSources: [apiSource("a.js", { routes: [route("GET", "/x")] })],
    });
    assert.equal(routeOf(graph, "route:GET:/x").protection, MIDDLEWARE_PROTECTION_STATES.UNKNOWN);
  });

  it("reports `unknown` when the declaring file's registrations are truncated", () => {
    const graph = graphOf({
      middlewareSources: [middlewareSource("a.js", { truncated: true })],
      apiSources: [apiSource("a.js", { routes: [route("GET", "/x")] })],
    });
    assert.equal(routeOf(graph, "route:GET:/x").protection, MIDDLEWARE_PROTECTION_STATES.UNKNOWN);
  });

  it("keeps its documented shape, with no verdict field", async () => {
    const { model } = await scanOf(fullRepo());
    assert.deepEqual(Object.keys(model.middleware.graph).sort(), [
      "coverage",
      "edges",
      "established",
      "nodes",
      "routes",
      "state",
      "unresolved",
      "version",
    ]);
  });

  it("is deterministic and deeply frozen", async () => {
    const first = (await scanOf(fullRepo())).model.middleware.graph;
    const second = (await scanOf(fullRepo())).model.middleware.graph;
    assert.deepEqual(clone(first), clone(second));
    assert.equal(Object.isFrozen(first), true);
    assert.equal(Object.isFrozen(first.nodes[0]), true);
    assert.equal(Object.isFrozen(first.edges[0].evidenceIds), true);
    assert.equal(Object.isFrozen(first.coverage), true);
    assert.equal(Object.isFrozen(first.coverage.classifications), true);
    assert.equal(Object.isFrozen(first.unresolved[0]), true);
  });

  it("carries every documented graph state and protection value", () => {
    assert.deepEqual([...MIDDLEWARE_GRAPH_STATE_VALUES].sort(), [
      "complete",
      "partial",
      "truncated",
      "unknown",
      "unsupported",
    ]);
    assert.deepEqual([...MIDDLEWARE_PROTECTION_VALUES].sort(), [
      "none-observed",
      "protected",
      "unknown",
      "unresolved",
    ]);
    assert.equal(isEstablishedMiddlewareState(MIDDLEWARE_GRAPH_STATES.PARTIAL), true);
    assert.equal(isEstablishedMiddlewareState(MIDDLEWARE_GRAPH_STATES.TRUNCATED), true);
    assert.equal(isEstablishedMiddlewareState(MIDDLEWARE_GRAPH_STATES.UNSUPPORTED), false);
    assert.equal(isEstablishedMiddlewareState(MIDDLEWARE_GRAPH_STATES.UNKNOWN), false);
    assert.equal(isMiddlewareSourceEstablished({ status: "parsed", established: true }), true);
    assert.equal(isMiddlewareSourceEstablished({ status: "unsupported", established: true }), false);
    assert.equal(isMiddlewareSourceEstablished({ status: "parsed", established: false }), false);
  });
});

// ─── Coverage ────────────────────────────────────────────────────────────────

describe("middleware coverage", () => {
  it("is complete for a fully established repository", async () => {
    const { model } = await scanOf(fullRepo());
    assert.equal(model.middleware.graph.state, MIDDLEWARE_GRAPH_STATES.COMPLETE);
    assert.equal(model.middleware.graph.established, true);
    assert.equal(model.middleware.graph.coverage.complete, true);
    assert.equal(model.middleware.graph.coverage.truncated, false);
  });

  it("is partial when a source establishes only part of its claim", () => {
    const graph = graphOf({
      middlewareSources: [middlewareSource("a.js", { problems: [MIDDLEWARE_PROBLEMS.RECEIVER_LIMIT] })],
    });
    assert.equal(graph.state, MIDDLEWARE_GRAPH_STATES.PARTIAL);
    assert.equal(graph.established, true);
    assert.equal(graph.coverage.parsed, 1);
  });

  it("is truncated when a bound bit", () => {
    const graph = graphOf({ middlewareSources: [middlewareSource("a.js", { truncated: true })] });
    assert.equal(graph.state, MIDDLEWARE_GRAPH_STATES.TRUNCATED);
    assert.equal(graph.established, true);
    assert.equal(graph.coverage.truncated, true);
  });

  it("is unsupported when every module source is a format this build does not read", () => {
    const graph = graphOf({
      middlewareSources: [
        middlewareSource("a.tsx", {
          status: "unsupported",
          reason: "format-not-interpreted",
          detail: ".tsx",
        }),
      ],
    });
    assert.equal(graph.state, MIDDLEWARE_GRAPH_STATES.UNSUPPORTED);
    assert.equal(graph.established, false);
    assert.deepEqual(graph.nodes, []);
    assert.equal(graph.coverage.unsupported, 1);
  });

  it("is unknown when nothing established a graph", () => {
    assert.equal(
      middlewareGraphState({
        sources: [],
        scanComplete: false,
        scanTruncated: false,
        hasScanState: true,
        projectionTruncated: false,
        uninterpretedSources: 0,
      }),
      MIDDLEWARE_GRAPH_STATES.UNKNOWN,
    );
    assert.equal(
      middlewareGraphState({
        sources: [],
        scanComplete: true,
        scanTruncated: false,
        hasScanState: false,
        projectionTruncated: false,
      }),
      MIDDLEWARE_GRAPH_STATES.UNKNOWN,
    );
    assert.equal(
      middlewareGraphState({
        sources: [],
        scanComplete: true,
        scanTruncated: false,
        hasScanState: true,
        projectionTruncated: false,
        uninterpretedSources: 2,
      }),
      MIDDLEWARE_GRAPH_STATES.UNSUPPORTED,
    );
  });

  it("names the sources behind an unestablished graph", () => {
    const graph = graphOf({
      middlewareSources: [middlewareSource("a.js", { status: "failed", reason: "unreadable" })],
    });
    assert.equal(graph.state, MIDDLEWARE_GRAPH_STATES.UNKNOWN);
    assert.deepEqual(
      graph.coverage.unestablishedSources.map((entry) => entry.path),
      ["a.js"],
    );
    assert.equal(graph.coverage.unestablished, 1);
  });

  it("counts what it contains without claiming what it does not", async () => {
    const { query } = await scanOf(fullRepo());
    const coverage = query.middlewareCoverage();
    assert.equal(coverage.state, MIDDLEWARE_GRAPH_STATES.COMPLETE);
    assert.equal(coverage.middleware > 0, true);
    assert.equal(coverage.protectedRoutes > 0, true);
    assert.equal(coverage.unprotectedRoutes, 0);
    assert.equal(coverage.unresolvedRoutes, 0);
    assert.equal(coverage.classifications.authentication > 0, true);
    assert.equal(coverage.classifications.unknown > 0, true);
    assert.equal(coverage.unresolved, coverage.unresolvedReported);
    assert.deepEqual(
      Object.keys(coverage.unresolvedByReason).sort(),
      [...MIDDLEWARE_UNRESOLVED_REASON_VALUES].sort(),
    );
    assert.equal(coverage.sources > 0, true);
    assert.equal(coverage.declaringModules > 0, true);
  });
});

// ─── Query API ───────────────────────────────────────────────────────────────

describe("middleware query API", () => {
  it("answers middlewareGraph with the nodes, edges, routes and a guarantee", async () => {
    const { query } = await scanOf(fullRepo());
    const graph = query.middlewareGraph();
    assert.equal(graph.state, MIDDLEWARE_GRAPH_STATES.COMPLETE);
    assert.equal(graph.established, true);
    assert.equal(graph.coverage, COVERAGE_GUARANTEES.COMPLETE);
    assert.equal(graph.nodes.length > 0, true);
    assert.equal(Object.isFrozen(graph), true);
    assert.equal(Object.isFrozen(graph.nodes), true);
    assert.equal(Object.isFrozen(graph.routes), true);
  });

  it("filters middleware and rejects a vocabulary it never records", async () => {
    const { query } = await scanOf(fullRepo());
    const auth = query.middleware({ classification: "authentication" });
    assert.equal(auth.middleware.length > 0, true);
    assert.equal(auth.middleware.every((node) => node.classification === "authentication"), true);
    assert.equal(query.middleware({ scope: "router" }).middleware.length > 0, true);
    assert.equal(query.middleware({ registration: "hook" }).middleware.length > 0, true);
    assert.equal(query.middleware({ receiver: "server" }).middleware.length > 0, true);
    assert.equal(query.middleware({ name: "corsMiddleware" }).middleware.length, 1);
    assert.equal(query.middleware({ path: "src/fast.js" }).middleware.length > 0, true);
    // Every closed criterion is checked against its vocabulary, so an impossible filter never
    // returns an empty list that reads like "this repository has none of those".
    assert.throws(() => query.middleware({ classification: "totally-unknown" }), RepositoryQueryError);
    assert.throws(() => query.middleware({ scope: "middlewareish" }), RepositoryQueryError);
    assert.throws(() => query.middleware({ registration: "mount" }), RepositoryQueryError);
    assert.throws(() => query.middleware({ nope: 1 }), RepositoryQueryError);
    assert.throws(() => query.middleware({ name: "" }), RepositoryQueryError);
  });

  it("answers middlewareForRoute with the chain, the applied set and the protection", async () => {
    const { query } = await scanOf(fullRepo());
    const entry = query.middlewareForRoute("route:GET:/admin");
    assert.equal(entry.route.id, "route:GET:/admin");
    assert.deepEqual(
      entry.middleware.map((node) => node.symbol.id),
      ["symbol:src/app.js#requireAdmin", "symbol:src/app.js#validateBody"],
    );
    assert.deepEqual(
      entry.applied.map((node) => node.id),
      [
        "symbol:src/app.js#corsMiddleware",
        "symbol:src/app.js#logger",
        "symbol:src/app.js#requireAdmin",
        "symbol:src/app.js#requireAuth",
        "symbol:src/app.js#validateBody",
      ],
    );
    assert.equal(entry.protection, MIDDLEWARE_PROTECTION_STATES.PROTECTED);
    assert.deepEqual(entry.unresolved, []);
    assert.equal(Object.isFrozen(entry), true);
  });

  it("returns an ordinary miss for an unknown route, never `none-observed`", async () => {
    const { query } = await scanOf(fullRepo());
    const miss = query.middlewareForRoute("route:GET:/nope");
    assert.equal(miss.route, null);
    assert.equal(miss.protection, null);
    assert.deepEqual(miss.middleware, []);
    assert.deepEqual(miss.applied, []);
  });

  it("answers routesProtectedBy from the graph's own route view", async () => {
    const { query } = await scanOf(fullRepo());
    const result = query.routesProtectedBy("symbol:src/app.js#corsMiddleware");
    assert.equal(result.symbol.name, "corsMiddleware");
    assert.equal(result.routes.some((entry) => entry.route === "route:GET:/admin"), true);
    for (const entry of result.routes) {
      assert.equal(entry.middleware.includes("symbol:src/app.js#corsMiddleware"), true);
    }
    assert.equal(query.routesProtectedBy("symbol:src/app.js#nothing").symbol, null);
    assert.deepEqual(query.routesProtectedBy("symbol:src/app.js#nothing").routes, []);
  });

  it("answers authorizationChains only for routes that actually have a chain", () => {
    const { query } = modelOf({
      middlewareSources: [middlewareSource("a.js")],
      apiSources: [apiSource("a.js", { routes: [route("GET", "/bare")] })],
      complete: true,
    });
    // The route exists, was established as carrying no middleware, and still has no chain:
    // a chain is a statement about declared middleware, and it has none.
    const entry = routeOf(query.middlewareGraph(), "route:GET:/bare");
    assert.equal(entry.protection, MIDDLEWARE_PROTECTION_STATES.NONE_OBSERVED);
    assert.deepEqual(entry.middleware, []);
    assert.deepEqual(query.authorizationChains().chains, []);
    assert.deepEqual(query.authorizationChains({ route: "route:GET:/bare" }).chains, []);
  });

  it("answers authorizationChains for one route and for the whole repository", async () => {
    const { query } = await scanOf(fullRepo());
    const all = query.authorizationChains();
    assert.equal(all.chains.length > 0, true);
    for (const chain of all.chains) {
      assert.equal(chain.middleware.length > 0, true);
      assert.equal(Object.isFrozen(chain), true);
      assert.equal(MIDDLEWARE_PROTECTION_VALUES.includes(chain.protection), true);
      for (const entry of chain.middleware) {
        assert.equal(MIDDLEWARE_CLASSIFICATION_VALUES.includes(entry.classification), true);
      }
    }
    assert.equal(query.authorizationChains({ route: "route:GET:/open" }).chains.length, 1);
    assert.throws(() => query.authorizationChains({ nope: true }), RepositoryQueryError);
  });

  it("answers unresolvedMiddleware separately from established middleware", async () => {
    const { query } = await scanOf(fullRepo());
    const unresolved = query.unresolvedMiddleware();
    assert.equal(unresolved.unresolved.length > 0, true);
    assert.equal(
      unresolved.unresolved.every((record) =>
        MIDDLEWARE_UNRESOLVED_REASON_VALUES.includes(record.reason),
      ),
      true,
    );
    assert.equal(
      query
        .unresolvedMiddleware({ kind: "registration" })
        .unresolved.every((record) => record.kind === "registration"),
      true,
    );
    assert.throws(() => query.unresolvedMiddleware({ kind: "nope" }), RepositoryQueryError);
    assert.throws(() => query.unresolvedMiddleware({ nope: 1 }), RepositoryQueryError);

    // A receiver-scope observation and a route-scope observation are both unresolved, and the
    // kind criterion separates them: a caller that wants only route middleware gets only
    // route middleware.
    const mixed = modelOf({
      middlewareSources: [
        middlewareSource("a.js", {
          registrations: [
            registration({ middleware: [{ form: "reference", name: "ghost", member: null }] }),
          ],
        }),
      ],
      apiSources: [
        apiSource("a.js", {
          routes: [
            route("GET", "/x", {
              middleware: [{ form: "reference", name: "other", member: null }],
            }),
          ],
        }),
      ],
    });
    const kinds = new Set(
      mixed.query.unresolvedMiddleware().unresolved.map((record) => record.kind),
    );
    assert.deepEqual([...kinds].sort(), ["registration", "route-middleware"]);
    const onlyRoute = mixed.query.unresolvedMiddleware({ kind: "route-middleware" }).unresolved;
    const onlyRegistration = mixed.query.unresolvedMiddleware({ kind: "registration" }).unresolved;
    assert.equal(onlyRoute.length > 0, true);
    assert.equal(onlyRegistration.length > 0, true);
    assert.equal(onlyRoute.every((record) => record.kind === "route-middleware"), true);
    assert.equal(onlyRegistration.every((record) => record.kind === "registration"), true);
  });

  it("exposes the coverage object and the guarantee separately", async () => {
    const { query } = await scanOf(fullRepo());
    assert.equal(query.middlewareCoverage().state, MIDDLEWARE_GRAPH_STATES.COMPLETE);
    assert.equal(query.middlewareCoverage().established, true);
    assert.equal(query.middlewareGraph().coverage, COVERAGE_GUARANTEES.COMPLETE);
  });

  it("returns frozen, deterministic lists for the same model", () => {
    const { query } = modelOf({
      middlewareSources: [
        middlewareSource("a.js", {
          registrations: [
            registration({ middleware: [{ form: "reference", name: "auth", member: null }] }),
          ],
        }),
      ],
      semantics: [semanticsSource("a.js", ["auth"])],
    });
    const first = query.middleware({});
    const second = query.middleware({});
    assert.deepEqual(clone(first), clone(second));
    assert.equal(Object.isFrozen(first), true);
    assert.equal(Object.isFrozen(first.middleware[0]), true);
    assert.equal(first.middleware[0].id, "symbol:a.js#auth");
  });
});

// ─── Rule pack and analyzer ──────────────────────────────────────────────────

describe("middleware rule pack", () => {
  const runOf = async (files) => {
    const { model } = await scanOf(files);
    const engine = createRuleEngine({
      registry: createMiddlewareRuleRegistry({ rules: middlewareRules }),
    });
    return { model, run: await engine.runAll(contextOf(model)) };
  };
  const runOfModel = async (model) => {
    const engine = createRuleEngine({
      registry: createMiddlewareRuleRegistry({ rules: middlewareRules }),
    });
    return engine.runAll(contextOf(model));
  };
  const inventoryOf = (run) =>
    run.rules.find((entry) => entry.rule.id === MIDDLEWARE_RULE_IDS.GRAPH_INVENTORY);

  it("declares its rule in the pack namespace", () => {
    assert.deepEqual(middlewareRuleSetIssues(middlewareRules), []);
    assert.equal(MIDDLEWARE_RULE_IDS.GRAPH_INVENTORY.startsWith("middleware."), true);
    assert.deepEqual(
      middlewareRules.map((rule) => rule.id),
      [MIDDLEWARE_RULE_IDS.GRAPH_INVENTORY],
    );
    assert.equal(middlewareRules[0].severity, "info");
    assert.deepEqual(middlewareRules[0].applicability, {});
    assert.deepEqual(middlewareRules[0].remediation, {});
    assert.equal(typeof middlewareRules[0].detect, "function");
  });

  it("refuses a rule set that leaves the pack contract", () => {
    assert.deepEqual(middlewareRuleSetIssues("nope"), ["middlewareRules: must be an array of rules"]);
    assert.equal(middlewareRuleSetIssues([{ id: "api.graph.inventory" }]).length > 0, true);
    assert.equal(middlewareRuleSetIssues([]).length > 0, true);
    assert.equal(
      middlewareRuleSetIssues([middlewareRules[0], middlewareRules[0]]).some((issue) =>
        issue.includes("twice"),
      ),
      true,
    );
    assert.throws(() => createMiddlewareRuleRegistry({ rules: [] }), Error);
  });

  it("describes every value of every vocabulary the graph can state", () => {
    assert.deepEqual(
      [...MIDDLEWARE_DESCRIBED_EDGE_TYPES].sort(),
      [...MIDDLEWARE_EDGE_TYPE_VALUES].sort(),
    );
    assert.deepEqual(
      [...MIDDLEWARE_DESCRIBED_UNRESOLVED_REASONS].sort(),
      [...MIDDLEWARE_UNRESOLVED_REASON_VALUES].sort(),
    );
    assert.deepEqual(
      Object.keys(MIDDLEWARE_PROTECTION_WORDING).sort(),
      [...MIDDLEWARE_PROTECTION_VALUES].sort(),
    );
    assert.deepEqual(
      Object.keys(MIDDLEWARE_EDGE_TYPE_WORDING).sort(),
      [...MIDDLEWARE_EDGE_TYPE_VALUES].sort(),
    );
    assert.equal(Object.values(MIDDLEWARE_UNRESOLVED_REASON_WORDING).length > 0, true);
  });

  it("reports one finding per established middleware", async () => {
    const { run, model } = await runOf(fullRepo());
    const inventory = inventoryOf(run);
    assert.equal(inventory.metadata.established, true);
    assert.equal(inventory.findings.length, model.middleware.graph.nodes.length);
    assert.equal(inventory.metadata.capped, false);
    for (const finding of inventory.findings) {
      assert.equal(finding.severity, "info");
      assert.equal(finding.metadata.basis, MIDDLEWARE_BASIS);
      assert.equal(finding.confidence, MIDDLEWARE_CONFIDENCE.OBSERVED_REGISTRATION);
      assert.equal(finding.category, "architecture");
      assert.equal(finding.evidence.length > 0, true);
      assert.equal(
        finding.description.includes("says nothing about whether the middleware runs"),
        true,
      );
    }
  });

  it("offers no missing-auth, ordering, CORS, rate-limit or exposure verdict", async () => {
    const { run } = await runOf(fullRepo());
    for (const finding of inventoryOf(run).findings) {
      assert.equal(finding.severity, "info");
      const text = `${finding.description} ${JSON.stringify(finding.metadata)}`.toLowerCase();
      for (const banned of [
        "is insecure",
        "should require",
        "missing auth",
        "missing middleware",
        "vulnerab",
        "exposed",
        "incorrect order",
        "misconfigured",
        "not protected",
        "quality score",
      ]) {
        assert.equal(text.includes(banned), false, `must not judge: ${banned}`);
      }
      // The classification is reported as name-shaped, never as a behaviour claim: the
      // description carries the wording for the classification, and the metadata carries the
      // value itself.
      assert.equal(finding.description.includes("whose own name is"), true);
      assert.equal(
        finding.description.includes(
          MIDDLEWARE_CLASSIFICATION_WORDING[finding.metadata.classification],
        ),
        true,
        `${finding.metadata.name} must read as its own classification`,
      );
      assert.equal(JSON.stringify(finding.metadata).includes("authentication-shaped"), false);
    }
  });

  it("reports unresolved middleware as metadata, never as a registration", async () => {
    const { run } = await runOf(fullRepo());
    const inventory = inventoryOf(run);
    assert.equal(inventory.metadata.unresolved.count > 0, true);
    assert.equal(inventory.metadata.unresolved.byReason["array-not-established"], 1);
    const names = new Set(inventory.findings.map((finding) => finding.metadata.name));
    assert.equal(names.has("debugLogger"), false);
    assert.equal(names.has("requireAuth"), true);
  });

  it("caps a large set of middleware and says so", () => {
    const registrations = [];
    const names = [];
    for (let index = 0; index < MAX_MIDDLEWARE_FINDINGS + 5; index += 1) {
      names.push(`mw${index}`);
      registrations.push(
        registration({
          sequence: index,
          middleware: [{ form: "reference", name: `mw${index}`, member: null }],
        }),
      );
    }
    const { model } = modelOf({
      middlewareSources: [middlewareSource("a.js", { registrations })],
      semantics: [semanticsSource("a.js", names)],
      complete: true,
    });
    return runOfModel(model).then((run) => {
      const inventory = inventoryOf(run);
      assert.equal(inventory.findings.length, MAX_MIDDLEWARE_FINDINGS);
      assert.equal(inventory.metadata.capped, true);
      assert.equal(inventory.metadata.middleware, MAX_MIDDLEWARE_FINDINGS + 5);
    });
  });

  it("produces deterministic, uniquely fingerprinted findings", async () => {
    const first = await runOf(fullRepo());
    const second = await runOf(fullRepo());
    const engine = createAnalyzerEngine({
      registry: createAnalyzerRegistry([createMiddlewareAnalyzer()]),
    });
    const analyzed = await engine.runAll(contextOf(first.model));
    assert.equal(
      new Set(analyzed.findings.map((finding) => finding.fingerprint)).size,
      analyzed.findings.length,
    );
    assert.deepEqual(
      inventoryOf(first.run).findings.map((finding) => finding.metadata.fingerprintKey),
      inventoryOf(second.run).findings.map((finding) => finding.metadata.fingerprintKey),
    );
  });

  it("runs as an ordinary analyzer over the accepted framework", async () => {
    const { model } = await scanOf(fullRepo());
    const engine = createAnalyzerEngine({
      registry: createAnalyzerRegistry([createMiddlewareAnalyzer()]),
    });
    const result = await engine.runAll(contextOf(model));
    assert.equal(result.analyzers.length, 1);
    assert.equal(result.analyzers[0].analyzer.id, MIDDLEWARE_ANALYZER_ID);
    assert.equal(result.analyzers[0].analyzer.scope, MIDDLEWARE_ANALYZER_SCOPE);
    assert.equal(result.findings.length > 0, true);
  });

  it("abstains instead of reporting a repository it could not read", async () => {
    const { model } = await scanOf(tsxOnlyRepo());
    const run = await runOfModel(model);
    const inventory = inventoryOf(run);
    assert.deepEqual(inventory.findings, []);
    assert.equal(inventory.status, RULE_OUTCOME_STATUSES.UNKNOWN);
    assert.equal(inventory.applicability.coverage, "unknown");
  });

  it("abstains rather than pass when only unresolved middleware exists", () => {
    const { model } = modelOf({
      middlewareSources: [
        middlewareSource("a.js", {
          registrations: [
            registration({ middleware: [{ form: "reference", name: "ghost", member: null }] }),
          ],
        }),
      ],
      apiSources: [apiSource("a.js", { routes: [route("GET", "/x")] })],
      complete: true,
    });
    return runOfModel(model).then((run) => {
      const inventory = inventoryOf(run);
      assert.deepEqual(inventory.findings, []);
      assert.equal(inventory.status, RULE_OUTCOME_STATUSES.UNKNOWN);
      assert.equal(inventory.metadata.protectionStates.unresolved, 1);
      assert.equal(inventory.applicability.coverage, "unknown");
    });
  });

  it("exposes coverage and absence through the signal helpers", async () => {
    const { query } = await scanOf(fullRepo());
    assert.equal(middlewareCoverage(query).state, MIDDLEWARE_GRAPH_STATES.COMPLETE);
    assert.equal(middlewareNodes(query).length > 0, true);
    assert.equal(middlewareUnresolved(query).length > 0, true);
    assert.equal(middlewareAbsence(query).established, true);
    assert.equal(middlewareAbsence(query).reason, null);
  });

  it("reads the graph only through the query API", () => {
    const packFiles = [
      "src/rules/middleware/contracts.js",
      "src/rules/middleware/signals.js",
      "src/rules/middleware/registry.js",
      "src/rules/middleware/analyzer.js",
      "src/rules/middleware/index.js",
      "src/rules/middleware/rules/index.js",
      "src/rules/middleware/rules/inventory.js",
    ];
    for (const file of packFiles) {
      const text = readFileSync(repoFile(file), "utf8");
      const statements = text
        .split("\n")
        .filter((line) => /^\s*(import|export)\b/.test(line) || /\bfrom\s+["']/.test(line))
        .join("\n");
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
        "repository/scanner",
      ]) {
        assert.equal(statements.includes(forbidden), false, `${file} must not import ${forbidden}`);
      }
    }
    assert.equal(
      readFileSync(repoFile("src/rules/middleware/signals.js"), "utf8").includes(
        "createRepositoryQuery",
      ),
      true,
    );
  });
});

// ─── Model validation ────────────────────────────────────────────────────────

describe("middleware model contract", () => {
  const validModel = () =>
    modelOf({
      middlewareSources: [
        middlewareSource("a.js", {
          registrations: [
            registration({ middleware: [{ form: "reference", name: "auth", member: null }] }),
          ],
        }),
      ],
      apiSources: [
        apiSource("a.js", {
          routes: [
            route("GET", "/x", { middleware: [{ form: "reference", name: "auth", member: null }] }),
          ],
        }),
      ],
      semantics: [semanticsSource("a.js", ["auth"])],
      complete: true,
    }).model;

  it("accepts a coherent middleware area", () => {
    const model = validModel();
    assert.equal(validateRepositoryModelGraph(model), model);
    assert.deepEqual(
      model.middleware.graph.nodes.map((node) => node.id),
      ["symbol:a.js#auth"],
    );
    assert.equal(model.middleware.count, 1);
    assert.equal(model.middleware.detected, true);
    assert.equal(model.middleware.graph.nodes[0].scopes.includes("app"), true);
    assert.equal(model.middleware.graph.nodes[0].scopes.includes("route"), true);
  });

  it("rejects a middleware node that is not a symbol the symbol graph carries", () => {
    const tampered = clone(validModel());
    const from = tampered.middleware.graph.nodes[0].id;
    const to = "symbol:a.js#invented";
    // Rename the node *and* every edge and route entry that names it, so the only thing wrong
    // with the model is that the middleware no longer reuses a Phase 17 symbol identity.
    for (const node of tampered.middleware.graph.nodes) {
      if (node.id === from) {
        node.id = to;
        node.symbolId = to;
      }
    }
    for (const edge of tampered.middleware.graph.edges) {
      if (edge.from === from) edge.from = to;
      if (edge.to === from) edge.to = to;
    }
    for (const entry of tampered.middleware.graph.routes) {
      entry.middleware = entry.middleware.map((id) => (id === from ? to : id));
    }
    sortEdges(tampered.middleware.graph.edges);

    const issues = issuesOfValidate(tampered);
    assert.notEqual(issues, null, "an invented middleware identity must be rejected");
    assert.equal(issues.includes("middleware.graph.nodes[0].id"), true, issues);
  });

  it("rejects a middleware node whose identity disagrees with its symbolId", () => {
    const tampered = clone(validModel());
    tampered.middleware.graph.nodes[0].symbolId = "symbol:a.js#other";
    const issues = issuesOfValidate(tampered);
    assert.notEqual(issues, null);
    assert.equal(issues.includes("middleware.graph.nodes[0].symbolId"), true, issues);
  });

  it("rejects a protection edge that names a route the API graph does not carry", () => {
    const tampered = clone(validModel());
    const apiIds = new Set(tampered.api.graph.nodes.map((node) => node.id));
    assert.equal(apiIds.has("route:GET:/invented"), false);
    tampered.middleware.graph.edges[0].to = "route:GET:/invented";
    sortEdges(tampered.middleware.graph.edges);
    const issues = issuesOfValidate(tampered);
    assert.notEqual(issues, null);
    assert.equal(issues.includes("middleware.graph.edges"), true, issues);
  });

  it("rejects an edge list that states a relationship twice", () => {
    const tampered = clone(validModel());
    tampered.middleware.graph.edges.push(clone(tampered.middleware.graph.edges[0]));
    tampered.middleware.graph.coverage.edges = tampered.middleware.graph.edges.length;
    const issues = issuesOfValidate(tampered);
    assert.notEqual(issues, null);
    assert.equal(issues.includes("must state each relationship once"), true, issues);
  });

  it("rejects a route whose protection disagrees with its own counts", () => {
    const tampered = clone(validModel());
    const entry = tampered.middleware.graph.routes[0];
    assert.equal(entry.protection, MIDDLEWARE_PROTECTION_STATES.PROTECTED);
    entry.protection = MIDDLEWARE_PROTECTION_STATES.NONE_OBSERVED;
    tampered.middleware.graph.coverage.protectedRoutes -= 1;
    tampered.middleware.graph.coverage.unprotectedRoutes += 1;
    assert.throws(() => validateRepositoryModelGraph(tampered), ValidationError);
  });

  it("rejects a route marked protected without established middleware", () => {
    const tampered = clone(validModel());
    const entry = tampered.middleware.graph.routes[0];
    entry.middleware = [];
    entry.middlewareCount = 0;
    tampered.middleware.graph.coverage.protectedRoutes -= 1;
    tampered.middleware.graph.coverage.unprotectedRoutes += 1;
    assert.throws(() => validateRepositoryModelGraph(tampered), ValidationError);
  });

  it("rejects a duplicate chain on a route", () => {
    const tampered = clone(validModel());
    const entry = tampered.middleware.graph.routes[0];
    entry.middleware = [entry.middleware[0], entry.middleware[0]];
    assert.throws(() => validateRepositoryModelGraph(tampered), ValidationError);
  });

  it("rejects an unknown classification", () => {
    const tampered = clone(validModel());
    tampered.middleware.graph.nodes[0].classification = "definitely-not-a-classification";
    assert.throws(() => validateRepositoryModelGraph(tampered), ValidationError);
  });

  it("rejects an unknown unresolved reason", () => {
    const tampered = clone(validModel());
    tampered.middleware.graph.unresolved.push({
      path: "a.js",
      kind: "registration",
      reason: "totally-unknown",
      receiver: "app",
      scope: "app",
      registration: "use",
      name: null,
      member: null,
      route: null,
      evidenceId: null,
      count: 1,
    });
    tampered.middleware.graph.coverage.unresolved += 1;
    assert.throws(() => validateRepositoryModelGraph(tampered), ValidationError);
  });

  it("rejects coverage that disagrees with the graph it summarises", () => {
    const counts = clone(validModel());
    counts.middleware.graph.coverage.middleware += 1;
    assert.throws(() => validateRepositoryModelGraph(counts), ValidationError);

    const state = clone(validModel());
    state.middleware.graph.coverage.state = MIDDLEWARE_GRAPH_STATES.PARTIAL;
    assert.throws(() => validateRepositoryModelGraph(state), ValidationError);

    const edges = clone(validModel());
    edges.middleware.graph.coverage.edges += 1;
    assert.throws(() => validateRepositoryModelGraph(edges), ValidationError);
  });

  it("treats a malformed middleware graph as a validation failure, never a finding", async () => {
    const model = validModel();
    const engine = createRuleEngine({
      registry: createMiddlewareRuleRegistry({ rules: middlewareRules }),
    });
    const run = await engine.runAll(contextOf(model));
    const inventory = run.rules.find(
      (entry) => entry.rule.id === MIDDLEWARE_RULE_IDS.GRAPH_INVENTORY,
    );
    assert.equal(inventory.findings.every((finding) => finding.severity === "info"), true);
    assert.equal(
      inventory.findings.some((finding) => finding.metadata.middleware === undefined),
      false,
    );
    const tampered = clone(model);
    tampered.middleware.graph.nodes[0].classification = "nope";
    assert.throws(() => validateRepositoryModelGraph(tampered), ValidationError);
  });

  it("validates the middleware section of a ScanResult", () => {
    const bad = createScanResult({
      root: "/repo",
      scannedAt: "2026-01-01T00:00:00.000Z",
      middleware: { inspected: true, complete: true, truncated: false, files: [{ path: "/abs.js" }] },
    });
    assert.throws(() => validateScanResult(bad), Error);
  });

  it("reconciles the model vocabularies with the scanner's", () => {
    assert.deepEqual(
      [...MIDDLEWARE_SOURCE_STATUSES].sort(),
      Object.values(SCANNER_SOURCE_STATUSES).sort(),
    );
    assert.deepEqual([...MIDDLEWARE_FRAMEWORKS].sort(), Object.values(SCANNER_FRAMEWORKS).sort());
    assert.deepEqual(
      [...MIDDLEWARE_PROBLEM_REASONS].sort(),
      Object.values(MIDDLEWARE_PROBLEMS).sort(),
    );
    assert.deepEqual(
      Object.values(MIDDLEWARE_UNRESOLVED_REASONS).sort(),
      Object.values(SCANNER_UNRESOLVED_REASONS).sort(),
    );
    // Both sides of the model re-declare this vocabulary — the acquisition-side list the
    // projection validates against, and the graph's own — so both are pinned to the scanner.
    assert.deepEqual(
      [...MIDDLEWARE_SOURCE_UNRESOLVED_REASONS].sort(),
      Object.values(SCANNER_UNRESOLVED_REASONS).sort(),
    );
    assert.deepEqual([...MIDDLEWARE_SCOPES].sort(), Object.values(SCANNER_SCOPES).sort());
    assert.deepEqual(
      [...MIDDLEWARE_REGISTRATIONS].sort(),
      Object.values(SCANNER_REGISTRATIONS).sort(),
    );
    assert.deepEqual([...MODEL_CALLABLE_FORMS].sort(), [...MIDDLEWARE_CALLABLE_FORMS].sort());
    assert.equal(Object.values(MIDDLEWARE_SOURCE_REASONS).includes("unreadable"), true);
    // The graph vocabulary is a documented superset: it adds the route-scope registration the
    // API acquisition establishes, and `route` is the one value it adds to the scanner's scopes.
    for (const scope of Object.values(SCANNER_SCOPES)) {
      assert.equal(MIDDLEWARE_GRAPH_SCOPES.includes(scope), true);
      assert.equal(MIDDLEWARE_SCOPES.includes(scope), true);
    }
    assert.deepEqual(
      [...MIDDLEWARE_GRAPH_SCOPES].sort(),
      [...Object.values(SCANNER_SCOPES), MIDDLEWARE_ROUTE_SCOPE].sort(),
    );
    for (const kind of ["use", "hook", "register"]) {
      assert.equal(MIDDLEWARE_GRAPH_REGISTRATIONS.includes(kind), true);
    }
    assert.deepEqual([...MIDDLEWARE_GRAPH_REGISTRATIONS].sort(), [
      "hook",
      "register",
      "route",
      "use",
    ]);
  });

  it("keeps the middleware area out of the judgment vocabulary", () => {
    const model = validModel();
    const area = model.middleware;
    assert.deepEqual(Object.keys(area).sort(), ["count", "coverage", "detected", "entries", "graph"]);
    assert.equal(Object.keys(model.middleware.graph.coverage).includes("classifications"), true);
    for (const banned of ["score", "risk", "severity", "verdict", "recommendation"]) {
      assert.equal(
        Object.keys(model.middleware.graph).includes(banned),
        false,
        `the graph must not state a ${banned}`,
      );
      assert.equal(Object.keys(model.middleware.graph.coverage).includes(banned), false);
    }
  });
});

// ─── Integration ─────────────────────────────────────────────────────────────

describe("middleware integration", () => {
  it("agrees with the API graph about route identity", async () => {
    const { model } = await scanOf(fullRepo());
    const apiIds = new Set(model.api.graph.nodes.map((node) => node.id));
    assert.equal(model.middleware.graph.routes.length > 0, true);
    for (const entry of model.middleware.graph.routes) {
      assert.equal(apiIds.has(entry.route), true);
      assert.equal(entry.route, `route:${entry.method}:${entry.path}`);
    }
  });

  it("agrees with the API graph about route-scope middleware", async () => {
    const { model } = await scanOf(fullRepo());
    const apiMiddleware = new Set(
      model.api.graph.edges
        .filter((edge) => edge.type === "middleware")
        .map((edge) => `${edge.from}\u0000${edge.to}`),
    );
    const protects = edgesOf(model.middleware.graph, MIDDLEWARE_EDGE_TYPES.PROTECTS);
    assert.equal(protects.length > 0, true);
    for (const edge of protects) {
      assert.equal(apiMiddleware.has(`${edge.to}\u0000${edge.from}`), true);
    }
  });

  it("agrees with the Symbol graph about middleware identity", async () => {
    const { model } = await scanOf(fullRepo());
    const symbols = new Map(model.symbols.graph.nodes.map((node) => [node.id, node]));
    for (const node of model.middleware.graph.nodes) {
      const symbol = symbols.get(node.id);
      assert.notEqual(symbol, undefined);
      assert.equal(node.name, symbol.name);
      assert.equal(node.path, symbol.path);
    }
  });

  it("keeps the area coverage in step with the graph it summarises", async () => {
    const { model } = await scanOf(fullRepo());
    const area = model.middleware;
    const graph = model.middleware.graph;
    assert.equal(area.coverage.unresolved, graph.coverage.unresolved);
    assert.equal(area.coverage.registrations, graph.coverage.registrations);
    assert.equal(area.coverage.mounts, graph.coverage.mounts);
    assert.equal(area.coverage.sources, graph.coverage.sources);
    assert.equal(area.coverage.middleware, graph.coverage.registrations === 0 ? 0 : area.coverage.middleware);
    assert.equal(area.count, area.entries.length);
    assert.equal(area.entries.length, graph.coverage.sources);
    assert.equal(area.detected, true);
  });

  it("projects the same facts the scanner recorded", async () => {
    const { scan, model } = await scanOf(fullRepo());
    const scanned = scan.middleware.files.reduce(
      (total, source) => total + source.counts.registrations,
      0,
    );
    const projected = model.middleware.entries.reduce(
      (total, source) => total + source.counts.registrations,
      0,
    );
    assert.equal(projected, scanned);
    assert.equal(
      model.middleware.graph.coverage.paths === undefined,
      true,
      "the graph states sources, not a second path list",
    );
  });

  it("reaches the rule engine through the whole scan boundary", async () => {
    const { model } = await scanOf(fullRepo());
    const engine = createAnalyzerEngine({
      registry: createAnalyzerRegistry([createMiddlewareAnalyzer()]),
    });
    const result = await engine.runAll(contextOf(model));
    const names = new Set(result.findings.map((finding) => finding.metadata.name));
    assert.equal(names.has("corsMiddleware"), true);
    assert.equal(names.has("validateBody"), true);
    assert.equal(
      result.findings.every((finding) => finding.metadata.basis === MIDDLEWARE_BASIS),
      true,
    );
    assert.equal(
      result.findings.every((finding) => finding.metadata.routeCount > 0),
      true,
    );
  });
});

// ─── Security ────────────────────────────────────────────────────────────────

describe("middleware security", () => {
  it("introduces no server, request, process or evaluation capability in the projection", () => {
    for (const file of [
      "src/repository/model/middleware-graph.js",
      "src/repository/scanner/policies/middleware.js",
      "src/repository/scanner/detectors/middleware.js",
    ]) {
      const text = readFileSync(repoFile(file), "utf8");
      for (const forbidden of [
        "node:fs",
        "node:path",
        "child_process",
        "node:net",
        "node:http",
        "node:https",
        "node:dns",
        "node:worker_threads",
        "eval(",
        "new Function",
      ]) {
        assert.equal(text.includes(forbidden), false, `${file} must not reference ${forbidden}`);
      }
    }
  });

  it("classifies from the name, never from what the middleware's body looks like", async () => {
    // `innocent` reads a JWT and checks a role inside its body. Nothing in this build inspects
    // that body, so the classification stays `unknown`: a name-only function cannot be
    // upgraded by implementation-shaped code, and it cannot be downgraded either.
    const { model } = await scanOf({
      "package.json": packageJson(),
      "src/app.js": [
        'import express from "express";',
        "const app = express();",
        "app.use(innocent);",
        "app.use(requireAuth);",
        "function innocent() {",
        '  const token = verifyJwt(req.headers.authorization);',
        '  if (!token.role || token.role !== "admin") throw new Error("forbidden");',
        "}",
        "function requireAuth() {}",
        "function verifyJwt(value) { return value; }",
        "export default app;",
        "",
      ].join("\n"),
    });
    const byName = new Map(model.middleware.graph.nodes.map((node) => [node.name, node]));
    assert.deepEqual([...byName.keys()].sort(), ["innocent", "requireAuth"]);
    assert.equal(byName.get("innocent").classification, "unknown");
    assert.equal(byName.get("requireAuth").classification, "authentication");
    // The body's identifiers are not registrations: only a receiver-scope call states one.
    assert.equal(byName.has("verifyJwt"), false);
  });

  it("leaks no absolute host path through the graph", async () => {
    const { model } = await scanOf(fullRepo());
    for (const value of stringsIn(model.middleware.graph)) {
      assert.equal(value.includes(TMP_ROOT), false, `host path leaked: ${value}`);
      assert.equal(/^[A-Za-z]:\\/.test(value), false, `drive path leaked: ${value}`);
    }
  });

  it("exposes no raw scanner error, stack or cause through the graph", async () => {
    const { model } = await scanOf(fullRepo());
    const json = JSON.stringify(model.middleware.graph);
    assert.equal(json.includes('"stack"'), false);
    assert.equal(json.includes('"cause"'), false);
    assert.equal(json.includes(model.identity.root), false);
  });

  it("carries every middleware identity as a symbol identity, never a host path", async () => {
    const { model } = await scanOf(fullRepo());
    for (const node of model.middleware.graph.nodes) {
      assert.equal(node.id.startsWith("symbol:"), true);
      assert.equal(node.path.startsWith("/"), false);
    }
  });
});
