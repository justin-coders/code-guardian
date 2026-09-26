/**
 * Code Guardian — API & Service Graph Tests (Phase 18)
 *
 * Three fixture styles, chosen deliberately:
 *
 *   - **real repositories** written to a temporary directory and scanned through the
 *     accepted Phase 8A boundary, Phase 8C scanner, Phase 8D model builder and Phase 18
 *     projection, so acquisition, model and graph agree end to end. This is the only way
 *     to prove that what a source file literally states is what the graph exposes.
 *   - **hand-built API sources** for facts a tiny repository cannot reach on demand (a
 *     lexer that failed, a source whose route set is not established, a bound that bit)
 *     and for tampering, so the fail-closed behaviour of the graph contract is stated
 *     exactly.
 *   - **mutation-style tampering** inside the model's own API area, because the point of
 *     the contract is that a malformed graph fails validation instead of becoming a
 *     finding.
 *
 * The suite's central claim is the phase's central requirement: a route is recorded only
 * when the repository *establishes* it, and a handler is connected only to a Phase 17
 * symbol. Most of the tests below pin one place where the graph *refuses* to make a claim
 * — an unestablished receiver, an unsupported framework, a computed path, a member-access
 * handler, an inline handler, an `unknown` coverage state.
 *
 * No test starts a server, sends a request, spawns a process, contacts a network,
 * installs a package or writes to the repository under test.
 *
 * Run with: node --test tests/api-graph.test.js
 */

import { after, describe, it } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { ValidationError } from "../src/core/index.js";

import {
  API_ACQUISITION_LIMITS,
  API_FRAMEWORKS as SCANNER_FRAMEWORKS,
  API_HTTP_METHODS,
  API_PROBLEMS,
  API_ROUTE_METHODS as SCANNER_ROUTE_METHODS,
  API_SHAPE_REASONS,
  API_SOURCE_REASONS,
  API_SOURCE_STATUSES,
  API_UNSUPPORTED_FRAMEWORKS as SCANNER_UNSUPPORTED_FRAMEWORKS,
  createScanResult,
  scanApiRoutes,
  scanRepository,
  validateScanResult,
} from "../src/repository/scanner/index.js";

import {
  API_CALLABLE_FORMS,
  API_FRAMEWORKS,
  API_GRAPH_EDGE_TYPES,
  API_GRAPH_EDGE_TYPE_VALUES,
  API_GRAPH_LIMITS,
  API_GRAPH_STATES,
  API_GRAPH_STATE_VALUES,
  API_GRAPH_VERSION,
  API_PROBLEM_REASONS,
  API_RECEIVER_KINDS,
  API_ROUTE_METHODS,
  API_SHAPE_REASONS as MODEL_SHAPE_REASONS,
  API_SOURCE_STATUSES as MODEL_SOURCE_STATUSES,
  API_UNSUPPORTED_FRAMEWORKS,
  API_UNRESOLVED_KINDS,
  API_UNRESOLVED_REASONS,
  API_UNRESOLVED_REASON_VALUES,
  COVERAGE_GUARANTEES,
  RepositoryQueryError,
  apiGraphState,
  apiRouteIdOf,
  buildRepositoryModel,
  createRepositoryQuery,
  isApiSourceEstablished,
  isEstablishedApiState,
  validateRepositoryModelGraph,
} from "../src/repository/model/index.js";

import {
  buildAnalysisContext,
  createAnalyzerEngine,
  createAnalyzerRegistry,
} from "../src/analysis/index.js";

import {
  API_ANALYZER_ID,
  API_ANALYZER_SCOPE,
  API_BASIS,
  API_CONFIDENCE,
  API_DESCRIBED_EDGE_TYPES,
  API_DESCRIBED_UNRESOLVED_REASONS,
  API_EDGE_TYPE_WORDING,
  API_RULE_IDS,
  API_UNRESOLVED_REASON_WORDING,
  MAX_API_FINDINGS,
  RULE_OUTCOME_STATUSES,
  apiAbsence,
  apiCoverage,
  apiRoutes,
  apiRuleSetIssues,
  apiRules,
  apiUnresolved,
  createApiAnalyzer,
  createApiRuleRegistry,
  createRuleEngine,
} from "../src/rules/index.js";

// ─── Fixtures ────────────────────────────────────────────────────────────────

const TMP_ROOT = join(tmpdir(), `cg-api-${process.pid}-${Date.now()}`);
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
    established = true,
    frameworks = ["express"],
    unsupportedFrameworks = [],
    receivers = [{ name: "app", framework: "express", supported: true, kind: "app" }],
    routes = [],
    shapes = [],
    problems = [],
    truncated = false,
    bytesInspected = 120,
    counts,
  } = options;
  const extension = path.slice(path.lastIndexOf("."));
  return {
    path,
    extension,
    language: extension === ".ts" ? "typescript" : "javascript",
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
      counts ?? { tokens: 20, routes: routes.length, shapes: shapes.length, receivers: receivers.length },
  };
}

/** A validated ScanResult literal carrying only an `api` section. */
function scanLiteral({ sources = [], complete = false, truncated = false, scanComplete = true } = {}) {
  const sorted = [...sources].sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  const files = sorted.map((source) => ({
    path: source.path,
    name: source.path.slice(source.path.lastIndexOf("/") + 1),
    extension: source.extension,
    depth: source.path.split("/").length,
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
        .map((path) => ({ path, name: path.slice(path.lastIndexOf("/") + 1), depth: path.split("/").length })),
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
      api: { inspected: sorted.length > 0, complete, truncated, files: sorted, limits: {} },
      scan: { complete: scanComplete, truncated },
    }),
  );
}

function modelOf(input) {
  const model = buildRepositoryModel(scanLiteral(input));
  return { model, query: createRepositoryQuery(model) };
}

const graphOf = (input) => modelOf(input).model.api.graph;
const clone = (value) => JSON.parse(JSON.stringify(value));
const edgeTypesOf = (graph) => [...new Set(graph.edges.map((edge) => edge.type))].sort();

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

// ─── Real-repository fixtures ────────────────────────────────────────────────

const fullRepo = () => ({
  "package.json": packageJson(),
  "src/app.js": [
    'import express from "express";',
    'import { listUsers, createUser, auth } from "./users.js";',
    "const app = express();",
    "const router = express.Router();",
    "app.get(\"/users\", listUsers);",
    "app.post(\"/users\", auth, createUser);",
    "app.get(\"/health\", (req, res) => res.end());",
    "app.get(\"/missing\", notDeclaredFn);",
    "app.get(path, handler);",
    "app.route(\"/teams\").get(listUsers).post(createUser);",
    "router.delete(\"/users/:id\", controller.remove);",
    'cache.get("/not-a-route");',
    "export default app;",
    "",
  ].join("\n"),
  "src/users.js": [
    "export function listUsers() {}",
    "export function createUser() {}",
    "export function auth() {}",
    "",
  ].join("\n"),
  "src/fast.js": [
    'import fastify from "fastify";',
    "const server = fastify({ logger: true });",
    'server.put("/things/:id", update);',
    "function update() {}",
    "",
  ].join("\n"),
});

const unsupportedFrameworkRepo = () => ({
  "package.json": packageJson(),
  "src/koa.js": [
    'import Koa from "koa";',
    "const app = new Koa();",
    'app.get("/koa-route", handler);',
    "function handler() {}",
    "",
  ].join("\n"),
});

const tsxOnlyRepo = () => ({
  "package.json": packageJson(),
  "src/component.tsx": "export function Widget() { return 1; }\n",
});

// ─── Acquisition ─────────────────────────────────────────────────────────────

describe("api acquisition (real repositories)", () => {
  it("records express routes and their resolved handlers", async () => {
    const { model } = await scanOf(fullRepo());
    const byId = new Map(model.api.graph.nodes.map((node) => [node.id, node]));

    assert.equal(byId.has("route:GET:/users"), true);
    assert.equal(byId.has("route:POST:/users"), true);
    assert.equal(byId.has("route:GET:/health"), true);
    assert.equal(byId.has("route:GET:/teams"), true);
    assert.equal(byId.has("route:POST:/teams"), true);
    assert.deepEqual(byId.get("route:GET:/users").frameworks, ["express"]);
  });

  it("records a Fastify route", async () => {
    const { model } = await scanOf(fullRepo());
    const fast = model.api.graph.nodes.find((node) => node.id === "route:PUT:/things/:id");
    assert.ok(fast);
    assert.deepEqual(fast.frameworks, ["fastify"]);
  });

  it("records a nested router registered off express.Router()", async () => {
    const { model } = await scanOf(fullRepo());
    const nested = model.api.graph.nodes.find((node) => node.id === "route:DELETE:/users/:id");
    assert.ok(nested);
    assert.deepEqual(nested.receiverKinds, ["router"]);
  });

  it("walks a route chain into one route per chained method", async () => {
    const { model } = await scanOf(fullRepo());
    const chainIds = model.api.graph.nodes
      .filter((node) => node.path === "/teams")
      .map((node) => node.id)
      .sort();
    assert.deepEqual(chainIds, ["route:GET:/teams", "route:POST:/teams"]);
  });

  it("records every HTTP verb the scanner supports", () => {
    const source = [
      'import express from "express";',
      "const app = express();",
      'app.get("/a", h);',
      'app.post("/b", h);',
      'app.put("/c", h);',
      'app.patch("/d", h);',
      'app.delete("/e", h);',
      'app.head("/f", h);',
      'app.options("/g", h);',
      "function h() {}",
      "",
    ].join("\n");
    const scanned = scanApiRoutes(source, { extension: ".js" });
    assert.deepEqual(
      scanned.routes.map((entry) => `${entry.method} ${entry.path}`).sort(),
      ["DELETE /e", "GET /a", "HEAD /f", "OPTIONS /g", "PATCH /d", "POST /b", "PUT /c"],
    );
  });

  it("records an unsupported framework as an observation, never a route", async () => {
    const { model } = await scanOf(unsupportedFrameworkRepo());
    assert.deepEqual(model.api.graph.nodes, []);
    const records = model.api.graph.unresolved.filter((entry) => entry.kind === "route");
    assert.equal(records.length, 1);
    assert.equal(records[0].reason, API_UNRESOLVED_REASONS.FRAMEWORK_UNSUPPORTED);
    assert.equal(records[0].framework, "koa");
  });

  it("records a computed path as an observation", () => {
    const scanned = scanApiRoutes(
      'import express from "express";\nconst app = express();\napp.get("/a" + suffix, h);\napp.get(`/t/${x}`, h);\n',
      { extension: ".js" },
    );
    assert.deepEqual(scanned.routes, []);
    assert.deepEqual(
      scanned.shapes.map((shape) => shape.reason).sort(),
      [API_SHAPE_REASONS.PATH_COMPUTED, API_SHAPE_REASONS.PATH_CONCATENATED].sort(),
    );
  });

  it("refuses to read text inside a comment or string as a route", () => {
    const scanned = scanApiRoutes(
      [
        'import express from "express";',
        "const app = express();",
        '// app.get("/commented", h);',
        'const text = "app.get(\\"/string\\", h)";',
        "function h() {}",
        "",
      ].join("\n"),
      { extension: ".js" },
    );
    assert.deepEqual(scanned.routes, []);
    assert.deepEqual(scanned.shapes, []);
  });

  it("records the object shorthand as an observation", () => {
    const scanned = scanApiRoutes(
      'import express from "express";\nconst app = express();\napp.route({ method: "GET", url: "/x", handler: h });\n',
      { extension: ".js" },
    );
    assert.deepEqual(scanned.routes, []);
    assert.equal(scanned.shapes[0].reason, API_SHAPE_REASONS.SHORTHAND_NOT_ESTABLISHED);
  });
});

// ─── Graph ───────────────────────────────────────────────────────────────────

describe("api graph", () => {
  it("connects a route to its resolved handler symbol", async () => {
    const { model } = await scanOf(fullRepo());
    const edges = model.api.graph.edges.filter(
      (edge) => edge.from === "route:GET:/users" && edge.type === API_GRAPH_EDGE_TYPES.HANDLED_BY,
    );
    assert.equal(edges.length, 1);
    assert.equal(edges[0].to, "symbol:src/app.js#listUsers");
  });

  it("connects a route to its middleware symbols", async () => {
    const { model } = await scanOf(fullRepo());
    const edge = model.api.graph.edges.find(
      (edge) => edge.from === "route:POST:/users" && edge.type === API_GRAPH_EDGE_TYPES.MIDDLEWARE,
    );
    assert.ok(edge);
    assert.equal(edge.to, "symbol:src/app.js#auth");
  });

  it("never duplicates a symbol node — handler edges point at the Phase 17 node", async () => {
    const { model } = await scanOf(fullRepo());
    const symbolIds = new Set(model.symbols.graph.nodes.map((node) => node.id));
    for (const edge of model.api.graph.edges) {
      if (edge.type === API_GRAPH_EDGE_TYPES.HANDLED_BY || edge.type === API_GRAPH_EDGE_TYPES.MIDDLEWARE) {
        assert.equal(symbolIds.has(edge.to), true, `${edge.to} must be a symbol node`);
      }
    }
    assert.equal(model.api.graph.nodes.some((node) => node.id.startsWith("symbol:")), false);
  });

  it("marks a member-access handler unresolved rather than resolving the controller", async () => {
    const { model } = await scanOf(fullRepo());
    const record = model.api.graph.unresolved.find(
      (entry) => entry.route === "route:DELETE:/users/:id" && entry.kind === "handler",
    );
    assert.equal(record.reason, API_UNRESOLVED_REASONS.MEMBER_EXPRESSION);
    assert.equal(record.name, "controller");
    assert.equal(record.member, "remove");
  });

  it("marks an inline handler unresolved", async () => {
    const { model } = await scanOf(fullRepo());
    const record = model.api.graph.unresolved.find(
      (entry) => entry.route === "route:GET:/health" && entry.kind === "handler",
    );
    assert.equal(record.reason, API_UNRESOLVED_REASONS.INLINE_HANDLER);
  });

  it("marks a handler name that is not a module-scope binding unresolved", async () => {
    const { model } = await scanOf(fullRepo());
    const record = model.api.graph.unresolved.find(
      (entry) => entry.route === "route:GET:/missing" && entry.kind === "handler",
    );
    assert.equal(record.reason, API_UNRESOLVED_REASONS.HANDLER_NOT_ESTABLISHED);
    assert.equal(record.name, "notDeclaredFn");
  });

  it("records a route whose receiver is not a framework registrar as an observation", async () => {
    const { model } = await scanOf(fullRepo());
    const record = model.api.graph.unresolved.find((entry) => entry.name === "cache");
    assert.equal(record.reason, API_UNRESOLVED_REASONS.RECEIVER_NOT_ESTABLISHED);
    assert.equal(model.api.graph.nodes.some((node) => node.path === "/not-a-route"), false);
  });

  it("merges two declarations of one endpoint into a single route node", () => {
    const graph = graphOf({
      sources: [
        apiSource("a.js", { routes: [route("GET", "/x")] }),
        apiSource("b.js", { routes: [route("GET", "/x")] }),
      ],
    });
    assert.equal(graph.nodes.length, 1);
    assert.deepEqual(graph.nodes[0].sourcePaths, ["a.js", "b.js"]);
  });

  it("declares every route from its declaring file", () => {
    const graph = graphOf({ sources: [apiSource("a.js", { routes: [route("GET", "/x")] })] });
    const declares = graph.edges.find((edge) => edge.type === API_GRAPH_EDGE_TYPES.DECLARES);
    assert.equal(declares.from, "file:a.js");
    assert.equal(declares.to, "route:GET:/x");
  });

  it("skips a source whose route set is not established", () => {
    const graph = graphOf({
      sources: [
        apiSource("a.js", { established: false, routes: [route("GET", "/x")] }),
      ],
    });
    assert.deepEqual(graph.nodes, []);
    assert.equal(graph.coverage.unestablished, 1);
  });
});

// ─── Coverage ────────────────────────────────────────────────────────────────

describe("api coverage", () => {
  it("reports complete only when every source established its route set", () => {
    const graph = graphOf({
      sources: [apiSource("a.js", { routes: [route("GET", "/x")] })],
      complete: true,
      scanComplete: true,
    });
    assert.equal(graph.state, API_GRAPH_STATES.COMPLETE);
    assert.equal(graph.established, true);
    assert.equal(graph.coverage.complete, true);
  });

  it("reports partial when a source establishes its route set only partly", () => {
    const graph = graphOf({
      sources: [apiSource("a.js", { established: false })],
      complete: false,
      scanComplete: true,
    });
    assert.equal(graph.state, API_GRAPH_STATES.PARTIAL);
    assert.equal(graph.coverage.unestablished, 1);
  });

  it("reports truncated when a bound bit", () => {
    const graph = graphOf({
      sources: [apiSource("a.js", { truncated: true })],
      truncated: true,
      scanComplete: false,
    });
    assert.equal(graph.state, API_GRAPH_STATES.TRUNCATED);
    assert.equal(graph.coverage.truncated, true);
  });

  it("reports unsupported for a JSX/TSX-only repository", async () => {
    const { model } = await scanOf(tsxOnlyRepo());
    assert.equal(model.api.graph.state, API_GRAPH_STATES.UNSUPPORTED);
    assert.equal(model.api.graph.established, false);
  });

  it("reports unknown when nothing established a graph at all", () => {
    const graph = graphOf({ sources: [], scanComplete: false });
    assert.equal(graph.state, API_GRAPH_STATES.UNKNOWN);
    assert.equal(graph.established, false);
  });

  it("reports complete for a genuinely empty but scanned repository", () => {
    const graph = graphOf({ sources: [], scanComplete: true });
    assert.equal(graph.state, API_GRAPH_STATES.COMPLETE);
    assert.deepEqual(graph.nodes, []);
  });

  it("keeps the graph state values as the documented five", () => {
    assert.deepEqual([...API_GRAPH_STATE_VALUES].sort(), [
      "complete",
      "partial",
      "truncated",
      "unknown",
      "unsupported",
    ]);
    assert.equal(isEstablishedApiState(API_GRAPH_STATES.COMPLETE), true);
    assert.equal(isEstablishedApiState(API_GRAPH_STATES.UNKNOWN), false);
  });

  it("agrees with the pure state function", () => {
    assert.equal(
      apiGraphState({ sources: [], scanComplete: false, scanTruncated: false, hasScanState: false }),
      API_GRAPH_STATES.UNKNOWN,
    );
    assert.equal(
      apiGraphState({
        sources: [],
        scanComplete: true,
        scanTruncated: false,
        hasScanState: true,
        uninterpretedSources: 3,
      }),
      API_GRAPH_STATES.UNSUPPORTED,
    );
  });
});

// ─── Query API ───────────────────────────────────────────────────────────────

describe("api query surface", () => {
  const queryOf = async (files) => (await scanOf(files)).query;

  it("answers apiGraph, routes and routeByPath consistently", async () => {
    const query = await queryOf(fullRepo());
    const graph = query.apiGraph();
    const routes = query.routes();
    assert.equal(graph.nodes.length, routes.routes.length);
    const lookup = query.routeByPath("GET", "/users");
    assert.equal(lookup.route.id, "route:GET:/users");
    assert.equal(lookup.coverage, COVERAGE_GUARANTEES.COMPLETE);
  });

  it("answers handlersForRoute, middlewareForRoute and routesForHandler", async () => {
    const query = await queryOf(fullRepo());
    const handlers = query.handlersForRoute("route:GET:/users");
    assert.equal(handlers.handlers[0].symbol.id, "symbol:src/app.js#listUsers");

    const middleware = query.middlewareForRoute("route:POST:/users");
    assert.equal(middleware.middleware[0].symbol.id, "symbol:src/app.js#auth");

    const routes = query.routesForHandler("symbol:src/app.js#listUsers");
    assert.deepEqual(
      routes.routes.map((entry) => entry.id).sort(),
      ["route:GET:/teams", "route:GET:/users"],
    );
  });

  it("answers services as the modules that declare a resolved handler", async () => {
    const query = await queryOf(fullRepo());
    const services = query.services();
    // The handler symbol is the imported binding in the declaring module, so the
    // handler module is the route file, not the module the binding points at.
    const paths = services.modules.map((entry) => entry.path);
    assert.equal(paths.includes("src/app.js"), true);
    assert.equal(services.modules.every((entry) => entry.handlerCount > 0), true);
  });

  it("answers unresolvedRoutes from the graph's own observations", async () => {
    const query = await queryOf(fullRepo());
    const unresolved = query.unresolvedRoutes();
    assert.equal(unresolved.unresolved.some((record) => record.name === "cache"), true);
    assert.equal(unresolved.unresolved.every((record) => record.kind === "route"), true);
  });

  it("returns frozen results", async () => {
    const query = await queryOf(fullRepo());
    const graph = query.apiGraph();
    assert.equal(Object.isFrozen(graph), true);
    assert.equal(Object.isFrozen(graph.nodes), true);
    assert.equal(Object.isFrozen(graph.nodes[0]), true);
    assert.equal(Object.isFrozen(query.routes().routes), true);
  });

  it("rejects an unknown route method and an invalid criterion", async () => {
    const query = await queryOf(fullRepo());
    assert.throws(() => query.routeByPath("FETCH", "/users"), RepositoryQueryError);
    assert.throws(() => query.routes({ method: "FETCH" }), RepositoryQueryError);
    assert.throws(() => query.routes({ nope: 1 }), RepositoryQueryError);
  });

  it("treats an unknown route lookup as an ordinary miss", async () => {
    const query = await queryOf(fullRepo());
    const lookup = query.routeByPath("GET", "/does-not-exist");
    assert.equal(lookup.route, null);
  });

  it("is deterministic across two identical scans", async () => {
    const first = await queryOf(fullRepo());
    const second = await queryOf(fullRepo());
    assert.deepEqual(first.apiGraph().nodes, second.apiGraph().nodes);
    assert.deepEqual(first.apiGraph().edges, second.apiGraph().edges);
    assert.deepEqual(first.services().modules, second.services().modules);
  });
});

// ─── Contract & validation ───────────────────────────────────────────────────

describe("api contract", () => {
  it("pins every model vocabulary against the scanner's", () => {
    assert.deepEqual([...API_FRAMEWORKS].sort(), Object.values(SCANNER_FRAMEWORKS).sort());
    assert.deepEqual([...API_ROUTE_METHODS].sort(), [...SCANNER_ROUTE_METHODS].sort());
    assert.deepEqual([...API_RECEIVER_KINDS].sort(), ["app", "router"]);
    assert.deepEqual([...API_CALLABLE_FORMS].sort(), ["inline", "reference"]);
    assert.deepEqual([...MODEL_SHAPE_REASONS].sort(), Object.values(API_SHAPE_REASONS).sort());
    assert.deepEqual([...API_PROBLEM_REASONS].sort(), Object.values(API_PROBLEMS).sort());
    assert.deepEqual([...MODEL_SOURCE_STATUSES].sort(), Object.values(API_SOURCE_STATUSES).sort());
    assert.deepEqual(
      [...API_UNSUPPORTED_FRAMEWORKS].sort(),
      [...new Set(Object.values(SCANNER_UNSUPPORTED_FRAMEWORKS))].sort(),
    );
    assert.deepEqual(
      API_HTTP_METHODS.map((method) => method.toUpperCase()).sort(),
      [...API_ROUTE_METHODS].sort(),
    );
  });

  it("keeps the api area required by the Core model contract", async () => {
    const { model } = await scanOf(fullRepo());
    assert.equal(typeof model.api.detected, "boolean");
    assert.equal(model.api.count, model.api.entries.length);
    assert.equal(model.api.graph.version, API_GRAPH_VERSION);
  });

  it("rejects a malformed graph node", async () => {
    const { model } = await scanOf(fullRepo());
    const tampered = clone(model);
    // Change the node's *path* while leaving its id in order, so only the id-vs-identity
    // invariant can reject it: the sorted check cannot.
    tampered.api.graph.nodes[0].path = "/forged";
    assert.throws(() => validateRepositoryModelGraph(tampered), ValidationError);
  });

  it("rejects a route edge that names a symbol the symbol graph does not carry", async () => {
    const { model } = await scanOf(fullRepo());
    const tampered = clone(model);
    const edge = tampered.api.graph.edges.find((entry) => entry.type === "handled-by");
    edge.to = "symbol:src/ghost.js#nobody";
    assert.throws(() => validateRepositoryModelGraph(tampered), ValidationError);
  });

  it("rejects a duplicate route node", async () => {
    const { model } = await scanOf(fullRepo());
    const tampered = clone(model);
    tampered.api.graph.nodes.push(tampered.api.graph.nodes[0]);
    // A duplicate changes the count the coverage claims, so validation must fail.
    assert.throws(() => validateRepositoryModelGraph(tampered), ValidationError);
  });

  it("rejects a coverage count that disagrees with the graph", async () => {
    const { model } = await scanOf(fullRepo());
    const tampered = clone(model);
    tampered.api.graph.coverage.routes += 1;
    assert.throws(() => validateRepositoryModelGraph(tampered), ValidationError);
  });

  it("rejects an unsorted node list", async () => {
    const { model } = await scanOf(fullRepo());
    const tampered = clone(model);
    tampered.api.graph.nodes.reverse();
    assert.throws(() => validateRepositoryModelGraph(tampered), ValidationError);
  });

  it("rejects an unknown unresolved reason", () => {
    // The projection trusts only closed vocabularies, so a tampered graph carrying a
    // made-up reason must fail model validation rather than become a finding.
    const { model } = modelOf({ sources: [apiSource("a.js")] });
    const tampered = clone(model);
    tampered.api.graph.unresolved.push({
      path: "a.js",
      kind: "route",
      reason: "made-up",
      name: "x",
      member: null,
      method: "GET",
      route: "route:GET:/x",
      framework: null,
      evidenceId: null,
      count: 1,
    });
    // Keep the count in agreement so only the reason vocabulary rejects it.
    tampered.api.graph.coverage.unresolved += 1;
    tampered.api.coverage.unresolved += 1;
    assert.throws(() => validateRepositoryModelGraph(tampered), ValidationError);
  });

  it("declares exactly the documented edge vocabulary", () => {
    assert.deepEqual([...API_GRAPH_EDGE_TYPE_VALUES].sort(), ["declares", "handled-by", "middleware"]);
    assert.deepEqual([...API_UNRESOLVED_KINDS].sort(), ["handler", "middleware", "route"]);
    assert.equal(API_UNRESOLVED_REASON_VALUES.includes(API_UNRESOLVED_REASONS.MEMBER_EXPRESSION), true);
    assert.equal(API_GRAPH_LIMITS.MAX_ROUTES > 0, true);
  });

  it("builds a route identity that is stable and content-free", () => {
    assert.equal(apiRouteIdOf("GET", "/users"), "route:GET:/users");
    const graph = graphOf({ sources: [apiSource("a.js", { routes: [route("GET", "/users")] })] });
    assert.equal(graph.nodes[0].id, apiRouteIdOf("GET", "/users"));
  });

  it("treats only a parsed, established source as establishing its routes", () => {
    assert.equal(isApiSourceEstablished({ status: "parsed", established: true }), true);
    assert.equal(isApiSourceEstablished({ status: "parsed", established: false }), false);
    assert.equal(isApiSourceEstablished({ status: "unsupported", established: false }), false);
  });
});

// ─── Rule pack and analyzer ──────────────────────────────────────────────────

describe("api rule pack", () => {
  const runOf = async (files) => {
    const { model } = await scanOf(files);
    const engine = createRuleEngine({ registry: createApiRuleRegistry({ rules: apiRules }) });
    return { model, run: await engine.runAll(contextOf(model)) };
  };
  const runOfModel = async (model) => {
    const engine = createRuleEngine({ registry: createApiRuleRegistry({ rules: apiRules }) });
    return engine.runAll(contextOf(model));
  };
  const inventoryOf = (run) => run.rules.find((entry) => entry.rule.id === API_RULE_IDS.GRAPH_INVENTORY);

  it("declares its rule in the pack namespace", () => {
    assert.deepEqual(apiRuleSetIssues(apiRules), []);
    assert.equal(API_RULE_IDS.GRAPH_INVENTORY.startsWith("api."), true);
    assert.deepEqual(
      apiRules.map((rule) => rule.id),
      [API_RULE_IDS.GRAPH_INVENTORY],
    );
    assert.equal(apiRules[0].severity, "info");
    assert.deepEqual(apiRules[0].applicability, {});
    assert.equal(typeof apiRules[0].detect, "function");
  });

  it("refuses a rule set that leaves the pack contract", () => {
    assert.deepEqual(apiRuleSetIssues("nope"), ["apiRules: must be an array of rules"]);
    assert.equal(apiRuleSetIssues([{ id: "security.analysis.dependencies" }]).length > 0, true);
    assert.equal(apiRuleSetIssues([]).length > 0, true);
    assert.equal(
      apiRuleSetIssues([apiRules[0], apiRules[0]]).some((issue) => issue.includes("twice")),
      true,
    );
    assert.throws(() => createApiRuleRegistry({ rules: [] }), Error);
  });

  it("describes every value of every vocabulary the graph can state", () => {
    assert.deepEqual([...API_DESCRIBED_EDGE_TYPES].sort(), [...API_GRAPH_EDGE_TYPE_VALUES].sort());
    assert.deepEqual(
      [...API_DESCRIBED_UNRESOLVED_REASONS].sort(),
      [...API_UNRESOLVED_REASON_VALUES].sort(),
    );
  });

  it("reports one finding per established endpoint", async () => {
    const { run } = await runOf(fullRepo());
    const inventory = inventoryOf(run);
    assert.equal(inventory.metadata.established, true);
    assert.equal(inventory.findings.length > 0, true);
    for (const finding of inventory.findings) {
      assert.equal(finding.severity, "info");
      assert.equal(finding.metadata.basis, API_BASIS);
      assert.equal(finding.confidence, API_CONFIDENCE.OBSERVED_ENDPOINT);
      assert.equal(finding.evidence.length > 0, true);
      assert.equal(finding.description.includes("says nothing about whether the route is reachable"), true);
    }
  });

  it("offers no authentication, quality or missing-middleware verdict", async () => {
    const { run } = await runOf(fullRepo());
    for (const finding of inventoryOf(run).findings) {
      assert.equal(finding.severity, "info");
      const text = `${finding.description} ${JSON.stringify(finding.metadata)}`.toLowerCase();
      for (const banned of ["is insecure", "should require", "missing middleware", "quality score", "vulnerab"]) {
        assert.equal(text.includes(banned), false, `must not judge: ${banned}`);
      }
    }
  });

  it("reports route-shaped occurrences as metadata, never as findings", async () => {
    const { run } = await runOf(fullRepo());
    const inventory = inventoryOf(run);
    assert.equal(inventory.metadata.unresolved.count > 0, true);
    assert.equal(
      inventory.findings.some((finding) => finding.metadata.route === "route:GET:/not-a-route"),
      false,
    );
  });

  it("caps a large API and says so", () => {
    const routes = [];
    for (let index = 0; index < MAX_API_FINDINGS + 5; index += 1) {
      routes.push(route("GET", `/r/${index}`));
    }
    const { model } = modelOf({ sources: [apiSource("a.js", { routes })], complete: true, scanComplete: true });
    return runOfModel(model).then((run) => {
      const inventory = inventoryOf(run);
      assert.equal(inventory.findings.length, MAX_API_FINDINGS);
      assert.equal(inventory.metadata.capped, true);
    });
  });

  it("produces deterministic, uniquely fingerprinted findings", async () => {
    const first = await runOf(fullRepo());
    const second = await runOf(fullRepo());
    const engine = createAnalyzerEngine({ registry: createAnalyzerRegistry([createApiAnalyzer()]) });
    const analyzed = await engine.runAll(contextOf(first.model));
    assert.equal(new Set(analyzed.findings.map((finding) => finding.fingerprint)).size, analyzed.findings.length);
    assert.deepEqual(
      inventoryOf(first.run).findings.map((finding) => finding.metadata.fingerprintKey),
      inventoryOf(second.run).findings.map((finding) => finding.metadata.fingerprintKey),
    );
  });

  it("runs as an ordinary analyzer over the accepted framework", async () => {
    const { model } = await scanOf(fullRepo());
    const engine = createAnalyzerEngine({ registry: createAnalyzerRegistry([createApiAnalyzer()]) });
    const result = await engine.runAll(contextOf(model));
    assert.equal(result.analyzers.length, 1);
    assert.equal(result.analyzers[0].analyzer.id, API_ANALYZER_ID);
    assert.equal(result.analyzers[0].analyzer.scope, API_ANALYZER_SCOPE);
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

  it("exposes coverage and absence through the signal helpers", async () => {
    const { query } = await scanOf(fullRepo());
    const coverage = apiCoverage(query);
    assert.equal(coverage.state, API_GRAPH_STATES.COMPLETE);
    assert.equal(apiRoutes(query).length > 0, true);
    assert.equal(apiUnresolved(query).length > 0, true);
    assert.equal(apiAbsence(query).established, true);
  });

  it("reads the graph only through the query API", () => {
    const source = readFileSync(repoFile("src/rules/api/signals.js"), "utf8");
    const packFiles = [
      "src/rules/api/contracts.js",
      "src/rules/api/signals.js",
      "src/rules/api/registry.js",
      "src/rules/api/analyzer.js",
      "src/rules/api/index.js",
      "src/rules/api/rules/index.js",
      "src/rules/api/rules/inventory.js",
    ];
    for (const file of packFiles) {
      const text = readFileSync(repoFile(file), "utf8");
      // Only the import/export lines matter: a doc comment may name a module it forbids.
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
      ]) {
        assert.equal(statements.includes(forbidden), false, `${file} must not import ${forbidden}`);
      }
    }
    assert.equal(source.includes("createRepositoryQuery"), true);
  });
});

// ─── Security ────────────────────────────────────────────────────────────────

describe("api security", () => {
  it("introduces no server, request or process capability in the projection", () => {
    const text = readFileSync(repoFile("src/repository/model/api-graph.js"), "utf8");
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
    ]) {
      assert.equal(text.includes(forbidden), false, `api-graph.js must not reference ${forbidden}`);
    }
  });

  it("leaks no absolute host path through the graph", async () => {
    const { model } = await scanOf(fullRepo());
    for (const value of stringsIn(model.api.graph)) {
      assert.equal(value.includes(TMP_ROOT), false, `host path leaked: ${value}`);
      assert.equal(/^[A-Za-z]:\\/.test(value), false, `drive path leaked: ${value}`);
    }
  });

  it("never reads through a symlink that escapes the repository root", async () => {
    // The API detector reads module sources through the Phase 8A boundary, so the
    // boundary's own no-follow policy applies unchanged; a symlink target is never read.
    const root = makeRepo({ "src/app.js": 'const x = 1;\n' });
    writeFileSync(join(root, "escape.js"), "export const y = 2;\n");
    const model = buildRepositoryModel(await scanRepository(root));
    const paths = model.api.graph.nodes.flatMap((node) => node.sourcePaths);
    assert.equal(paths.every((path) => !path.startsWith("/")), true);
  });

  it("exposes no raw scanner error, stack or cause through the graph", async () => {
    const { model } = await scanOf(fullRepo());
    const json = JSON.stringify(model.api.graph);
    assert.equal(json.includes("\"stack\""), false);
    assert.equal(json.includes("\"cause\""), false);
    assert.equal(json.includes(model.identity.root), false);
  });

  it("keeps the acquisition bounds explicit", () => {
    assert.equal(API_ACQUISITION_LIMITS.maxFiles > 0, true);
    assert.equal(API_ACQUISITION_LIMITS.maxFileBytes > 0, true);
    assert.equal(API_ACQUISITION_LIMITS.maxRoutesPerFile > 0, true);
    assert.equal(API_ACQUISITION_LIMITS.maxChainMethods > 0, true);
  });

  it("validates the api section of a ScanResult", () => {
    const bad = createScanResult({
      root: "/repo",
      scannedAt: "2026-01-01T00:00:00.000Z",
      api: { inspected: true, complete: true, truncated: false, files: [{ path: "/abs.js" }] },
    });
    assert.throws(() => validateScanResult(bad), Error);
  });

  it("reconciles the model source-reason vocabulary with the scanner's", () => {
    assert.deepEqual(
      [...MODEL_SOURCE_STATUSES].sort(),
      Object.values(API_SOURCE_STATUSES).sort(),
    );
    assert.equal(Object.values(API_SOURCE_REASONS).sort().includes("unreadable"), true);
  });
});
