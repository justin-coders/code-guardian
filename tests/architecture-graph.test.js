/**
 * Code Guardian — Architecture Graph Tests (Phase 15)
 *
 * Two fixture styles, chosen deliberately:
 *
 *   - **real repositories** written to a temporary directory and scanned through the
 *     accepted Phase 8A boundary, Phase 8C scanner, Phase 8D model builder and
 *     Phase 15 projection, so the inventory, the model and the graph agree end to end.
 *     This is the only way to prove that what the repository establishes is what the
 *     graph exposes.
 *   - **hand-built ScanResults and models** for states a real scan cannot reach on
 *     demand (a scan that never finished, a model that predates the projection) and for
 *     tampering, so the fail-closed behaviour of the graph contract can be stated
 *     exactly.
 *
 * No test spawns a process, contacts a network, installs a package or writes to the
 * repository under test.
 *
 * Run with: node --test tests/architecture-graph.test.js
 */

import { after, describe, it } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { ValidationError } from "../src/core/index.js";

import { createScanResult, scanRepository, validateScanResult } from "../src/repository/scanner/index.js";

import {
  ARCHITECTURE_EDGE_TYPES,
  ARCHITECTURE_EDGE_TYPE_VALUES,
  ARCHITECTURE_GRAPH_LIMITS,
  ARCHITECTURE_GRAPH_STATES,
  ARCHITECTURE_GRAPH_STATE_VALUES,
  ARCHITECTURE_GRAPH_VERSION,
  ARCHITECTURE_NODE_KINDS,
  COVERAGE_GUARANTEES,
  ENTITY_KINDS,
  REPOSITORY_NODE_KIND,
  RepositoryQueryError,
  buildRepositoryModel,
  createRepositoryQuery,
  validateRepositoryModelGraph,
} from "../src/repository/model/index.js";

import {
  buildAnalysisContext,
  createAnalyzerEngine,
  createAnalyzerRegistry,
} from "../src/analysis/index.js";
import {
  ARCHITECTURE_ANALYZER_ID,
  ARCHITECTURE_ANALYZER_SCOPE,
  ARCHITECTURE_BASIS,
  ARCHITECTURE_DESCRIBED_EDGE_TYPES,
  ARCHITECTURE_RULE_IDS,
  EDGE_WORDING,
  MAX_ARCHITECTURE_FINDINGS,
  RULE_OUTCOME_STATUSES,
  architectureAbsence,
  architectureCoverage,
  architectureRelationships,
  architectureRuleSetIssues,
  architectureRules,
  createArchitectureAnalyzer,
  createArchitectureRuleRegistry,
  createRuleEngine,
} from "../src/rules/index.js";

// ─── Fixtures ────────────────────────────────────────────────────────────────

const TMP_ROOT = join(tmpdir(), `cg-arch-${process.pid}-${Date.now()}`);
let counter = 0;

/** Write a repository into a temporary directory and return its root. */
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

/** Scan a repository and build its model, returning both plus a query handle. */
async function scanModel(root) {
  const scan = await scanRepository(root);
  const model = buildRepositoryModel(scan);
  return { scan, model, query: createRepositoryQuery(model) };
}

const scanOf = (files) => scanModel(makeRepo(files));
const contextOf = (model) => buildAnalysisContext({ repository: model });
const repositoryNodeOf = (model) => model.identity.repositoryId;
const node = (name) => `dependency:node:${name}`;

const packageJson = (value) => JSON.stringify(value, null, 2);

/**
 * A repository that exercises every relationship the graph can state.
 *
 * `docker-compose.yml` declares two builds: one from the repository root (which has no
 * directory entity, so the repository node stands in) and one nested. `jest.config.js`
 * makes the `jest` framework observed, and `package.json` declares a *dependency* also
 * called `jest` — the graph must keep those two facts apart.
 */
const fullRepo = () => ({
  "package.json": packageJson({
    name: "demo",
    dependencies: { express: "^4.0.0" },
    devDependencies: { jest: "^29.0.0" },
  }),
  "src/app.js": "export const a = 1;\n",
  "src/app.test.js": "test('a', () => {});\n",
  "src/Dockerfile": "FROM node:20\n",
  Dockerfile: "FROM node:20\n",
  "web/Dockerfile": "FROM node:20\n",
  "web/index.js": "1;\n",
  "docker-compose.yml":
    "services:\n  root:\n    build:\n      context: .\n      dockerfile: Dockerfile\n  web:\n    build: ./web\n",
  "jest.config.js": "module.exports = {};\n",
  ".github/workflows/ci.yml": "name: ci\n",
  "README.md": "# demo\n",
  "tsconfig.json": "{}\n",
});

/** A repository whose Compose build declaration cannot be established. */
const ambiguousComposeRepo = () => ({
  "Dockerfile": "FROM node:20\n",
  "docker-compose.yml":
    "services:\n  web:\n    build:\n      context: ./src\n      dockerfile: ../Dockerfile\n",
  "src/index.js": "1;\n",
});

const edgeOf = (graph, type, from, to) =>
  graph.edges.find((edge) => edge.type === type && edge.from === from && edge.to === to);

// ─── Construction ────────────────────────────────────────────────────────────

describe("architecture graph: construction", () => {
  it("projects the repository node and every architectural entity to one node each", async () => {
    const { model } = await scanOf(fullRepo());
    const graph = model.architecture.graph;
    const entityIds = Object.keys(model.indexes.entitiesById).sort();

    assert.equal(graph.version, ARCHITECTURE_GRAPH_VERSION);
    assert.equal(graph.state, ARCHITECTURE_GRAPH_STATES.COMPLETE);
    assert.equal(graph.established, true);
    assert.deepEqual(
      model.architecture.detected,
      true,
      "an inventory with entities is detected",
    );

    const nodeIds = graph.nodes.map((entry) => entry.id);
    assert.deepEqual(nodeIds, [...nodeIds].sort(), "nodes are sorted by id");
    const repositoryNode = graph.nodes.find((entry) => entry.id === repositoryNodeOf(model));
    assert.deepEqual(repositoryNode, {
      id: repositoryNodeOf(model),
      kind: REPOSITORY_NODE_KIND,
      name: null,
      path: null,
    });
    for (const entityId of entityIds) {
      const entity = model.indexes.entitiesById[entityId];
      if (!ARCHITECTURE_NODE_KINDS.includes(entity.kind)) continue;
      assert.ok(nodeIds.includes(entityId), `${entityId} must be a graph node`);
    }
  });

  it("keeps classifications and the git entity out of the architecture nodes", async () => {
    const { model } = await scanOf(fullRepo());
    const kinds = new Set(model.architecture.graph.nodes.map((entry) => entry.kind));

    assert.equal(kinds.has("language"), false, "a language is a classification, not a component");
    assert.equal(kinds.has("ecosystem"), false, "an ecosystem is a classification");
    assert.equal(kinds.has("git"), false, "the repository is one git entity, not a component");
    for (const kind of kinds) {
      assert.ok(
        kind === REPOSITORY_NODE_KIND || ARCHITECTURE_NODE_KINDS.includes(kind),
        `undocumented node kind "${kind}"`,
      );
    }
  });

  it("states containment once, from the container to the child", async () => {
    const { model } = await scanOf(fullRepo());
    const graph = model.architecture.graph;
    const repositoryId = repositoryNodeOf(model);

    assert.ok(
      edgeOf(graph, ARCHITECTURE_EDGE_TYPES.CONTAINS, repositoryId, "file:src/app.js") === undefined,
      "a nested file is contained by its directory, not by the repository",
    );
    assert.ok(
      edgeOf(graph, ARCHITECTURE_EDGE_TYPES.CONTAINS, "directory:src", "file:src/app.js") !== undefined,
    );
    assert.ok(
      edgeOf(graph, ARCHITECTURE_EDGE_TYPES.CONTAINS, repositoryId, "file:Dockerfile") !== undefined,
      "a root-level entity is contained by the repository node",
    );
    assert.ok(
      edgeOf(graph, ARCHITECTURE_EDGE_TYPES.CONTAINS, repositoryId, "directory:src") !== undefined,
    );
    assert.ok(
      edgeOf(graph, ARCHITECTURE_EDGE_TYPES.CONTAINS, "directory:web", "file:web/index.js") !== undefined,
    );

    // One fact, one direction: the model's `located_in` / `parent` statements are not
    // repeated as graph edges in the other direction.
    for (const edge of graph.edges) {
      assert.equal(
        ARCHITECTURE_EDGE_TYPE_VALUES.includes(edge.type),
        true,
        `undocumented edge type "${edge.type}"`,
      );
      assert.notEqual(edge.type, "located_in");
      assert.notEqual(edge.type, "parent");
    }
  });

  it("traces a containment edge to the child's own observations", async () => {
    const { model } = await scanOf(fullRepo());
    const graph = model.architecture.graph;
    const repositoryId = repositoryNodeOf(model);
    const edge = edgeOf(graph, ARCHITECTURE_EDGE_TYPES.CONTAINS, repositoryId, "file:package.json");
    const child = model.indexes.entitiesById["file:package.json"];

    assert.deepEqual(edge.evidenceIds, child.evidenceIds);
    assert.deepEqual(edge.sourcePaths, ["package.json"]);
    assert.deepEqual(edge.services, []);
  });

  it("records one declares-dependency edge per manifest declaration, with its observation", async () => {
    const { model } = await scanOf(fullRepo());
    const graph = model.architecture.graph;

    const express = edgeOf(
      graph,
      ARCHITECTURE_EDGE_TYPES.DECLARES_DEPENDENCY,
      "manifest:package.json",
      node("express"),
    );
    assert.ok(express !== undefined);
    assert.deepEqual(express.sourcePaths, ["package.json"]);

    const dependency = model.indexes.entitiesById[node("express")];
    assert.deepEqual(express.evidenceIds, dependency.declarations[0].evidenceIds);
  });

  it("connects a test artifact to the framework it reported using", async () => {
    const { model } = await scanOf(fullRepo());
    const graph = model.architecture.graph;
    const edge = edgeOf(
      graph,
      ARCHITECTURE_EDGE_TYPES.FRAMEWORK,
      "test:jest.config.js",
      "framework:jest",
    );

    assert.ok(edge !== undefined, "a test configuration reports its framework");
    assert.deepEqual(edge.sourcePaths, ["jest.config.js"]);
    assert.deepEqual(edge.evidenceIds, model.indexes.entitiesById["test:jest.config.js"].evidenceIds);
  });

  it("never links a declared framework package to the framework entity", async () => {
    const { model } = await scanOf(fullRepo());
    const graph = model.architecture.graph;

    // `package.json` declares a dependency named `jest` and a test artifact reports the
    // `jest` framework. Matching them by name would be a guess about tooling, so the
    // graph keeps both facts separate and connects neither.
    assert.ok(model.indexes.entitiesById[node("jest")] !== undefined);
    assert.ok(model.indexes.entitiesById["framework:jest"] !== undefined);
    assert.equal(
      graph.edges.some((edge) => edge.from === node("jest") || edge.to === "framework:jest"
        ? edge.from === node("jest")
        : false),
      false,
    );
    assert.equal(
      graph.edges.some(
        (edge) => edge.type === ARCHITECTURE_EDGE_TYPES.FRAMEWORK && edge.to === node("jest"),
      ),
      false,
    );
    assert.equal(
      graph.edges.some((edge) => edge.from === "dependency:node:jest" && edge.type === ARCHITECTURE_EDGE_TYPES.FRAMEWORK),
      false,
    );
  });

  it("states container build wiring in full and as two binary edges", async () => {
    const { model } = await scanOf(fullRepo());
    const graph = model.architecture.graph;

    assert.deepEqual(
      graph.buildContexts.map((record) => [record.source, record.service, record.dockerfile, record.context]),
      [
        ["docker-compose.yml", "root", "Dockerfile", null],
        ["docker-compose.yml", "web", "web/Dockerfile", "web"],
      ],
    );
    assert.ok(graph.buildContexts.every((record) => record.evidenceId.startsWith("evidence:")));

    const declaresBuild = edgeOf(
      graph,
      ARCHITECTURE_EDGE_TYPES.DECLARES_BUILD,
      "configuration:docker-compose.yml",
      "file:web/Dockerfile",
    );
    assert.ok(declaresBuild !== undefined);
    assert.deepEqual(declaresBuild.services, ["web"]);
    assert.deepEqual(declaresBuild.sourcePaths, ["docker-compose.yml"]);

    const context = edgeOf(
      graph,
      ARCHITECTURE_EDGE_TYPES.BUILD_CONTEXT,
      "file:web/Dockerfile",
      "directory:web",
    );
    assert.ok(context !== undefined);
    assert.deepEqual(context.services, ["web"]);

    // Both views come from the same observation, so they can never disagree.
    assert.deepEqual(declaresBuild.evidenceIds, context.evidenceIds);
  });

  it("stands the repository node in for the root build context", async () => {
    const { model } = await scanOf(fullRepo());
    const graph = model.architecture.graph;

    assert.ok(
      edgeOf(
        graph,
        ARCHITECTURE_EDGE_TYPES.BUILD_CONTEXT,
        "file:Dockerfile",
        repositoryNodeOf(model),
      ) !== undefined,
      "the repository root has no directory entity, so the repository node stands in",
    );
  });

  it("keeps every edge endpoint a node the graph contains", async () => {
    const { model } = await scanOf(fullRepo());
    const graph = model.architecture.graph;
    const ids = new Set(graph.nodes.map((entry) => entry.id));

    assert.ok(graph.edges.length > 0);
    for (const edge of graph.edges) {
      assert.ok(ids.has(edge.from), `${edge.from} must be a node`);
      assert.ok(ids.has(edge.to), `${edge.to} must be a node`);
      assert.ok(edge.evidenceIds.length > 0, "every edge cites at least one observation");
      assert.ok(edge.sourcePaths.length > 0, "every edge names the path that stated it");
    }
  });

  it("states no relationship the repository does not establish", async () => {
    const { model } = await scanOf(fullRepo());
    const types = new Set(model.architecture.graph.edges.map((edge) => edge.type));

    for (const absent of ["imports", "calls", "inherits", "tested-by", "uses-ci-workflow", "configured-by"]) {
      assert.equal(types.has(absent), false, `"${absent}" is not established by this architecture`);
    }
    assert.deepEqual([...types].sort(), [...new Set(types)].sort());
  });

  it("produces byte-identical graphs for one repository state", async () => {
    const files = fullRepo();
    const first = await scanOf(files);
    const second = await scanOf(files);

    assert.equal(
      JSON.stringify(first.model.architecture.graph),
      JSON.stringify(second.model.architecture.graph),
    );
  });

  it("keeps node paths repository-relative and free of host paths", async () => {
    const root = makeRepo(fullRepo());
    const { model } = await scanModel(root);
    const serialized = JSON.stringify(model.architecture.graph);

    for (const entry of model.architecture.graph.nodes) {
      if (entry.path === null) continue;
      assert.equal(entry.path.startsWith("/"), false);
      assert.equal(entry.path.includes(root), false);
    }
    assert.equal(serialized.includes(root.replace(/\\/g, "/")), false);
    assert.equal(serialized.includes(tmpdir().replace(/\\/g, "/")), false);
  });
});

// ─── Coverage ────────────────────────────────────────────────────────────────

describe("architecture graph: coverage", () => {
  it("reports complete for a repository whose sources were all interpreted", async () => {
    const { model } = await scanOf(fullRepo());
    const coverage = model.architecture.graph.coverage;

    assert.equal(coverage.state, ARCHITECTURE_GRAPH_STATES.COMPLETE);
    assert.equal(coverage.complete, true);
    assert.equal(coverage.truncated, false);
    assert.deepEqual(coverage.unestablishedSources, []);
    assert.equal(coverage.nodes, model.architecture.graph.nodes.length);
    assert.equal(coverage.edges, model.architecture.graph.edges.length);
    assert.equal(coverage.buildContexts, model.architecture.graph.buildContexts.length);
  });

  it("reports partial and names the file when a Compose declaration cannot be established", async () => {
    const { model } = await scanOf(ambiguousComposeRepo());
    const coverage = model.architecture.graph.coverage;

    assert.equal(coverage.state, ARCHITECTURE_GRAPH_STATES.PARTIAL);
    assert.equal(coverage.established, true);
    assert.deepEqual(
      coverage.unestablishedSources.map((entry) => entry.path),
      ["docker-compose.yml"],
    );
    assert.equal(coverage.unestablishedSources[0].reason, "ambiguous");
    assert.equal(coverage.unestablishedSources[0].detail, "dockerfile-outside-context");
    assert.equal(model.architecture.graph.buildContexts.length, 0);
  });

  it("reports partial for a scan that did not cover the repository", async () => {
    const draft = validateScanResult(
      createScanResult({
        root: "C:/repo",
        scannedAt: "2026-01-01T00:00:00.000Z",
        files: [{ path: "index.js", name: "index.js", extension: ".js", depth: 1 }],
        directories: [],
        scan: { complete: false, truncated: true },
      }),
    );
    const model = buildRepositoryModel(draft);
    const coverage = model.architecture.graph.coverage;

    assert.equal(coverage.state, ARCHITECTURE_GRAPH_STATES.PARTIAL);
    assert.equal(coverage.established, true);
    assert.equal(coverage.truncated, true);
    assert.equal(coverage.complete, false);
  });

  it("reports unsupported when the inventory establishes no architectural entity", async () => {
    const { model, query } = await scanModel(makeRepo({}));

    assert.equal(model.architecture.graph.state, ARCHITECTURE_GRAPH_STATES.UNSUPPORTED);
    assert.equal(model.architecture.graph.established, false);
    assert.equal(model.architecture.detected, false);
    assert.deepEqual(
      model.architecture.graph.nodes.map((entry) => entry.id),
      [repositoryNodeOf(model)],
      "only the repository node exists, and it establishes nothing",
    );
    assert.equal(query.architectureGraph().established, false);
  });

  it("reports unknown when the model records no scan state at all", async () => {
    const draft = validateScanResult(
      createScanResult({
        root: "C:/repo",
        scannedAt: "2026-01-01T00:00:00.000Z",
        scan: { complete: false, truncated: true },
      }),
    );
    const model = buildRepositoryModel(draft);

    assert.equal(model.architecture.graph.state, ARCHITECTURE_GRAPH_STATES.UNKNOWN);
    assert.equal(model.architecture.graph.established, false);
  });

  it("reports unknown through the query layer when a model carries no architecture graph", () => {
    // A model that predates the projection (or a draft) is still queryable: the query
    // layer answers `unknown` rather than pretending it saw an empty architecture.
    const model = {
      identity: { repositoryId: "repository:00000000", root: "C:/repo" },
      indexes: { entitiesById: {} },
      scan: { complete: true, truncated: false },
      relationships: [],
      evidence: [],
    };
    const query = createRepositoryQuery(model);

    const graph = query.architectureGraph();
    assert.equal(graph.state, ARCHITECTURE_GRAPH_STATES.UNKNOWN);
    assert.equal(graph.established, false);
    assert.deepEqual(graph.nodes, []);
    assert.deepEqual(graph.edges, []);
    assert.equal(query.architectureEdges().edges.length, 0);
    assert.equal(query.containerOf("file:a.js"), null);
    assert.equal(query.componentOf("file:a.js"), null);
    assert.deepEqual(query.containerBuildDeclarations().declarations, []);
    assert.equal(query.architectureCoverage().nodes, 0);
  });

  it("never reports established for a state that established nothing", async () => {
    for (const state of ARCHITECTURE_GRAPH_STATE_VALUES) {
      const established =
        state === ARCHITECTURE_GRAPH_STATES.COMPLETE || state === ARCHITECTURE_GRAPH_STATES.PARTIAL;
      assert.equal(
        established,
        state !== ARCHITECTURE_GRAPH_STATES.UNKNOWN && state !== ARCHITECTURE_GRAPH_STATES.UNSUPPORTED,
      );
    }

    const empty = await scanModel(makeRepo({}));
    const draft = buildRepositoryModel(
      validateScanResult(
        createScanResult({
          root: "C:/repo",
          scannedAt: "2026-01-01T00:00:00.000Z",
          scan: { complete: false, truncated: true },
        }),
      ),
    );
    for (const model of [empty.model, draft]) {
      assert.equal(model.architecture.graph.established, false);
      assert.equal(model.architecture.graph.edges.length, 0);
    }
  });

  it("keeps the scan guarantee and the graph state separate", async () => {
    const { query } = await scanOf(ambiguousComposeRepo());
    const result = query.architectureGraph();

    assert.equal(result.state, ARCHITECTURE_GRAPH_STATES.PARTIAL);
    assert.equal(result.coverage, COVERAGE_GUARANTEES.COMPLETE);
    assert.equal(architecturalCoverageState(query), result.state);
  });

  function architecturalCoverageState(query) {
    return query.architectureCoverage().state;
  }
});

// ─── Query API ───────────────────────────────────────────────────────────────

describe("architecture graph: query API", () => {
  it("returns a frozen, coverage-aware whole-graph result", async () => {
    const { query } = await scanOf(fullRepo());
    const result = query.architectureGraph();

    assert.equal(Object.isFrozen(result), true);
    assert.equal(Object.isFrozen(result.nodes), true);
    assert.equal(Object.isFrozen(result.edges), true);
    assert.throws(() => {
      result.edges.push({});
    }, TypeError);
    assert.equal(result.coverage, COVERAGE_GUARANTEES.COMPLETE);
    assert.equal(result.state, ARCHITECTURE_GRAPH_STATES.COMPLETE);
    assert.equal(result.established, true);
    assert.equal(result.truncated, false);
  });

  it("filters and bounds the architecture edge list, and rejects an unknown type", async () => {
    const { query } = await scanOf(fullRepo());

    const all = query.architectureEdges();
    assert.ok(all.edges.length > 0);
    assert.equal(all.limited, false);

    const contains = query.architectureEdges({ type: ARCHITECTURE_EDGE_TYPES.CONTAINS });
    assert.ok(contains.edges.length > 0);
    assert.ok(contains.edges.every((edge) => edge.type === "contains"));

    assert.deepEqual(
      query.architectureEdges({ from: "configuration:docker-compose.yml" }).edges.map((edge) => edge.type),
      [ARCHITECTURE_EDGE_TYPES.DECLARES_BUILD, ARCHITECTURE_EDGE_TYPES.DECLARES_BUILD].sort(),
    );

    const capped = query.architectureEdges({ maxResults: 1 });
    assert.equal(capped.edges.length, 1);
    assert.equal(capped.limited, true);

    assert.throws(() => query.architectureEdges({ type: "depends-on" }), RepositoryQueryError);
    assert.throws(() => query.architectureEdges({ direction: "out" }), RepositoryQueryError);
  });

  it("walks containment one hop by default and further on request", async () => {
    const { model, query } = await scanOf(fullRepo());
    const repositoryId = repositoryNodeOf(model);

    const direct = query.containedEntities(repositoryId);
    assert.ok(direct.nodes.every((entry) => entry.depth === 1));
    assert.ok(direct.nodes.some((entry) => entry.id === "directory:web"));
    assert.equal(
      direct.nodes.some((entry) => entry.id === "file:web/index.js"),
      false,
      "one hop does not reach a grandchild",
    );

    const deep = query.containedEntities(repositoryId, { maxDepth: 4 });
    assert.ok(deep.nodes.some((entry) => entry.id === "file:web/index.js"));
    const file = deep.nodes.find((entry) => entry.id === "file:web/index.js");
    assert.equal(file.depth, 2);

    assert.deepEqual(query.containedEntities("file:web/index.js").nodes, []);
    assert.deepEqual(query.containedEntities("file:missing.js").nodes, []);
    assert.deepEqual(query.containedEntities(undefined).nodes, []);
  });

  it("bounds a containment walk and says so", async () => {
    const { model, query } = await scanOf(fullRepo());
    const repositoryId = repositoryNodeOf(model);

    const bounded = query.containedEntities(repositoryId, { maxDepth: 4, maxResults: 2 });
    assert.equal(bounded.nodes.length, 2);
    assert.equal(bounded.limited, true);

    const depthBound = query.containedEntities(repositoryId, { maxDepth: 0 });
    assert.deepEqual(depthBound.nodes, []);
  });

  it("answers which container holds an entity", async () => {
    const { model, query } = await scanOf(fullRepo());
    const repositoryId = repositoryNodeOf(model);

    assert.equal(query.containerOf("file:src/app.js").id, "directory:src");
    assert.equal(query.containerOf("directory:src").id, repositoryId);
    assert.equal(query.containerOf("file:Dockerfile").id, repositoryId);
    assert.equal(query.containerOf("directory:web").id, repositoryId);
    assert.equal(query.containerOf(repositoryId), null);
    assert.equal(query.containerOf("file:missing.js"), null);
    assert.equal(query.containerOf(undefined), null);
  });

  it("resolves the innermost observed component", async () => {
    const { model, query } = await scanOf(fullRepo());
    const repositoryId = repositoryNodeOf(model);

    // Only the repository root holds a manifest here, so every path-bearing entity
    // belongs to the repository component.
    assert.equal(query.componentOf("file:src/app.js").id, repositoryId);
    assert.equal(query.componentOf("manifest:package.json").id, repositoryId);
    assert.equal(query.componentOf(repositoryId).id, repositoryId);
    assert.equal(query.componentOf(node("express")), null, "a package has no component");
    assert.equal(query.componentOf("framework:jest"), null);
    assert.equal(query.componentOf("file:missing.js"), null);
  });

  it("resolves a nested component by the manifest it holds", async () => {
    const { model, query } = await scanOf({
      "package.json": packageJson({ name: "root" }),
      "services/api/package.json": packageJson({ name: "api" }),
      "services/api/src/server.js": "1;\n",
    });

    assert.equal(query.componentOf("file:services/api/src/server.js").id, "directory:services/api");
    assert.equal(query.componentOf("manifest:services/api/package.json").id, "directory:services/api");
    assert.equal(query.componentOf("directory:services").id, repositoryNodeOf(model));
  });

  it("finds a bounded path between two nodes, following edges in either direction", async () => {
    const { model, query } = await scanOf(fullRepo());

    const build = query.architecturePath("configuration:docker-compose.yml", "file:web/Dockerfile");
    assert.equal(build.found, true);
    assert.deepEqual(build.edges.map((edge) => edge.type), [ARCHITECTURE_EDGE_TYPES.DECLARES_BUILD]);
    assert.deepEqual(build.nodes.map((entry) => entry.depth), [0, 1]);

    // Undirected on purpose: a file reaches its sibling through the directory that
    // holds both, which is the architectural answer to "how are these related".
    const siblings = query.architecturePath("file:src/app.js", "test:src/app.test.js");
    assert.equal(siblings.found, true);
    assert.deepEqual(siblings.nodes.map((entry) => entry.id), [
      "file:src/app.js",
      "directory:src",
      "test:src/app.test.js",
    ]);

    const contextPath = query.architecturePath("file:web/Dockerfile", "directory:web");
    assert.deepEqual(contextPath.edges.map((edge) => edge.type), [ARCHITECTURE_EDGE_TYPES.BUILD_CONTEXT]);

    assert.equal(query.architecturePath("file:missing.js", "file:Dockerfile").found, false);
    assert.equal(query.architecturePath(repositoryNodeOf(model), repositoryNodeOf(model)).found, true);
    assert.deepEqual(
      query.architecturePath(repositoryNodeOf(model), repositoryNodeOf(model)).edges,
      [],
      "a node is trivially reachable from itself without inventing an edge",
    );

    const bounded = query.architecturePath("file:src/app.js", "test:src/app.test.js", { maxDepth: 1 });
    assert.equal(bounded.found, false);
  });

  it("reports the container build declarations the model observed", async () => {
    const { model, query } = await scanOf(fullRepo());
    const result = query.containerBuildDeclarations();

    assert.equal(result.limited, false);
    assert.deepEqual(
      result.declarations.map((entry) => [entry.service, entry.dockerfile, entry.context]),
      [
        ["root", "Dockerfile", null],
        ["web", "web/Dockerfile", "web"],
      ],
    );
    const root = result.declarations.find((entry) => entry.service === "root");
    assert.equal(root.contextId, repositoryNodeOf(model), "the root context is the repository node");
    assert.equal(root.dockerfileId, "file:Dockerfile");
    assert.equal(root.evidenceIds.length, 1);

    assert.deepEqual(
      query.containerBuildDeclarations({ service: "web" }).declarations.map((entry) => entry.dockerfile),
      ["web/Dockerfile"],
    );
    assert.deepEqual(query.containerBuildDeclarations({ dockerfile: "nothing" }).declarations, []);
    assert.equal(query.containerBuildDeclarations({ maxResults: 1 }).limited, true);
    assert.throws(() => query.containerBuildDeclarations({ service: "" }), RepositoryQueryError);
    assert.throws(() => query.containerBuildDeclarations({ context: "web" }), RepositoryQueryError);
  });

  it("answers which test artifacts sit inside a container, by containment", async () => {
    const { model, query } = await scanOf(fullRepo());
    const repositoryId = repositoryNodeOf(model);

    const all = query.testsWithin(repositoryId, { maxDepth: 4 });
    assert.ok(all.nodes.every((entry) => entry.kind === "test"));
    assert.deepEqual(all.nodes.map((entry) => entry.id), [
      "test:jest.config.js",
      "test:src/app.test.js",
    ]);

    assert.deepEqual(query.testsWithin("directory:web").nodes, []);
    assert.deepEqual(query.testsWithin("file:missing.js").nodes, []);

    // The default is the bounded whole subtree, so "which tests are inside this
    // repository" is answered without the caller guessing a depth.
    const shallow = query.testsWithin(repositoryId, { maxDepth: 1 });
    assert.deepEqual(shallow.nodes.map((entry) => entry.id), ["test:jest.config.js"]);
  });

  it("answers which frameworks the model observed and what reported them", async () => {
    const { query } = await scanOf(fullRepo());
    const result = query.frameworkUsage();

    assert.deepEqual(result.frameworks, [
      { id: "framework:jest", name: "jest", tests: ["test:jest.config.js"] },
    ]);
    assert.equal(Object.isFrozen(result.frameworks[0].tests), true);

    const none = await scanOf({ "src/app.js": "1;\n" });
    assert.deepEqual(none.query.frameworkUsage().frameworks, []);
  });

  it("terminates on a containment cycle a hand-built graph can state", () => {
    // The scanner cannot observe a directory inside itself, but the query layer must
    // not depend on that: a cycle in its input still has to terminate, because a walk
    // that loops until it runs out of memory is a denial of service, not a traversal.
    const node = (id, kind, path) => ({ id, kind, name: null, path });
    const edge = (from, to) => ({
      from,
      to,
      type: ARCHITECTURE_EDGE_TYPES.CONTAINS,
      evidenceIds: ["evidence:inventory:a"],
      sourcePaths: ["a"],
      services: [],
    });
    const model = {
      identity: { repositoryId: "repository:00000000", root: "C:/repo" },
      indexes: { entitiesById: {} },
      scan: { complete: true, truncated: false },
      relationships: [],
      evidence: [],
      architecture: {
        detected: true,
        graph: {
          version: ARCHITECTURE_GRAPH_VERSION,
          state: ARCHITECTURE_GRAPH_STATES.COMPLETE,
          established: true,
          nodes: [
            node("repository:00000000", REPOSITORY_NODE_KIND, null),
            node("directory:a", "directory", "a"),
            node("directory:b", "directory", "b"),
          ],
          edges: [
            edge("repository:00000000", "directory:a"),
            edge("directory:a", "directory:b"),
            edge("directory:b", "directory:a"),
          ],
          buildContexts: [],
          coverage: {
            state: ARCHITECTURE_GRAPH_STATES.COMPLETE,
            established: true,
            complete: true,
            truncated: false,
            nodes: 3,
            edges: 3,
            buildContexts: 0,
            unestablishedSources: [],
            limits: {},
          },
        },
      },
    };
    const query = createRepositoryQuery(model);

    const subtree = query.containedEntities("repository:00000000", { maxDepth: 8 });
    assert.deepEqual(subtree.nodes.map((entry) => entry.id), ["directory:a", "directory:b"]);
    assert.equal(subtree.limited, false);

    const cyclic = query.architecturePath("directory:b", "directory:a", { maxDepth: 8 });
    assert.equal(cyclic.found, true);
    assert.equal(cyclic.nodes.length >= 2, true);
  });

  it("keeps the graph's coverage statement queryable", async () => {
    const { model, query } = await scanOf(fullRepo());
    const coverage = query.architectureCoverage();

    assert.equal(coverage.state, ARCHITECTURE_GRAPH_STATES.COMPLETE);
    assert.equal(coverage.established, true);
    assert.equal(coverage.nodes, model.architecture.graph.nodes.length);
    assert.deepEqual(coverage.limits, ARCHITECTURE_GRAPH_LIMITS);
  });

  it("returns the same answers for two query handles over one model", async () => {
    const { model } = await scanOf(fullRepo());
    const first = createRepositoryQuery(model);
    const second = createRepositoryQuery(model);

    assert.equal(
      JSON.stringify(first.architectureGraph()),
      JSON.stringify(second.architectureGraph()),
    );
    assert.equal(
      JSON.stringify(first.containerBuildDeclarations()),
      JSON.stringify(second.containerBuildDeclarations()),
    );
  });
});

// ─── Provenance and model integrity ──────────────────────────────────────────

describe("architecture graph: provenance and model integrity", () => {
  it("accepts a well-formed model", async () => {
    const { model } = await scanOf(fullRepo());
    assert.equal(validateRepositoryModelGraph(model), model);
  });

  it("traces every edge to observations the model contains", async () => {
    const { model } = await scanOf(fullRepo());
    const evidenceIds = new Set(Object.keys(model.indexes.evidenceById));

    for (const edge of model.architecture.graph.edges) {
      for (const id of edge.evidenceIds) {
        assert.ok(evidenceIds.has(id), `${id} must be an observation the model contains`);
      }
    }
    for (const record of model.architecture.graph.buildContexts) {
      assert.ok(evidenceIds.has(record.evidenceId));
    }
  });

  it("resolves a containment edge's observations back through the child entity", async () => {
    const { model, query } = await scanOf(fullRepo());
    const edge = query.architectureEdges({ type: ARCHITECTURE_EDGE_TYPES.CONTAINS }).edges.find(
      (entry) => entry.to === "file:src/app.js",
    );
    const evidence = query.getEvidenceForEntity(edge.to).evidence;

    assert.ok(evidence.some((record) => edge.evidenceIds.includes(record.id)));
  });

  /**
   * Tamper with a copy of the graph and assert the model rejects it.
   *
   * The graph is deeply frozen, so every level is copied before it is broken — a
   * shallow copy would throw a `TypeError` while mutating and hide the fact that the
   * validator never ran.
   */
  async function rejects(mutate, files = fullRepo()) {
    const { model } = await scanOf(files);
    const source = model.architecture.graph;
    const graph = mutate({
      ...source,
      nodes: source.nodes.map((entry) => ({ ...entry })),
      edges: source.edges.map((edge) => ({
        ...edge,
        evidenceIds: [...edge.evidenceIds],
        sourcePaths: [...edge.sourcePaths],
        services: [...edge.services],
      })),
      buildContexts: source.buildContexts.map((entry) => ({ ...entry })),
      coverage: {
        ...source.coverage,
        unestablishedSources: source.coverage.unestablishedSources.map((entry) => ({ ...entry })),
      },
    });
    const tampered = { ...model, architecture: { ...model.architecture, graph } };
    assert.throws(() => validateRepositoryModelGraph(tampered), ValidationError);
  }

  it("rejects an architecture area that carries no graph", async () => {
    const { model } = await scanOf(fullRepo());
    assert.throws(
      () => validateRepositoryModelGraph({ ...model, architecture: {} }),
      ValidationError,
    );
    assert.throws(
      () => validateRepositoryModelGraph({ ...model, architecture: { graph: null } }),
      ValidationError,
    );
  });

  it("rejects a node that names no entity the model contains", async () => {
    await rejects((graph) => {
      graph.nodes.push({ id: "file:ghost.js", kind: "file", name: "ghost.js", path: "ghost.js" });
      graph.nodes.sort((a, b) => (a.id < b.id ? -1 : 1));
      // The count is kept consistent on purpose, so the *only* invariant the tampered
      // graph can break is the one under test: a node must name a real entity.
      graph.coverage.nodes = graph.nodes.length;
      return graph;
    });
  });

  it("rejects a node whose kind disagrees with the entity it names", async () => {
    await rejects((graph) => {
      graph.nodes = graph.nodes.map((entry) =>
        entry.id === "file:src/app.js" ? { ...entry, kind: "manifest" } : entry,
      );
      return graph;
    });
  });

  it("rejects a duplicated or unsorted node list", async () => {
    await rejects((graph) => {
      graph.nodes.push({ ...graph.nodes[0] });
      return graph;
    });
    await rejects((graph) => {
      graph.nodes.reverse();
      return graph;
    });
  });

  it("rejects a graph that omits an entity it should describe", async () => {
    await rejects((graph) => {
      graph.nodes = graph.nodes.filter((entry) => entry.id !== "file:src/app.js");
      graph.coverage.nodes = graph.nodes.length;
      return graph;
    });
  });

  it("rejects an edge whose endpoint is not a node", async () => {
    await rejects((graph) => {
      graph.edges.push({
        from: "file:src/app.js",
        to: "file:ghost.js",
        type: ARCHITECTURE_EDGE_TYPES.CONTAINS,
        evidenceIds: [graph.edges[0].evidenceIds[0]],
        sourcePaths: ["ghost.js"],
        services: [],
      });
      graph.edges.sort((a, b) => (a.from === b.from ? (a.to < b.to ? -1 : 1) : a.from < b.from ? -1 : 1));
      graph.coverage.edges = graph.edges.length;
      return graph;
    });
  });

  it("rejects an undocumented edge type", async () => {
    await rejects((graph) => {
      graph.edges[0].type = "imports";
      return graph;
    });
  });

  it("rejects a repeated edge", async () => {
    await rejects((graph) => {
      graph.edges.push({ ...graph.edges[0], evidenceIds: [...graph.edges[0].evidenceIds] });
      graph.coverage.edges = new Set(
        graph.edges.map((edge) => `${edge.from}\u0000${edge.to}\u0000${edge.type}`),
      ).size;
      return graph;
    });
  });

  it("rejects an edge with no observation, or an unknown one", async () => {
    await rejects((graph) => {
      graph.edges[0].evidenceIds = [];
      return graph;
    });
    await rejects((graph) => {
      graph.edges[0].evidenceIds = ["evidence:not:a:real:observation"];
      return graph;
    });
  });

  it("rejects a containment edge the model's relationships do not state", async () => {
    await rejects((graph) => {
      // The endpoints exist, but nothing in the model says the Dockerfile sits inside
      // the `src` directory: containment is not free-form.
      graph.edges.push({
        from: "directory:src",
        to: "file:Dockerfile",
        type: ARCHITECTURE_EDGE_TYPES.CONTAINS,
        evidenceIds: [graph.edges[0].evidenceIds[0]],
        sourcePaths: ["Dockerfile"],
        services: [],
      });
      graph.edges.sort((a, b) => (a.from === b.from ? (a.to < b.to ? -1 : 1) : a.from < b.from ? -1 : 1));
      graph.coverage.edges = graph.edges.length;
      return graph;
    });
  });

  it("rejects a framework or declaration edge the model's relationships do not state", async () => {
    await rejects((graph) => {
      graph.edges.push({
        from: "manifest:package.json",
        to: "framework:jest",
        type: ARCHITECTURE_EDGE_TYPES.FRAMEWORK,
        evidenceIds: [graph.edges[0].evidenceIds[0]],
        sourcePaths: ["package.json"],
        services: [],
      });
      graph.edges.sort((a, b) => (a.from === b.from ? (a.to < b.to ? -1 : 1) : a.from < b.from ? -1 : 1));
      graph.coverage.edges = graph.edges.length;
      return graph;
    });
  });

  it("rejects a container edge with no container declaration behind it", async () => {
    await rejects((graph) => {
      graph.edges.push({
        from: "configuration:docker-compose.yml",
        to: "file:src/Dockerfile",
        type: ARCHITECTURE_EDGE_TYPES.DECLARES_BUILD,
        evidenceIds: [graph.edges[0].evidenceIds[0]],
        sourcePaths: ["docker-compose.yml"],
        services: ["ghost"],
      });
      graph.edges.sort((a, b) => (a.from === b.from ? (a.to < b.to ? -1 : 1) : a.from < b.from ? -1 : 1));
      graph.coverage.edges = graph.edges.length;
      return graph;
    });
  });

  it("rejects a build declaration that cites a foreign observation", async () => {
    await rejects((graph) => {
      graph.buildContexts[0].evidenceId = "evidence:inventory:package.json";
      return graph;
    });
  });

  it("rejects a coverage statement that disagrees with the graph", async () => {
    await rejects((graph) => {
      graph.coverage.nodes = graph.nodes.length + 1;
      return graph;
    });
    await rejects((graph) => {
      graph.coverage.state = ARCHITECTURE_GRAPH_STATES.PARTIAL;
      return graph;
    });
    await rejects((graph) => {
      graph.established = !graph.established;
      return graph;
    });
  });

  it("refuses to call a graph complete while a source is unestablished", async () => {
    await rejects((graph) => {
      graph.coverage.unestablishedSources.push({
        path: "docker-compose.yml",
        reason: "ambiguous",
        detail: "dockerfile-outside-context",
        evidenceId: graph.edges[0].evidenceIds[0],
      });
      return graph;
    });
  });

  it("rejects an absolute path in a node or a provenance field", async () => {
    await rejects((graph) => {
      graph.nodes = graph.nodes.map((entry) =>
        entry.id === "file:Dockerfile" ? { ...entry, path: "/etc/passwd" } : entry,
      );
      return graph;
    });
    await rejects((graph) => {
      graph.edges[0].sourcePaths = ["/etc/passwd"];
      return graph;
    });
  });
});

// ─── Rule pack and integration ───────────────────────────────────────────────

describe("architecture graph: rule pack and integration", () => {
  const runRules = async (files, { rules = architectureRules } = {}) => {
    const { model } = await scanOf(files);
    const engine = createRuleEngine({ registry: createArchitectureRuleRegistry({ rules }) });
    return { model, run: await engine.runAll(contextOf(model)) };
  };

  const inventoryOf = (run) =>
    run.rules.find((entry) => entry.rule.id === ARCHITECTURE_RULE_IDS.GRAPH_INVENTORY);

  it("declares its rule in the pack namespace and accepts the shipped pack", () => {
    assert.deepEqual(architectureRuleSetIssues(architectureRules), []);
    assert.equal(ARCHITECTURE_RULE_IDS.GRAPH_INVENTORY.startsWith("architecture."), true);
    assert.deepEqual(
      architectureRules.map((rule) => rule.id),
      [ARCHITECTURE_RULE_IDS.GRAPH_INVENTORY],
    );
    assert.equal(createArchitectureRuleRegistry({ rules: architectureRules }).size, 1);
  });

  it("rejects a rule outside the namespace, or a missing declared rule", () => {
    assert.throws(
      () => createArchitectureRuleRegistry({ rules: [{ ...architectureRules[0], id: "security.x" }] }),
      (error) => (error.details?.issues ?? []).join(" ").includes("namespace"),
    );
    assert.throws(
      () => createArchitectureRuleRegistry({ rules: [] }),
      (error) => (error.details?.issues ?? []).join(" ").includes("missing from the pack"),
    );
  });

  it("describes every edge type the graph can state", () => {
    for (const type of ARCHITECTURE_EDGE_TYPE_VALUES) {
      assert.equal(
        typeof EDGE_WORDING[type],
        "string",
        `edge type "${type}" has no wording, so a finding could not describe it`,
      );
    }
    assert.deepEqual([...ARCHITECTURE_DESCRIBED_EDGE_TYPES].sort(), [...ARCHITECTURE_EDGE_TYPE_VALUES].sort());
  });

  it("reports one finding per established relationship, citing its evidence", async () => {
    const { model, run } = await runRules(fullRepo());
    const entry = inventoryOf(run);
    const evidenceIds = new Set(Object.keys(model.indexes.evidenceById));

    assert.equal(entry.status, RULE_OUTCOME_STATUSES.VIOLATION);
    assert.equal(entry.findings.length, model.architecture.graph.edges.length);
    assert.equal(inventoryRelationships(model), entry.findings.length);
    assert.equal(entry.metadata.reported, entry.findings.length);

    for (const finding of entry.findings) {
      assert.equal(finding.severity, "info");
      assert.ok(finding.evidence.length > 0);
      for (const id of finding.evidence) assert.ok(evidenceIds.has(id));
      assert.equal(finding.metadata.basis, ARCHITECTURE_BASIS);
      assert.equal(typeof finding.metadata.fingerprintKey, "string");
      assert.ok(EDGE_WORDING[finding.metadata.relationshipType] !== undefined);
    }

    function inventoryRelationships(model) {
      return architectureRelationships(createRepositoryQuery(model)).length;
    }
  });

  it("names both endpoints, the declaration and the declaring services", async () => {
    const { run } = await runRules(fullRepo());
    const entry = inventoryOf(run);
    const build = entry.findings.find(
      (finding) =>
        finding.metadata.relationshipType === ARCHITECTURE_EDGE_TYPES.DECLARES_BUILD &&
        finding.metadata.toPath === "web/Dockerfile",
    );

    assert.ok(build !== undefined);
    assert.deepEqual(build.metadata.services, ["web"]);
    assert.equal(build.metadata.fromPath, "docker-compose.yml");
    assert.equal(build.metadata.toPath, "web/Dockerfile");
    assert.ok(build.description.includes("declares a build of"));
    assert.ok(build.description.includes("`web/Dockerfile`"));
  });

  it("reports the graph's own coverage on every run", async () => {
    const { run } = await runRules(fullRepo());
    const entry = inventoryOf(run);

    assert.equal(entry.metadata.state, ARCHITECTURE_GRAPH_STATES.COMPLETE);
    assert.equal(entry.metadata.established, true);
    assert.equal(entry.metadata.capped, false);
    assert.equal(entry.metadata.buildContexts, 2);
    assert.equal(entry.metadata.unestablishedSources, 0);
    assert.ok(entry.metadata.nodes > 0);
  });

  it("produces deterministic, uniquely fingerprinted findings", async () => {
    const first = await runRules(fullRepo());
    const second = await runRules(fullRepo());
    const engine = createAnalyzerEngine({
      registry: createAnalyzerRegistry([createArchitectureAnalyzer()]),
    });
    const run = await engine.runAll(contextOf(first.model));
    const repeated = await engine.runAll(contextOf(second.model));

    assert.deepEqual(
      run.findings.map((finding) => finding.id),
      repeated.findings.map((finding) => finding.id),
    );
    assert.equal(new Set(run.findings.map((finding) => finding.fingerprint)).size, run.findings.length);
    assert.deepEqual(
      inventoryOf(first.run).findings.map((finding) => finding.metadata.fingerprintKey),
      inventoryOf(second.run).findings.map((finding) => finding.metadata.fingerprintKey),
    );
  });

  it("caps a large inventory and says that it did", async () => {
    const files = {};
    for (let index = 0; index < MAX_ARCHITECTURE_FINDINGS + 15; index += 1) {
      files[`src/file-${String(index).padStart(3, "0")}.js`] = "1;\n";
    }
    const { run } = await runRules(files);
    const entry = inventoryOf(run);

    assert.equal(entry.findings.length, MAX_ARCHITECTURE_FINDINGS);
    assert.equal(entry.metadata.reported, MAX_ARCHITECTURE_FINDINGS);
    assert.equal(entry.metadata.capped, true);
    assert.ok(entry.metadata.edges > MAX_ARCHITECTURE_FINDINGS);
  });

  it("abstains instead of reporting a clean repository it cannot support", async () => {
    // An empty repository establishes no architectural entity, so "no relationship" is
    // not a supported claim — the rule must answer `unknown`, not `pass`.
    const { run } = await runRules({});
    const entry = inventoryOf(run);

    assert.equal(entry.findings.length, 0);
    assert.equal(entry.status, RULE_OUTCOME_STATUSES.UNKNOWN);
    assert.equal(entry.metadata.established, false);
    assert.match(entry.applicability.reason, /establishes no architectural entity/);
  });

  it("cannot report pass, and says so by abstaining on every repository", async () => {
    // Every established architecture contains at least one containment relationship —
    // an entity is somewhere — so an empty relationship list cannot mean "the
    // repository relates nothing"; it means the graph was not established, which is a
    // `unknown`, never a clean bill of health.
    for (const files of [{}, { "README.md": "# demo\n" }, fullRepo()]) {
      const { run } = await runRules(files);
      const entry = inventoryOf(run);
      assert.notEqual(entry.status, RULE_OUTCOME_STATUSES.PASS);
    }
  });

  it("reports abstention with the reason when a source could not be established", async () => {
    const { model } = await scanOf(ambiguousComposeRepo());
    const query = createRepositoryQuery(model);
    const absence = architectureAbsence(query);

    assert.equal(absence.established, false);
    assert.equal(absence.state, ARCHITECTURE_GRAPH_STATES.PARTIAL);
    assert.match(absence.reason, /docker-compose\.yml/);
    assert.equal(architectureCoverage(query).state, ARCHITECTURE_GRAPH_STATES.PARTIAL);
  });

  it("runs as an analyzer through the accepted framework", async () => {
    const { model } = await scanOf(fullRepo());
    const engine = createAnalyzerEngine({
      registry: createAnalyzerRegistry([createArchitectureAnalyzer()]),
    });
    const run = await engine.runAll(contextOf(model));
    const analyzer = run.analyzers[0];

    assert.equal(analyzer.analyzer.id, ARCHITECTURE_ANALYZER_ID);
    assert.equal(analyzer.analyzer.scope, ARCHITECTURE_ANALYZER_SCOPE);
    assert.equal(run.findings.length > 0, true);
    assert.ok(run.findings.every((finding) => finding.category === "architecture"));
  });

  it("imports nothing but Core, the model query layer and its own modules", () => {
    const PACK_DIR = fileURLToPath(new URL("../src/rules/architecture", import.meta.url));
    const FORBIDDEN = [
      "node:fs",
      "node:fs/promises",
      "node:path",
      "node:child_process",
      "child_process",
      "node:net",
      "node:http",
      "node:https",
      "node:dns",
      "node:worker_threads",
      "acorn",
      "babel",
      "typescript",
      "tree-sitter",
      "@babel",
      "tools.js",
      "tool-registry",
      "../filesystem",
      "../../execution",
    ];

    const sources = [];
    const collect = (directory, prefix) => {
      for (const name of readdirSync(directory, { withFileTypes: true })) {
        const relative = `${prefix}${name.name}`;
        if (name.isDirectory()) {
          collect(join(directory, name.name), `${relative}/`);
          continue;
        }
        if (!name.name.endsWith(".js")) continue;
        sources.push({ name: relative, text: readFileSync(join(directory, name.name), "utf8") });
      }
    };
    collect(PACK_DIR, "");

    assert.ok(sources.length > 0);
    for (const { name, text } of sources) {
      for (const match of text.matchAll(/from\s+"([^"]+)"/g)) {
        const specifier = match[1];
        assert.ok(
          specifier.startsWith(".") || specifier === "../../../core/index.js",
          `${name} imports "${specifier}"`,
        );
      }
      const importLines = text
        .split("\n")
        .filter((line) => line.trim().startsWith("import ") || line.includes("from \""));
      const importedText = importLines.join("\n");
      for (const forbidden of FORBIDDEN) {
        assert.equal(
          importedText.includes(`"${forbidden}"`),
          false,
          `${name} imports "${forbidden}"`,
        );
      }
      assert.equal(/\brequire\s*\(/.test(text), false, `${name} must not use require`);
    }
  });

  it("reads the model only through the query API", () => {
    const PACK_DIR = fileURLToPath(new URL("../src/rules/architecture", import.meta.url));
    const RULES_DIR = join(PACK_DIR, "rules");

    // A rule must ask questions through `signals.js`, which is the one module allowed
    // to build a query handle; nothing in the pack may read the model's areas itself.
    for (const name of readdirSync(RULES_DIR)) {
      if (!name.endsWith(".js")) continue;
      const text = readFileSync(join(RULES_DIR, name), "utf8");
      assert.equal(
        text.includes("context.repository"),
        false,
        `rules/${name} must not reach past the query API into the model`,
      );
    }

    const all = ["contracts.js", "signals.js", "registry.js", "analyzer.js", "index.js"];
    for (const name of [...all, ...readdirSync(RULES_DIR).map((entry) => `rules/${entry}`)]) {
      const text = readFileSync(join(PACK_DIR, name), "utf8");
      assert.equal(
        text.includes("model.architecture"),
        false,
        `${name} must not read the architecture graph off the model directly`,
      );
      assert.equal(
        text.includes("model.dependencies"),
        false,
        `${name} must not read dependency internals`,
      );
      assert.equal(
        text.includes("createRepositoryQuery") && name !== "signals.js",
        false,
        `${name} must build a query handle only in signals.js`,
      );
    }
  });
});
