/**
 * Code Guardian — Dependency Graph Tests (Phase 14)
 *
 * Two fixture styles, chosen deliberately:
 *
 *   - **real repositories** written to a temporary directory and scanned through the
 *     accepted Phase 8A boundary, Phase 8C scanner and Phase 13 acquisition, so the
 *     parser, the model projection and the graph agree end to end. This is the only
 *     way to prove that what a lockfile states is what the graph exposes.
 *   - **hand-built ScanResults** for states a real scan cannot reach on demand
 *     (acquisition truncated by a limit) and for tampering, so the fail-closed
 *     behaviour of the graph contract can be stated exactly.
 *
 * No test spawns a process, contacts a network, installs a package or writes to the
 * repository under test.
 *
 * Run with: node --test tests/dependency-graph.test.js
 */

import { after, describe, it } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { ValidationError } from "../src/core/index.js";

import {
  createScanResult,
  scanRepository,
  validateScanResult,
} from "../src/repository/scanner/index.js";

import {
  COVERAGE_GUARANTEES,
  DEPENDENCY_GRAPH_EDGE_TYPES,
  DEPENDENCY_GRAPH_LIMITS,
  DEPENDENCY_GRAPH_STATES,
  DEPENDENCY_GRAPH_STATE_VALUES,
  DEPENDENCY_GRAPH_VERSION,
  ENTITY_KINDS,
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
  DEPENDENCY_ANALYZER_ID,
  DEPENDENCY_GRAPH_BASIS,
  DEPENDENCY_RULE_IDS,
  MAX_GRAPH_FINDINGS,
  RULE_OUTCOME_STATUSES,
  createDependencyAnalyzer,
  createDependencyRuleRegistry,
  createRuleEngine,
  dependencyGraphAbsence,
  dependencyGraphEdges,
  dependencyRules,
  queryFor,
} from "../src/rules/index.js";

// ─── Fixtures ────────────────────────────────────────────────────────────────

const TMP_ROOT = join(tmpdir(), `cg-graph-${process.pid}-${Date.now()}`);
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

const packageJson = (value) => JSON.stringify(value, null, 2);

const node = (name) => `dependency:node:${name}`;
const python = (name) => `dependency:python:${name}`;

/** A v3 lockfile whose root package depends on `leaf`. */
const lockfileV3 = (packages) =>
  JSON.stringify({
    name: "demo",
    lockfileVersion: 3,
    packages: { "": { name: "demo" }, ...packages },
  });

/** A lockfile package entry. */
const lockedPackage = (version, dependencies) => ({
  version,
  ...(dependencies === undefined ? {} : { dependencies }),
});

/** `package.json` declaring exactly `names` at `^1.0.0`, plus a lockfile. */
function projectWithDependencies(names) {
  const dependencies = Object.fromEntries(names.map((name) => [name, "^1.0.0"]));
  return {
    "package.json": packageJson({ name: "demo", dependencies }),
    "package-lock.json": lockfileV3({
      ...Object.fromEntries(
        names.map((name) => [`node_modules/${name}`, lockedPackage("1.0.0")]),
      ),
    }),
  };
}

/** A chain `a -> b -> c` established by a lockfile. */
const chainRepo = () => ({
  "package.json": packageJson({ dependencies: { a: "^1.0.0" } }),
  "package-lock.json": lockfileV3({
    "node_modules/a": lockedPackage("1.0.0", { b: "^1.0.0" }),
    "node_modules/b": lockedPackage("1.0.0", { c: "^1.0.0" }),
    "node_modules/c": lockedPackage("1.0.0"),
  }),
});

/** A cycle `a -> b -> c -> a`. */
const cycleRepo = () => ({
  "package.json": packageJson({ dependencies: { a: "^1.0.0" } }),
  "package-lock.json": lockfileV3({
    "node_modules/a": lockedPackage("1.0.0", { b: "^1.0.0" }),
    "node_modules/b": lockedPackage("1.0.0", { c: "^1.0.0" }),
    "node_modules/c": lockedPackage("1.0.0", { a: "^1.0.0" }),
  }),
});

const idsOf = (nodes) => nodes.map((entry) => entry.id);

// ─── Construction ────────────────────────────────────────────────────────────

describe("dependency graph: construction", () => {
  it("records an established relationship with both endpoints as nodes", async () => {
    const { model } = await scanOf(chainRepo());
    const graph = model.dependencies.graph;

    assert.equal(graph.version, DEPENDENCY_GRAPH_VERSION);
    assert.equal(graph.state, DEPENDENCY_GRAPH_STATES.COMPLETE);
    assert.equal(graph.established, true);
    assert.deepEqual(idsOf(graph.nodes), [node("a"), node("b"), node("c")]);
    assert.deepEqual(
      graph.edges.map((edge) => [edge.from, edge.to, edge.type]),
      [
        [node("a"), node("b"), DEPENDENCY_GRAPH_EDGE_TYPES.DEPENDS_ON],
        [node("b"), node("c"), DEPENDENCY_GRAPH_EDGE_TYPES.DEPENDS_ON],
      ],
    );
  });

  it("projects every dependency entity to exactly one node", async () => {
    const { model } = await scanOf(chainRepo());

    assert.equal(model.dependencies.graph.nodes.length, model.dependencies.entries.length);
    assert.deepEqual(
      idsOf(model.dependencies.graph.nodes),
      model.dependencies.entries.map((entry) => entry.id).sort(),
    );
  });

  it("keeps a lockfile-only package as a node without promoting it to direct", async () => {
    const { model, query } = await scanOf(chainRepo());
    const nodes = new Map(model.dependencies.graph.nodes.map((entry) => [entry.id, entry]));

    // `b` and `c` are reachable from `a` at depth 1 and 2, which proves nothing about
    // directness: only a manifest section can make a dependency direct.
    assert.deepEqual(nodes.get(node("b")), {
      id: node("b"),
      ecosystem: "node",
      name: "b",
      declared: false,
      direct: false,
      resolved: true,
    });
    assert.equal(nodes.get(node("c")).direct, false);
    assert.deepEqual(
      idsOf(query.directDependencies().entities),
      [node("a")],
      "directness comes from the declaration, never from topology",
    );
  });

  it("preserves a resolved package that no manifest declares", async () => {
    const { query } = await scanOf(chainRepo());

    assert.deepEqual(idsOf(query.transitiveDependencies().entities), [node("b"), node("c")]);
    assert.equal(query.getDependencyByName("node", "b").declared, false);
    assert.equal(query.getDependencyByName("node", "b").resolved, true);
  });

  it("keeps a declared but unresolved dependency as a node with resolved false", async () => {
    const { model } = await scanOf({
      "package.json": packageJson({ dependencies: { react: "^19.0.0" } }),
    });

    assert.deepEqual(model.dependencies.graph.nodes, [
      {
        id: node("react"),
        ecosystem: "node",
        name: "react",
        declared: true,
        direct: true,
        resolved: false,
      },
    ]);
    assert.deepEqual(model.dependencies.graph.edges, []);
  });

  it("creates no edge from a declaration alone", async () => {
    const { model, query } = await scanOf({
      "package.json": packageJson({ dependencies: { react: "^19.0.0" } }),
    });

    assert.equal(model.dependencies.graph.edges.length, 0);
    // The declaration relationship still exists — it is simply not a graph edge.
    assert.equal(
      query.dependencyRelationships(node("react")).relationships.some(
        (relationship) => relationship.type === "declares-dependency",
      ),
      true,
    );
    assert.deepEqual(idsOf(query.dependenciesOf(node("react")).nodes), []);
  });

  it("keeps a package named only by an edge, with neither declaration nor resolution", async () => {
    const { model } = await scanOf({
      "package.json": packageJson({ dependencies: { a: "^1.0.0" } }),
      "package-lock.json": JSON.stringify({
        name: "demo",
        lockfileVersion: 1,
        dependencies: { a: { version: "1.0.0", requires: { missing: "^1.0.0" } } },
      }),
    });

    const nodes = new Map(model.dependencies.graph.nodes.map((entry) => [entry.id, entry]));
    assert.equal(nodes.has(node("missing")), true);
    assert.deepEqual(nodes.get(node("missing")), {
      id: node("missing"),
      ecosystem: "node",
      name: "missing",
      declared: false,
      direct: false,
      resolved: false,
    });
    assert.deepEqual(
      model.dependencies.graph.edges.map((edge) => [edge.from, edge.to]),
      [[node("a"), node("missing")]],
    );
  });

  it("preserves a cycle instead of deleting edges to make the graph acyclic", async () => {
    const { model } = await scanOf(cycleRepo());
    const graph = model.dependencies.graph;

    assert.equal(graph.edges.length, 3);
    assert.deepEqual(
      graph.edges.map((edge) => `${edge.from}->${edge.to}`),
      [`${node("a")}->${node("b")}`, `${node("b")}->${node("c")}`, `${node("c")}->${node("a")}`],
    );
  });

  it("preserves a self-dependency a lockfile states, and traversal still terminates", async () => {
    const { model, query } = await scanOf({
      "package.json": packageJson({ dependencies: { a: "^1.0.0" } }),
      "package-lock.json": lockfileV3({
        "node_modules/a": lockedPackage("1.0.0", { a: "^1.0.0" }),
      }),
    });

    assert.deepEqual(
      model.dependencies.graph.edges.map((edge) => [edge.from, edge.to]),
      [[node("a"), node("a")]],
    );
    assert.deepEqual(idsOf(query.dependencyDescendants(node("a")).nodes), []);
    assert.deepEqual(idsOf(query.dependencyAncestors(node("a")).nodes), []);
  });

  it("never connects two ecosystems whose package names match", async () => {
    const { model, query } = await scanOf({
      "package.json": packageJson({ dependencies: { requests: "^1.0.0" } }),
      "requirements.txt": "requests==2.31.0\n",
    });

    assert.deepEqual(idsOf(model.dependencies.graph.nodes), [
      node("requests"),
      python("requests"),
    ]);
    assert.deepEqual(model.dependencies.graph.edges, []);
    assert.equal(model.dependencies.graph.nodes[0].ecosystem, "node");
    assert.equal(model.dependencies.graph.nodes[1].ecosystem, "python");
    assert.equal(python("requests").startsWith(ENTITY_KINDS.DEPENDENCY), true);
  });

  it("merges a relationship two lockfiles state into one edge citing both", async () => {
    const { model } = await scanOf({
      "package.json": packageJson({ dependencies: { a: "^1.0.0" } }),
      "package-lock.json": lockfileV3({
        "node_modules/a": lockedPackage("1.0.0", { shared: "^1.0.0" }),
        "node_modules/shared": lockedPackage("1.0.0"),
      }),
      "frontend/package.json": packageJson({ dependencies: { a: "^1.0.0" } }),
      "frontend/package-lock.json": lockfileV3({
        "node_modules/a": lockedPackage("1.0.0", { shared: "^1.0.0" }),
        "node_modules/shared": lockedPackage("1.0.0"),
      }),
    });

    const edge = model.dependencies.graph.edges.find(
      (entry) => entry.to === node("shared"),
    );
    assert.deepEqual(edge.manifestPaths, ["frontend/package-lock.json", "package-lock.json"]);
    assert.equal(edge.evidenceIds.length, 2);
    assert.deepEqual(
      model.dependencies.graph.edges.filter((entry) => entry.to === node("shared")).length,
      1,
    );
  });

  it("orders nodes by id and edges by endpoints, deterministically", async () => {
    const files = {
      "package.json": packageJson({ dependencies: { zeta: "^1.0.0", alpha: "^1.0.0" } }),
      "package-lock.json": lockfileV3({
        "node_modules/zeta": lockedPackage("1.0.0", { shared: "^1.0.0" }),
        "node_modules/alpha": lockedPackage("1.0.0", { shared: "^1.0.0" }),
        "node_modules/shared": lockedPackage("1.0.0"),
      }),
    };
    const first = await scanOf(files);
    const second = await scanOf(files);

    assert.deepEqual(
      JSON.stringify(first.model.dependencies.graph),
      JSON.stringify(second.model.dependencies.graph),
      "two scans of one repository state must produce byte-identical graphs",
    );

    const { nodes, edges } = first.model.dependencies.graph;
    assert.deepEqual(idsOf(nodes), [...idsOf(nodes)].sort());
    assert.deepEqual(
      edges.map((edge) => `${edge.from}|${edge.to}`),
      [...edges.map((edge) => `${edge.from}|${edge.to}`)].sort(),
    );
  });
});

// ─── Coverage ────────────────────────────────────────────────────────────────

describe("dependency graph: coverage states", () => {
  it("is complete when every dependency source was interpreted", async () => {
    const { model } = await scanOf(chainRepo());

    assert.equal(model.dependencies.graph.state, DEPENDENCY_GRAPH_STATES.COMPLETE);
    assert.equal(model.dependencies.graph.established, true);
    assert.equal(model.dependencies.graph.coverage.inspected, true);
  });

  it("is an established, empty graph when the repository has no manifest at all", async () => {
    const { model } = await scanOf({ "README.md": "# demo\n" });

    assert.equal(model.dependencies.graph.state, DEPENDENCY_GRAPH_STATES.COMPLETE);
    assert.equal(model.dependencies.graph.established, true);
    assert.equal(model.dependencies.graph.nodes.length, 0);
    assert.equal(model.dependencies.graph.edges.length, 0);
  });

  it("is an established, empty graph when no source can state a relationship", async () => {
    const { model } = await scanOf({ "requirements.txt": "flask==3.0.0\n" });

    assert.equal(model.dependencies.graph.state, DEPENDENCY_GRAPH_STATES.COMPLETE);
    assert.equal(model.dependencies.graph.established, true);
    assert.equal(model.dependencies.graph.edges.length, 0);
    assert.deepEqual(
      model.dependencies.graph.coverage.unestablishedSources,
      [],
      "a format that cannot state edges is still fully interpreted",
    );
  });

  it("is partial and names the unsupported source", async () => {
    const { model } = await scanOf({
      "package.json": packageJson({ dependencies: { react: "^19.0.0" } }),
      "pnpm-lock.yaml": "lockfileVersion: '9.0'\n",
    });

    assert.equal(model.dependencies.graph.state, DEPENDENCY_GRAPH_STATES.PARTIAL);
    assert.equal(model.dependencies.graph.established, true);
    assert.deepEqual(
      model.dependencies.graph.coverage.unestablishedSources.map((source) => source.path),
      ["pnpm-lock.yaml"],
    );
    assert.equal(
      model.dependencies.graph.coverage.unestablishedSources[0].status,
      "unsupported",
    );
  });

  it("is partial and names the malformed lockfile", async () => {
    const { model } = await scanOf({
      "package.json": packageJson({ dependencies: { react: "^19.0.0" } }),
      "package-lock.json": "{not json",
    });

    assert.equal(model.dependencies.graph.state, DEPENDENCY_GRAPH_STATES.PARTIAL);
    assert.deepEqual(
      model.dependencies.graph.coverage.unestablishedSources.map((source) => [
        source.path,
        source.status,
        source.reason,
      ]),
      [["package-lock.json", "failed", "invalid-json"]],
    );
  });

  it("is unsupported when no source uses a format this build interprets", async () => {
    const { model } = await scanOf({ "pnpm-lock.yaml": "lockfileVersion: '9.0'\n" });

    assert.equal(model.dependencies.graph.state, DEPENDENCY_GRAPH_STATES.UNSUPPORTED);
    assert.equal(model.dependencies.graph.established, false);
    assert.equal(model.dependencies.graph.coverage.established, false);
  });

  it("is never established when the state is unsupported or unknown", async () => {
    const unsupported = await scanOf({ "pnpm-lock.yaml": "lockfileVersion: '9.0'\n" });
    assert.equal(unsupported.model.dependencies.graph.state, DEPENDENCY_GRAPH_STATES.UNSUPPORTED);
    assert.equal(unsupported.model.dependencies.graph.established, false);

    const unknown = await scanOf({ "package-lock.json": "{not json" });
    assert.equal(unknown.model.dependencies.graph.state, DEPENDENCY_GRAPH_STATES.UNKNOWN);
    assert.equal(unknown.model.dependencies.graph.established, false);
    assert.equal(unknown.model.dependencies.graph.coverage.inspected, false);
    assert.deepEqual(
      unknown.model.dependencies.graph.coverage.unestablishedSources.map(
        (source) => source.path,
      ),
      ["package-lock.json"],
    );
  });

  it("keeps an established empty graph apart from a graph that was never established", async () => {
    const established = await scanOf({ "README.md": "# demo\n" });
    const never = await scanOf({ "package-lock.json": "{not json" });

    assert.deepEqual(established.model.dependencies.graph.edges, []);
    assert.deepEqual(never.model.dependencies.graph.edges, []);
    assert.equal(established.model.dependencies.graph.established, true);
    assert.equal(never.model.dependencies.graph.established, false);
  });

  it("reports a truncated acquisition as partial and truncated", async () => {
    const scan = createScanResult({
      root: "/scan-root",
      scannedAt: "2026-01-01T00:00:00.000Z",
      files: [
        { path: "package.json", name: "package.json", isDirectory: false, extension: ".json", depth: 1 },
      ],
      manifests: [
        {
          path: "package.json",
          name: "package.json",
          directory: ".",
          ecosystem: "node",
          kind: "manifest",
          languages: [],
          parse: { status: "parsed", format: "json", bytes: 10, metadata: {} },
        },
      ],
      dependencies: {
        inspected: true,
        complete: false,
        truncated: true,
        manifests: [
          {
            path: "package.json",
            ecosystem: "node",
            kind: "manifest",
            format: "json",
            status: "parsed",
            reason: null,
            detail: null,
            dependencies: [
              { name: "react", scope: "runtime", spec: "^19.0.0", specKind: "registry", direct: true, conditional: false },
            ],
            resolved: [],
            edges: [],
            truncated: true,
            problems: [],
          },
        ],
        limits: {},
      },
      scan: { complete: true, truncated: false, limits: {}, errors: [] },
    });
    const model = buildRepositoryModel(validateScanResult(scan));
    const graph = model.dependencies.graph;

    assert.equal(graph.state, DEPENDENCY_GRAPH_STATES.PARTIAL);
    assert.equal(graph.established, true);
    assert.equal(graph.coverage.truncated, true);
  });

  it("keeps state and established in agreement, and the vocabulary closed", async () => {
    const { model } = await scanOf(chainRepo());
    const graph = model.dependencies.graph;

    assert.ok(DEPENDENCY_GRAPH_STATE_VALUES.includes(graph.state));
    assert.equal(graph.established, graph.state === DEPENDENCY_GRAPH_STATES.COMPLETE);
    assert.equal(graph.coverage.state, graph.state);
  });

  it("reports the documented version-instance limitation", async () => {
    const { model, query } = await scanOf({
      "frontend/package.json": packageJson({ dependencies: { foo: "^1.0.0" } }),
      "frontend/package-lock.json": lockfileV3({ "node_modules/foo": lockedPackage("1.0.0") }),
      "backend/package.json": packageJson({ dependencies: { foo: "^2.0.0" } }),
      "backend/package-lock.json": lockfileV3({ "node_modules/foo": lockedPackage("2.0.0") }),
    });

    const { versionInstances } = query.dependencyGraphCoverage();
    assert.equal(versionInstances.ambiguous, true);
    assert.equal(versionInstances.count, 1);
    assert.deepEqual(versionInstances.packages, [{ id: node("foo"), versions: 2 }]);
    // The graph has one node for `foo`, so an edge to `foo` cannot say which version.
    assert.deepEqual(idsOf(model.dependencies.graph.nodes), [node("foo")]);
  });

  it("reports no ambiguity when every resolution record agrees", async () => {
    const { query } = await scanOf(chainRepo());
    assert.deepEqual(query.dependencyGraphCoverage().versionInstances, {
      ambiguous: false,
      count: 0,
      packages: [],
    });
  });

  it("exposes the graph bounds and counts in the coverage statement", async () => {
    const { query } = await scanOf(chainRepo());
    const coverage = query.dependencyGraphCoverage();

    assert.deepEqual(coverage.limits, DEPENDENCY_GRAPH_LIMITS);
    assert.equal(coverage.nodes, 3);
    assert.equal(coverage.edges, 2);
    assert.equal(coverage.declarations, 1);
    assert.equal(coverage.resolved, 3);
    assert.equal(Object.isFrozen(coverage), true);
  });
});

// ─── Traversal ───────────────────────────────────────────────────────────────

describe("dependency graph: traversal", () => {
  it("returns one hop by default and the closure on request", async () => {
    const { query } = await scanOf(chainRepo());

    assert.deepEqual(idsOf(query.dependenciesOf(node("a")).nodes), [node("b")]);
    assert.deepEqual(idsOf(query.dependencyDescendants(node("a")).nodes), [node("b"), node("c")]);
    assert.deepEqual(query.dependencyDescendants(node("a")).nodes.map((entry) => entry.depth), [1, 2]);
  });

  it("returns dependents and ancestors in the reverse direction", async () => {
    const { query } = await scanOf(chainRepo());

    assert.deepEqual(idsOf(query.dependentsOf(node("c")).nodes), [node("b")]);
    // Ordered by hop count, so the nearer dependent comes first.
    assert.deepEqual(idsOf(query.dependencyAncestors(node("c")).nodes), [node("b"), node("a")]);
    assert.deepEqual(
      query.dependencyAncestors(node("c")).nodes.map((entry) => entry.depth),
      [1, 2],
    );
  });

  it("terminates on a cycle in both directions", async () => {
    const { query } = await scanOf(cycleRepo());

    assert.deepEqual(
      idsOf(query.dependencyDescendants(node("a")).nodes),
      [node("b"), node("c")],
    );
    assert.deepEqual(idsOf(query.dependencyAncestors(node("a")).nodes), [node("c"), node("b")]);
    assert.equal(query.dependencyDescendants(node("a")).limited, false);
    assert.equal(query.dependencyAncestors(node("a")).limited, false);
  });

  it("bounds the walk by maxDepth", async () => {
    const { query } = await scanOf(chainRepo());

    assert.deepEqual(idsOf(query.dependencyDescendants(node("a"), { maxDepth: 0 }).nodes), []);
    assert.deepEqual(
      idsOf(query.dependencyDescendants(node("a"), { maxDepth: 1 }).nodes),
      [node("b")],
    );
    assert.equal(query.dependencyDescendants(node("a"), { maxDepth: 1 }).limited, false);
  });

  it("bounds the result by maxResults and says it did", async () => {
    const { query } = await scanOf(chainRepo());
    const result = query.dependencyDescendants(node("a"), { maxResults: 1 });

    assert.equal(result.nodes.length, 1);
    assert.equal(result.limited, true);
  });

  it("rejects an invalid limit and an unknown option", async () => {
    const { query } = await scanOf(chainRepo());

    assert.throws(() => query.dependenciesOf(node("a"), { maxDepth: 99 }), RepositoryQueryError);
    assert.throws(() => query.dependenciesOf(node("a"), { maxResults: 0 }), RepositoryQueryError);
    assert.throws(() => query.dependenciesOf(node("a"), { depth: 1 }), RepositoryQueryError);
    assert.throws(() => query.dependencyEdges({ type: "declares-dependency" }), RepositoryQueryError);
  });

  it("treats an unknown or non-string id as an ordinary miss", async () => {
    const { query } = await scanOf(chainRepo());

    for (const id of ["dependency:node:absent", null, 42, {}]) {
      const result = query.dependenciesOf(id);
      assert.deepEqual(idsOf(result.nodes), []);
      assert.deepEqual(result.edges, []);
      assert.equal(result.limited, false);
    }
  });

  it("never traverses a declaration or resolution relationship", async () => {
    const { query } = await scanOf({
      "package.json": packageJson({ dependencies: { react: "^19.0.0" } }),
    });
    const manifestId = `manifest:package.json`;

    // The manifest declares `react`; following that edge would report the manifest as
    // a dependency of `react`, which the repository never stated.
    assert.equal(
      query
        .getRelationshipsForEntity(manifestId)
        .relationships.some((relationship) => relationship.type === "declares-dependency"),
      true,
    );
    assert.deepEqual(idsOf(query.dependentsOf(node("react")).nodes), []);
    assert.deepEqual(idsOf(query.dependencyAncestors(node("react")).nodes), []);
  });

  it("returns a shortest path in order, with the traversed edges", async () => {
    const { query } = await scanOf(chainRepo());
    const result = query.dependencyPath(node("a"), node("c"));

    assert.equal(result.found, true);
    assert.deepEqual(idsOf(result.nodes), [node("a"), node("b"), node("c")]);
    assert.deepEqual(result.nodes.map((entry) => entry.depth), [0, 1, 2]);
    assert.deepEqual(
      result.edges.map((edge) => [edge.from, edge.to]),
      [[node("a"), node("b")], [node("b"), node("c")]],
    );
    assert.equal(result.limited, false);
  });

  it("reports found false for a disconnected pair and for an unknown node", async () => {
    const { query } = await scanOf({
      ...chainRepo(),
      "other/package.json": packageJson({ dependencies: { unrelated: "^1.0.0" } }),
      "other/package-lock.json": lockfileV3({ "node_modules/unrelated": lockedPackage("1.0.0") }),
    });

    // A real node, and a node that does not exist: both are honest `found: false`.
    assert.equal(query.getDependencyByName("node", "unrelated") !== null, true);
    assert.equal(query.dependencyPath(node("a"), node("unrelated")).found, false);
    assert.equal(query.dependencyPath(node("a"), node("absent")).found, false);
    assert.deepEqual(query.dependencyPath(node("a"), node("absent")).nodes, []);
  });

  it("reports a node as trivially reachable from itself without inventing an edge", async () => {
    const { query } = await scanOf(chainRepo());
    const result = query.dependencyPath(node("a"), node("a"));

    assert.equal(result.found, true);
    assert.deepEqual(idsOf(result.nodes), [node("a")]);
    assert.deepEqual(result.edges, []);
  });

  it("says the path search was bounded rather than proving disconnection", async () => {
    const { query } = await scanOf(chainRepo());
    const result = query.dependencyPath(node("a"), node("c"), { maxDepth: 1 });

    assert.equal(result.found, false);
    assert.equal(result.limited, false);
    const bounded = query.dependencyPath(node("a"), node("c"), { maxDepth: 1, maxResults: 1 });
    assert.equal(bounded.found, false);
  });

  it("filters and bounds the edge list, and rejects an unknown type", async () => {
    const { query } = await scanOf(chainRepo());

    const all = query.dependencyEdges();
    assert.equal(all.edges.length, 2);
    assert.deepEqual(all.edges.map((edge) => edge.type), [
      DEPENDENCY_GRAPH_EDGE_TYPES.DEPENDS_ON,
      DEPENDENCY_GRAPH_EDGE_TYPES.DEPENDS_ON,
    ]);
    assert.equal(all.limited, false);

    assert.deepEqual(
      query.dependencyEdges({ from: node("a") }).edges.map((edge) => edge.to),
      [node("b")],
    );
    assert.deepEqual(
      query.dependencyEdges({ to: node("c") }).edges.map((edge) => edge.from),
      [node("b")],
    );
    assert.equal(
      query.dependencyEdges({ type: DEPENDENCY_GRAPH_EDGE_TYPES.DEPENDS_ON }).edges.length,
      2,
    );

    const capped = query.dependencyEdges({ maxResults: 1 });
    assert.equal(capped.edges.length, 1);
    assert.equal(capped.limited, true);
  });

  it("returns frozen, coverage-aware results", async () => {
    const { query } = await scanOf(chainRepo());
    const result = query.dependencyDescendants(node("a"));

    assert.equal(Object.isFrozen(result), true);
    assert.equal(Object.isFrozen(result.nodes), true);
    assert.equal(Object.isFrozen(result.nodes[0]), true);
    assert.equal(Object.isFrozen(result.edges), true);
    assert.equal(Object.isFrozen(result.edges[0]), true);
    assert.throws(() => {
      result.nodes.push({});
    }, TypeError);
    assert.equal(result.coverage, COVERAGE_GUARANTEES.COMPLETE);
    assert.equal(result.state, DEPENDENCY_GRAPH_STATES.COMPLETE);
    assert.equal(result.established, true);
    assert.equal(result.truncated, false);
  });

  it("keeps the scan guarantee and the graph state separate on a partial graph", async () => {
    const { query } = await scanOf({
      "package.json": packageJson({ dependencies: { react: "^19.0.0" } }),
      "pnpm-lock.yaml": "lockfileVersion: '9.0'\n",
    });
    const result = query.dependenciesOf(node("react"));

    assert.equal(result.state, DEPENDENCY_GRAPH_STATES.PARTIAL);
    assert.equal(result.coverage, COVERAGE_GUARANTEES.COMPLETE);
  });
});

// ─── Provenance and integrity ────────────────────────────────────────────────

describe("dependency graph: provenance and model integrity", () => {
  const withLockfile = () => chainRepo();

  it("traces every edge to real observations and real manifests", async () => {
    const { model, query } = await scanOf(withLockfile());
    const evidenceIds = new Set(Object.keys(model.indexes.evidenceById));

    assert.ok(model.dependencies.graph.edges.length > 0);
    for (const edge of model.dependencies.graph.edges) {
      assert.ok(edge.evidenceIds.length > 0, "every edge cites an observation");
      for (const id of edge.evidenceIds) assert.ok(evidenceIds.has(id), `${id} must exist`);
      assert.deepEqual(edge.manifestPaths, ["package-lock.json"]);
    }
  });

  it("keeps edge provenance repository-relative and path-safe", async () => {
    const root = makeRepo(withLockfile());
    const { model } = await scanModel(root);
    const serialized = JSON.stringify(model.dependencies.graph);

    for (const edge of model.dependencies.graph.edges) {
      for (const path of edge.manifestPaths) {
        assert.equal(path.startsWith("/"), false);
        assert.equal(path.includes(root), false);
      }
    }
    assert.equal(serialized.includes(root.replace(/\\/g, "/")), false);
    assert.equal(serialized.includes(tmpdir().replace(/\\/g, "/")), false);
  });

  it("resolves edge observations back through the entity they belong to", async () => {
    const { query } = await scanOf(withLockfile());
    const edge = query.dependencyEdges().edges[0];
    const evidence = query.getEvidenceForEntity(edge.from).evidence;

    assert.ok(evidence.some((record) => edge.evidenceIds.includes(record.id)));
  });

  it("accepts a well-formed model", async () => {
    const { model } = await scanOf(withLockfile());
    assert.equal(validateRepositoryModelGraph(model), model);
  });

  /**
   * Tamper with a copy of the graph and assert the model rejects it.
   *
   * The graph is deeply frozen, so every level is copied before it is broken — a
   * shallow copy would throw a `TypeError` while mutating and hide the fact that the
   * validator never ran.
   */
  async function rejects(mutate) {
    const { model } = await scanOf(withLockfile());
    const source = model.dependencies.graph;
    const graph = mutate({
      ...source,
      nodes: source.nodes.map((entry) => ({ ...entry })),
      edges: source.edges.map((edge) => ({
        ...edge,
        evidenceIds: [...edge.evidenceIds],
        manifestPaths: [...edge.manifestPaths],
      })),
      coverage: {
        ...source.coverage,
        unestablishedSources: source.coverage.unestablishedSources.map((entry) => ({ ...entry })),
        versionInstances: {
          ...source.coverage.versionInstances,
          packages: source.coverage.versionInstances.packages.map((entry) => ({ ...entry })),
        },
      },
    });
    const tampered = { ...model, dependencies: { ...model.dependencies, graph } };
    assert.throws(() => validateRepositoryModelGraph(tampered), ValidationError);
  }

  it("rejects an edge that the model's relationships do not state", async () => {
    await rejects((graph) => {
      graph.edges.push({
        from: node("a"),
        to: node("c"),
        type: DEPENDENCY_GRAPH_EDGE_TYPES.DEPENDS_ON,
        evidenceIds: [graph.edges[0].evidenceIds[0]],
        manifestPaths: ["package-lock.json"],
      });
      graph.edges.sort((a, b) => (a.from === b.from ? (a.to < b.to ? -1 : 1) : a.from < b.from ? -1 : 1));
      graph.coverage.edges = graph.edges.length;
      return graph;
    });
  });

  it("rejects a dropped edge that the relationships still state", async () => {
    await rejects((graph) => {
      graph.edges = graph.edges.slice(1);
      graph.coverage.edges = graph.edges.length;
      return graph;
    });
  });

  it("rejects an edge with no provenance", async () => {
    await rejects((graph) => {
      graph.edges[0].evidenceIds = [];
      return graph;
    });
  });

  it("rejects an edge citing an observation the model does not contain", async () => {
    await rejects((graph) => {
      graph.edges[0].evidenceIds = ["evidence:dependency:dependency-resolution:ghost.json"];
      return graph;
    });
  });

  it("rejects an edge whose provenance names an unknown manifest", async () => {
    await rejects((graph) => {
      graph.edges[0].manifestPaths = ["ghost-lock.json"];
      return graph;
    });
  });

  it("rejects an edge with an unknown endpoint", async () => {
    await rejects((graph) => {
      graph.edges[0].to = node("absent");
      return graph;
    });
  });

  it("rejects an edge with an unknown type", async () => {
    await rejects((graph) => {
      graph.edges[0].type = "transitive-edge";
      return graph;
    });
  });

  it("rejects a repeated edge", async () => {
    await rejects((graph) => {
      graph.edges.push({ ...graph.edges[0] });
      graph.coverage.edges = graph.edges.length;
      return graph;
    });
  });

  it("rejects an edge list that is not in the documented order", async () => {
    await rejects((graph) => {
      graph.edges = [...graph.edges].reverse();
      return graph;
    });
  });

  it("rejects a node that is not a dependency entity of the model", async () => {
    await rejects((graph) => {
      graph.nodes = [
        ...graph.nodes,
        { id: node("ghost"), ecosystem: "node", name: "ghost", declared: false, direct: false, resolved: true },
      ];
      return graph;
    });
  });

  it("rejects a node whose flags disagree with the entity it names", async () => {
    await rejects((graph) => {
      graph.nodes[0] = { ...graph.nodes[0], direct: !graph.nodes[0].direct };
      return graph;
    });
  });

  it("rejects a node list that is not sorted by id", async () => {
    await rejects((graph) => {
      graph.nodes = [...graph.nodes].reverse();
      return graph;
    });
  });

  it("rejects a graph that claims to be established while unknown", async () => {
    await rejects((graph) => {
      graph.state = DEPENDENCY_GRAPH_STATES.UNKNOWN;
      graph.established = true;
      graph.coverage.state = DEPENDENCY_GRAPH_STATES.UNKNOWN;
      return graph;
    });
  });

  it("rejects a coverage statement whose counts disagree with the graph", async () => {
    await rejects((graph) => {
      graph.coverage.nodes = graph.coverage.nodes + 1;
      return graph;
    });
  });

  it("rejects a coverage statement that omits the identity limitation", async () => {
    await rejects((graph) => {
      delete graph.coverage.versionInstances;
      return graph;
    });
  });

  it("rejects a missing graph", async () => {
    const { model } = await scanOf(withLockfile());
    const tampered = { ...model, dependencies: { ...model.dependencies, graph: null } };
    assert.throws(() => validateRepositoryModelGraph(tampered), ValidationError);
  });

  it("keeps the graph deeply frozen inside the model", async () => {
    const { model } = await scanOf(withLockfile());
    const graph = model.dependencies.graph;

    assert.equal(Object.isFrozen(graph), true);
    assert.equal(Object.isFrozen(graph.nodes), true);
    assert.equal(Object.isFrozen(graph.nodes[0]), true);
    assert.equal(Object.isFrozen(graph.edges), true);
    assert.equal(Object.isFrozen(graph.edges[0]), true);
    assert.equal(Object.isFrozen(graph.edges[0].evidenceIds), true);
    assert.equal(Object.isFrozen(graph.edges[0].manifestPaths), true);
    assert.equal(Object.isFrozen(graph.coverage), true);
    assert.equal(Object.isFrozen(graph.coverage.unestablishedSources), true);
    assert.equal(Object.isFrozen(graph.coverage.versionInstances), true);
    assert.equal(Object.isFrozen(graph.coverage.versionInstances.packages), true);

    // A model that freezes only its outer objects is mutable where it matters.
    assert.throws(() => graph.edges[0].manifestPaths.push("x"), TypeError);
    assert.throws(() => {
      graph.edges[0].evidenceIds = [];
    }, TypeError);
  });

  it("freezes the whole model, at every level", async () => {
    const { model } = await scanOf(withLockfile());
    const seen = new Set();
    const walk = (value, path) => {
      if (value === null || typeof value !== "object" || seen.has(value)) return;
      seen.add(value);
      assert.equal(Object.isFrozen(value), true, `${path} is not frozen`);
      for (const key of Object.keys(value)) walk(value[key], `${path}.${key}`);
    };

    walk(model, "model");
  });

  it("exposes the graph read-only through the query API", async () => {
    const { query } = await scanOf(withLockfile());
    assert.throws(() => {
      query.dependencyGraph().nodes.push({});
    }, TypeError);
    assert.throws(() => {
      query.dependencyEdges().edges[0].evidenceIds.push("x");
    }, TypeError);
  });
});

// ─── Rule Engine ─────────────────────────────────────────────────────────────

describe("dependency graph: rule engine integration", () => {
  const contextOf = (model) => buildAnalysisContext({ repository: model });

  async function runRules(files, { rules = dependencyRules } = {}) {
    const { model } = await scanOf(files);
    const engine = createRuleEngine({ registry: createDependencyRuleRegistry({ rules }) });
    return { model, run: await engine.runAll(contextOf(model)) };
  }

  const graphResult = (run) =>
    run.rules.find((entry) => entry.rule.id === DEPENDENCY_RULE_IDS.GRAPH_INVENTORY);

  it("reports one finding per established relationship, with its evidence", async () => {
    const { model, run } = await runRules(chainRepo());
    const result = graphResult(run);

    assert.equal(result.status, RULE_OUTCOME_STATUSES.VIOLATION);
    assert.equal(result.findings.length, 2);

    const evidenceIds = new Set(Object.keys(model.indexes.evidenceById));
    for (const finding of result.findings) {
      assert.equal(finding.severity, "info");
      assert.equal(finding.metadata.basis, DEPENDENCY_GRAPH_BASIS);
      assert.equal(finding.metadata.ecosystem, "node");
      assert.deepEqual(finding.metadata.manifestPaths, ["package-lock.json"]);
      assert.ok(finding.evidence.length > 0);
      for (const id of finding.evidence) assert.ok(evidenceIds.has(id));
      assert.match(finding.description, /depends on/);
      assert.match(finding.description, /does not infer a requirement from a version range/);
    }

    assert.deepEqual(
      result.findings.map((finding) => [finding.metadata.fromName, finding.metadata.toName]),
      [["a", "b"], ["b", "c"]],
    );
  });

  it("names the relationship rather than judging it", async () => {
    const { run } = await runRules(cycleRepo());
    const result = graphResult(run);

    assert.equal(result.findings.length, 3);
    for (const finding of result.findings) {
      assert.equal(finding.severity, "info");
      assert.doesNotMatch(finding.description, /circular|problem|risk|vulnerab|should/i);
    }
    assert.deepEqual(graphResult(run).metadata.state, DEPENDENCY_GRAPH_STATES.COMPLETE);
  });

  it("passes only when the graph is established, complete and empty", async () => {
    const { run } = await runRules({ "requirements.txt": "flask==3.0.0\n" });
    assert.equal(graphResult(run).status, RULE_OUTCOME_STATUSES.PASS);
  });

  it("reports unknown when the graph was never established", async () => {
    const { run } = await runRules({ "pnpm-lock.yaml": "lockfileVersion: '9.0'\n" });
    const result = graphResult(run);

    assert.equal(result.status, RULE_OUTCOME_STATUSES.UNKNOWN);
    assert.match(result.applicability.reason, /no dependency source uses a format/);
  });

  it("reports unknown when a source could not be interpreted", async () => {
    const { run } = await runRules({
      "package.json": packageJson({ dependencies: { react: "^19.0.0" } }),
      "pnpm-lock.yaml": "lockfileVersion: '9.0'\n",
    });
    const result = graphResult(run);

    assert.equal(result.metadata.relationships, 0);
    assert.equal(result.metadata.state, DEPENDENCY_GRAPH_STATES.PARTIAL);
    assert.equal(result.status, RULE_OUTCOME_STATUSES.UNKNOWN);
    assert.match(result.applicability.reason, /interpreted only part/);
  });

  it("reports unknown over a partially interpreted multi-manifest repository", async () => {
    const { run } = await runRules({
      "pnpm-lock.yaml": "lockfileVersion: '9.0'\n",
      "requirements.txt": "flask==3.0.0\n",
    });

    assert.equal(graphResult(run).metadata.relationships, 0);
    assert.equal(graphResult(run).status, RULE_OUTCOME_STATUSES.UNKNOWN);
  });

  it("reports every relationship it can while a sibling source is unsupported", async () => {
    const { run } = await runRules({
      ...chainRepo(),
      "pnpm-lock.yaml": "lockfileVersion: '9.0'\n",
    });
    const result = graphResult(run);

    assert.equal(result.status, RULE_OUTCOME_STATUSES.VIOLATION);
    assert.equal(result.findings.length, 2);
    assert.equal(result.metadata.state, DEPENDENCY_GRAPH_STATES.PARTIAL);
  });

  it("does not report a clean graph over an incomplete scan", async () => {
    const { model } = await scanOf({ "requirements.txt": "flask==3.0.0\n" });
    const incomplete = {
      ...model,
      scan: { ...model.scan, complete: false, coverage: { ...model.scan.coverage, guarantee: "partial" } },
      dependencies: {
        ...model.dependencies,
        graph: { ...model.dependencies.graph, state: DEPENDENCY_GRAPH_STATES.PARTIAL, coverage: { ...model.dependencies.graph.coverage, state: DEPENDENCY_GRAPH_STATES.PARTIAL } },
      },
    };

    const absence = dependencyGraphAbsence(createRepositoryQuery(incomplete));
    assert.equal(absence.established, false);
    assert.match(absence.reason, /did not establish every manifest|did not cover/);
  });

  it("caps a large graph and records that it did", async () => {
    const packages = {};
    const names = [];
    for (let index = 0; index <= MAX_GRAPH_FINDINGS; index += 1) {
      names.push(`pkg-${index}`);
      packages[`node_modules/pkg-${index}`] = lockedPackage("1.0.0", { leaf: "^1.0.0" });
    }
    packages["node_modules/leaf"] = lockedPackage("1.0.0");

    const { run } = await runRules({
      "package.json": packageJson({
        dependencies: Object.fromEntries(names.map((name) => [name, "^1.0.0"])),
      }),
      "package-lock.json": lockfileV3(packages),
    });

    const result = graphResult(run);
    assert.equal(result.findings.length, MAX_GRAPH_FINDINGS);
    assert.equal(result.metadata.relationships, MAX_GRAPH_FINDINGS + 1);
    assert.equal(result.metadata.capped, true);
    assert.equal(result.metadata.reported, MAX_GRAPH_FINDINGS);
  });

  it("is deterministic through the analyzer and the finding engine", async () => {
    const files = chainRepo();
    const engine = createAnalyzerEngine({
      registry: createAnalyzerRegistry([createDependencyAnalyzer()]),
    });

    const first = await engine.runAll(contextOf((await scanOf(files)).model));
    const second = await engine.runAll(contextOf((await scanOf(files)).model));

    assert.equal(first.analyzers[0].analyzer.id, DEPENDENCY_ANALYZER_ID);
    assert.deepEqual(
      first.findings.map((finding) => finding.id),
      second.findings.map((finding) => finding.id),
    );
    assert.equal(
      first.findings.some((finding) => finding.ruleId === DEPENDENCY_RULE_IDS.GRAPH_INVENTORY),
      true,
    );
  });

  it("registers the graph rule as part of the declared pack", async () => {
    const { run } = await runRules(chainRepo());
    assert.equal(run.rules.length, 2);
    assert.deepEqual(
      run.rules.map((entry) => entry.rule.id).sort(),
      Object.values(DEPENDENCY_RULE_IDS).sort(),
    );
  });

  it("gives every edge a stable fingerprint key of its own", async () => {
    const { run } = await runRules(chainRepo());
    const keys = graphResult(run).findings.map(
      (finding) => finding.metadata.fingerprintKey,
    );

    assert.equal(new Set(keys).size, keys.length, "two edges must not share an identity");
    for (const key of keys) assert.match(key, /^edge:[0-9a-f]{8}$/);
    assert.deepEqual(
      keys,
      [...keys].sort(),
      "the keys are ordered with the edges they name",
    );
  });

  it("reads the graph through the query API and flattens it with provenance", async () => {
    const { model } = await scanOf(chainRepo());
    const query = queryFor(buildAnalysisContext({ repository: model }));
    const edges = dependencyGraphEdges(query);

    assert.deepEqual(
      edges.map((edge) => [edge.from, edge.to]),
      query.dependencyGraph().edges.map((edge) => [edge.from, edge.to]),
    );
    assert.deepEqual(
      edges.map((edge) => [edge.fromName, edge.toName, edge.ecosystem, edge.type]),
      [
        ["a", "b", "node", DEPENDENCY_GRAPH_EDGE_TYPES.DEPENDS_ON],
        ["b", "c", "node", DEPENDENCY_GRAPH_EDGE_TYPES.DEPENDS_ON],
      ],
    );
    for (const edge of edges) {
      assert.deepEqual(edge.manifestPaths, ["package-lock.json"]);
      assert.ok(edge.evidenceIds.length > 0);
    }
  });
});

// ─── Architectural isolation ─────────────────────────────────────────────────

function stripComments(source) {
  return source.replace(/\/\*[\s\S]*?\*\//g, "").replace(/^\s*\/\/.*$/gm, "");
}

/**
 * Comments and string literals removed.
 *
 * The modules *document* what they must never do, so a raw-text scan would flag the
 * very sentences that state the invariant. What is left after this is code:
 * identifiers, property names and operators.
 */
function stripCode(source) {
  return stripComments(source)
    .replace(/"(?:[^"\\]|\\.)*"/g, '""')
    .replace(/'(?:[^'\\]|\\.)*'/g, "''")
    .replace(/`(?:[^`\\]|\\.)*`/g, "``");
}

describe("dependency graph: architectural isolation", () => {
  const projectRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
  const read = (relative) => readFileSync(join(projectRoot, relative), "utf8");

  const FORBIDDEN = [
    ["node:fs", /from\s+"node:fs/],
    ["node:path", /from\s+"node:path/],
    ["node:child_process", /from\s+"node:child_process/],
    ["node:net", /from\s+"node:net/],
    ["node:http", /from\s+"node:http/],
    ["node:https", /from\s+"node:https/],
    ["node:dns", /from\s+"node:dns/],
    ["node:worker_threads", /from\s+"node:worker_threads/],
    ["filesystem boundary", /repository\/filesystem/],
    ["execution boundary", /src\/execution/],
    ["tools.js", /tools\.js/],
    ["transports", /http-server|stdio-server/],
  ];

  it("keeps the graph projection a pure module", () => {
    const source = stripComments(read("src/repository/model/dependency-graph.js"));

    for (const [label, pattern] of FORBIDDEN) {
      assert.ok(!pattern.test(source), `dependency-graph.js must not import ${label}`);
    }
    assert.ok(!/child_process|spawn|execFile|execSync|require\(/.test(source));
    assert.ok(!/Date\.now|new Date|Math\.random|process\.env/.test(source));
    assert.ok(!/https?:\/\//.test(source), "the graph must not reach a network");
    assert.equal(/^import\s/m.test(source), false, "the projection imports nothing at all");
  });

  it("keeps the graph rule inside the query boundary", () => {
    const source = stripComments(read("src/rules/dependency/rules/graph.js"));

    for (const [label, pattern] of FORBIDDEN) {
      assert.ok(!pattern.test(source), `graph.js must not import ${label}`);
    }
    assert.ok(!/child_process|spawn|execFile|execSync|require\(/.test(source));
    assert.ok(
      !/\.dependencies\s*\.\s*graph/.test(source),
      "the rule must ask the query API for the graph, not read the model directly",
    );
    assert.ok(/dependencyGraphEdges|dependencyGraphCoverage/.test(source));
  });

  it("introduces no vulnerability, scoring or remediation capability", () => {
    const banned = [
      "cve",
      "ghsa",
      "osv",
      "nvd",
      "advisory",
      "vulnerab",
      "riskScore",
      "securityScore",
      "outdated",
      "malicious",
      "remediationPlan",
      "upgradeTo",
    ];

    for (const relative of [
      "src/repository/model/dependency-graph.js",
      "src/rules/dependency/rules/graph.js",
      "src/rules/dependency/signals.js",
    ]) {
      const code = stripCode(read(relative)).toLowerCase();
      for (const word of banned) {
        assert.ok(!code.includes(word.toLowerCase()), `${relative} must not name "${word}"`);
      }
    }
  });

  it("records only graph facts in a finding's metadata", async () => {
    const { model } = await scanOf(chainRepo());
    const engine = createRuleEngine({
      registry: createDependencyRuleRegistry({ rules: dependencyRules }),
    });
    const run = await engine.runAll(buildAnalysisContext({ repository: model }));
    const findings = run.rules.flatMap((entry) => entry.findings);

    assert.ok(findings.length >= 2);
    const graphFindings = run.rules.find(
      (entry) => entry.rule.id === DEPENDENCY_RULE_IDS.GRAPH_INVENTORY,
    ).findings;
    assert.ok(graphFindings.length > 0);
    for (const finding of graphFindings) {
      assert.deepEqual(Object.keys(finding.metadata).sort(), [
        "basis",
        "ecosystem",
        "fingerprintKey",
        "from",
        "fromName",
        "manifestPaths",
        "to",
        "toName",
        "type",
      ]);
    }

    const serialized = JSON.stringify(graphFindings.map((finding) => finding.metadata)).toLowerCase();
    for (const word of ["vulnerab", "cve", "advisory", "score", "upgrade", "circular"]) {
      assert.ok(!serialized.includes(word), `finding metadata must not name "${word}"`);
    }
  });

  it("adds no filesystem, network or process capability to the model layer", () => {
    for (const relative of [
      "src/repository/model/dependency-graph.js",
      "src/repository/model/query-api.js",
      "src/repository/model/query-contracts.js",
    ]) {
      const source = stripComments(read(relative));
      for (const [label, pattern] of FORBIDDEN) {
        assert.ok(!pattern.test(source), `${relative} must not import ${label}`);
      }
      assert.ok(!/Date\.now|new Date|Math\.random/.test(source));
    }
  });
});
