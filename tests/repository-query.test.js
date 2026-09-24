/**
 * Code Guardian — Repository Query Tests (Phase 11)
 *
 * The fixtures are real Phase 8D models built from hand-built ScanResults, so the
 * query layer is exercised against the contract it will actually receive —
 * including real scanner evidence ids — without touching the filesystem. A couple
 * of hand-built model-shaped objects are used where the *builder* cannot legally
 * produce the shape being tested (a relationship cycle, an entity referencing a
 * missing observation), because the query layer must behave safely over any
 * model-shaped input, not only builder output.
 *
 * Run with: node --test tests/repository-query.test.js
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { createRule } from "../src/core/index.js";

import { createScanResult } from "../src/repository/scanner/index.js";
import {
  COVERAGE_CLASSES,
  COVERAGE_GUARANTEES,
  ENTITY_KINDS,
  QUERY_DIRECTIONS,
  QUERY_ERROR_KINDS,
  QUERY_LIMITS,
  RepositoryQueryError,
  buildRepositoryModel,
  createRepositoryQuery,
  getEntity,
  getEvidence,
  inspectCompleteness,
} from "../src/repository/model/index.js";

import {
  buildAnalysisContext,
  createAnalyzerEngine,
  createAnalyzerRegistry,
} from "../src/analysis/index.js";

import { createRuleAnalyzer } from "../src/rules/index.js";

// ─── Fixtures: real RepositoryModels ─────────────────────────────────────────

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
const sig = (path, signal, extra = {}) => ({ path, signal, ...extra });

const FILE_PATHS = [
  "Dockerfile",
  "README.md",
  "package.json",
  "src/app.js",
  "src/util.js",
  "tests/app.test.js",
  "tsconfig.json",
];

function scanOf(overrides = {}) {
  return createScanResult({
    root: "/scan-root",
    scannedAt: ISO,
    files: filesOf(...FILE_PATHS),
    directories: dirsOf(".github", ".github/workflows", "src", "tests"),
    languages: [
      {
        id: "javascript",
        fileCount: 3,
        extensions: [".js"],
        evidence: [
          sig("src/app.js", "source-extension"),
          sig("src/util.js", "source-extension"),
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
        sig("tests", "test-directory", { kind: "directory", framework: null }),
        sig("tests/app.test.js", "test-file", { kind: "file", framework: "node-test" }),
      ],
      evidenceTruncated: false,
    },
    cicd: {
      detected: true,
      providers: ["github"],
      evidence: [
        sig(".github/workflows/ci.yml", "github-workflow", { provider: "github" }),
      ],
      evidenceTruncated: false,
    },
    documentation: {
      detected: true,
      evidence: [sig("README.md", "readme")],
      evidenceTruncated: false,
    },
    configuration: {
      detected: true,
      evidence: [
        sig("Dockerfile", "container"),
        sig("tsconfig.json", "typescript-config"),
      ],
      evidenceTruncated: false,
    },
    git: {
      detected: true,
      head: { kind: "branch", branch: "main", ref: "refs/heads/main", commit: "abc1234" },
      evidence: [sig(".git/HEAD", "git-head")],
    },
    statistics: {
      filesScanned: FILE_PATHS.length,
      directoriesScanned: 4,
      symlinksScanned: 0,
      ignored: 0,
      unreadable: 0,
      truncatedBy: [],
    },
    scan: { complete: true, truncated: false, limits: { maxFiles: 10000, maxDepth: 20 }, errors: [] },
    ...overrides,
  });
}

const MODEL = buildRepositoryModel(scanOf());

/** Complete scan, but with an ignored policy path and an unreadable path. */
const MODEL_WITH_GAPS = buildRepositoryModel(
  scanOf({
    ignored: [{ path: "vendor", policy: "default-ignored" }],
    statistics: {
      filesScanned: FILE_PATHS.length,
      directoriesScanned: 4,
      symlinksScanned: 0,
      ignored: 1,
      unreadable: 1,
      truncatedBy: [],
    },
    scan: {
      complete: true,
      truncated: false,
      limits: { maxFiles: 10000, maxDepth: 20 },
      errors: [
        {
          kind: "filesystem-error",
          code: "CG_FS_PERMISSION_DENIED",
          operation: "readFile",
          path: "secret.txt",
        },
      ],
    },
  }),
);

/** Incomplete scan: only two files observed, then truncated. */
const MODEL_PARTIAL = buildRepositoryModel(
  createScanResult({
    root: "/scan-root",
    scannedAt: ISO,
    files: filesOf("package.json", "src/app.js"),
    directories: dirsOf("src"),
    languages: [
      {
        id: "javascript",
        fileCount: 1,
        extensions: [".js"],
        evidence: [sig("src/app.js", "source-extension")],
        evidenceTruncated: false,
      },
    ],
    statistics: {
      filesScanned: 2,
      directoriesScanned: 1,
      symlinksScanned: 0,
      ignored: 0,
      unreadable: 0,
      truncatedBy: ["maxFiles"],
    },
    scan: { complete: false, truncated: true, limits: { maxFiles: 2, maxDepth: 20 }, errors: [] },
  }),
);

const queryOf = (model = MODEL) => createRepositoryQuery(model);

const ids = (result) => result.entities.map((entity) => entity.id);

/** A minimal model-shaped object, for shapes the builder cannot legally produce. */
function syntheticModel({ entities = [], relationships = [], evidence = [], scan = {} } = {}) {
  const entitiesById = {};
  for (const entity of [...entities].sort((a, b) => (a.id < b.id ? -1 : 1))) {
    entitiesById[entity.id] = entity;
  }
  const evidenceById = {};
  for (const record of evidence) evidenceById[record.id] = record;
  const relationshipsByFrom = {};
  const relationshipsByTo = {};
  relationships.forEach((relationship, index) => {
    (relationshipsByFrom[relationship.from] ??= []).push(index);
    (relationshipsByTo[relationship.to] ??= []).push(index);
  });
  return {
    identity: { repositoryId: "repository:synthetic", root: "/scan-root", name: null },
    scan: {
      complete: true,
      truncated: false,
      limits: { maxFiles: 100, maxDepth: 20 },
      coverage: { guarantee: "complete", ignored: { paths: [] }, unreadable: { paths: [] } },
      ...scan,
    },
    relationships,
    evidence,
    files: {},
    indexes: { entitiesById, evidenceById, relationshipsByFrom, relationshipsByTo },
  };
}

const fileEntity = (path) => ({
  id: `file:${path}`,
  kind: ENTITY_KINDS.FILE,
  path,
  name: path,
  depth: 1,
  languageId: null,
  directoryId: "repository:synthetic",
  extension: "",
  evidenceIds: [],
});

// ─── Entity queries ──────────────────────────────────────────────────────────

describe("repository query: entity queries", () => {
  it("lists entities by kind in id order", () => {
    const result = queryOf().listEntities(ENTITY_KINDS.FILE);
    assert.deepEqual(
      result.entities.map((entity) => entity.path),
      [...FILE_PATHS],
    );
    assert.ok(Object.isFrozen(result));
  });

  it("gets an entity by id and returns null for an unknown or non-string id", () => {
    const query = queryOf();
    assert.equal(query.getEntity("manifest:package.json").path, "package.json");
    assert.equal(query.getEntity("file:does-not-exist.js"), null);
    assert.equal(query.getEntity(42), null);
    assert.equal(query.getEntity(null), null);
  });

  it("rejects an unknown entity kind instead of returning an empty list", () => {
    assert.throws(
      () => queryOf().listEntities("framwork"),
      (error) => {
        assert.ok(error instanceof RepositoryQueryError);
        assert.equal(error.kind, QUERY_ERROR_KINDS.INVALID_ENTITY_KIND);
        return true;
      },
    );
    assert.throws(() => queryOf().findEntities({ kind: "/etc/passwd" }), RepositoryQueryError);
  });

  it("filters by kind and language", () => {
    const result = queryOf().findEntities({ kind: ENTITY_KINDS.FILE, language: "javascript" });
    assert.deepEqual(
      result.entities.map((entity) => entity.path),
      ["src/app.js", "src/util.js", "tests/app.test.js"],
    );

    // Without the kind filter, the language entity and any manifest that declares
    // the language are included too; results stay sorted by id.
    assert.deepEqual(ids(queryOf().findEntities({ language: "javascript" })), [
      "file:src/app.js",
      "file:src/util.js",
      "file:tests/app.test.js",
      "language:javascript",
      "manifest:package.json",
    ]);
  });

  it("filters by ecosystem, framework and path", () => {
    assert.deepEqual(ids(queryOf().findEntities({ ecosystem: "node" })), [
      "ecosystem:node",
      "manifest:package.json",
    ]);
    assert.deepEqual(ids(queryOf().findEntities({ framework: "node-test" })), [
      "framework:node-test",
      "test:tests/app.test.js",
    ]);
    // The same path can be both a file and a configuration signal; both are real
    // entities and both match an exact-path query.
    assert.deepEqual(ids(queryOf().findEntities({ path: "tsconfig.json" })), [
      "configuration:tsconfig.json",
      "file:tsconfig.json",
    ]);
  });

  it("rejects unknown criteria and a non-relative path", () => {
    assert.throws(() => queryOf().findEntities({ kinds: "file" }), RepositoryQueryError);
    assert.throws(() => queryOf().findEntities({ path: "/etc/passwd" }), RepositoryQueryError);
    assert.throws(() => queryOf().findEntities({ path: "a/../b" }), RepositoryQueryError);
    assert.throws(() => queryOf().findEntities("file"), RepositoryQueryError);
    // A wrong-typed id must not silently match nothing.
    assert.throws(() => queryOf().findEntities({ language: 42 }), RepositoryQueryError);
    assert.throws(() => queryOf().findEntities({ ecosystem: "" }), RepositoryQueryError);
    assert.throws(() => queryOf().findEntities({ framework: null }), RepositoryQueryError);
  });

  it("is deterministic regardless of the order criteria are applied", () => {
    const first = queryOf().findEntities({ language: "javascript", kind: ENTITY_KINDS.FILE });
    const second = queryOf().findEntities({ kind: ENTITY_KINDS.FILE, language: "javascript" });
    assert.deepEqual(first, second);
  });
});

// ─── Relationships ───────────────────────────────────────────────────────────

describe("repository query: relationships", () => {
  it("returns outgoing and incoming relationships deterministically", () => {
    const query = queryOf();
    const out = query.getRelationshipsForEntity("file:src/app.js", {
      direction: QUERY_DIRECTIONS.OUT,
    });
    assert.deepEqual(
      out.relationships.map((relationship) => relationship.type),
      ["located_in", "signals"],
    );

    const incoming = query.getRelationshipsForEntity("directory:src", {
      direction: QUERY_DIRECTIONS.IN,
    });
    assert.ok(incoming.relationships.every((relationship) => relationship.to === "directory:src"));
    assert.ok(incoming.relationships.length >= 3);
  });

  it("sorts merged relationship queries deterministically", () => {
    // This directory has both incoming and outgoing edges whose sources interleave
    // when sorted, so concatenation order and canonical order differ.
    const result = queryOf().getRelationshipsForEntity("directory:.github/workflows", {
      direction: QUERY_DIRECTIONS.BOTH,
    });
    const keys = result.relationships.map((r) => `${r.from}|${r.type}|${r.to}`);
    assert.deepEqual(keys, [...keys].sort());
    assert.ok(result.relationships.length >= 3);
  });

  it("filters by relationship type", () => {
    const result = queryOf().getRelationshipsForEntity("manifest:package.json", {
      type: "declares",
    });
    assert.deepEqual(result.relationships, [
      { from: "manifest:package.json", type: "declares", to: "language:javascript" },
    ]);
  });

  it("returns no relationships for an unknown entity or a non-string id", () => {
    const query = queryOf();
    assert.deepEqual(query.getRelationshipsForEntity("file:nope.js").relationships, []);
    assert.deepEqual(query.getRelationshipsForEntity(42).relationships, []);
  });

  it("lists relationships by filter", () => {
    const result = queryOf().listRelationships({ type: "ecosystem" });
    assert.deepEqual(result.relationships, [
      { from: "manifest:package.json", type: "ecosystem", to: "ecosystem:node" },
    ]);
  });

  it("rejects an unknown relationship type, direction or malformed filter", () => {
    const query = queryOf();
    // `imports` became a documented relationship type in Phase 16, so the unknown
    // type this test needs is one no phase declares.
    assert.throws(() => query.getRelationshipsForEntity("file:src/app.js", { type: "calls" }), RepositoryQueryError);
    assert.throws(() => query.getRelationshipsForEntity("file:src/app.js", { direction: "sideways" }), RepositoryQueryError);
    assert.throws(() => query.listRelationships({ from: 42 }), RepositoryQueryError);
    assert.throws(() => query.listRelationships({ nope: true }), RepositoryQueryError);
  });

  it("de-duplicates a self-loop when querying both directions", () => {
    const model = syntheticModel({
      entities: [fileEntity("a.js")],
      relationships: [{ from: "file:a.js", type: "signals", to: "file:a.js" }],
    });
    const result = queryOf(model).getRelationshipsForEntity("file:a.js", {
      direction: QUERY_DIRECTIONS.BOTH,
    });
    assert.equal(result.relationships.length, 1);
  });
});

// ─── Coverage ────────────────────────────────────────────────────────────────

describe("repository query: coverage", () => {
  it("reports complete coverage and classifies observed vs absent paths", () => {
    const query = queryOf();
    assert.equal(query.coverage().guarantee, COVERAGE_GUARANTEES.COMPLETE);
    assert.equal(query.coverageOfPath("src/app.js"), COVERAGE_CLASSES.OBSERVED);
    assert.equal(query.coverageOfPath("src/missing.js"), COVERAGE_CLASSES.ABSENT);
    assert.equal(query.isKnownAbsent("src/missing.js"), true);
    assert.equal(query.isKnownAbsent("src/app.js"), false);
  });

  it("reports partial coverage and never calls an unobserved path absent", () => {
    const query = queryOf(MODEL_PARTIAL);
    assert.equal(query.coverage().guarantee, COVERAGE_GUARANTEES.PARTIAL);
    assert.equal(query.coverageOfPath("src/app.js"), COVERAGE_CLASSES.OBSERVED);
    assert.equal(query.coverageOfPath("src/never-seen.js"), COVERAGE_CLASSES.UNKNOWN);
    assert.notEqual(query.coverageOfPath("src/never-seen.js"), COVERAGE_CLASSES.ABSENT);
    assert.equal(query.isKnownAbsent("src/never-seen.js"), false);
  });

  it("preserves the ignored and unreadable distinctions", () => {
    const query = queryOf(MODEL_WITH_GAPS);
    assert.equal(query.coverageOfPath("vendor"), COVERAGE_CLASSES.IGNORED);
    assert.equal(query.coverageOfPath("vendor/nested.js"), COVERAGE_CLASSES.IGNORED);
    assert.equal(query.coverageOfPath("secret.txt"), COVERAGE_CLASSES.UNREADABLE);
    assert.equal(query.coverageOfPath("other.txt"), COVERAGE_CLASSES.ABSENT);
  });

  it("treats a non-relative path as unknown, never as absent", () => {
    const query = queryOf();
    assert.equal(query.coverageOfPath("/etc/passwd"), COVERAGE_CLASSES.UNKNOWN);
    assert.equal(query.coverageOfPath("a/../b"), COVERAGE_CLASSES.UNKNOWN);
    assert.equal(query.coverageOfPath(42), COVERAGE_CLASSES.UNKNOWN);
  });

  it("carries the coverage guarantee on every collection envelope", () => {
    const complete = queryOf().listEntities(ENTITY_KINDS.FILE);
    assert.equal(complete.coverage, COVERAGE_GUARANTEES.COMPLETE);
    assert.equal(complete.truncated, false);

    const partial = queryOf(MODEL_PARTIAL).listEntities(ENTITY_KINDS.FILE);
    assert.equal(partial.coverage, COVERAGE_GUARANTEES.PARTIAL);
    assert.equal(partial.truncated, true);
  });
});

// ─── Evidence ────────────────────────────────────────────────────────────────

describe("repository query: evidence", () => {
  it("returns an entity's evidence records, sorted by id", () => {
    const result = queryOf().getEvidenceForEntity("manifest:package.json");
    assert.deepEqual(
      result.evidence.map((record) => record.id),
      [
        "evidence:inventory:package.json",
        "evidence:manifest:manifest-manifest:package.json",
      ],
    );
    assert.ok(result.evidence.every((record) => record.location.path === "package.json"));
  });

  it("returns empty evidence for an unknown entity", () => {
    assert.deepEqual(queryOf().getEvidenceForEntity("file:nope.js").evidence, []);
  });

  it("drops evidence that does not resolve inside the model or is not repository-relative", () => {
    const model = syntheticModel({
      entities: [
        {
          ...fileEntity("a.js"),
          evidenceIds: ["evidence:missing", "evidence:unsafe"],
        },
      ],
      evidence: [
        {
          id: "evidence:unsafe",
          type: "file",
          location: { path: "/etc/passwd" },
          source: {},
          data: {},
          provenance: { deterministic: true },
        },
      ],
    });
    assert.deepEqual(queryOf(model).getEvidenceForEntity("file:a.js").evidence, []);
  });

  it("returns the model's own records unchanged (no fabrication, no re-provenance)", () => {
    const record = getEvidence(MODEL, "evidence:inventory:src/app.js");
    const returned = queryOf().getEvidenceForEntity("file:src/app.js").evidence;
    const match = returned.find((entry) => entry.id === record.id);
    assert.equal(match, record);
  });
});

// ─── Traversal ───────────────────────────────────────────────────────────────

describe("repository query: traversal", () => {
  /** a → b → c → d, all `signals` edges. */
  const chain = syntheticModel({
    entities: [fileEntity("a.js"), fileEntity("b.js"), fileEntity("c.js"), fileEntity("d.js")],
    relationships: [
      { from: "file:a.js", type: "signals", to: "file:b.js" },
      { from: "file:b.js", type: "signals", to: "file:c.js" },
      { from: "file:c.js", type: "signals", to: "file:d.js" },
    ],
  });

  it("depth 0 returns nothing and depth 1 returns direct neighbours", () => {
    const query = queryOf(chain);
    assert.deepEqual(ids(query.findRelatedEntities("file:a.js", { maxDepth: 0 })), []);
    assert.deepEqual(ids(query.findRelatedEntities("file:a.js", { maxDepth: 1 })), ["file:b.js"]);
  });

  it("traverses multiple hops up to maxDepth", () => {
    const query = queryOf(chain);
    assert.deepEqual(ids(query.findRelatedEntities("file:a.js", { maxDepth: 2 })), [
      "file:b.js",
      "file:c.js",
    ]);
    assert.deepEqual(ids(query.findRelatedEntities("file:a.js", { maxDepth: 3 })), [
      "file:b.js",
      "file:c.js",
      "file:d.js",
    ]);
  });

  it("accepts a relationship type as the second argument", () => {
    const result = queryOf(chain).findRelatedEntities("file:a.js", "signals");
    assert.deepEqual(ids(result), ["file:b.js"]);
  });

  it("enforces maxResults and reports that the result was limited", () => {
    const result = queryOf(chain).findRelatedEntities("file:a.js", { maxDepth: 5, maxResults: 2 });
    assert.deepEqual(ids(result), ["file:b.js", "file:c.js"]);
    assert.equal(result.limited, true);
  });

  it("rejects invalid limits and unknown option keys", () => {
    const query = queryOf(chain);
    for (const maxDepth of [NaN, Infinity, -1, 1.5, QUERY_LIMITS.MAX_DEPTH + 1]) {
      assert.throws(() => query.findRelatedEntities("file:a.js", { maxDepth }), RepositoryQueryError, `maxDepth ${maxDepth}`);
    }
    for (const maxResults of [NaN, Infinity, 0, -5, 2.5, QUERY_LIMITS.MAX_RESULTS + 1]) {
      assert.throws(() => query.findRelatedEntities("file:a.js", { maxResults }), RepositoryQueryError, `maxResults ${maxResults}`);
    }
    assert.throws(() => query.findRelatedEntities("file:a.js", { depth: 2 }), RepositoryQueryError);
  });

  it("is deterministic and unaffected by relationship insertion order", () => {
    const reversed = syntheticModel({
      entities: [fileEntity("a.js"), fileEntity("b.js"), fileEntity("c.js"), fileEntity("d.js")],
      relationships: [
        { from: "file:c.js", type: "signals", to: "file:d.js" },
        { from: "file:b.js", type: "signals", to: "file:c.js" },
        { from: "file:a.js", type: "signals", to: "file:b.js" },
      ],
    });
    assert.deepEqual(
      ids(queryOf(chain).findRelatedEntities("file:a.js", { maxDepth: 5 })),
      ids(queryOf(reversed).findRelatedEntities("file:a.js", { maxDepth: 5 })),
    );
  });

  it("terminates on a cyclic relationship graph", () => {
    const cyclic = syntheticModel({
      entities: [fileEntity("a.js"), fileEntity("b.js")],
      relationships: [
        { from: "file:a.js", type: "signals", to: "file:b.js" },
        { from: "file:b.js", type: "signals", to: "file:a.js" },
      ],
    });
    const result = queryOf(cyclic).findRelatedEntities("file:a.js", { maxDepth: QUERY_LIMITS.MAX_DEPTH });
    // The cycle must not loop forever, and the start node is not re-reported.
    assert.deepEqual(ids(result), ["file:b.js"]);
  });

  it("only returns entities that actually exist in the model", () => {
    const broken = syntheticModel({
      entities: [fileEntity("a.js"), fileEntity("b.js")],
      relationships: [
        { from: "file:a.js", type: "signals", to: "file:ghost.js" },
        { from: "file:a.js", type: "signals", to: "file:b.js" },
      ],
    });
    const result = queryOf(broken).findRelatedEntities("file:a.js", { maxDepth: 1 });
    assert.deepEqual(ids(result), ["file:b.js"]);
    assert.ok(result.entities.every((entity) => getEntity(broken, entity.id) !== undefined));
  });

  it("follows incoming relationships when asked", () => {
    const result = queryOf(chain).findRelatedEntities("file:d.js", {
      direction: QUERY_DIRECTIONS.IN,
      maxDepth: 1,
    });
    assert.deepEqual(ids(result), ["file:c.js"]);
  });
});

// ─── Immutability ────────────────────────────────────────────────────────────

describe("repository query: immutability", () => {
  it("freezes every result envelope and its collections", () => {
    const query = queryOf();
    assert.ok(Object.isFrozen(query));
    const list = query.listEntities(ENTITY_KINDS.FILE);
    assert.ok(Object.isFrozen(list));
    assert.ok(Object.isFrozen(list.entities));
    assert.throws(() => {
      list.entities.push("nope");
    }, TypeError);
  });

  it("does not let a caller mutate the model through returned values", () => {
    const query = queryOf();
    const entity = query.getEntity("file:src/app.js");
    assert.ok(Object.isFrozen(entity));
    assert.throws(() => {
      entity.path = "hacked.js";
    }, TypeError);

    const before = inspectCompleteness(MODEL);
    const returned = query.listEntities(ENTITY_KINDS.FILE);
    // A returned collection cannot be mutated in place, so it can never reach the
    // model; a caller that wants a modified list must copy it.
    assert.throws(() => {
      returned.entities.splice(0, 1);
    }, TypeError);
    assert.equal(MODEL.files.count, FILE_PATHS.length);
    assert.deepEqual(inspectCompleteness(MODEL), before);
    assert.equal(query.getEntity("file:Dockerfile").path, "Dockerfile");
  });

  it("still sees the same model across repeated queries", () => {
    const query = queryOf();
    const first = query.listEntities(ENTITY_KINDS.FILE).entities.map((entity) => entity.id);
    assert.deepEqual(query.listEntities(ENTITY_KINDS.FILE).entities.map((entity) => entity.id), first);
  });
});

// ─── Semantic helpers ────────────────────────────────────────────────────────

describe("repository query: semantic helpers", () => {
  it("exposes thin views over the query API", () => {
    const query = queryOf();
    assert.deepEqual(
      query.filesByLanguage("javascript").entities.map((entity) => entity.path),
      ["src/app.js", "src/util.js", "tests/app.test.js"],
    );
    assert.deepEqual(
      ids(query.manifestsByEcosystem("node")),
      ["manifest:package.json"],
    );
    assert.deepEqual(ids(query.frameworksObserved()), ["framework:node-test"]);
    assert.deepEqual(ids(query.testsForFramework("node-test")), ["test:tests/app.test.js"]);
  });
});

// ─── Validation errors ───────────────────────────────────────────────────────

describe("repository query: validation", () => {
  it("rejects a value that is not model-shaped", () => {
    for (const value of [null, {}, { indexes: {} }, "model", { scan: {} }]) {
      assert.throws(
        () => createRepositoryQuery(value),
        (error) => {
          assert.ok(error instanceof RepositoryQueryError);
          assert.equal(error.kind, QUERY_ERROR_KINDS.INVALID_MODEL);
          return true;
        },
      );
    }
  });

  it("produces a serializable, path-safe error", () => {
    let captured = null;
    try {
      queryOf().listEntities("/etc/passwd");
    } catch (error) {
      captured = error;
    }
    const serialized = JSON.stringify(captured);
    assert.ok(!serialized.includes("/etc/passwd"), "must not reflect a hostile value");
    assert.ok(!serialized.includes("stack"));
    assert.equal(captured.code, "CG_QUERY_ENTITY_KIND_INVALID");
    assert.equal(captured.expose, true);
    assert.equal(captured.details.received, null);
  });
});

// ─── Architectural boundary ──────────────────────────────────────────────────

describe("repository query: architectural boundary", () => {
  const DIR = join(dirname(fileURLToPath(import.meta.url)), "..", "src", "repository", "model");
  const files = ["query-api.js", "query-contracts.js", "query-errors.js"];

  it("imports only Core and sibling model modules", () => {
    for (const file of files) {
      const source = readFileSync(join(DIR, file), "utf8");
      // Matches both `import ... from "x"` and a bare `import "x"`.
      const imports = [...source.matchAll(/(?:from|import)\s+"([^"]+)"/g)].map(
        (match) => match[1],
      );
      for (const specifier of imports) {
        assert.ok(
          specifier === "../../core/index.js" || specifier.startsWith("."),
          `${file} imports a disallowed module "${specifier}"`,
        );
      }
    }
  });

  it("has no filesystem, process, network, worker or transport access", () => {
    const forbidden = [
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
      "tools.js",
      "tool-registry",
    ];
    for (const file of files) {
      const source = readFileSync(join(DIR, file), "utf8");
      for (const needle of forbidden) {
        assert.ok(!source.includes(`"${needle}"`), `${file} must not reference "${needle}"`);
      }
    }
  });
});

// ─── Rule engine integration ─────────────────────────────────────────────────

describe("repository query: rule engine integration", () => {
  it("lets a rule query the repository and reach the Phase 9 finding engine", async () => {
    const rule = createRule({
      id: "testing.container-without-config",
      version: "1.0.0",
      category: "testing",
      title: "Container without a matching config",
      description: "fixture",
      severity: "low",
      applicability: {},
      detect: (context) => {
        const query = createRepositoryQuery(context.repository);
        const container = query.findEntities({ path: "Dockerfile" });
        if (container.entities.length === 0) return [];
        const evidence = query.getEvidenceForEntity(container.entities[0].id);
        return [
          {
            confidence: 1,
            evidence: evidence.evidence.map((record) => record.id),
            title: "container observed",
          },
        ];
      },
      remediation: {},
      metadata: {},
    });

    const analyzer = createRuleAnalyzer({
      id: "testing.rules",
      name: "Testing rules",
      version: "1.0.0",
      scope: "testing",
      rules: [rule],
    });

    const engine = createAnalyzerEngine({ registry: createAnalyzerRegistry([analyzer]) });
    const result = await engine.runAll(buildAnalysisContext({ repository: MODEL }));

    assert.equal(result.analyzers[0].status, "completed");
    assert.equal(result.findings.length, 1);
    assert.ok(result.findings[0].fingerprint.startsWith("cg-fp1-"));
    assert.ok(result.findings[0].evidence.length >= 1);
  });

  it("gives a rule no capability beyond the frozen model it already receives", async () => {
    let received = null;
    const rule = createRule({
      id: "testing.context-probe",
      version: "1.0.0",
      category: "testing",
      title: "probe",
      description: "",
      severity: "info",
      applicability: {},
      detect: (context) => {
        received = context;
        return [];
      },
      remediation: {},
      metadata: {},
    });
    const analyzer = createRuleAnalyzer({
      id: "testing.rules",
      name: "Testing rules",
      version: "1.0.0",
      scope: "testing",
      rules: [rule],
    });
    const engine = createAnalyzerEngine({ registry: createAnalyzerRegistry([analyzer]) });
    await engine.runAll(buildAnalysisContext({ repository: MODEL }));

    for (const capability of ["filesystem", "fs", "spawn", "exec", "fetch", "mcp", "tools"]) {
      assert.equal(capability in received, false);
    }
    assert.equal(received.repository, MODEL);
  });
});
