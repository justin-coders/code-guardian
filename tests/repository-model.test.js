/**
 * Code Guardian — RepositoryModel Tests (Phase 8D)
 *
 * Two kinds of fixture are used deliberately:
 *
 *   - hand-built `ScanResult` literals, so hostile and inconsistent *inputs* can be
 *     stated exactly (an absolute path, a `..`, a missing parent directory), which
 *     a real scan would never produce;
 *   - a real `scanRepository` run over a temporary repository, so the model is also
 *     proven end-to-end against the accepted Phase 8C output.
 *
 * No test spawns a process, touches the network, or writes to the repository under
 * test.
 *
 * Run with: node --test tests/repository-model.test.js
 */

import { after, describe, it } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

import {
  REPOSITORY_MODEL_JUDGMENT_AREAS,
  REPOSITORY_MODEL_OPTIONAL_AREAS,
  REPOSITORY_MODEL_VERSION,
  ValidationError,
  createRepositoryModel,
  validateRepositoryModel,
} from "../src/core/index.js";

import { createScanResult, scanRepository } from "../src/repository/scanner/index.js";

import {
  COVERAGE_CLASSES,
  COVERAGE_GUARANTEES,
  ENTITY_KINDS,
  EVIDENCE_SUBJECTS,
  GIT_HEAD_KINDS,
  GRAPH_ENTITY_KINDS,
  MODEL_IMMUTABILITY,
  RELATIONSHIP_TYPES,
  TEST_KINDS,
  buildRepositoryModel,
  coverageClass,
  entityIdsForEvidence,
  getDirectoryByPath,
  getEntity,
  getEntityEvidence,
  getEvidence,
  getFileByPath,
  getManifestByPath,
  inspectCompleteness,
  isKnownAbsent,
  listEntitiesByKind,
  listFilesByLanguage,
  listManifestsByEcosystem,
  listRelationships,
  relationshipsFrom,
  relationshipsTo,
  validateRepositoryModelGraph,
} from "../src/repository/model/index.js";

// ─── Fixtures ────────────────────────────────────────────────────────────────

const ISO = "2026-01-01T00:00:00.000Z";
const SCAN_ROOT = "/scan-root";

const TMP_ROOT = join(tmpdir(), `cg-model-${process.pid}-${Date.now()}`);
let counter = 0;

function makeRepo(files = {}, dirs = []) {
  const root = join(TMP_ROOT, `repo-${counter++}`);
  mkdirSync(root, { recursive: true });
  for (const dir of dirs) mkdirSync(join(root, dir), { recursive: true });
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

const byPath = (a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0);

function toEntry(path, { isDirectory = false } = {}) {
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

const entriesOf = (...paths) => paths.map((path) => toEntry(path)).sort(byPath);
const dirsOf = (...paths) => paths.map((path) => toEntry(path, { isDirectory: true })).sort(byPath);

/**
 * A ScanResult literal, defaulting to a complete empty scan.
 *
 * The scanner's draft factory refuses to claim completeness on its own, so the
 * fixture states it explicitly — exactly as `scanRepository` does.
 */
function scanOf(overrides = {}) {
  return createScanResult({
    root: SCAN_ROOT,
    scannedAt: ISO,
    scan: { complete: true, truncated: false, limits: { maxFiles: 10000, maxDepth: 20 }, errors: [] },
    ...overrides,
  });
}

function language(id, extensions, evidence, fileCount = evidence.length) {
  return { id, fileCount, extensions, evidence, evidenceTruncated: false };
}

function signal(path, signalId, extra = {}) {
  return { path, signal: signalId, ...extra };
}

/** A content-inspection candidate record, defaulting to a fully inspected file. */
function candidate(path, extra = {}) {
  return {
    path,
    candidate: "npm-config",
    inspected: true,
    reason: null,
    bytesInspected: 0,
    truncated: false,
    patterns: [],
    ...extra,
  };
}

/** A representative populated scan, used by many construction tests. */
function populatedScan(overrides = {}) {
  return scanOf({
    files: entriesOf(
      "package.json",
      "src/app.ts",
      "src/util.ts",
      "tests/app.test.ts",
      "README.md",
      ".github/workflows/ci.yml",
      "tsconfig.json",
    ),
    directories: dirsOf("src", "tests", ".github", ".github/workflows"),
    // The scan contract requires languages sorted by id; the model preserves that.
    languages: [
      language("javascript", [], [signal("package.json", "manifest")], 0),
      language(
        "typescript",
        [".ts"],
        [signal("src/app.ts", "source-extension"), signal("src/util.ts", "source-extension")],
      ),
    ],
    manifests: [
      {
        path: "package.json",
        name: "package.json",
        directory: ".",
        ecosystem: "node",
        kind: "manifest",
        languages: ["javascript"],
        parse: { status: "parsed", format: "json", bytes: 12, metadata: { name: "demo" } },
      },
    ],
    tests: {
      detected: true,
      frameworks: ["jest"],
      evidence: [
        signal("tests", "test-directory", { kind: "directory", framework: null }),
        signal("tests/app.test.ts", "test-file", { kind: "file", framework: "jest" }),
      ],
      evidenceTruncated: false,
    },
    cicd: {
      detected: true,
      providers: ["github-actions"],
      evidence: [signal(".github/workflows/ci.yml", "ci-configuration", { provider: "github-actions" })],
      evidenceTruncated: false,
    },
    documentation: {
      detected: true,
      evidence: [signal("README.md", "readme", { isDirectory: false })],
      evidenceTruncated: false,
    },
    configuration: {
      detected: true,
      evidence: [signal("tsconfig.json", "build-configuration")],
      evidenceTruncated: false,
    },
    git: {
      detected: true,
      head: { kind: "branch", branch: "main", ref: "refs/heads/main" },
      evidence: [signal(".git", "git-directory")],
    },
    statistics: {
      filesScanned: 7,
      directoriesScanned: 4,
      symlinksScanned: 0,
      ignored: 0,
      unreadable: 0,
      truncatedBy: [],
    },
    ...overrides,
  });
}

const pathList = (entities) => entities.map((entry) => entry.path);
const ids = (entities) => entities.map((entry) => entry.id);
const relative = (relationships) =>
  relationships.map((relationship) => `${relationship.from} -${relationship.type}-> ${relationship.to}`);

// ─── Construction ────────────────────────────────────────────────────────────

describe("model: construction", () => {
  it("builds a complete, empty model from an empty scan", () => {
    const model = buildRepositoryModel(scanOf());

    assert.equal(model.version, REPOSITORY_MODEL_VERSION);
    assert.deepEqual(model.files.entries, []);
    assert.deepEqual(model.files.directories, []);
    assert.deepEqual(model.languages, []);
    assert.deepEqual(model.manifests.entries, []);
    assert.deepEqual(model.tests.entries, []);
    assert.equal(model.scan.complete, true);
    assert.equal(model.scan.truncated, false);
    assert.equal(model.scan.coverage.guarantee, COVERAGE_GUARANTEES.COMPLETE);
    assert.equal(model.metadata.entityCount, 1); // the git entity only
  });

  it("provides every contracted Core area, including the optional ones", () => {
    const model = buildRepositoryModel(scanOf());
    for (const area of [...REPOSITORY_MODEL_OPTIONAL_AREAS]) {
      assert.ok(area in model, `model should provide "${area}"`);
    }
    assert.equal(validateRepositoryModel(model), model);
    assert.equal(validateRepositoryModelGraph(model), model);
  });

  it("represents files, directories and symlinks as entities with ids", () => {
    const model = buildRepositoryModel(populatedScan());
    assert.deepEqual(pathList(model.files.entries), [
      ".github/workflows/ci.yml",
      "README.md",
      "package.json",
      "src/app.ts",
      "src/util.ts",
      "tests/app.test.ts",
      "tsconfig.json",
    ]);
    assert.deepEqual(pathList(model.files.directories), [
      ".github",
      ".github/workflows",
      "src",
      "tests",
    ]);
    for (const file of model.files.entries) {
      assert.equal(file.id, `file:${file.path}`);
      assert.equal(file.kind, ENTITY_KINDS.FILE);
      assert.ok(file.evidenceIds.length >= 1);
    }
  });

  it("models mixed languages, manifests, tests, CI, documentation and configuration", () => {
    const model = buildRepositoryModel(populatedScan());

    assert.deepEqual(model.languages.map((l) => l.languageId), ["javascript", "typescript"]);
    assert.deepEqual(model.manifests.entries.map((m) => m.path), ["package.json"]);
    assert.deepEqual(model.manifests.ecosystems.map((e) => e.name), ["node"]);
    assert.deepEqual(model.manifests.entries[0].languages, ["language:javascript"]);
    assert.equal(model.manifests.entries[0].parse.status, "parsed");
    assert.equal(model.manifests.entries[0].parse.metadata.name, "demo");

    assert.deepEqual(pathList(model.tests.entries), ["tests", "tests/app.test.ts"]);
    assert.deepEqual(model.tests.frameworks, ["jest"]);
    assert.deepEqual(model.ci.providers, ["github-actions"]);
    assert.deepEqual(pathList(model.ci.entries), [".github/workflows/ci.yml"]);
    assert.deepEqual(pathList(model.documentation.entries), ["README.md"]);
    assert.deepEqual(pathList(model.configuration.entries), ["tsconfig.json"]);
    assert.equal(model.configuration.entries[0].signal, "build-configuration");
    assert.equal(model.git.entity.detected, true);
    assert.deepEqual(model.git.entity.head, {
      kind: "branch",
      branch: "main",
      ref: "refs/heads/main",
    });
  });

  it("records the file language signal from the scan's own extension table", () => {
    const model = buildRepositoryModel(populatedScan());
    assert.equal(getFileByPath(model, "src/app.ts").languageId, "language:typescript");
    assert.equal(getFileByPath(model, "package.json").languageId, null);
  });

  it("does not invent a primary language", () => {
    const model = buildRepositoryModel(populatedScan());
    for (const entry of model.languages) {
      assert.ok(!("primary" in entry));
      assert.ok(!("primaryLanguage" in entry));
    }
  });

  it("models a nested repository through the real scanner", async () => {
    const root = makeRepo({
      "index.js": "",
      "src/deep/nested/file.js": "",
      "lib/util.js": "",
    });
    const scan = await scanRepository(root);
    const model = buildRepositoryModel(scan);

    assert.equal(model.identity.root, scan.root);
    assert.deepEqual(pathList(model.files.directories), ["lib", "src", "src/deep", "src/deep/nested"]);
    assert.equal(
      getDirectoryByPath(model, "src/deep").parentId,
      "directory:src",
    );
    assert.equal(getFileByPath(model, "src/deep/nested/file.js").directoryId, "directory:src/deep/nested");
    assert.deepEqual(listFilesByLanguage(model, "javascript").map((f) => f.path), [
      "index.js",
      "lib/util.js",
      "src/deep/nested/file.js",
    ]);
  });

  it("uses only the documented entity kinds, test kinds, head kinds and relationships", () => {
    const model = buildRepositoryModel(populatedScan());
    for (const entity of Object.values(model.indexes.entitiesById)) {
      assert.ok(
        GRAPH_ENTITY_KINDS.includes(entity.kind),
        `undocumented entity kind "${entity.kind}"`,
      );
    }
    for (const test of model.tests.entries) {
      assert.ok(Object.values(TEST_KINDS).includes(test.testKind));
    }
    assert.ok(Object.values(GIT_HEAD_KINDS).includes(model.git.entity.head.kind));
    assert.equal(RELATIONSHIP_TYPES.IMPORTS, undefined, "there is no import graph yet");
  });

  it("keeps dependency, script and architecture intelligence deliberately empty", () => {
    const model = buildRepositoryModel(populatedScan());
    assert.deepEqual(model.dependencies, {});
    assert.deepEqual(model.scripts, {});
    assert.deepEqual(model.architecture, {});
    for (const relationship of model.relationships) {
      assert.ok(
        ["contains", "parent", "located_in", "signals", "declares", "ecosystem", "framework"].includes(
          relationship.type,
        ),
        `unexpected relationship type "${relationship.type}"`,
      );
    }
  });
});

// ─── Identity ────────────────────────────────────────────────────────────────

describe("model: identity", () => {
  it("derives ids from kind and path, never from randomness", () => {
    const model = buildRepositoryModel(populatedScan());
    assert.equal(getFileByPath(model, "README.md").id, "file:README.md");
    assert.equal(getDirectoryByPath(model, "src").id, "directory:src");
    assert.equal(getManifestByPath(model, "package.json").id, "manifest:package.json");
    assert.equal(model.tests.entries[0].id, "test:tests");
    assert.equal(model.ci.entries[0].id, "cicd:.github/workflows/ci.yml");
    assert.equal(model.git.entity.id, "git");
    assert.match(model.identity.repositoryId, /^repository:[0-9a-f]{8}$/);
  });

  it("keeps ids stable for the same repository state", () => {
    const first = buildRepositoryModel(populatedScan());
    const second = buildRepositoryModel(populatedScan());
    assert.equal(first.identity.repositoryId, second.identity.repositoryId);
    assert.deepEqual(ids(first.files.entries), ids(second.files.entries));
  });

  it("changes the repository id when the observed inventory changes", () => {
    const original = buildRepositoryModel(populatedScan());
    const changed = buildRepositoryModel(
      populatedScan({ files: entriesOf("index.js") }),
    );
    assert.notEqual(original.identity.repositoryId, changed.identity.repositoryId);
  });

  it("does not put an absolute path into any id", () => {
    const model = buildRepositoryModel(populatedScan());
    for (const entity of Object.values(model.indexes.entitiesById)) {
      assert.ok(!entity.id.includes(SCAN_ROOT), `id leaked the scan root: ${entity.id}`);
      assert.ok(!entity.id.startsWith("/"), `id must not be absolute: ${entity.id}`);
    }
  });

  it("rejects duplicate entity ids from a contradictory scan", () => {
    const duplicated = populatedScan({
      files: entriesOf("src/app.ts", "src/app.ts"),
    });
    assert.throws(() => buildRepositoryModel(duplicated), (error) => {
      assert.ok(error instanceof ValidationError);
      assert.equal(error.details.contract, "ScanResult");
      return true;
    });
  });
});

// ─── Relationships ───────────────────────────────────────────────────────────

describe("model: relationships", () => {
  it("connects the repository to every entity", () => {
    const model = buildRepositoryModel(populatedScan());
    const contained = listRelationships(model, {
      from: model.identity.repositoryId,
      type: RELATIONSHIP_TYPES.CONTAINS,
    }).map((relationship) => relationship.to);
    const allIds = Object.keys(model.indexes.entitiesById);
    for (const id of allIds) {
      assert.ok(contained.includes(id), `"${id}" must be contained by the repository`);
    }
  });

  it("records directory parent relationships down to the root", () => {
    const model = buildRepositoryModel(populatedScan());
    assert.equal(getDirectoryByPath(model, "src").parentId, null);
    assert.equal(getDirectoryByPath(model, ".github/workflows").parentId, "directory:.github");
    assert.deepEqual(
      relative(relationshipsFrom(model, "directory:.github/workflows")),
      ["directory:.github/workflows -parent-> directory:.github"],
    );
  });

  it("locates files and directories in their parent, or in the repository at the root", () => {
    const model = buildRepositoryModel(populatedScan());
    assert.deepEqual(relative(relationshipsFrom(model, "file:src/app.ts")), [
      "file:src/app.ts -located_in-> directory:src",
      "file:src/app.ts -signals-> language:typescript",
    ]);
    assert.deepEqual(relative(listRelationships(model, { from: "file:README.md" })), [
      `file:README.md -located_in-> ${model.identity.repositoryId}`,
    ]);
  });

  it("links manifests to their ecosystem and declared languages", () => {
    const model = buildRepositoryModel(populatedScan());
    const manifestEdges = relative(relationshipsFrom(model, "manifest:package.json"));
    assert.deepEqual(manifestEdges, [
      "manifest:package.json -declares-> language:javascript",
      "manifest:package.json -ecosystem-> ecosystem:node",
      "manifest:package.json -located_in-> " + model.identity.repositoryId,
    ]);
  });

  it("links test evidence to its framework", () => {
    const model = buildRepositoryModel(populatedScan());
    assert.deepEqual(relative(relationshipsFrom(model, "test:tests/app.test.ts")), [
      "test:tests/app.test.ts -framework-> framework:jest",
      "test:tests/app.test.ts -located_in-> directory:tests",
    ]);
  });

  it("keeps relationships deterministically sorted", () => {
    const model = buildRepositoryModel(populatedScan());
    const serialized = model.relationships.map(
      (relationship) => `${relationship.from}\u0000${relationship.type}\u0000${relationship.to}`,
    );
    assert.deepEqual(serialized, [...serialized].sort());
  });

  it("never references an unknown endpoint", () => {
    const model = buildRepositoryModel(populatedScan());
    const known = new Set([...Object.keys(model.indexes.entitiesById), model.identity.repositoryId]);
    for (const relationship of model.relationships) {
      assert.ok(known.has(relationship.from));
      assert.ok(known.has(relationship.to));
    }
  });
});

// ─── Evidence / provenance ───────────────────────────────────────────────────

describe("model: evidence", () => {
  it("traces every entity back to scanner observations", () => {
    const model = buildRepositoryModel(populatedScan());
    for (const entity of Object.values(model.indexes.entitiesById)) {
      if (entity.kind === ENTITY_KINDS.GIT && entity.detected === false) continue;
      assert.ok(entity.evidenceIds.length >= 1, `${entity.id} must reference an observation`);
    }
  });

  it("keeps multiple provenance references for a doubly-observed path", () => {
    const model = buildRepositoryModel(populatedScan());
    const testFile = getFileByPath(model, "tests/app.test.ts");
    assert.ok(testFile.evidenceIds.includes("evidence:inventory:tests/app.test.ts"));
    assert.ok(testFile.evidenceIds.includes("evidence:test:test-file:tests/app.test.ts"));

    const subjects = getEntityEvidence(model, "file:tests/app.test.ts").map(
      (record) => `${record.source.analyzer}:${record.type}`,
    );
    assert.deepEqual(subjects, [
      "phase-8d-repository-model:file",
      "phase-8d-repository-model:test",
    ]);
  });

  it("stores Core Evidence records with explicit deterministic provenance", () => {
    const model = buildRepositoryModel(populatedScan());
    assert.ok(model.evidence.length > 0);
    for (const record of model.evidence) {
      assert.equal(record.provenance.deterministic, true);
      assert.equal(record.provenance.collector, "phase-8c-repository-scanner");
      assert.ok(record.location.path.length > 0);
      assert.equal(record.cause, undefined);
      assert.equal(record.stack, undefined);
      assert.ok(!JSON.stringify(record).includes("stack"));
    }
  });

  it("keeps observation ids unique and repository-relative", () => {
    const model = buildRepositoryModel(populatedScan());
    const seen = new Set();
    for (const record of model.evidence) {
      assert.ok(!seen.has(record.id), `duplicate observation id ${record.id}`);
      seen.add(record.id);
      assert.ok(!record.location.path.startsWith("/"));
    }
  });

  it("indexes evidence in both directions", () => {
    const model = buildRepositoryModel(populatedScan());
    // One observation legitimately supports more than one entity: `README.md` was
    // observed once and modelled as both a file and a documentation artifact.
    assert.deepEqual(entityIdsForEvidence(model, "evidence:inventory:README.md"), [
      "documentation:README.md",
      "file:README.md",
    ]);
    assert.equal(getEvidence(model, "evidence:inventory:README.md").type, "file");
    assert.equal(getEvidence(model, "evidence:does-not-exist"), null);
    assert.deepEqual(getEntityEvidence(model, "file:does-not-exist"), []);
  });

  it("emits the documented observation subjects", () => {
    // One candidate whose content was fully inspected, and one the inspection could
    // not reach, so the content subject is exercised in both of its two shapes.
    const model = buildRepositoryModel(
      populatedScan({
        content: {
          inspected: true,
          complete: false,
          truncated: true,
          candidates: [
            candidate("README.md", { candidate: "dotenv", bytesInspected: 42, patterns: ["credential-assignment"] }),
            candidate("tsconfig.json", { candidate: "build-config", inspected: false, reason: "budget-exhausted" }),
          ],
          limits: { maxFileBytes: 65536, maxTotalBytes: 262144, maxFiles: 12 },
        },
      }),
    );
    const subjects = new Set(
      model.evidence.map((record) => record.id.split(":")[1]),
    );
    for (const subject of Object.values(EVIDENCE_SUBJECTS)) {
      assert.ok(subjects.has(subject), `expected an observation for subject "${subject}"`);
    }
  });
});

// ─── Completeness ────────────────────────────────────────────────────────────

describe("model: completeness", () => {
  it("reports a complete scan as a complete guarantee", () => {
    const model = buildRepositoryModel(populatedScan());
    const completeness = inspectCompleteness(model);
    assert.equal(completeness.complete, true);
    assert.equal(completeness.guarantee, COVERAGE_GUARANTEES.COMPLETE);
    assert.equal(coverageClass(model, "src/missing.ts"), COVERAGE_CLASSES.ABSENT);
    assert.equal(isKnownAbsent(model, "src/missing.ts"), true);
  });

  it("never lets a truncated scan become a complete model", () => {
    const model = buildRepositoryModel(
      populatedScan({
        statistics: {
          filesScanned: 7,
          directoriesScanned: 4,
          symlinksScanned: 0,
          ignored: 0,
          unreadable: 0,
          truncatedBy: ["file-limit"],
        },
        scan: {
          complete: false,
          truncated: true,
          limits: { maxFiles: 5, maxDepth: 20 },
          errors: [],
        },
      }),
    );

    assert.equal(model.scan.complete, false);
    assert.equal(model.scan.truncated, true);
    assert.equal(model.files.truncated, true);
    assert.equal(model.scan.coverage.guarantee, COVERAGE_GUARANTEES.PARTIAL);
    assert.deepEqual(model.scan.coverage.truncatedBy, ["file-limit"]);
    // An unobserved path is *unknown*, not absent: the scan stopped early.
    assert.equal(coverageClass(model, "src/missing.ts"), COVERAGE_CLASSES.UNKNOWN);
    assert.equal(isKnownAbsent(model, "src/missing.ts"), false);
  });

  it("reports depth truncation separately from file truncation", () => {
    const model = buildRepositoryModel(
      populatedScan({
        statistics: {
          filesScanned: 7,
          directoriesScanned: 4,
          symlinksScanned: 0,
          ignored: 0,
          unreadable: 0,
          truncatedBy: ["depth-limit"],
        },
        scan: {
          complete: false,
          truncated: true,
          limits: { maxFiles: 10000, maxDepth: 2 },
          errors: [],
        },
      }),
    );
    assert.deepEqual(model.scan.coverage.truncatedBy, ["depth-limit"]);
    assert.equal(model.scan.coverage.guarantee, COVERAGE_GUARANTEES.PARTIAL);
  });

  it("keeps ignored paths distinct from unreadable paths", () => {
    const model = buildRepositoryModel(
      populatedScan({
        ignored: [{ path: "vendor", name: "vendor", isDirectory: true, policy: "default-directory" }],
        statistics: {
          filesScanned: 7,
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
          errors: [{ kind: "permission-error", code: "EACCES", operation: "read", path: "private" }],
        },
      }),
    );

    assert.equal(coverageClass(model, "vendor"), COVERAGE_CLASSES.IGNORED);
    assert.equal(coverageClass(model, "vendor/deep/file.js"), COVERAGE_CLASSES.IGNORED);
    assert.equal(coverageClass(model, "private"), COVERAGE_CLASSES.UNREADABLE);
    assert.equal(coverageClass(model, "private/secret.js"), COVERAGE_CLASSES.UNREADABLE);
    assert.equal(coverageClass(model, "src/app.ts"), COVERAGE_CLASSES.OBSERVED);
    assert.equal(coverageClass(model, "src/missing.ts"), COVERAGE_CLASSES.ABSENT);
    // An ignored path was seen; it is not evidence that anything is missing.
    assert.equal(isKnownAbsent(model, "vendor"), false);
    assert.deepEqual(model.scan.errors, [
      { kind: "permission-error", code: "EACCES", operation: "read", path: "private" },
    ]);
  });

  it("treats a path outside the repository as unknown, never absent", () => {
    const model = buildRepositoryModel(populatedScan());
    assert.equal(coverageClass(model, "/etc/passwd"), COVERAGE_CLASSES.UNKNOWN);
    assert.equal(coverageClass(model, "../outside"), COVERAGE_CLASSES.UNKNOWN);
    assert.equal(isKnownAbsent(model, "/etc/passwd"), false);
  });

  it("refuses a ScanResult that claims to be complete and truncated", () => {
    assert.throws(
      () =>
        buildRepositoryModel(
          scanOf({ scan: { complete: true, truncated: true, limits: {}, errors: [] } }),
        ),
      ValidationError,
    );
  });
});

// ─── Queryability ────────────────────────────────────────────────────────────

describe("model: queryability", () => {
  it("looks entities up by id and path", () => {
    const model = buildRepositoryModel(populatedScan());
    assert.equal(getEntity(model, "file:src/app.ts").path, "src/app.ts");
    assert.equal(getEntity(model, "nope:nope"), null);
    assert.equal(getFileByPath(model, "src/app.ts").id, "file:src/app.ts");
    assert.equal(getFileByPath(model, "src"), null);
    assert.equal(getDirectoryByPath(model, "src").id, "directory:src");
    assert.equal(getManifestByPath(model, "package.json").ecosystemId, "ecosystem:node");
    assert.equal(getFileByPath(model, "/etc/passwd"), null);
    assert.equal(getFileByPath(model, "../x"), null);
  });

  it("lists entities by kind", () => {
    const model = buildRepositoryModel(populatedScan());
    assert.deepEqual(ids(listEntitiesByKind(model, ENTITY_KINDS.MANIFEST)), [
      "manifest:package.json",
    ]);
    assert.deepEqual(listEntitiesByKind(model, "unknown-kind"), []);
  });

  it("lists files by language and manifests by ecosystem", () => {
    const model = buildRepositoryModel(populatedScan());
    assert.deepEqual(pathList(listFilesByLanguage(model, "typescript")), [
      "src/app.ts",
      "src/util.ts",
      "tests/app.test.ts",
    ]);
    assert.deepEqual(pathList(listManifestsByEcosystem(model, "node")), ["package.json"]);
    assert.deepEqual(listFilesByLanguage(model, "cobol"), []);
    assert.deepEqual(listManifestsByEcosystem(model, "cobol"), []);
  });

  it("filters relationships by from, to and type", () => {
    const model = buildRepositoryModel(populatedScan());
    assert.equal(listRelationships(model, { type: RELATIONSHIP_TYPES.PARENT }).length, 1);
    assert.equal(relationshipsTo(model, "directory:src").length >= 1, true);
    assert.equal(
      listRelationships(model, { from: "file:src/app.ts", type: RELATIONSHIP_TYPES.SIGNALS }).length,
      1,
    );
    // The `to` index must agree with a brute-force filter.
    const bruteForce = model.relationships.filter(
      (relationship) => relationship.to === "language:typescript",
    );
    assert.deepEqual(relationshipsTo(model, "language:typescript"), bruteForce);
  });

  it("summarises coverage without judging anything", () => {
    const model = buildRepositoryModel(populatedScan());
    const completeness = inspectCompleteness(model);
    assert.deepEqual(Object.keys(completeness).sort(), [
      "complete",
      "errors",
      "guarantee",
      "ignoredCount",
      "limits",
      "observed",
      "truncated",
      "truncatedBy",
      "unreadableCount",
    ]);
  });
});

// ─── Determinism ─────────────────────────────────────────────────────────────

describe("model: determinism", () => {
  it("produces an identical model for identical input", () => {
    const scan = populatedScan();
    const first = buildRepositoryModel(scan);
    const second = buildRepositoryModel(scan);
    assert.deepEqual(second, first);
    assert.equal(JSON.stringify(second), JSON.stringify(first));
  });

  it("does not depend on the scan timestamp or the host root", () => {
    const first = buildRepositoryModel(populatedScan());
    const second = buildRepositoryModel(
      populatedScan({ root: "/another/root", scannedAt: "2030-12-31T23:59:59.000Z" }),
    );

    const strip = (model) => {
      const clone = JSON.parse(JSON.stringify(model));
      clone.identity.root = null;
      clone.identity.provenance.scannedAt = null;
      clone.metadata.scanScannedAt = null;
      return clone;
    };

    assert.deepEqual(strip(second), strip(first));
    assert.equal(second.identity.repositoryId, first.identity.repositoryId);
  });

  it("serialises deterministically through JSON for a real scan", async () => {
    const root = makeRepo({ "package.json": "{}", "src/a.js": "", "src/b.js": "" });
    const scan = await scanRepository(root);
    const first = JSON.stringify(buildRepositoryModel(scan));
    const second = JSON.stringify(buildRepositoryModel(scan));
    assert.equal(first, second);
  });
});

// ─── Invalid input ───────────────────────────────────────────────────────────

describe("model: invalid input", () => {
  it("rejects a ScanResult that is not contract-valid", () => {
    assert.throws(() => buildRepositoryModel({ files: [] }), ValidationError);
    assert.throws(
      () => buildRepositoryModel(createScanResult({ root: SCAN_ROOT })),
      ValidationError,
      "a scan without scannedAt must be rejected",
    );
    assert.throws(() => buildRepositoryModel(null), ValidationError);
  });

  it("rejects a file whose parent directory was never observed", () => {
    assert.throws(
      () => buildRepositoryModel(populatedScan({ directories: [] })),
      (error) => {
        assert.ok(error instanceof ValidationError);
        assert.equal(error.details.contract, "ScanResult");
        assert.ok(error.details.issues.some((issue) => issue.includes("parent directory")));
        return true;
      },
    );
  });

  it("rejects a manifest that declares an unobserved language", () => {
    assert.throws(
      () =>
        buildRepositoryModel(
          populatedScan({
            manifests: [
              {
                path: "package.json",
                name: "package.json",
                directory: ".",
                ecosystem: "node",
                kind: "manifest",
                languages: ["cobol"],
                parse: { status: "parsed", format: "json" },
              },
            ],
          }),
        ),
      (error) => {
        assert.ok(error.details.issues.some((issue) => issue.includes("declared language")));
        return true;
      },
    );
  });

  it("rejects a language reported without evidence", () => {
    assert.throws(
      () => buildRepositoryModel(populatedScan({ languages: [language("typescript", [".ts"], [])] })),
      ValidationError,
    );
  });

  it("drops a framework claim the scan cannot support with evidence", () => {
    const model = buildRepositoryModel(
      populatedScan({
        tests: {
          detected: true,
          frameworks: ["jest", "ghost"],
          evidence: [signal("tests/app.test.ts", "test-file", { kind: "file", framework: "jest" })],
          evidenceTruncated: false,
        },
      }),
    );
    assert.deepEqual(model.tests.frameworks, ["jest"]);
    assert.deepEqual(ids(model.frameworks), ["framework:jest"]);
  });

  it("rejects an undocumented manifest parse status", () => {
    assert.throws(
      () =>
        buildRepositoryModel(
          populatedScan({
            manifests: [
              {
                path: "package.json",
                name: "package.json",
                directory: ".",
                ecosystem: "node",
                kind: "manifest",
                languages: ["javascript"],
                parse: { status: "totally-fine", format: "json" },
              },
            ],
          }),
        ),
      ValidationError,
    );
  });

  it("rejects an undocumented test evidence kind", () => {
    assert.throws(
      () =>
        buildRepositoryModel(
          populatedScan({
            tests: {
              detected: true,
              frameworks: [],
              evidence: [signal("tests/app.test.ts", "test-file", { kind: "script", framework: null })],
              evidenceTruncated: false,
            },
          }),
        ),
      ValidationError,
    );
  });

  it("rejects git detected without any observation", () => {
    assert.throws(
      () => buildRepositoryModel(populatedScan({ git: { detected: true, head: null, evidence: [] } })),
      ValidationError,
    );
  });

  it("rejects a model literal whose graph contradicts itself", () => {
    const model = JSON.parse(JSON.stringify(buildRepositoryModel(populatedScan())));

    const withGhostEdge = JSON.parse(JSON.stringify(model));
    withGhostEdge.relationships.push({ from: "file:src/app.ts", type: "contains", to: "file:ghost" });
    assert.throws(() => validateRepositoryModelGraph(withGhostEdge), ValidationError);

    const withUnknownType = JSON.parse(JSON.stringify(model));
    withUnknownType.relationships[0].type = "imports";
    assert.throws(() => validateRepositoryModelGraph(withUnknownType), ValidationError);

    const withDuplicateId = JSON.parse(JSON.stringify(model));
    withDuplicateId.languages[0].id = "file:src/app.ts";
    assert.throws(() => validateRepositoryModelGraph(withDuplicateId), ValidationError);

    // A nested directory that claims to have no parent, and a file that claims
    // the wrong containing directory, are both contradictions.
    const withBrokenParent = JSON.parse(JSON.stringify(model));
    withBrokenParent.files.directories.find(
      (directory) => directory.path === ".github/workflows",
    ).parentId = null;
    assert.throws(() => validateRepositoryModelGraph(withBrokenParent), ValidationError);

    const withBrokenContainment = JSON.parse(JSON.stringify(model));
    withBrokenContainment.files.entries.find((file) => file.path === "src/app.ts").directoryId =
      withBrokenContainment.identity.repositoryId;
    assert.throws(() => validateRepositoryModelGraph(withBrokenContainment), ValidationError);
  });

  it("rejects a model whose completeness guarantee contradicts its scan state", () => {
    const model = JSON.parse(JSON.stringify(buildRepositoryModel(populatedScan())));
    model.scan.complete = false;
    assert.throws(() => validateRepositoryModelGraph(model), ValidationError);
  });

  it("rejects a model that loses provenance", () => {
    const model = JSON.parse(JSON.stringify(buildRepositoryModel(populatedScan())));
    model.files.entries[0].evidenceIds = [];
    assert.throws(() => validateRepositoryModelGraph(model), ValidationError);
  });

  it("rejects a model that drops the graph from its indexes", () => {
    const model = JSON.parse(JSON.stringify(buildRepositoryModel(populatedScan())));
    delete model.indexes.entitiesById["file:src/app.ts"];
    assert.throws(() => validateRepositoryModelGraph(model), ValidationError);
  });
});

// ─── Security / boundary ─────────────────────────────────────────────────────

describe("model: security", () => {
  it("rejects absolute entity paths", () => {
    for (const path of ["/etc/passwd", "C:/Windows/system32", "C:\\Windows", "//host/share"]) {
      assert.throws(
        () => buildRepositoryModel(populatedScan({ files: entriesOf(path) })),
        (error) => {
          assert.ok(error instanceof ValidationError);
          assert.equal(error.details.contract, "RepositoryModelPath");
          return true;
        },
        `must reject "${path}"`,
      );
    }
  });

  it("rejects traversal, dotted, backslash and NUL paths", () => {
    for (const path of ["../escape", "a/../../x", "./a.js", "a//b.js", "a/./b.js", "a\\b.js", "a\u0000b.js", "src/"]) {
      assert.throws(
        () => buildRepositoryModel(populatedScan({ files: entriesOf(path) })),
        ValidationError,
        `must reject "${JSON.stringify(path)}"`,
      );
    }
  });

  it("rejects hostile paths injected through non-inventory sections", () => {
    assert.throws(
      () =>
        buildRepositoryModel(
          populatedScan({
            ignored: [{ path: "/etc", name: "etc", isDirectory: true, policy: "gitignore" }],
          }),
        ),
      ValidationError,
    );
    assert.throws(
      () =>
        buildRepositoryModel(
          populatedScan({
            scan: {
              complete: true,
              truncated: false,
              limits: {},
              errors: [{ kind: "permission-error", code: "EACCES", operation: "read", path: "/etc/shadow" }],
            },
          }),
        ),
      ValidationError,
    );
    assert.throws(
      () =>
        buildRepositoryModel(
          populatedScan({
            documentation: {
              detected: true,
              evidence: [signal("../../.ssh/id_rsa", "readme", { isDirectory: false })],
              evidenceTruncated: false,
            },
          }),
        ),
      ValidationError,
    );
  });

  it("never echoes a rejected path back in the error", () => {
    const error = (() => {
      try {
        buildRepositoryModel(populatedScan({ files: entriesOf("/etc/passwd") }));
        return null;
      } catch (caught) {
        return caught;
      }
    })();
    assert.ok(error instanceof ValidationError);
    assert.ok(!JSON.stringify(error.toJSON()).includes("/etc/passwd"));
  });

  it("projects a hostile git HEAD into the closed head vocabulary", () => {
    for (const head of [
      { kind: "branch", branch: "/etc/passwd", ref: "/etc/passwd" },
      { kind: "branch", branch: "../../escape", ref: "refs/heads/../../x" },
      { kind: "branch", branch: "main", ref: "C:/Windows" },
      { kind: "detached", commit: "../../secret" },
      { kind: "detached", commit: "AKIA-not-a-commit" },
      { kind: "totally-made-up" },
      { malicious: true },
    ]) {
      const model = buildRepositoryModel(populatedScan({ git: { detected: true, head, evidence: [signal(".git", "git-directory")] } }));
      const serialized = JSON.stringify(model.git.entity);
      assert.ok(!serialized.includes("/etc"), `head leaked a host path: ${serialized}`);
      assert.ok(!serialized.includes(".."), `head leaked traversal: ${serialized}`);
      assert.ok(!serialized.includes("AKIA"), `head leaked arbitrary text: ${serialized}`);
      assert.ok(
        ["branch", "detached", "gitfile", "unknown"].includes(model.git.entity.head.kind),
      );
    }
  });

  it("keeps the absolute scan root out of everything but identity.root", async () => {
    const root = makeRepo({ "package.json": "{}", "src/app.js": "", ".gitignore": "dist\n" });
    const scan = await scanRepository(root);
    const model = buildRepositoryModel(scan);
    const serialized = JSON.stringify(model);
    const occurrences = serialized.split(JSON.stringify(root)).length - 1;
    assert.equal(occurrences, 1, "the absolute root must appear exactly once (identity.root)");
    assert.equal(model.identity.root, root);
    for (const record of model.evidence) {
      assert.ok(!JSON.stringify(record).includes(root));
    }
  });

  it("never fabricates a host path from a relative scan", () => {
    const model = buildRepositoryModel(populatedScan());
    const serialized = JSON.stringify(model);
    assert.ok(!/[A-Za-z]:\\\\/.test(serialized));
    assert.ok(!serialized.includes("file://"));
  });
});

// ─── Immutability and Core integration ───────────────────────────────────────

describe("model: immutability", () => {
  it("returns a deeply frozen model", () => {
    const model = buildRepositoryModel(populatedScan());
    assert.equal(Object.isFrozen(model), true);
    assert.equal(Object.isFrozen(model.files), true);
    assert.equal(Object.isFrozen(model.files.entries[0]), true);
    assert.equal(Object.isFrozen(model.files.entries[0].evidenceIds), true);
    assert.equal(Object.isFrozen(model.indexes.entitiesById), true);
    assert.equal(Object.isFrozen(model.indexes.entitiesById["file:src/app.ts"]), true);
    assert.equal(Object.isFrozen(model.relationships[0]), true);
    assert.equal(Object.isFrozen(model.evidence[0]), true);
    assert.equal(Object.isFrozen(model.scan.coverage), true);
    assert.equal(model.metadata.immutability, MODEL_IMMUTABILITY);
  });

  it("cannot be mutated by an analyzer", () => {
    const model = buildRepositoryModel(populatedScan());
    assert.throws(() => {
      model.files.entries[0].path = "tampered";
    }, TypeError);
    assert.throws(() => {
      model.relationships.push({ from: "x", type: "contains", to: "y" });
    }, TypeError);
    assert.equal(getFileByPath(model, "README.md").path, "README.md");
  });

  it("records no judgment areas", () => {
    const model = buildRepositoryModel(populatedScan());
    for (const judgment of REPOSITORY_MODEL_JUDGMENT_AREAS) {
      assert.ok(!(judgment in model), `"${judgment}" must not appear in the model`);
    }
    const serialized = JSON.stringify(model);
    for (const judgment of REPOSITORY_MODEL_JUDGMENT_AREAS) {
      assert.ok(!serialized.includes(`"${judgment}"`));
    }
  });

  it("stays a valid Core RepositoryModel while the Core factory keeps its defaults", () => {
    const draft = createRepositoryModel();
    assert.equal(draft.scan.complete, false);
    for (const area of REPOSITORY_MODEL_OPTIONAL_AREAS) assert.ok(area in draft);
    assert.equal(validateRepositoryModel(draft), draft);

    // Core validates the nested graph structures it now knows about.
    const invalidRelationships = { ...draft, relationships: [{ from: "a", type: "", to: "b" }] };
    assert.throws(() => validateRepositoryModel(invalidRelationships), ValidationError);
    const invalidEvidence = { ...draft, evidence: [{ id: "e1" }] };
    assert.throws(() => validateRepositoryModel(invalidEvidence), ValidationError);
    const invalidIndexes = { ...draft, indexes: [] };
    assert.throws(() => validateRepositoryModel(invalidIndexes), ValidationError);
  });
});

// ─── Architectural boundary ──────────────────────────────────────────────────

describe("model: architectural boundary", () => {
  const MODEL_DIR = join(process.cwd(), "src", "repository", "model");
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
    "../filesystem",
    "../../execution",
    "../execution",
    "tools.js",
    "tool-registry",
  ];
  const ALLOWED_PREFIXES = ["../../core/index.js", "../scanner/index.js"];

  const sources = readdirSync(MODEL_DIR)
    .filter((name) => name.endsWith(".js"))
    .map((name) => ({ name, text: readFileSync(join(MODEL_DIR, name), "utf8") }));

  it("imports nothing but the Core and the scanner boundary", () => {
    assert.ok(sources.length > 0);
    for (const { name, text } of sources) {
      for (const match of text.matchAll(/from\s+"([^"]+)"/g)) {
        const specifier = match[1];
        const allowed =
          specifier.startsWith("./") ||
          ALLOWED_PREFIXES.includes(specifier);
        assert.ok(allowed, `${name} imports "${specifier}"`);
      }
      for (const match of text.matchAll(/import\s*\(\s*"([^"]+)"\s*\)/g)) {
        assert.fail(`${name} uses a dynamic import of "${match[1]}"`);
      }
    }
  });

  it("never reaches for the filesystem, a process, the network or the clock", () => {
    for (const { name, text } of sources) {
      for (const forbidden of FORBIDDEN) {
        assert.ok(!text.includes(`"${forbidden}"`), `${name} references "${forbidden}"`);
      }
      assert.ok(!/\bnew Date\b/.test(text), `${name} must not construct a Date`);
      assert.ok(!/\bDate\.now\b/.test(text), `${name} must not read the clock`);
      assert.ok(!/\bMath\.random\b/.test(text), `${name} must not use randomness`);
      assert.ok(!/\bprocess\.env\b/.test(text), `${name} must not read the environment`);
    }
  });

  it("builds the model without ever scanning the repository itself", async () => {
    const root = makeRepo({ "a.js": "" });
    const scan = await scanRepository(root);
    rmSync(root, { recursive: true, force: true });
    // The scan's root no longer exists, so a builder that rescanned would fail.
    const model = buildRepositoryModel(scan);
    assert.equal(model.files.entries[0].path, "a.js");
  });
});
