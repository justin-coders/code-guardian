/**
 * Code Guardian — Dependency Intelligence Tests (Phase 13)
 *
 * Two fixture styles, chosen deliberately:
 *
 *   - **real repositories** written to a temporary directory and scanned through the
 *     accepted Phase 8A boundary and Phase 8C scanner, so acquisition, the scan
 *     contract, the model builder and the query layer are exercised end to end. This
 *     is the only way to prove that a parser, a budget and a contract agree.
 *   - **hand-built ScanResults** for inputs a real scan would never produce (a
 *     traversal path, an absolute path, an unobserved source, an unsafe name), so the
 *     fail-closed behaviour can be stated exactly.
 *
 * No test spawns a process, contacts a network, installs a package or writes to the
 * repository under test.
 *
 * Run with: node --test tests/dependency-intelligence.test.js
 */

import { after, describe, it } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { ValidationError } from "../src/core/index.js";

import {
  DEPENDENCY_LIMITS,
  DEPENDENCY_SCOPES,
  DEPENDENCY_SOURCE_STATUSES,
  DEPENDENCY_SPEC_KINDS,
  SCAN_SIGNALS,
  createScanResult,
  scanRepository,
  validateScanResult,
} from "../src/repository/scanner/index.js";

import {
  COVERAGE_GUARANTEES,
  ENTITY_KINDS,
  RepositoryQueryError,
  buildRepositoryModel,
  createRepositoryQuery,
  validateRepositoryModelGraph,
} from "../src/repository/model/index.js";

import {
  createAnalyzerEngine,
  createAnalyzerRegistry,
  buildAnalysisContext,
} from "../src/analysis/index.js";
import { createRuleEngine } from "../src/rules/index.js";
import {
  DEPENDENCY_ANALYZER_ID,
  DEPENDENCY_CONFIDENCE,
  DEPENDENCY_RULE_IDS,
  MAX_DECLARATION_FINDINGS,
  RULE_OUTCOME_STATUSES,
  createDependencyAnalyzer,
  createDependencyRuleRegistry,
  dependencyRuleSetIssues,
  dependencyRules,
} from "../src/rules/index.js";

// ─── Fixtures ────────────────────────────────────────────────────────────────

const TMP_ROOT = join(tmpdir(), `cg-deps-${process.pid}-${Date.now()}`);
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

/** A dependency entity's declarations, flattened to `name@manifest:scope`. */
const declarationKeys = (dependency) =>
  dependency.declarations.map((entry) => `${entry.manifestPath}:${entry.scope}`);

const idsOf = (entities) => entities.map((entity) => entity.id);

// ─── Acquisition: node ───────────────────────────────────────────────────────

describe("dependency acquisition: node manifests", () => {
  it("records each declaration section with the scope the format establishes", async () => {
    const { model, query } = await scanOf({
      "package.json": packageJson({
        name: "demo",
        dependencies: { react: "^19.0.0" },
        devDependencies: { jest: "^29.0.0" },
        optionalDependencies: { fsevents: "^2.3.0" },
        peerDependencies: { "react-dom": "^19.0.0" },
      }),
    });

    assert.equal(model.dependencies.count, 4);
    const byName = new Map(
      query.listDependencies().entities.map((entity) => [entity.name, entity]),
    );

    assert.deepEqual(byName.get("react").scopes, [DEPENDENCY_SCOPES.RUNTIME]);
    assert.deepEqual(byName.get("jest").scopes, [DEPENDENCY_SCOPES.DEVELOPMENT]);
    assert.deepEqual(byName.get("fsevents").scopes, [DEPENDENCY_SCOPES.OPTIONAL]);
    assert.deepEqual(byName.get("react-dom").scopes, [DEPENDENCY_SCOPES.PEER]);

    // Directness comes from the manifest section, never from the package name.
    for (const declaration of query.directDependencies().entities) {
      assert.equal(declaration.direct, true);
    }
    assert.equal(model.dependencies.coverage.complete, true);
    assert.equal(model.dependencies.coverage.inspected, true);
    assert.deepEqual(model.dependencies.sources.map((source) => source.status), ["parsed"]);
  });

  it("classifies registry, local, git, url, workspace and alias specifiers", async () => {
    const { query } = await scanOf({
      "package.json": packageJson({
        dependencies: {
          alias: "npm:other@^1.0.0",
          "from-git": "git+https://example.invalid/x.git",
          "from-url": "https://example.invalid/x.tgz",
          local: "file:../left-pad",
          plain: "^1.2.3",
          ws: "workspace:*",
        },
      }),
    });

    const kinds = new Map(
      query.listDependencies().entities.map((entity) => [
        entity.name,
        entity.declarations[0].specKind,
      ]),
    );
    assert.equal(kinds.get("plain"), DEPENDENCY_SPEC_KINDS.REGISTRY);
    assert.equal(kinds.get("ws"), DEPENDENCY_SPEC_KINDS.WORKSPACE);
    assert.equal(kinds.get("local"), DEPENDENCY_SPEC_KINDS.LOCAL);
    assert.equal(kinds.get("from-git"), DEPENDENCY_SPEC_KINDS.GIT);
    assert.equal(kinds.get("from-url"), DEPENDENCY_SPEC_KINDS.URL);
    assert.equal(kinds.get("alias"), DEPENDENCY_SPEC_KINDS.ALIAS);
  });

  it("preserves a duplicate declaration in one manifest instead of choosing", async () => {
    const { model, query } = await scanOf({
      "package.json": packageJson({
        dependencies: { react: "^19.0.0" },
        devDependencies: { react: "^18.0.0" },
      }),
    });

    const dependency = query.getDependencyByName("node", "react");
    assert.equal(dependency.declarations.length, 2);
    assert.deepEqual([...dependency.scopes].sort(), ["development", "runtime"]);
    assert.deepEqual(
      dependency.declarations.map((entry) => entry.spec).sort(),
      ["^18.0.0", "^19.0.0"],
    );
    assert.equal(model.dependencies.sources[0].problems.includes("duplicate-declaration"), true);
    assert.equal(model.dependencies.coverage.complete, false);
  });

  it("rejects hostile dependency names without carrying them into the model", async () => {
    const { model, query } = await scanOf({
      "package.json": packageJson({
        dependencies: {
          "../evil": "1.0.0",
          "UPPER": "1.0.0",
          "has space": "1.0.0",
          good: "1.0.0",
        },
      }),
    });

    assert.deepEqual(idsOf(query.listDependencies().entities), ["dependency:node:good"]);
    const problems = model.dependencies.sources[0].problems;
    assert.equal(problems.filter((reason) => reason === "invalid-name").length, 3);
    const serialized = JSON.stringify(model.dependencies);
    for (const hostile of ["../evil", "UPPER", "has space"]) {
      assert.ok(!serialized.includes(hostile), `"${hostile}" must not reach the model`);
    }
  });

  it("keeps a declaration whose specifier is unusable, and reports the specifier", async () => {
    const { model, query } = await scanOf({
      "package.json": packageJson({ dependencies: { react: { version: "^19.0.0" } } }),
    });

    const dependency = query.getDependencyByName("node", "react");
    assert.equal(dependency.declarations[0].spec, null);
    assert.equal(dependency.declarations[0].specKind, DEPENDENCY_SPEC_KINDS.UNKNOWN);
    assert.equal(model.dependencies.sources[0].problems.includes("invalid-spec"), true);
  });

  it("reports an empty dependency set as established, not as unknown", async () => {
    const { model, query } = await scanOf({
      "package.json": packageJson({ name: "demo", dependencies: {} }),
    });

    assert.equal(model.dependencies.count, 0);
    assert.equal(model.dependencies.coverage.complete, true);
    assert.equal(model.dependencies.coverage.inspected, true);
    assert.deepEqual(query.dependencyCoverage().unestablishedSources, []);
  });

  it("records a malformed manifest as a failure without losing the other sources", async () => {
    const { model } = await scanOf({
      "package.json": "{ not json",
      "go.mod": "module example.invalid/x\n\nrequire example.invalid/y v1.2.3\n",
    });

    const statuses = new Map(
      model.dependencies.sources.map((source) => [source.path, `${source.status}:${source.reason}`]),
    );
    assert.equal(statuses.get("package.json"), "failed:invalid-json");
    assert.equal(statuses.get("go.mod"), "parsed:null");
    assert.equal(model.dependencies.coverage.complete, false);
    assert.equal(model.dependencies.coverage.inspected, true);
  });

  it("records every uninterpreted format as unsupported, never as empty", async () => {
    const { model, scan } = await scanOf({
      "Cargo.toml": '[package]\nname = "demo"\n\n[dependencies]\nserde = "1"\n',
      "pnpm-lock.yaml": "lockfileVersion: '9.0'\n",
      "pyproject.toml": "[project]\nname = \"demo\"\ndependencies = [\"requests\"]\n",
    });

    assert.equal(model.dependencies.count, 0, "an unparsed format declares nothing *known*");
    for (const source of model.dependencies.sources) {
      assert.equal(source.status, "unsupported");
      assert.equal(source.reason, "format-not-interpreted");
    }
    assert.equal(model.dependencies.coverage.complete, false);
    // The manifest inventory itself is unaffected: identification is Phase 8C's job.
    assert.deepEqual(
      scan.manifests.map((entry) => entry.path),
      ["Cargo.toml", "pnpm-lock.yaml", "pyproject.toml"],
    );
  });
});

// ─── Acquisition: python and go ──────────────────────────────────────────────

describe("dependency acquisition: python and go manifests", () => {
  it("parses requirements.txt with PEP 508 normalization", async () => {
    const { model, query } = await scanOf({
      "requirements.txt": [
        "# runtime",
        "Flask==3.0.1",
        "requests[security]>=2.31,<3 ; python_version >= \"3.9\"",
        "urlpkg @ https://example.invalid/pkg.tar.gz",
        "bare-name",
        "--index-url https://example.invalid/simple",
        "-e git+https://example.invalid/repo.git#egg=thing",
        "-r other.txt",
      ].join("\n"),
    });

    const byName = new Map(
      query.listDependencies().entities.map((entity) => [entity.name, entity]),
    );
    assert.deepEqual([...byName.keys()].sort(), ["bare-name", "flask", "requests", "urlpkg"]);
    assert.equal(byName.get("flask").declarations[0].spec, "==3.0.1");
    assert.equal(byName.get("requests").declarations[0].spec, ">=2.31,<3");
    assert.equal(byName.get("requests").declarations[0].conditional, true);
    assert.equal(byName.get("flask").declarations[0].conditional, false);
    assert.equal(byName.get("urlpkg").declarations[0].specKind, DEPENDENCY_SPEC_KINDS.URL);
    assert.equal(byName.get("bare-name").declarations[0].spec, null);

    const problems = model.dependencies.sources[0].problems;
    assert.equal(problems.includes("editable-requirement"), true);
    assert.equal(problems.includes("include-directive"), true);
    assert.equal(
      problems.includes("invalid-name"),
      false,
      "an option line is not a malformed requirement",
    );
  });

  it("reads go.mod requirements and Go's own indirect marker", async () => {
    const { model, query } = await scanOf({
      "go.mod": [
        "module example.invalid/app",
        "",
        "go 1.22",
        "",
        "require example.invalid/direct v1.2.3",
        "",
        "require (",
        "\texample.invalid/indirect v0.4.0 // indirect",
        "\texample.invalid/second v2.0.0",
        ")",
        "",
        "replace example.invalid/old => example.invalid/new v1.0.0",
      ].join("\n"),
    });

    const byName = new Map(
      query.listDependencies().entities.map((entity) => [entity.name, entity]),
    );
    assert.equal(byName.get("example.invalid/direct").direct, true);
    assert.equal(byName.get("example.invalid/second").direct, true);
    assert.equal(byName.get("example.invalid/indirect").direct, false);
    assert.equal(byName.get("example.invalid/indirect").declared, true);
    assert.equal(
      model.dependencies.sources[0].problems.includes("replace-directive"),
      true,
      "a replace directive changes resolution and must be reported, not ignored",
    );
  });
});

// ─── Acquisition: lockfiles ──────────────────────────────────────────────────

describe("dependency acquisition: lockfiles", () => {
  const LOCK_V3 = packageJson({
    name: "demo",
    lockfileVersion: 3,
    packages: {
      "": { name: "demo", dependencies: { react: "^19.0.0" } },
      "node_modules/react": { version: "19.1.0", dependencies: { "loose-envify": "^1.1.0" } },
      "node_modules/loose-envify": { version: "1.4.0", dependencies: { "js-tokens": "^4.0.0" } },
      "node_modules/js-tokens": { version: "4.0.0" },
      "packages/workspace-a": { version: "1.0.0", dependencies: { react: "^19.0.0" } },
      "node_modules/linked": { link: true },
    },
  });

  it("resolves packages and edges from a v3 packages map", async () => {
    const { model, query } = await scanOf({
      "package.json": packageJson({ dependencies: { react: "^19.0.0" } }),
      "package-lock.json": LOCK_V3,
    });

    assert.deepEqual(idsOf(query.resolvedDependencies().entities), [
      "dependency:node:js-tokens",
      "dependency:node:loose-envify",
      "dependency:node:react",
    ]);
    // A workspace folder is not a resolved dependency; a link entry has no version.
    assert.equal(query.getDependencyByName("node", "packages/workspace-a"), null);
    assert.equal(query.getDependencyByName("node", "linked"), null);

    assert.deepEqual(
      query
        .dependencyRelationships("dependency:node:react")
        .relationships.filter((edge) => edge.type === "depends-on")
        .map((edge) => edge.to),
      ["dependency:node:loose-envify"],
    );
  });

  it("marks lockfile-only packages as resolved but not direct", async () => {
    const { query } = await scanOf({
      "package.json": packageJson({ dependencies: { react: "^19.0.0" } }),
      "package-lock.json": LOCK_V3,
    });

    assert.equal(query.getDependencyByName("node", "react").direct, true);
    assert.equal(query.getDependencyByName("node", "react").resolved, true);
    assert.equal(query.getDependencyByName("node", "js-tokens").direct, false);
    assert.equal(query.getDependencyByName("node", "js-tokens").resolved, true);

    assert.deepEqual(idsOf(query.transitiveDependencies().entities), [
      "dependency:node:js-tokens",
      "dependency:node:loose-envify",
    ]);
  });

  it("walks a v1 nested tree with its requires edges", async () => {
    const { query } = await scanOf({
      "package.json": packageJson({ dependencies: { a: "^1.0.0" } }),
      "package-lock.json": packageJson({
        name: "demo",
        lockfileVersion: 1,
        dependencies: {
          a: {
            version: "1.0.0",
            requires: { b: "^1.0.0" },
            dependencies: { b: { version: "1.2.0" } },
          },
        },
      }),
    });

    assert.deepEqual(idsOf(query.resolvedDependencies().entities), [
      "dependency:node:a",
      "dependency:node:b",
    ]);
    assert.deepEqual(
      query
        .dependencyRelationships("dependency:node:a")
        .relationships.filter((edge) => edge.type === "depends-on")
        .map((edge) => edge.to),
      ["dependency:node:b"],
    );
  });

  it("records an unrecognised lockfile structure as unsupported", async () => {
    const { model } = await scanOf({
      "package.json": packageJson({ name: "demo" }),
      "package-lock.json": packageJson({ name: "demo", lockfileVersion: 7, whatever: {} }),
    });

    const lockfile = model.dependencies.sources.find(
      (source) => source.path === "package-lock.json",
    );
    assert.equal(lockfile.status, "unsupported");
    assert.equal(lockfile.reason, "format-not-interpreted");
    assert.equal(lockfile.detail, "lockfile-structure");
  });

  it("bounds a pathologically deep v1 lockfile instead of recursing", async () => {
    let node = { version: "1.0.0" };
    for (let depth = 0; depth < 80; depth += 1) {
      node = { version: "1.0.0", dependencies: { [`p${depth}`]: node } };
    }
    const { model, query } = await scanOf({
      "package.json": packageJson({ name: "demo" }),
      "package-lock.json": packageJson({ lockfileVersion: 1, dependencies: { root: node } }),
    });

    const lockfile = model.dependencies.sources.find(
      (source) => source.path === "package-lock.json",
    );
    assert.equal(lockfile.problems.includes("depth-limit"), true);
    assert.ok(
      query.listDependencies().entities.length <= DEPENDENCY_LIMITS.maxResolved + 1,
      "a deep tree must stay bounded",
    );
  });
});

// ─── Multi-manifest repositories ─────────────────────────────────────────────

describe("dependency intelligence: multiple manifests", () => {
  it("keeps one entity per package with a declaration per manifest", async () => {
    // The two manifests declare different *scopes* as well as different versions, so
    // the ordering assertion below distinguishes "ordered by manifest" from
    // "ordered by scope" — the two only disagree in a fixture shaped like this one.
    const { model, query } = await scanOf({
      "frontend/package.json": packageJson({ devDependencies: { react: "^19.0.0" } }),
      "backend/package.json": packageJson({ dependencies: { react: "^18.0.0" } }),
    });

    assert.equal(model.dependencies.count, 1, "one dependency, two declarations");
    const dependency = query.getDependencyByName("node", "react");
    assert.deepEqual(declarationKeys(dependency), [
      "backend/package.json:runtime",
      "frontend/package.json:development",
    ]);
    assert.deepEqual(
      dependency.declarations.map((entry) => entry.spec),
      ["^18.0.0", "^19.0.0"],
      "contradictory declarations are both preserved, never reconciled",
    );

    assert.deepEqual(
      idsOf(query.manifestsForDependency(dependency.id).entities),
      ["manifest:backend/package.json", "manifest:frontend/package.json"],
    );
    assert.deepEqual(
      idsOf(query.dependenciesForManifest("manifest:backend/package.json").entities),
      ["dependency:node:react"],
    );
    const frontend = query.dependenciesForManifest("manifest:frontend/package.json")
      .entities[0]
      .declarations.find((entry) => entry.manifestPath === "frontend/package.json");
    assert.equal(frontend.spec, "^19.0.0", "each manifest's own specifier is preserved");
    assert.equal(frontend.scope, DEPENDENCY_SCOPES.DEVELOPMENT);
    assert.equal(
      query.getDependencyByName("node", "react").declarations.find(
        (entry) => entry.manifestPath === "backend/package.json",
      ).scope,
      DEPENDENCY_SCOPES.RUNTIME,
      "one dependency can carry two scopes, one per declaring manifest",
    );
  });

  it("keeps the same package name in two ecosystems apart", async () => {
    const { model, query } = await scanOf({
      "package.json": packageJson({ dependencies: { requests: "^1.0.0" } }),
      "requirements.txt": "requests==2.31.0\n",
    });

    assert.equal(model.dependencies.count, 2);
    assert.equal(query.findDependencies({ ecosystem: "python" }).entities.length, 1);
    assert.equal(query.findDependencies({ ecosystem: "node" }).entities.length, 1);
    assert.deepEqual(idsOf(query.findDependencies({ ecosystem: "python" }).entities), [
      "dependency:python:requests",
    ]);
  });

  it("associates each manifest with its own ecosystem and dependencies", async () => {
    const { query } = await scanOf({
      "services/api/requirements.txt": "flask==3.0.1\n",
      "services/worker/requirements.txt": "celery==5.3.0\n",
    });

    assert.equal(
      query.findDependencies({ manifest: "manifest:services/api/requirements.txt" }).entities[0]
        .name,
      "flask",
    );
    assert.equal(
      query.findDependencies({ manifest: "manifest:services/worker/requirements.txt" }).entities[0]
        .name,
      "celery",
    );
    assert.equal(query.findDependencies({ name: "flask" }).entities.length, 1);
  });
});

// ─── Bounds and coverage ─────────────────────────────────────────────────────

describe("dependency intelligence: bounds and coverage", () => {
  it("does not read a manifest larger than the documented bound", async () => {
    const huge = JSON.stringify({
      name: "demo",
      dependencies: Object.fromEntries(
        Array.from({ length: 40000 }, (_entry, index) => [`package-name-${index}`, "^1.0.0"]),
      ),
    });
    assert.ok(huge.length > DEPENDENCY_LIMITS.maxManifestBytes);
    const { model } = await scanOf({ "package.json": huge });

    const source = model.dependencies.sources[0];
    assert.equal(source.status, DEPENDENCY_SOURCE_STATUSES.FAILED);
    assert.equal(source.reason, "exceeds-max-manifest-bytes");
    assert.equal(model.dependencies.coverage.truncated, true);
    assert.equal(model.dependencies.count, 0);
  });

  it("records a source it never read because the budget was spent", async () => {
    const files = {};
    for (let index = 0; index < DEPENDENCY_LIMITS.maxManifests + 1; index += 1) {
      files[`p${String(index).padStart(3, "0")}/package.json`] = packageJson({
        dependencies: { [`dep-${index}`]: "^1.0.0" },
      });
    }
    const { model } = await scanOf(files);

    const skipped = model.dependencies.sources.filter(
      (source) => source.reason === "budget-exhausted",
    );
    assert.equal(skipped.length, 1, "the source past the budget is recorded, not dropped");
    assert.equal(model.dependencies.coverage.truncated, true);
    assert.equal(model.dependencies.coverage.complete, false);
  });

  it("caps the declarations one scan retains and says so", async () => {
    const dependencies = Object.fromEntries(
      Array.from({ length: DEPENDENCY_LIMITS.maxDeclarations + 50 }, (_entry, index) => [
        `pkg-${String(index).padStart(5, "0")}`,
        "^1.0.0",
      ]),
    );
    const { model } = await scanOf({ "package.json": packageJson({ dependencies }) });

    assert.equal(model.dependencies.coverage.declarations, DEPENDENCY_LIMITS.maxDeclarations);
    assert.equal(model.dependencies.sources[0].truncated, true);
    assert.equal(model.dependencies.coverage.complete, false);
  });

  it("reports uninterpreted sources as unestablished coverage", async () => {
    const { query } = await scanOf({
      "package.json": packageJson({ dependencies: { react: "^19.0.0" } }),
      "pyproject.toml": "[project]\nname = \"demo\"\n",
    });

    const coverage = query.dependencyCoverage();
    assert.equal(coverage.complete, false);
    assert.deepEqual(
      coverage.unestablishedSources.map((source) => source.path),
      ["pyproject.toml"],
    );
    assert.equal(coverage.unestablishedSources[0].status, "unsupported");
    assert.equal(
      typeof coverage.unestablishedSources[0].evidenceId,
      "string",
      "the reason must be citable as evidence",
    );
  });

  it("treats a repository with no manifest as established absence", async () => {
    const { model, query } = await scanOf({ "README.md": "# demo\n" });

    assert.equal(model.dependencies.count, 0);
    assert.equal(model.dependencies.coverage.inspected, false);
    assert.equal(model.dependencies.coverage.complete, true);
    assert.deepEqual(query.dependencyCoverage().unestablishedSources, []);
  });
});

// ─── Query API ───────────────────────────────────────────────────────────────

describe("dependency query API", () => {
  const FIXTURE = {
    "package.json": packageJson({
      dependencies: { react: "^19.0.0" },
      devDependencies: { jest: "^29.0.0" },
    }),
    "package-lock.json": packageJson({
      lockfileVersion: 3,
      packages: {
        "": {},
        "node_modules/react": { version: "19.1.0" },
        "node_modules/jest": { version: "29.7.0" },
        "node_modules/transitive-only": { version: "1.0.0" },
      },
    }),
  };

  it("answers the documented questions", async () => {
    const { query } = await scanOf(FIXTURE);

    assert.deepEqual(
      idsOf(query.listDependencies().entities),
      [
        "dependency:node:jest",
        "dependency:node:react",
        "dependency:node:transitive-only",
      ],
      "every list is sorted by id",
    );
    assert.equal(query.getDependency("dependency:node:react").name, "react");
    assert.equal(query.getDependency("dependency:node:missing"), null);
    assert.equal(query.getDependencyByName("node", "react").id, "dependency:node:react");
    assert.equal(query.getDependencyByName("python", "react"), null);

    assert.deepEqual(idsOf(query.findDependencies({ scope: "development" }).entities), [
      "dependency:node:jest",
    ]);
    assert.deepEqual(idsOf(query.findDependencies({ direct: true }).entities), [
      "dependency:node:jest",
      "dependency:node:react",
    ]);
    assert.deepEqual(idsOf(query.findDependencies({ declared: false }).entities), [
      "dependency:node:transitive-only",
    ]);
    assert.deepEqual(
      idsOf(query.findDependencies({ name: "react", resolved: false }).entities),
      [],
    );
    assert.deepEqual(
      idsOf(
        query.findDependencies({ manifest: "manifest:package-lock.json", name: "react" })
          .entities,
      ),
      ["dependency:node:react"],
    );
  });

  it("exposes declarations with their own evidence and coverage", async () => {
    const { query } = await scanOf(FIXTURE);
    const result = query.dependencyDeclarations("dependency:node:react");

    assert.equal(result.declarations.length, 1);
    assert.equal(result.declarations[0].manifestPath, "package.json");
    assert.equal(result.declarations[0].scope, DEPENDENCY_SCOPES.RUNTIME);
    assert.ok(result.declarations[0].evidenceIds.length > 0);
    assert.equal(result.coverage, COVERAGE_GUARANTEES.COMPLETE);
    assert.equal(result.truncated, false);
  });

  it("rejects malformed criteria instead of answering nonsense", async () => {
    const { query } = await scanOf(FIXTURE);

    assert.throws(() => query.findDependencies({ nope: true }), RepositoryQueryError);
    assert.throws(() => query.findDependencies({ direct: "yes" }), RepositoryQueryError);
    assert.throws(() => query.findDependencies({ ecosystem: "" }), RepositoryQueryError);
    // An ordinary miss is not an error.
    assert.deepEqual(query.findDependencies({ name: "absent" }).entities, []);
  });

  it("reports the model's coverage with dependency queries", async () => {
    const { model } = await scanOf({
      "package.json": packageJson({ dependencies: { react: "^19.0.0" } }),
      "Cargo.toml": "[dependencies]\nserde = \"1\"\n",
    });
    const query = createRepositoryQuery(model);
    const envelope = query.listDependencies();

    assert.equal(envelope.coverage, COVERAGE_GUARANTEES.COMPLETE);
    assert.equal(envelope.truncated, false);
    assert.ok(Object.isFrozen(envelope));
    assert.ok(Object.isFrozen(envelope.entities));
    assert.ok(Object.isFrozen(envelope.entities[0]));

    // A scan that stopped at a limit reports `partial`, and the dependency list is
    // therefore "everything observed so far", never "everything that exists".
    const root = makeRepo({
      "package.json": packageJson({ dependencies: { react: "^19.0.0" } }),
      "src/app.js": "export const x = 1;\n",
    });
    const limited = buildRepositoryModel(await scanRepository(root, { maxFiles: 1 }));
    assert.equal(limited.scan.truncated, true);
    assert.equal(createRepositoryQuery(limited).listDependencies().coverage, "partial");
  });

  it("is deterministic and immutable", async () => {
    const root = makeRepo(FIXTURE);
    const first = await scanModel(root);
    const second = await scanModel(root);

    assert.deepEqual(first.scan.dependencies, second.scan.dependencies);
    assert.equal(
      JSON.stringify(first.model.dependencies),
      JSON.stringify(second.model.dependencies),
      "two scans of one repository produce identical dependency intelligence",
    );
    assert.ok(Object.isFrozen(first.model.dependencies));
    assert.ok(Object.isFrozen(first.model.dependencies.entries));
    assert.throws(() => {
      first.model.dependencies.entries[0].name = "tampered";
    }, TypeError);
  });
});

// ─── Graph and provenance ────────────────────────────────────────────────────

describe("dependency relationships and provenance", () => {
  it("connects manifests, dependencies and lockfiles with the documented vocabulary", async () => {
    const { query, model } = await scanOf({
      "package.json": packageJson({ dependencies: { react: "^19.0.0" } }),
      "package-lock.json": packageJson({
        lockfileVersion: 3,
        packages: {
          "": {},
          "node_modules/react": { version: "19.1.0", dependencies: { "loose-envify": "^1.1.0" } },
          "node_modules/loose-envify": { version: "1.4.0" },
        },
      }),
    });

    const react = query.dependencyRelationships("dependency:node:react").relationships;
    assert.deepEqual(
      react.map((edge) => `${edge.from} -${edge.type}-> ${edge.to}`).sort(),
      [
        "dependency:node:react -depends-on-> dependency:node:loose-envify",
        "dependency:node:react -resolved-by-> manifest:package-lock.json",
        "manifest:package.json -declares-dependency-> dependency:node:react",
      ],
      "a dependency is declared by its manifest, resolved by its lockfile, and depends on its graph neighbours",
    );

    // Peer-style edge endpoints that no lockfile resolved still become entities, so
    // no relationship ever dangles outside the model.
    const entityIds = new Set(Object.keys(model.indexes.entitiesById));
    for (const relationship of model.relationships) {
      assert.ok(entityIds.has(relationship.from) || relationship.from.startsWith("repository:"));
      assert.ok(entityIds.has(relationship.to) || relationship.to.startsWith("repository:"));
    }
  });

  it("gives every dependency fact an observation the scan actually recorded", async () => {
    const { model, query } = await scanOf({
      "package.json": packageJson({ dependencies: { react: "^19.0.0" } }),
      "package-lock.json": packageJson({
        lockfileVersion: 3,
        packages: { "": {}, "node_modules/react": { version: "19.1.0" } },
      }),
    });

    const evidenceIds = new Set(Object.keys(model.indexes.evidenceById));
    for (const dependency of query.listDependencies().entities) {
      assert.ok(dependency.evidenceIds.length > 0);
      for (const id of dependency.evidenceIds) {
        const record = model.indexes.evidenceById[id];
        assert.ok(record, `${id} must resolve inside the model`);
        assert.equal(record.type, "dependency");
        assert.equal(record.provenance.deterministic, true);
        assert.ok(!record.location.path.startsWith("/"), "no absolute host path in an observation");
      }
    }

    const react = query.getDependencyByName("node", "react");
    const declaration = react.declarations[0];
    assert.equal(
      model.indexes.evidenceById[declaration.evidenceIds[0]].location.path,
      "package.json",
      "a declaration is provenanced by the manifest that made it",
    );
    assert.equal(
      model.indexes.evidenceById[declaration.evidenceIds[0]].data.signal,
      "dependency-declaration",
      "a declaration cites a declaration observation, not a resolution one",
    );
    const resolution = react.resolutions[0];
    assert.equal(
      model.indexes.evidenceById[resolution.evidenceIds[0]].location.path,
      "package-lock.json",
      "a resolution is provenanced by the lockfile that stated it",
    );
    assert.equal(
      model.indexes.evidenceById[resolution.evidenceIds[0]].data.signal,
      "dependency-resolution",
      "a resolution cites a resolution observation",
    );

    // The entity itself must reach its own facts' provenance: a consumer that only
    // holds the entity has to be able to walk to the manifest observation.
    for (const entry of [...react.declarations, ...react.resolutions]) {
      for (const id of entry.evidenceIds) {
        assert.ok(
          react.evidenceIds.includes(id),
          "every dependency fact is reachable from the dependency entity",
        );
      }
    }
    assert.equal(declaration.manifestId, "manifest:package.json");
    assert.equal(resolution.manifestId, "manifest:package-lock.json");
  });

  it("never serializes an absolute host path in dependency intelligence", async () => {
    const root = makeRepo({
      "package.json": packageJson({ dependencies: { react: "^19.0.0" } }),
      "package-lock.json": packageJson({
        lockfileVersion: 3,
        packages: { "": {}, "node_modules/react": { version: "19.1.0" } },
      }),
    });
    const { model } = await scanModel(root);
    const serialized = JSON.stringify(model.dependencies);

    assert.ok(serialized.length > 0);
    assert.ok(!serialized.includes(root), "the scan root must not travel with dependency facts");
    assert.ok(!serialized.includes(tmpdir().replace(/\\/g, "/")));
  });
});

// ─── Fail-closed model validation ────────────────────────────────────────────

describe("dependency intelligence: fail-closed model validation", () => {
  const paths = ["package.json"];

  function entry(path, isDirectory = false) {
    const name = path.split("/").pop();
    return {
      path,
      name,
      isDirectory,
      extension: isDirectory ? "" : ".json",
      depth: path.split("/").length,
    };
  }

  function scanWithDependencies(dependencies) {
    return createScanResult({
      root: "/scan-root",
      scannedAt: "2026-01-01T00:00:00.000Z",
      files: paths.map((path) => entry(path)),
      directories: [],
      manifests: [
        {
          path: "package.json",
          name: "package.json",
          directory: ".",
          ecosystem: "node",
          kind: "manifest",
          languages: ["javascript"],
          parse: { status: "parsed", format: "json", bytes: 10, metadata: {} },
        },
      ],
      dependencies,
      scan: {
        complete: true,
        truncated: false,
        limits: { maxFiles: 10000, maxDepth: 20 },
        errors: [],
      },
    });
  }

  const sourceOf = (extra = {}) => ({
    path: "package.json",
    ecosystem: "node",
    kind: "manifest",
    format: "json",
    status: "parsed",
    reason: null,
    detail: null,
    dependencies: [],
    resolved: [],
    edges: [],
    truncated: false,
    problems: [],
    ...extra,
  });

  it("rejects a dependency source path that is not repository-relative", () => {
    assert.throws(
      () =>
        buildRepositoryModel(
          scanWithDependencies({
            inspected: true,
            complete: false,
            truncated: false,
            manifests: [sourceOf({ path: "../outside/package.json" })],
            limits: {},
          }),
        ),
      ValidationError,
    );
  });

  it("rejects a dependency source the inventory never observed", () => {
    assert.throws(
      () =>
        buildRepositoryModel(
          scanWithDependencies({
            inspected: true,
            complete: false,
            truncated: false,
            manifests: [sourceOf({ path: "unobserved.json" })],
            limits: {},
          }),
        ),
      (error) =>
        error instanceof ValidationError &&
        error.details.issues.some((issue) => issue.includes("the inventory observed")),
    );
  });

  it("rejects an unsafe dependency name even when the scan contract let it through", () => {
    assert.throws(
      () =>
        buildRepositoryModel(
          scanWithDependencies({
            inspected: true,
            complete: false,
            truncated: false,
            manifests: [
              sourceOf({
                dependencies: [
                  {
                    name: "../../evil",
                    spec: "^1.0.0",
                    specKind: "registry",
                    scope: "runtime",
                    direct: true,
                  },
                ],
              }),
            ],
            limits: {},
          }),
        ),
      (error) =>
        error instanceof ValidationError &&
        error.details.issues.some((issue) => issue.includes("path-free dependency name")),
    );
  });

  it("rejects an unknown scope or spec kind", () => {
    for (const broken of [
      { scope: "runtime-ish" },
      { specKind: "semver" },
    ]) {
      assert.throws(
        () =>
          buildRepositoryModel(
            scanWithDependencies({
              inspected: true,
              complete: false,
              truncated: false,
              manifests: [
                sourceOf({
                  dependencies: [
                    {
                      name: "react",
                      spec: "^19.0.0",
                      specKind: "registry",
                      scope: "runtime",
                      direct: true,
                      ...broken,
                    },
                  ],
                }),
              ],
              limits: {},
            }),
          ),
        ValidationError,
      );
    }
  });

  it("rejects a section that claims completeness over an unparsed source", () => {
    assert.throws(
      () =>
        validateScanResult(
          createScanResult({
            root: "/scan-root",
            scannedAt: "2026-01-01T00:00:00.000Z",
            dependencies: {
              inspected: true,
              complete: true,
              truncated: false,
              manifests: [sourceOf({ status: "unsupported", reason: "format-not-interpreted" })],
              limits: {},
            },
          }),
        ),
      ValidationError,
    );
  });

  it("rejects a source that is neither parsed nor explained", () => {
    assert.throws(
      () =>
        validateScanResult(
          createScanResult({
            root: "/scan-root",
            scannedAt: "2026-01-01T00:00:00.000Z",
            dependencies: {
              inspected: false,
              complete: false,
              truncated: false,
              manifests: [sourceOf({ status: "unsupported", reason: null })],
              limits: {},
            },
          }),
        ),
      ValidationError,
    );
  });

  it("rejects a dependency entity whose direct flag contradicts its declarations", async () => {
    const { model } = await scanOf({
      "package.json": packageJson({ dependencies: { react: "^19.0.0" } }),
    });
    const tampered = {
      ...model,
      dependencies: {
        ...model.dependencies,
        entries: model.dependencies.entries.map((dependency) => ({
          ...dependency,
          direct: false,
        })),
      },
    };

    assert.throws(() => validateRepositoryModelGraph(tampered), ValidationError);
  });
});

// ─── Rule Engine integration ─────────────────────────────────────────────────

describe("dependency rule pack", () => {
  const contextOf = (model) => buildAnalysisContext({ repository: model });

  async function runRules(files, { rules = dependencyRules } = {}) {
    const { model } = await scanOf(files);

    const engine = createRuleEngine({
      registry: createDependencyRuleRegistry({ rules }),
    });
    return { model, run: await engine.runAll(contextOf(model)) };
  }

  const ruleResult = (run) => run.rules.find((entry) => entry.rule.id === DEPENDENCY_RULE_IDS.DECLARATIONS);

  it("registers exactly the declared pack", () => {
    assert.deepEqual(dependencyRuleSetIssues(dependencyRules), []);

    const wrongNamespace = dependencyRuleSetIssues([
      { id: "security.dependency.x" },
    ]);
    assert.ok(wrongNamespace.some((issue) => issue.includes("namespace")));

    const missing = dependencyRuleSetIssues([]);
    assert.ok(missing.some((issue) => issue.includes("missing from the pack")));
  });

  it("reports one finding per declaration with the manifest's own facts", async () => {
    const { model, run } = await runRules({
      "package.json": packageJson({
        dependencies: { react: "^19.0.0" },
        devDependencies: { jest: "^29.0.0" },
      }),
    });

    const result = ruleResult(run);
    assert.equal(result.status, RULE_OUTCOME_STATUSES.VIOLATION);
    assert.equal(result.findings.length, 2);

    const evidenceIds = new Set(Object.keys(model.indexes.evidenceById));
    for (const finding of result.findings) {
      assert.equal(finding.severity, "info");
      assert.equal(finding.confidence, DEPENDENCY_CONFIDENCE.OBSERVED_DECLARATION);
      assert.equal(finding.metadata.basis, "manifest-declaration");
      assert.equal(finding.metadata.manifestPath, "package.json");
      assert.ok(finding.evidence.length > 0);
      for (const id of finding.evidence) assert.ok(evidenceIds.has(id));
    }

    const scopes = result.findings.map((finding) => finding.metadata.scope).sort();
    assert.deepEqual(scopes, ["development", "runtime"]);
  });

  it("reports declarations in a documented, stable order", async () => {
    const { run } = await runRules({
      "frontend/package.json": packageJson({ dependencies: { zod: "^3.0.0", axios: "^1.0.0" } }),
      "backend/package.json": packageJson({ dependencies: { express: "^4.0.0" } }),
    });

    const order = ruleResult(run).findings.map(
      (finding) => `${finding.metadata.manifestPath}:${finding.metadata.name}`,
    );
    assert.deepEqual(order, [
      "backend/package.json:express",
      "frontend/package.json:axios",
      "frontend/package.json:zod",
    ]);
    assert.deepEqual(order, [...order].sort(), "the order is the documented one, not fill order");
  });

  it("is deterministic through the analyzer and finding engine", async () => {
    const files = {
      "package.json": packageJson({ dependencies: { react: "^19.0.0", zod: "^3.0.0" } }),
    };
    const engine = createAnalyzerEngine({
      registry: createAnalyzerRegistry([createDependencyAnalyzer()]),
    });

    const first = await engine.runAll(contextOf((await scanOf(files)).model));
    const second = await engine.runAll(contextOf((await scanOf(files)).model));

    assert.equal(first.analyzers[0].analyzer.id, DEPENDENCY_ANALYZER_ID);
    assert.ok(first.findings.length > 0);
    assert.deepEqual(
      first.findings.map((finding) => finding.id),
      second.findings.map((finding) => finding.id),
      "fingerprints must not depend on anything but the model",
    );
    assert.deepEqual(
      first.findings.map((finding) => finding.ruleId),
      second.findings.map((finding) => finding.ruleId),
    );
  });

  it("passes only when the absence is established", async () => {
    const { run } = await runRules({ "package.json": packageJson({ name: "demo" }) });
    assert.equal(ruleResult(run).status, RULE_OUTCOME_STATUSES.PASS);
  });

  it("reports unknown when a manifest could not be interpreted", async () => {
    const { run } = await runRules({
      "package.json": packageJson({ name: "demo" }),
      "pyproject.toml": "[project]\nname = \"demo\"\n",
    });

    const result = ruleResult(run);
    assert.equal(result.status, RULE_OUTCOME_STATUSES.UNKNOWN);
    assert.match(result.applicability.reason, /not fully interpreted/);
  });

  it("reports unknown when the scan did not cover the repository", async () => {
    const root = makeRepo({
      "package.json": packageJson({ name: "demo" }),
      // Enough files that the one-file limit actually truncates the inventory.
      "src/a.js": "export const a = 1;\n",
      "src/b.js": "export const b = 1;\n",
    });
    const truncated = buildRepositoryModel(await scanRepository(root, { maxFiles: 1 }));
    assert.equal(truncated.scan.truncated, true);
    assert.equal(truncated.dependencies.count, 0);

    const engine = createRuleEngine({
      registry: createDependencyRuleRegistry({ rules: dependencyRules }),
    });
    const run = await engine.runAll(contextOf(truncated));
    assert.equal(ruleResult(run).status, RULE_OUTCOME_STATUSES.UNKNOWN);
  });

  it("bounds its findings and records that it did", async () => {
    const dependencies = Object.fromEntries(
      Array.from({ length: MAX_DECLARATION_FINDINGS + 5 }, (_entry, index) => [
        `pkg-${String(index).padStart(5, "0")}`,
        "^1.0.0",
      ]),
    );
    const { run } = await runRules({ "package.json": packageJson({ dependencies }) });

    const result = ruleResult(run);
    assert.equal(result.findings.length, MAX_DECLARATION_FINDINGS);
    assert.equal(result.metadata.capped, true);
    assert.equal(result.metadata.declarations, MAX_DECLARATION_FINDINGS + 5);
  });

  it("does not read a file, parse a manifest or execute anything", () => {
    const sources = dependencySourceFiles();
    assert.ok(sources.length >= 3);

    const forbidden = [
      /from\s+"node:/,
      /require\(\s*"node:/,
      /child_process/,
      /execSync|spawnSync|spawn\(/,
      /\bfetch\(/,
      /node_modules/,
      /scanner/,
      /src\/tools\.js/,
      /tool-registry/,
      /http-server|stdio-server/,
    ];
    for (const { path, source } of sources) {
      for (const pattern of forbidden) {
        assert.ok(
          !pattern.test(source),
          `${path} must not match ${String(pattern)}: dependency rules consume the model only`,
        );
      }
    }
  });

  it("routes every repository read through the query API", () => {
    const declarations = dependencySourceFiles().find((file) =>
      file.path.endsWith("rules/declarations.js"),
    );
    assert.ok(declarations);
    assert.ok(
      !declarations.source.includes("context.repository"),
      "the rule must ask the query layer, never reach into the model",
    );
    assert.ok(!declarations.source.includes(".indexes."));
    assert.ok(declarations.source.includes("dependencyDeclarations(query)"));

    const signals = dependencySourceFiles().find((file) => file.path.endsWith("signals.js"));
    assert.ok(signals.source.includes("createRepositoryQuery(context.repository)"));
  });
});

/**
 * Strip comments so a source-level check tests code, not prose.
 *
 * The packs *document* what they must never import ("no `node:fs`, no
 * `child_process`"), so a raw-text scan would flag the very sentences that state the
 * invariant.
 */
function stripComments(source) {
  return source.replace(/\/\*[\s\S]*?\*\//g, "").replace(/^\s*\/\/.*$/gm, "");
}

/** Every JavaScript source file the dependency pack ships, with comments stripped. */
function dependencySourceFiles() {
  const packRoot = join(dirname(fileURLToPath(import.meta.url)), "..", "src", "rules", "dependency");
  const files = [];
  const walk = (directory) => {
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      const full = join(directory, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (entry.name.endsWith(".js")) {
        files.push({
          path: full.replace(/\\/g, "/"),
          source: stripComments(readFileSync(full, "utf8")),
        });
      }
    }
  };
  walk(packRoot);
  return files;
}

// ─── Architectural isolation ─────────────────────────────────────────────────

describe("dependency intelligence: architectural isolation", () => {
  const projectRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
  const read = (relative) => stripComments(readFileSync(join(projectRoot, relative), "utf8"));

  const FORBIDDEN = [
    ["node:fs", /from\s+"node:fs/],
    ["node:path", /from\s+"node:path/],
    ["child_process", /from\s+"node:child_process/],
    ["node:net", /from\s+"node:net/],
    ["node:http", /from\s+"node:http/],
    ["node:https", /from\s+"node:https/],
    ["node:dns", /from\s+"node:dns/],
    ["node:worker_threads", /from\s+"node:worker_threads/],
    ["filesystem boundary", /repository\/filesystem/],
    ["execution boundary", /src\/execution|from\s+"\.\.\/\.\.\/execution/],
    ["tools.js", /tools\.js/],
    ["tool registry", /tool-registry/],
    ["transports", /http-server|stdio-server/],
  ];

  it("keeps the acquisition layer inside the scanner boundary", () => {
    for (const relative of [
      "src/repository/scanner/detectors/dependencies.js",
      "src/repository/scanner/policies/dependencies.js",
    ]) {
      const source = read(relative);
      for (const [label, pattern] of FORBIDDEN) {
        // The scanner may read the repository only through the injected view, so even
        // `node:fs` is forbidden here — acquisition never touches the disk itself.
        assert.ok(!pattern.test(source), `${relative} must not import ${label}`);
      }
      assert.ok(
        !/scanRepository/.test(source) || relative.includes("policies"),
        `${relative} must not start its own scan`,
      );
      assert.ok(
        !/child_process|spawnSync|execSync|execFile|require\(/.test(source),
        `${relative} must not execute anything`,
      );
      assert.ok(!/https?:\/\//.test(source.replace(/^\s*\*.*$/gm, "")), `${relative} must not reach a network`);
    }
  });

  it("keeps the model layer a pure transformation of the scan result", () => {
    for (const relative of [
      "src/repository/model/entities.js",
      "src/repository/model/graph.js",
      "src/repository/model/builder.js",
      "src/repository/model/query.js",
      "src/repository/model/query-api.js",
    ]) {
      const source = read(relative);
      for (const [label, pattern] of FORBIDDEN) {
        if (label === "filesystem boundary") continue;
        assert.ok(
          !pattern.test(source),
          `${relative} must not import ${label}: dependency data exists only in the model`,
        );
      }
      assert.ok(!/scanRepository\(/.test(source), `${relative} must not rescan`);
    }
  });

  it("never lets the scanner acquire dependencies without observing the manifest", async () => {
    // An ignored directory's manifest is not a dependency source: acquisition reads
    // the inventory the walk produced, and nothing else.
    const root = makeRepo({
      ".gitignore": "ignored/\n",
      "package.json": packageJson({ dependencies: { react: "^19.0.0" } }),
      "ignored/package.json": packageJson({ dependencies: { sneaky: "^1.0.0" } }),
    });
    const { scan, model } = await scanModel(root);

    assert.deepEqual(
      scan.dependencies.manifests.map((record) => record.path),
      ["package.json"],
    );
    assert.equal(model.dependencies.count, 1);
    assert.equal(model.dependencies.entries[0].name, "react");
  });
});

// ─── Vocabulary pinning ──────────────────────────────────────────────────────

describe("dependency vocabulary", () => {
  it("agrees between the acquisition contract and the model", async () => {
    const { model } = await scanOf({
      "package.json": packageJson({
        dependencies: { react: "^19.0.0" },
        devDependencies: { jest: "^29.0.0" },
      }),
      "requirements.txt": "flask==3.0.1\n",
      "pyproject.toml": "[project]\nname = \"demo\"\n",
    });

    const statuses = new Set(model.dependencies.sources.map((source) => source.status));
    assert.deepEqual([...statuses].sort(), ["parsed", "unsupported"]);

    const scopes = new Set(
      model.dependencies.entries.flatMap((dependency) => dependency.scopes),
    );
    assert.deepEqual([...scopes].sort(), ["development", "runtime"]);

    for (const dependency of model.dependencies.entries) {
      assert.equal(dependency.kind, ENTITY_KINDS.DEPENDENCY);
      assert.ok(dependency.id.startsWith("dependency:"));
      assert.equal(
        dependency.ecosystemId,
        `${ENTITY_KINDS.ECOSYSTEM}:${dependency.ecosystem}`,
        "every dependency belongs to the ecosystem that declared it",
      );
    }
    assert.deepEqual(
      idsOf(model.dependencies.entries),
      ["dependency:node:jest", "dependency:node:react", "dependency:python:flask"],
      "an entity id names its ecosystem, not a default one",
    );

    // The scanner's own vocabulary is the one the model re-declares.
    const section = (await scanRepository(makeRepo({ "package.json": packageJson({}) }))).dependencies;
    assert.ok(section.limits.maxDeclarations > 0);
    assert.equal(typeof SCAN_SIGNALS.MANIFEST, "string");
    assert.ok(createScanResult().dependencies.manifests.length === 0);
  });
});
