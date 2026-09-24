/**
 * Code Guardian — Import Graph Tests (Phase 16)
 *
 * Two fixture styles, chosen deliberately:
 *
 *   - **real repositories** written to a temporary directory and scanned through the
 *     accepted Phase 8A boundary, Phase 8C scanner, Phase 8D model builder and
 *     Phase 16 projection, so the acquisition, the model and the graph agree end to
 *     end. This is the only way to prove that what a source file literally states is
 *     what the graph exposes.
 *   - **hand-built ScanResults and models** for states a real scan cannot reach on
 *     demand (a scan that never finished, a module source nobody could read, a
 *     repository whose every module is TSX) and for tampering, so the fail-closed
 *     behaviour of the graph contract can be stated exactly.
 *
 * No test spawns a process, contacts a network, installs a package or writes to the
 * repository under test.
 *
 * Run with: node --test tests/import-graph.test.js
 */

import { after, describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { ValidationError } from "../src/core/index.js";

import {
  MODULE_FILE_EXTENSIONS,
  PARSED_MODULE_EXTENSIONS,
  UNSUPPORTED_MODULE_EXTENSIONS,
  IMPORT_ACQUISITION_LIMITS,
  IMPORT_NON_STATIC_REASONS,
  IMPORT_PROBLEM_REASONS,
  IMPORT_SOURCE_REASONS,
  IMPORT_SOURCE_STATUSES,
  IMPORT_SPECIFIER_KINDS,
  createScanResult,
  detectImports,
  moduleLanguageOf,
  parseModuleReferences,
  scanRepository,
  validateScanResult,
} from "../src/repository/scanner/index.js";

import {
  COVERAGE_GUARANTEES,
  ENTITY_KINDS,
  IMPORT_GRAPH_EDGE_TYPES,
  IMPORT_GRAPH_EDGE_TYPE_VALUES,
  IMPORT_GRAPH_LIMITS,
  IMPORT_GRAPH_STATES,
  IMPORT_GRAPH_STATE_VALUES,
  IMPORT_GRAPH_VERSION,
  IMPORT_MODULE_EXTENSIONS,
  IMPORT_PROBLEM_REASONS as MODEL_IMPORT_PROBLEM_REASONS,
  IMPORT_SOURCE_REASONS as MODEL_IMPORT_SOURCE_REASONS,
  IMPORT_SOURCE_STATUSES as MODEL_IMPORT_SOURCE_STATUSES,
  IMPORT_SPECIFIER_KINDS as MODEL_IMPORT_SPECIFIER_KINDS,
  RELATIONSHIP_TYPES,
  RepositoryQueryError,
  UNRESOLVED_REFERENCE_REASONS,
  UNRESOLVED_REFERENCE_REASON_VALUES,
  buildImportGraph,
  buildRepositoryModel,
  classifySpecifier,
  createRepositoryQuery,
  importGraphState,
  // The model boundary already exports an architecture-graph predicate under the bare
  // name `isEstablishedState` (Phase 15), so this phase's is reached by its alias.
  isImportGraphEstablishedState as isEstablishedState,
  joinRelativePath,
  resolveModuleReference,
  validateRepositoryModelGraph,
} from "../src/repository/model/index.js";

import { buildAnalysisContext, createAnalyzerEngine, createAnalyzerRegistry } from "../src/analysis/index.js";
import {
  IMPORT_ANALYZER_ID,
  IMPORT_ANALYZER_SCOPE,
  IMPORT_BASIS,
  IMPORT_DESCRIBED_UNRESOLVED_REASONS,
  IMPORT_RULE_IDS,
  KIND_WORDING,
  MAX_IMPORT_FINDINGS,
  RULE_OUTCOME_STATUSES,
  UNRESOLVED_REASON_WORDING,
  createImportAnalyzer,
  createImportRuleRegistry,
  createRuleEngine,
  importCoverage,
  importRelationships,
  importRuleSetIssues,
  importRules,
  importUnresolved,
  importsAbsence,
} from "../src/rules/index.js";

// ─── Fixtures ────────────────────────────────────────────────────────────────

const TMP_ROOT = join(tmpdir(), `cg-imports-${process.pid}-${Date.now()}`);
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
const packageJson = (value) => JSON.stringify(value, null, 2);

/**
 * A repository that exercises every reference form the acquisition layer extracts.
 *
 * The inventory is deliberately small enough to reason about by hand, and every
 * module statement in it is one this phase claims to understand — the unresolved and
 * non-static statements are here on purpose, so the tests can prove they are *not*
 * turned into edges.
 */
const fullRepo = () => ({
  "package.json": packageJson({ name: "demo", type: "module" }),
  "src/index.js": [
    'import { helper } from "./helper.js";',
    'import "./side-effect.js";',
    'export { thing } from "./lib/thing.js";',
    'export * from "./lib/all";',
    'const legacy = require("./legacy.cjs");',
    'const dynamic = await import("./dynamic.js");',
    'const deep = require("./nested/deep.js");',
    'const shared = require("../shared/outside-root.js");',
    'const config = require("./data.json");',
    'const pkg = require("express");',
    'const alias = require("@/utils");',
    'const missing = require("./does-not-exist.js");',
    "// require('./commented.js')",
    'const literal = "require(\\"./string-literal.js\\")";',
    "const pattern = /require\\('\\.\\/regex\\.js'\\)/;",
    "const template = `require('./template.js')`;",
    "const computed = require(name);",
  ].join("\n"),
  "src/helper.js": "export const helper = 1;\n",
  "src/side-effect.js": "globalThis.__loaded = true;\n",
  "src/legacy.cjs": "module.exports = {};\n",
  "src/dynamic.js": "export const dynamic = 1;\n",
  "src/nested/deep.js": "export const deep = 1;\n",
  "src/lib/thing.js": "export const thing = 1;\n",
  "src/lib/all.js": 'export * from "./thing.js";\n',
  "src/data.json": "{}\n",
  "shared/outside-root.js": "export const shared = 1;\n",
  "src/cycle-a.js": 'import "./cycle-b.js";\n',
  "src/cycle-b.js": 'import "./cycle-a.js";\n',
  "src/self.js": 'import "./self.js";\n',
  "src/orphan.js": "export const orphan = 1;\n",
  "src/util/index.ts": "export const util = 1;\n",
  "src/uses-util.ts": 'import { util } from "./util";\nimport { helper } from "./helper";\n',
  "src/widget.tsx": "export const Widget = () => null;\n",
});

/** The edges `fullRepo` establishes, as `from -> to` pairs. */
const FULL_REPO_EDGES = Object.freeze([
  "file:src/cycle-a.js -> file:src/cycle-b.js",
  "file:src/cycle-b.js -> file:src/cycle-a.js",
  "file:src/index.js -> file:src/data.json",
  "file:src/index.js -> file:src/dynamic.js",
  "file:src/index.js -> file:src/helper.js",
  "file:src/index.js -> file:src/legacy.cjs",
  "file:src/index.js -> file:src/lib/all.js",
  "file:src/index.js -> file:src/lib/thing.js",
  "file:src/index.js -> file:src/nested/deep.js",
  "file:src/index.js -> file:src/side-effect.js",
  "file:src/index.js -> file:shared/outside-root.js",
  "file:src/lib/all.js -> file:src/lib/thing.js",
  "file:src/self.js -> file:src/self.js",
  "file:src/uses-util.ts -> file:src/helper.js",
  "file:src/uses-util.ts -> file:src/util/index.ts",
]);

const edgePairs = (graph) => graph.edges.map((edge) => `${edge.from} -> ${edge.to}`).sort();
const moduleNodes = (graph) =>
  graph.nodes.filter((node) => node.module === true).map((node) => node.id);

// ─── Acquisition ─────────────────────────────────────────────────────────────

describe("import graph: acquisition", () => {
  it("extracts every supported declaration form from code, not text", async () => {
    const { model } = await scanOf(fullRepo());
    const index = model.imports.entries.find((entry) => entry.path === "src/index.js");

    assert.equal(index.status, IMPORT_SOURCE_STATUSES.PARSED);
    assert.equal(index.languageId, `${ENTITY_KINDS.LANGUAGE}:javascript`);
    assert.deepEqual(
      index.references.map((reference) => `${reference.kind}:${reference.specifier}`),
      [
        "static-import:./helper.js",
        "static-import:./side-effect.js",
        "export-from:./lib/thing.js",
        "export-from:./lib/all",
        "require:./legacy.cjs",
        "dynamic-import:./dynamic.js",
        "require:./nested/deep.js",
        "require:../shared/outside-root.js",
        "require:./data.json",
        "require:express",
        "require:@/utils",
        "require:./does-not-exist.js",
      ],
    );

    // Text inside a comment, a string, a regular expression or a template is text, and
    // the tokenizer turns each of those into a single opaque token — which is the
    // property a pattern search could never have.
    for (const specifier of index.references.map((reference) => reference.specifier)) {
      assert.ok(!specifier.includes("commented"), "a comment produced a reference");
      assert.ok(!specifier.includes("string-literal"), "a string produced a reference");
      assert.ok(!specifier.includes("regex"), "a regular expression produced a reference");
      assert.ok(!specifier.includes("template"), "a template produced a reference");
    }
  });

  it("records a non-static reference as a problem instead of guessing a path", async () => {
    const { model } = await scanOf(fullRepo());
    const index = model.imports.entries.find((entry) => entry.path === "src/index.js");

    assert.equal(index.nonStatic, 1);
    assert.ok(index.problems.includes(IMPORT_PROBLEM_REASONS.NON_STATIC_SPECIFIER));
    // Which is exactly why the file is not reported as a complete parse.
    assert.equal(model.imports.coverage.complete, false);
  });

  it("records every module reference form the scanner supports", async () => {
    const parsed = parseModuleReferences(
      [
        'import a from "x";',
        'import { b } from "x";',
        'import * as c from "x";',
        'import "x";',
        'export { d } from "x";',
        'export * from "x";',
        'export * as e from "x";',
        'const f = require("x");',
        'const g = require("x").nested;',
        'const h = import("x");',
        'import i = require("x");',
      ].join("\n"),
      { extension: ".ts" },
    );

    assert.deepEqual(
      parsed.references.map((reference) => reference.kind),
      [
        "static-import",
        "static-import",
        "static-import",
        "static-import",
        "export-from",
        "export-from",
        "export-from",
        "require",
        "require",
        "dynamic-import",
        "require",
      ],
    );
    assert.deepEqual(parsed.problems, []);
    assert.equal(parsed.truncated, false);
  });

  it("never treats a non-declaration as one", async () => {
    const parsed = parseModuleReferences(
      [
        "import.meta.resolve('./meta.js');",
        "const m = import.meta.url;",
        'const p = obj.require("./member.js");',
        "const q = obj?.require('./member.js');",
        "const o = { import: './object.js', export: './object.js', from: 'x' };",
        "const s = `import x from './sub.js'`;",
        "declare module './ambient' { export { a } from './ambient-a.js' }",
        "const type = 'import';",
      ].join("\n"),
      { extension: ".ts" },
    );

    assert.deepEqual(parsed.references, []);
    assert.deepEqual(parsed.problems, []);
  });

  it("reports an unsupported module format rather than parsing it as JavaScript", async () => {
    const { model } = await scanOf(fullRepo());
    const widget = model.imports.entries.find((entry) => entry.path === "src/widget.tsx");

    assert.equal(widget.status, IMPORT_SOURCE_STATUSES.UNSUPPORTED);
    assert.equal(widget.reason, IMPORT_SOURCE_REASONS.FORMAT_NOT_INTERPRETED);
    assert.equal(widget.detail, ".tsx");
    assert.deepEqual(widget.references, []);
  });

  it("records a module source it could not read, with a bounded reason", async () => {
    const draft = validateScanResult(
      createScanResult({
        root: "C:/repo",
        scannedAt: "2026-01-01T00:00:00.000Z",
        files: [
          { path: "a.js", name: "a.js", extension: ".js", depth: 1 },
          { path: "b.js", name: "b.js", extension: ".js", depth: 1 },
        ],
        languages: [javascriptLanguage(2, ["a.js", "b.js"])],
        imports: {
          inspected: true,
          complete: false,
          truncated: false,
          files: [
            moduleSource("a.js", { references: [{ kind: "require", specifier: "./b" }] }),
            moduleSource("b.js", {
              status: "failed",
              reason: "module-could-not-be-read",
              detail: "permission-denied",
            }),
          ],
          limits: {},
        },
        scan: { complete: true, truncated: false },
      }),
    );
    const model = buildRepositoryModel(draft);

    assert.equal(model.imports.entries[1].status, IMPORT_SOURCE_STATUSES.FAILED);
    assert.equal(model.imports.entries[1].reason, IMPORT_SOURCE_REASONS.UNREADABLE);
    assert.equal(model.imports.entries[1].detail, "permission-denied");
    assert.deepEqual(model.imports.entries[1].references, []);
    assert.equal(model.imports.graph.state, IMPORT_GRAPH_STATES.PARTIAL);
  });

  it("keeps the acquisition vocabularies closed and shared with the contract", () => {
    assert.deepEqual([...MODEL_IMPORT_SOURCE_STATUSES].sort(), [...Object.values(IMPORT_SOURCE_STATUSES)].sort());
    assert.deepEqual([...MODEL_IMPORT_SOURCE_REASONS].sort(), [...Object.values(IMPORT_SOURCE_REASONS)].sort());
    assert.deepEqual([...MODEL_IMPORT_SPECIFIER_KINDS].sort(), [...Object.values(IMPORT_SPECIFIER_KINDS)].sort());
    assert.deepEqual(
      [...MODEL_IMPORT_PROBLEM_REASONS].sort(),
      [...Object.values(IMPORT_PROBLEM_REASONS)].sort(),
    );
    assert.deepEqual([...IMPORT_MODULE_EXTENSIONS].sort(), [...MODULE_FILE_EXTENSIONS].sort());
    assert.equal(IMPORT_ACQUISITION_LIMITS.maxReferencesPerFile, 512);
    assert.equal(moduleLanguageOf(".tsx"), "typescript");
    assert.equal(PARSED_MODULE_EXTENSIONS[".mjs"], "javascript");
    assert.equal(UNSUPPORTED_MODULE_EXTENSIONS[".jsx"], "javascript");
  });

  it("names why a reference could not be established, in closed terms", () => {
    // Every form that cannot become a path is recorded as a *reason*, never as a
    // reference: the vocabulary is the contract, so the reason is asserted exactly
    // rather than only the fact that something was refused.
    const parsed = parseModuleReferences(
      [
        "const a = require(`./t.js`);",
        "const b = import(`./t.js`);",
        'const c = require("./a" + name);',
        "const d = require(name);",
        "const e = import(name);",
      ].join("\n"),
      { extension: ".js" },
    );

    assert.deepEqual(parsed.references, []);
    assert.deepEqual(
      parsed.nonStatic.map((entry) => `${entry.kind}:${entry.reason}`),
      [
        `require:${IMPORT_NON_STATIC_REASONS.TEMPLATE_SPECIFIER}`,
        `dynamic-import:${IMPORT_NON_STATIC_REASONS.TEMPLATE_SPECIFIER}`,
        `require:${IMPORT_NON_STATIC_REASONS.CONCATENATED_REQUIRE}`,
        `require:${IMPORT_NON_STATIC_REASONS.COMPUTED_REQUIRE}`,
        `dynamic-import:${IMPORT_NON_STATIC_REASONS.COMPUTED_DYNAMIC_IMPORT}`,
      ],
    );
    assert.deepEqual(parsed.problems, [IMPORT_PROBLEM_REASONS.NON_STATIC_SPECIFIER]);
  });

  it("never lets a binary file, a byte cap or a spent budget pass as interpreted source", async () => {
    // The detector's own bounds, characterized through a stub view: the acquisition
    // policy is a contract, and each way it stops has to be visible in the record
    // rather than inferred from an empty reference list.
    const file = (path) => ({
      path,
      name: path,
      extension: path.slice(path.lastIndexOf(".")),
      depth: 1,
    });
    const view = (files, read) => ({ files, read });

    const binary = await detectImports(
      view([file("a.js")], async () => ({
        ok: true,
        content: `const a = 1;${String.fromCharCode(0)}`,
        bytesRead: 14,
        truncated: false,
      })),
    );
    assert.equal(binary.files[0].status, IMPORT_SOURCE_STATUSES.FAILED);
    assert.equal(binary.files[0].reason, IMPORT_SOURCE_REASONS.NOT_TEXT);
    assert.deepEqual(binary.files[0].references, []);
    assert.equal(binary.inspected, false);

    // A file read only up to a cap was not fully read, so its references are a prefix.
    const cut = await detectImports(
      view([file("a.js")], async () => ({
        ok: true,
        content: 'import "./b.js";',
        bytesRead: IMPORT_ACQUISITION_LIMITS.maxFileBytes,
        truncated: true,
      })),
    );
    assert.equal(cut.files[0].status, IMPORT_SOURCE_STATUSES.PARSED);
    assert.equal(cut.files[0].truncated, true);
    assert.equal(cut.truncated, true);
    assert.equal(cut.complete, false);

    // The byte budget is shared by every source in one scan: once it is spent, the
    // next source is recorded as not inspected rather than read anyway.
    const exhausted = await detectImports(
      view([file("a.js"), file("b.js")], async () => ({
        ok: true,
        content: 'import "./c.js";',
        bytesRead: IMPORT_ACQUISITION_LIMITS.maxTotalBytes,
        truncated: false,
      })),
    );
    assert.equal(exhausted.files[0].status, IMPORT_SOURCE_STATUSES.PARSED);
    assert.equal(exhausted.files[1].status, IMPORT_SOURCE_STATUSES.NOT_INSPECTED);
    assert.equal(exhausted.files[1].reason, IMPORT_SOURCE_REASONS.BUDGET_EXHAUSTED);
    assert.equal(exhausted.truncated, true);
    assert.equal(exhausted.complete, false);

    // And a source whose parse was cut short is not a complete acquisition either.
    const unreadable = await detectImports(
      view([file("a.js"), file("b.js")], async (path) =>
        path === "a.js"
          ? { ok: true, content: "const a = 1;", bytesRead: 12, truncated: false }
          : { ok: false, error: { kind: "permission-denied" } },
      ),
    );
    assert.equal(unreadable.complete, false);
    assert.equal(unreadable.files[1].status, IMPORT_SOURCE_STATUSES.FAILED);
  });
});

// ─── Resolution ──────────────────────────────────────────────────────────────

describe("import graph: resolution", () => {
  const observed = new Set([
    "src/a.js",
    "src/a.ts",
    "src/dir/index.ts",
    "src/data.json",
  ]);

  it("resolves a relative specifier against the observed inventory only", () => {
    const resolve = (specifier, languageId = "language:javascript", fromPath = "src/main.js") =>
      resolveModuleReference({ fromPath, specifier, languageId, observedPaths: observed });

    assert.equal(resolve("./a").resolvedPath, "src/a.js");
    assert.equal(resolve("./a", "language:typescript").resolvedPath, "src/a.ts");
    assert.equal(resolve("./data.json").resolvedPath, "src/data.json");
    assert.equal(resolve("./dir").resolvedPath, "src/dir/index.ts");
    assert.equal(resolve("./dir/").resolvedPath, "src/dir/index.ts");
    assert.equal(resolve("./nothing").reason, UNRESOLVED_REFERENCE_REASONS.MODULE_NOT_OBSERVED);
  });

  it("refuses a path that leaves the repository before looking anything up", () => {
    const resolution = resolveModuleReference({
      fromPath: "src/main.js",
      specifier: "../../etc/passwd",
      languageId: "language:javascript",
      observedPaths: observed,
    });

    assert.equal(resolution.resolvedPath, null);
    assert.equal(resolution.reason, UNRESOLVED_REFERENCE_REASONS.OUTSIDE_REPOSITORY);
    assert.equal(joinRelativePath("src", "../a"), "a");
    assert.equal(joinRelativePath("src", "../../a"), null);
    assert.equal(joinRelativePath("", "./a"), "a");
  });

  it("classifies every specifier that is not a repository-relative path", () => {
    assert.equal(classifySpecifier("express").reason, UNRESOLVED_REFERENCE_REASONS.BARE_SPECIFIER);
    assert.equal(classifySpecifier("@/utils").reason, UNRESOLVED_REFERENCE_REASONS.BARE_SPECIFIER);
    assert.equal(classifySpecifier("#internal/x").reason, UNRESOLVED_REFERENCE_REASONS.BARE_SPECIFIER);
    assert.equal(classifySpecifier("/etc/passwd").reason, UNRESOLVED_REFERENCE_REASONS.ABSOLUTE_SPECIFIER);
    assert.equal(classifySpecifier("C:\\\\temp\\\\x").reason, UNRESOLVED_REFERENCE_REASONS.ABSOLUTE_SPECIFIER);
    assert.equal(classifySpecifier("\\\\\\\\host\\\\share").reason, UNRESOLVED_REFERENCE_REASONS.ABSOLUTE_SPECIFIER);
    assert.equal(classifySpecifier("./a?raw").reason, UNRESOLVED_REFERENCE_REASONS.SPECIFIER_NOT_RESOLVABLE);
    assert.equal(classifySpecifier("./a\\\\b").reason, UNRESOLVED_REFERENCE_REASONS.SPECIFIER_NOT_RESOLVABLE);
    assert.equal(classifySpecifier("").reason, UNRESOLVED_REFERENCE_REASONS.SPECIFIER_INVALID);
    assert.equal(
      classifySpecifier(`./a${String.fromCharCode(0)}b`).reason,
      UNRESOLVED_REFERENCE_REASONS.SPECIFIER_INVALID,
    );
    // The bound is part of the contract, not only of the lexer: a specifier the
    // resolver cannot use is refused before it can name a path candidate.
    assert.equal(
      classifySpecifier(`./${"x".repeat(600)}`).reason,
      UNRESOLVED_REFERENCE_REASONS.SPECIFIER_INVALID,
    );
    // Exactly at the bound is usable, one over is not, and the DEL character is not
    // printable text either — so the bound is pinned on both sides.
    assert.equal(classifySpecifier(`./${"x".repeat(510)}`).reason, null);
    assert.equal(`./${"x".repeat(510)}`.length, 512);
    assert.equal(
      classifySpecifier(`./${"x".repeat(511)}`).reason,
      UNRESOLVED_REFERENCE_REASONS.SPECIFIER_INVALID,
    );
    assert.equal(
      classifySpecifier(`./${String.fromCharCode(0x7f)}`).reason,
      UNRESOLVED_REFERENCE_REASONS.SPECIFIER_INVALID,
    );
    assert.equal(classifySpecifier("./a").reason, null);
  });
});

// ─── Construction ────────────────────────────────────────────────────────────

describe("import graph: construction", () => {
  it("projects exactly the references the repository establishes", async () => {
    const { model, query } = await scanOf(fullRepo());

    assert.equal(Object.isFrozen(model.imports.graph), true);
    assert.deepEqual(edgePairs(model.imports.graph), [...FULL_REPO_EDGES].sort());
    assert.deepEqual(edgePairs(query.importGraph()), [...FULL_REPO_EDGES].sort());
    assert.equal(model.imports.graph.version, IMPORT_GRAPH_VERSION);
    assert.equal(query.importCoverage().edges, FULL_REPO_EDGES.length);
  });

  it("states each edge once, with the specifiers and declaration forms behind it", async () => {
    const { query } = await scanOf(fullRepo());
    const edge = query
      .importEdges({ from: "file:src/index.js", to: "file:src/helper.js" })
      .edges.at(0);

    assert.equal(edge.type, IMPORT_GRAPH_EDGE_TYPES.IMPORTS);
    assert.deepEqual(edge.specifiers, ["./helper.js"]);
    assert.deepEqual(edge.kinds, ["static-import"]);
    assert.deepEqual(edge.sourcePaths, ["src/index.js"]);
    assert.deepEqual(edge.evidenceIds, ["evidence:import:import-source:src/index.js"]);
  });

  it("merges two references from one file to one target into a single edge", async () => {
    const { model } = await scanOf({
      "src/both.js": 'import "./target.js";\nconst second = require("./target.js");\n',
      "src/target.js": "export const t = 1;\n",
    });

    assert.deepEqual(edgePairs(model.imports.graph), ["file:src/both.js -> file:src/target.js"]);
    assert.deepEqual(model.imports.graph.edges[0].kinds, ["require", "static-import"]);
    assert.deepEqual(model.imports.graph.edges[0].specifiers, ["./target.js"]);

    // Two *different* specifiers that resolve to the same observed file are still one
    // relationship: the graph states what the file imports, not how many times it
    // wrote a path that happens to land on the same target.
    const distinct = await scanOf({
      "src/spelled.js": 'import "./target";\nconst second = require("./target.js");\n',
      "src/target.js": "export const t = 1;\n",
    });

    assert.deepEqual(edgePairs(distinct.model.imports.graph), [
      "file:src/spelled.js -> file:src/target.js",
    ]);
    assert.deepEqual(distinct.model.imports.graph.edges[0].specifiers, [
      "./target",
      "./target.js",
    ]);
    assert.deepEqual(distinct.model.imports.graph.edges[0].kinds, ["require", "static-import"]);
  });

  it("keeps a reference whose target the repository does not establish out of the edges", async () => {
    const { model, query } = await scanOf(fullRepo());
    const reasons = new Map(
      query.unresolvedImports({ maxResults: 1000 }).unresolved.map((record) => [
        record.specifier,
        record.reason,
      ]),
    );

    assert.equal(reasons.get("express"), UNRESOLVED_REFERENCE_REASONS.BARE_SPECIFIER);
    assert.equal(reasons.get("@/utils"), UNRESOLVED_REFERENCE_REASONS.BARE_SPECIFIER);
    assert.equal(reasons.get("./does-not-exist.js"), UNRESOLVED_REFERENCE_REASONS.MODULE_NOT_OBSERVED);
    for (const specifier of reasons.keys()) {
      assert.ok(
        !FULL_REPO_EDGES.some((pair) => pair.includes(specifier)),
        `"${specifier}" produced an edge`,
      );
    }
    assert.equal(model.imports.coverage.unresolved, model.imports.graph.unresolved.length);
  });

  it("keeps cycles, a self-reference and unresolved targets as they are", async () => {
    const { model } = await scanOf(fullRepo());
    const graph = model.imports.graph;

    assert.ok(graph.edges.some((edge) => edge.from === edge.to && edge.to === "file:src/self.js"));
    assert.ok(graph.edges.some((edge) => edge.to === "file:src/cycle-b.js"));
    assert.ok(graph.edges.some((edge) => edge.to === "file:src/cycle-a.js"));

    const dataNode = graph.nodes.find((node) => node.path === "src/data.json");
    assert.equal(dataNode.module, false, "a JSON target is a node, but it is not a module");
    assert.equal(dataNode.status, null);
  });

  it("makes every module source a node, whether or not it was parsed", async () => {
    const { model } = await scanOf(fullRepo());
    const graph = model.imports.graph;

    for (const entry of model.imports.entries) {
      assert.ok(
        graph.nodes.some((node) => node.path === entry.path),
        `module source "${entry.path}" is missing from the graph nodes`,
      );
    }
    assert.ok(moduleNodes(graph).includes("file:src/widget.tsx"));
    assert.equal(
      moduleNodes(graph).length,
      model.files.entries.filter((file) => IMPORT_MODULE_EXTENSIONS.includes(file.extension)).length,
    );
  });

  it("states every edge as an `imports` relationship of the model", async () => {
    const { model } = await scanOf(fullRepo());
    const relationships = model.relationships
      .filter((relationship) => relationship.type === RELATIONSHIP_TYPES.IMPORTS)
      .map((relationship) => `${relationship.from} -> ${relationship.to}`)
      .sort();

    assert.deepEqual(relationships, edgePairs(model.imports.graph));
  });

  it("is deterministic across two builds of one repository state", async () => {
    const first = await scanOf(fullRepo());
    const second = await scanOf(fullRepo());

    assert.deepEqual(first.model.imports.graph, second.model.imports.graph);
    assert.deepEqual(first.model.relationships, second.model.relationships);
  });

  it("reports no absolute host path anywhere in the graph", async () => {
    const { model } = await scanOf(fullRepo());
    const serialized = JSON.stringify(model.imports);

    assert.ok(!serialized.includes(TMP_ROOT));
    for (const node of model.imports.graph.nodes) {
      assert.ok(!node.path.startsWith("/"));
    }
  });
});

// ─── Coverage ────────────────────────────────────────────────────────────────

describe("import graph: coverage", () => {
  it("reports complete for a repository whose sources were all interpreted", async () => {
    const { model } = await scanOf({
      "src/a.js": 'import "./b.js";\n',
      "src/b.js": "export const b = 1;\n",
    });

    assert.equal(model.imports.graph.state, IMPORT_GRAPH_STATES.COMPLETE);
    assert.equal(model.imports.graph.established, true);
    assert.deepEqual(model.imports.graph.coverage.unestablishedSources, []);
    assert.equal(model.imports.graph.edges.length, 1);
  });

  it("reports complete and empty for a repository with no module source at all", async () => {
    const { model, query } = await scanOf({ "README.md": "# demo\n" });

    assert.equal(model.imports.graph.state, IMPORT_GRAPH_STATES.COMPLETE);
    assert.equal(model.imports.graph.established, true);
    assert.deepEqual(model.imports.graph.edges, []);
    assert.deepEqual(model.imports.graph.nodes, []);
    assert.equal(query.importGraph().edges.length, 0);
    // Nothing was skipped to reach that answer: a README is not a source file in any
    // language this scanner knows, so there is no unread code behind the claim.
    assert.equal(model.imports.graph.coverage.uninterpretedSources, 0);
    assert.deepEqual(model.imports.graph.coverage.uninterpretedExtensions, []);
  });

  it("reports unsupported — never a complete all-clear — when no source file is a format it reads", async () => {
    const { model, query } = await scanOf({
      "pkg/main.py": "import os\nfrom . import util\n",
      "cmd/tool.go": "package main\nimport \"fmt\"\n",
    });

    // The repository does import things. This build reads neither language, so the
    // honest answer is "nothing here was read", not "this repository has no imports".
    assert.equal(model.imports.graph.state, IMPORT_GRAPH_STATES.UNSUPPORTED);
    assert.equal(model.imports.graph.established, false);
    assert.deepEqual(model.imports.graph.edges, []);
    assert.deepEqual(query.importGraph().edges, []);
    assert.equal(model.imports.graph.coverage.uninterpretedSources, 2);
    assert.deepEqual(model.imports.graph.coverage.uninterpretedExtensions, [".go", ".py"]);
    assert.equal(importsAbsence(query).established, false);
  });

  it("records the source files it does not read beside the ones it does", async () => {
    const { model } = await scanOf({
      "src/a.js": 'import "./b.js";\n',
      "src/b.js": "export const b = 1;\n",
      "scripts/build.py": "print('hi')\n",
    });

    // JavaScript was interpreted completely, so the graph is complete *over its own
    // scope* — and the scope is stated rather than implied.
    assert.equal(model.imports.graph.state, IMPORT_GRAPH_STATES.COMPLETE);
    assert.equal(model.imports.graph.coverage.uninterpretedSources, 1);
    assert.deepEqual(model.imports.graph.coverage.uninterpretedExtensions, [".py"]);
    assert.equal(model.imports.graph.edges.length, 1);
  });

  it("reports partial for a repository that mixes parsed and unsupported sources", async () => {
    const { model } = await scanOf({
      "src/a.js": 'import "./b.js";\n',
      "src/b.js": "export const b = 1;\n",
      "src/widget.tsx": "export const Widget = () => null;\n",
    });

    assert.equal(model.imports.graph.state, IMPORT_GRAPH_STATES.PARTIAL);
    assert.equal(model.imports.graph.established, true);
    assert.deepEqual(
      model.imports.graph.coverage.unestablishedSources.map((entry) => entry.path),
      ["src/widget.tsx"],
    );
  });

  it("reports unsupported when every module source is a format this build does not parse", async () => {
    const { model, query } = await scanOf({
      "src/widget.tsx": "export const Widget = () => null;\n",
      "src/app.jsx": "export const App = () => null;\n",
    });

    assert.equal(model.imports.graph.state, IMPORT_GRAPH_STATES.UNSUPPORTED);
    assert.equal(model.imports.graph.established, false);
    assert.deepEqual(query.importGraph().edges, []);
    assert.equal(importsAbsence(query).established, false);
    assert.ok(!importsAbsence(query).reason.includes("no imports"));
  });

  it("reports unknown when every module source failed to be read", async () => {
    const draft = validateScanResult(
      createScanResult({
        root: "C:/repo",
        scannedAt: "2026-01-01T00:00:00.000Z",
        files: [{ path: "a.js", name: "a.js", extension: ".js", depth: 1 }],
        languages: [javascriptLanguage(1, ["a.js"])],
        imports: {
          inspected: false,
          complete: false,
          truncated: false,
          files: [
            moduleSource("a.js", {
              status: "failed",
              reason: "not-text",
              bytesInspected: 0,
            }),
          ],
          limits: {},
        },
        scan: { complete: true, truncated: false },
      }),
    );
    const model = buildRepositoryModel(draft);

    assert.equal(model.imports.graph.state, IMPORT_GRAPH_STATES.UNKNOWN);
    assert.equal(model.imports.graph.established, false);
    assert.equal(model.imports.graph.nodes.length, 1, "the file is still a node");
  });

  it("reports truncated when a bound stopped acquisition, never complete", async () => {
    const draft = validateScanResult(
      createScanResult({
        root: "C:/repo",
        scannedAt: "2026-01-01T00:00:00.000Z",
        files: [
          { path: "a.js", name: "a.js", extension: ".js", depth: 1 },
          { path: "b.js", name: "b.js", extension: ".js", depth: 1 },
        ],
        languages: [javascriptLanguage(2, ["a.js", "b.js"])],
        imports: {
          inspected: true,
          complete: false,
          truncated: true,
          files: [
            moduleSource("a.js", { references: [{ kind: "require", specifier: "./b" }] }),
            moduleSource("b.js", { status: "not-inspected", reason: "budget-exhausted" }),
          ],
          limits: {},
        },
        scan: { complete: true, truncated: false },
      }),
    );
    const model = buildRepositoryModel(draft);

    assert.equal(model.imports.graph.state, IMPORT_GRAPH_STATES.TRUNCATED);
    assert.equal(model.imports.graph.coverage.complete, false);
    assert.equal(model.imports.graph.coverage.notInspected, 1);
    // A bound is where knowledge stopped, not a reason to disown what was learned: a
    // truncated graph is still an established one, and the references it does carry are
    // claims the repository made.
    assert.equal(model.imports.graph.established, true);
    assert.equal(model.imports.graph.edges.length, 1);
  });

  it("reports truncated when the scan itself was truncated", async () => {
    const draft = validateScanResult(
      createScanResult({
        root: "C:/repo",
        scannedAt: "2026-01-01T00:00:00.000Z",
        files: [{ path: "a.js", name: "a.js", extension: ".js", depth: 1 }],
        languages: [javascriptLanguage(1, ["a.js"])],
        imports: {
          inspected: true,
          complete: true,
          truncated: false,
          files: [moduleSource("a.js")],
          limits: {},
        },
        scan: { complete: false, truncated: true, limits: { maxFiles: 1 } },
      }),
    );
    const model = buildRepositoryModel(draft);

    assert.equal(model.imports.graph.state, IMPORT_GRAPH_STATES.TRUNCATED);
    assert.equal(model.imports.graph.coverage.complete, false);
  });

  it("reports unknown for a graph acquisition that never ran, not empty", () => {
    const graph = buildImportGraph({
      files: [],
      sources: [],
      coverage: { scanComplete: undefined, scanTruncated: undefined },
    });
    assert.equal(graph.state, IMPORT_GRAPH_STATES.UNKNOWN);
    assert.equal(graph.established, false);

    // The same state function, characterized directly: empty is only complete when the
    // scan behind it actually finished.
    assert.equal(
      importGraphState({
        sources: [],
        scanComplete: true,
        scanTruncated: false,
        hasScanState: true,
        projectionTruncated: false,
      }),
      IMPORT_GRAPH_STATES.COMPLETE,
    );
    assert.equal(
      importGraphState({
        sources: [],
        scanComplete: false,
        scanTruncated: false,
        hasScanState: true,
        projectionTruncated: false,
      }),
      IMPORT_GRAPH_STATES.UNKNOWN,
    );
  });

  it("reports unknown through the query layer when a model carries no import area", () => {
    const model = {
      identity: { repositoryId: "repository:00000000", root: "C:/repo" },
      indexes: { entitiesById: {} },
      scan: { complete: true, truncated: false },
      relationships: [],
      evidence: [],
    };
    const query = createRepositoryQuery(model);

    assert.equal(query.importGraph().state, IMPORT_GRAPH_STATES.UNKNOWN);
    assert.equal(query.importGraph().established, false);
    assert.deepEqual(query.importGraph().edges, []);
    assert.deepEqual(query.unresolvedImports().unresolved, []);
    assert.deepEqual(query.importsOf("file:a.js").nodes, []);
    assert.deepEqual(query.entryPointCandidates().nodes, []);
    assert.deepEqual(query.orphanModules().nodes, []);
    assert.equal(query.importCoverage().nodes, 0);
  });

  it("calls exactly the states that state a graph, and the others empty", () => {
    // The projection's own predicate, not a restatement of it: `complete`, `partial`
    // and `truncated` are all graphs the repository established, and `unknown` and
    // `unsupported` establish nothing at all.
    assert.deepEqual(
      IMPORT_GRAPH_STATE_VALUES.filter((state) => isEstablishedState(state)),
      [
        IMPORT_GRAPH_STATES.COMPLETE,
        IMPORT_GRAPH_STATES.PARTIAL,
        IMPORT_GRAPH_STATES.TRUNCATED,
      ],
    );
    for (const state of IMPORT_GRAPH_STATE_VALUES) {
      assert.equal(
        isEstablishedState(state),
        state !== IMPORT_GRAPH_STATES.UNKNOWN && state !== IMPORT_GRAPH_STATES.UNSUPPORTED,
        `isEstablishedState(${state})`,
      );
    }

    // And the graph agrees with the predicate it publishes.
    const truncated = buildImportGraph({
      files: [{ id: "file:a.js", path: "a.js", extension: ".js", languageId: "language:javascript" }],
      sources: [moduleSource("a.js")],
      coverage: { scanComplete: false, scanTruncated: true },
    });
    assert.equal(truncated.state, IMPORT_GRAPH_STATES.TRUNCATED);
    assert.equal(truncated.established, isEstablishedState(truncated.state));
    assert.equal(truncated.coverage.established, true);
  });

  it("caps the projection at its own bound and says so", () => {
    // The cap cannot be reached from a repository the acquisition layer can produce,
    // so the projection is characterized directly: one more reference than the bound
    // must not be silently dropped.
    const files = [
      { id: "file:src/a.js", path: "src/a.js", extension: ".js", languageId: "language:javascript" },
    ];
    const references = Array.from({ length: IMPORT_GRAPH_LIMITS.MAX_UNRESOLVED + 1 }, (_, index) => ({
      kind: "require",
      specifier: `package-${String(index).padStart(6, "0")}`,
    }));
    const graph = buildImportGraph({
      files,
      sources: [moduleSource("src/a.js", { references })],
      coverage: { scanComplete: true, scanTruncated: false },
    });

    assert.equal(graph.unresolved.length, IMPORT_GRAPH_LIMITS.MAX_UNRESOLVED);
    assert.equal(graph.coverage.unresolvedReported, IMPORT_GRAPH_LIMITS.MAX_UNRESOLVED);
    assert.equal(graph.coverage.unresolved, IMPORT_GRAPH_LIMITS.MAX_UNRESOLVED + 1);
    assert.equal(graph.coverage.unresolvedTruncated, true);
    assert.equal(graph.state, IMPORT_GRAPH_STATES.TRUNCATED);
    assert.equal(graph.established, true);
    assert.deepEqual(graph.edges, []);
  });
});

// ─── Traversal and query API ─────────────────────────────────────────────────

describe("import graph: traversal", () => {
  it("answers what a file imports and what imports it", async () => {
    const { query } = await scanOf(fullRepo());

    assert.deepEqual(
      query.importsOf("file:src/index.js").nodes.map((node) => node.path),
      [
        "shared/outside-root.js",
        "src/data.json",
        "src/dynamic.js",
        "src/helper.js",
        "src/legacy.cjs",
        "src/lib/all.js",
        "src/lib/thing.js",
        "src/nested/deep.js",
        "src/side-effect.js",
      ],
    );
    assert.deepEqual(
      query.importedBy("file:src/lib/thing.js").nodes.map((node) => node.path),
      ["src/index.js", "src/lib/all.js"],
    );
    // The reverse direction is the same edge read backward, so the two answers cannot
    // disagree about a fact.
    assert.equal(query.importsOf("file:src/orphan.js").nodes.length, 0);
    assert.deepEqual(query.importsOf("file:src/orphan.js").edges, []);
  });

  it("follows cycles without looping, in both directions", async () => {
    const { query } = await scanOf(fullRepo());

    const fromCycle = query.importsOf("file:src/cycle-a.js", { maxDepth: 8 });
    assert.deepEqual(fromCycle.nodes.map((node) => node.path), ["src/cycle-b.js"]);
    assert.equal(fromCycle.limited, false);

    const back = query.importedBy("file:src/cycle-a.js", { maxDepth: 8 });
    assert.deepEqual(back.nodes.map((node) => node.path), ["src/cycle-b.js"]);
  });

  it("bounds a traversal in depth and results and says when it did", async () => {
    const { query } = await scanOf({
      "src/a.js": 'import "./b.js";\n',
      "src/b.js": 'import "./c.js";\n',
      "src/c.js": "export const c = 1;\n",
    });

    const oneHop = query.importsOf("file:src/a.js");
    assert.deepEqual(oneHop.nodes.map((node) => `${node.path}@${node.depth}`), ["src/b.js@1"]);

    // Depth 2 reaches the file `b` imports, which is *not* re-reported at depth 2 when
    // it was already reached at depth 1 — a breadth-first walk keeps the shallowest
    // distance, so a reference is never counted twice at two depths.
    const deep = query.importsOf("file:src/a.js", { maxDepth: 2 });
    assert.deepEqual(deep.nodes.map((node) => `${node.path}@${node.depth}`), [
      "src/b.js@1",
      "src/c.js@2",
    ]);

    const capped = query.importsOf("file:src/a.js", { maxDepth: 2, maxResults: 1 });
    assert.equal(capped.nodes.length, 1);
    assert.equal(capped.limited, true);
  });

  it("finds a directed path and refuses to invent one", async () => {
    const { query } = await scanOf(fullRepo());

    const path = query.importPath("file:src/index.js", "file:src/lib/thing.js");
    assert.equal(path.found, true);
    assert.deepEqual(path.nodes.map((node) => node.path), ["src/index.js", "src/lib/thing.js"]);
    assert.equal(path.edges.length, 1);

    assert.equal(query.importPath("file:src/lib/thing.js", "file:src/index.js").found, false);
    assert.equal(query.importPath("file:src/index.js", "file:nope.js").found, false);

    const self = query.importPath("file:src/index.js", "file:src/index.js");
    assert.equal(self.found, true);
    assert.deepEqual(self.edges, []);
  });

  it("reports entry-point and orphan candidates without judging them", async () => {
    const { query } = await scanOf(fullRepo());
    const entries = query.entryPointCandidates({ maxResults: 1000 }).nodes.map((node) => node.path);
    const orphans = query.orphanModules({ maxResults: 1000 }).nodes.map((node) => node.path);

    assert.ok(entries.includes("src/index.js"));
    assert.ok(entries.includes("src/orphan.js"));
    assert.ok(!entries.includes("src/helper.js"));
    // `src/widget.tsx` is an orphan *candidate* too: it is a module file, and no edge
    // touches it — because this build does not parse JSX, not because nothing imports
    // it. That is precisely why these are candidates and why the result carries the
    // graph's `partial` state.
    assert.deepEqual(orphans, ["src/orphan.js", "src/widget.tsx"]);
    // A non-module node is never reported as an orphan module.
    assert.ok(!orphans.includes("src/data.json"));
    // The candidate list carries the graph's state, because over a partial graph it is
    // a candidate list and not a statement about the repository.
    assert.equal(
      query.entryPointCandidates().state,
      IMPORT_GRAPH_STATES.PARTIAL,
    );
  });

  it("returns frozen results and never hands out a mutable model view", async () => {
    const { query } = await scanOf(fullRepo());
    const result = query.importGraph();

    assert.equal(Object.isFrozen(result), true);
    assert.equal(Object.isFrozen(result.edges), true);
    assert.equal(Object.isFrozen(result.edges[0]), true);
    assert.equal(Object.isFrozen(result.edges[0].specifiers), true);
    assert.throws(() => {
      result.edges.push({});
    }, TypeError);
    assert.throws(() => {
      query.importGraph().nodes[0].path = "other.js";
    }, TypeError);
    assert.equal(Object.isFrozen(query.importCoverage()), true);
    assert.equal(Object.isFrozen(query.importsOf("file:src/index.js").nodes), true);
  });

  it("filters the edge and unresolved lists by a closed vocabulary", async () => {
    const { query } = await scanOf(fullRepo());

    assert.equal(query.importEdges({ type: IMPORT_GRAPH_EDGE_TYPES.IMPORTS }).edges.length, FULL_REPO_EDGES.length);
    assert.equal(query.importEdges({ from: "file:src/self.js" }).edges.length, 1);
    assert.equal(
      query.unresolvedImports({ reason: "bare-specifier" }).unresolved.length,
      2,
    );
    assert.equal(query.unresolvedImports({ path: "src/index.js" }).unresolved.length, 3);

    assert.equal(query.importEdges({ maxResults: 1 }).limited, true);
    assert.equal(query.unresolvedImports({ maxResults: 1 }).limited, true);
    assert.equal(query.entryPointCandidates({ maxResults: 1 }).limited, true);
  });

  it("rejects a programmer error instead of answering it", async () => {
    const { query } = await scanOf(fullRepo());

    assert.throws(() => query.importEdges({ type: "calls" }), RepositoryQueryError);
    assert.throws(() => query.importEdges({ nope: true }), RepositoryQueryError);
    assert.throws(() => query.importEdges({ from: 42 }), RepositoryQueryError);
    assert.throws(() => query.importEdges({ maxResults: 0 }), RepositoryQueryError);
    assert.throws(() => query.unresolvedImports({ reason: "guessed" }), RepositoryQueryError);
    assert.throws(() => query.importsOf("file:a.js", { direction: "in" }), RepositoryQueryError);
    assert.throws(() => query.importsOf("file:a.js", { maxDepth: 99 }), RepositoryQueryError);
    assert.throws(() => query.orphanModules({ maxDepth: 2 }), RepositoryQueryError);
    // An unknown entity is an ordinary miss, not an error.
    assert.deepEqual(query.importsOf("file:ghost.js").nodes, []);
  });
});

// ─── Provenance and integrity ────────────────────────────────────────────────

describe("import graph: provenance and integrity", () => {
  it("cites an observation that exists and belongs to the importing file", async () => {
    const { model, query } = await scanOf(fullRepo());
    const evidenceIds = new Set(Object.keys(model.indexes.evidenceById));

    for (const edge of query.importEdges().edges) {
      assert.ok(edge.evidenceIds.length > 0);
      for (const id of edge.evidenceIds) {
        assert.ok(evidenceIds.has(id), `unknown observation "${id}"`);
        assert.equal(model.indexes.evidenceById[id].location.path, edge.sourcePaths[0]);
      }
      assert.deepEqual(edge.sourcePaths, [model.indexes.entitiesById[edge.from].path]);
    }
    for (const record of query.unresolvedImports().unresolved) {
      assert.ok(evidenceIds.has(record.evidenceId));
    }
  });

  it("resolves an edge's observations back through the importing entity", async () => {
    const { query } = await scanOf(fullRepo());
    const edge = query.importEdges({ from: "file:src/index.js" }).edges.at(0);
    const evidence = query.getEvidenceForEntity(edge.from).evidence;

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
    const source = model.imports;
    const graph = mutate({
      ...source.graph,
      nodes: source.graph.nodes.map((node) => ({ ...node })),
      edges: source.graph.edges.map((edge) => ({
        ...edge,
        specifiers: [...edge.specifiers],
        kinds: [...edge.kinds],
        evidenceIds: [...edge.evidenceIds],
        sourcePaths: [...edge.sourcePaths],
      })),
      unresolved: source.graph.unresolved.map((record) => ({ ...record })),
      coverage: { ...source.graph.coverage },
    });
    const tampered = {
      ...model,
      imports: { ...source, entries: source.entries.map((entry) => ({ ...entry })), graph },
    };
    assert.throws(() => validateRepositoryModelGraph(tampered), ValidationError);
  }

  it("rejects an import area that carries no graph", async () => {
    const { model } = await scanOf(fullRepo());
    assert.throws(
      () => validateRepositoryModelGraph({ ...model, imports: {} }),
      ValidationError,
    );
    assert.throws(
      () => validateRepositoryModelGraph({ ...model, imports: { ...model.imports, graph: null } }),
      ValidationError,
    );
  });

  it("rejects a node that names no file the model contains", async () => {
    await rejects((graph) => {
      graph.nodes.push({
        id: "file:ghost.js",
        path: "ghost.js",
        extension: ".js",
        languageId: "language:javascript",
        module: true,
        status: "parsed",
      });
      graph.nodes.sort((a, b) => (a.id < b.id ? -1 : 1));
      graph.coverage.nodes = graph.nodes.length;
      graph.coverage.moduleFiles = graph.nodes.filter((node) => node.module).length;
      return graph;
    });
  });

  it("rejects a node that claims a module status its source record does not have", async () => {
    await rejects((graph) => {
      graph.nodes = graph.nodes.map((node) =>
        node.id === "file:src/widget.tsx" ? { ...node, module: false } : node,
      );
      graph.coverage.moduleFiles = graph.nodes.filter((node) => node.module).length;
      return graph;
    });
  });

  it("rejects a graph that omits a module source it acquired", async () => {
    await rejects((graph) => {
      graph.nodes = graph.nodes.filter((node) => node.id !== "file:src/orphan.js");
      graph.coverage.nodes = graph.nodes.length;
      graph.coverage.moduleFiles = graph.nodes.filter((node) => node.module).length;
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

  it("rejects an edge whose endpoint is not a node, a duplicate edge, or an unknown type", async () => {
    await rejects((graph) => {
      graph.edges.push({
        from: "file:src/index.js",
        to: "file:ghost.js",
        type: IMPORT_GRAPH_EDGE_TYPES.IMPORTS,
        specifiers: ["./ghost.js"],
        kinds: ["static-import"],
        evidenceIds: ["evidence:import:import-source:src/index.js"],
        sourcePaths: ["src/index.js"],
      });
      graph.edges.sort((a, b) => (a.from < b.from ? -1 : a.from > b.from ? 1 : a.to < b.to ? -1 : 1));
      graph.coverage.edges = graph.edges.length;
      return graph;
    });
    await rejects((graph) => {
      graph.edges.push({ ...graph.edges[0] });
      graph.coverage.edges = graph.edges.length;
      return graph;
    });
    await rejects((graph) => {
      graph.edges = graph.edges.map((edge, index) =>
        index === 0 ? { ...edge, type: "calls" } : edge,
      );
      return graph;
    });
  });

  it("rejects an edge that cites a foreign observation or another file's provenance", async () => {
    await rejects((graph) => {
      graph.edges[0].evidenceIds = ["evidence:import:import-source:src/orphan.js"];
      return graph;
    });
    await rejects((graph) => {
      graph.edges = graph.edges.map((edge) =>
        edge.from === "file:src/index.js"
          ? { ...edge, sourcePaths: ["src/orphan.js"] }
          : edge,
      );
      return graph;
    });
    await rejects((graph) => {
      graph.edges[0].evidenceIds = [];
      return graph;
    });
  });

  it("rejects an edge that records no specifier or an unknown declaration form", async () => {
    await rejects((graph) => {
      graph.edges[0].specifiers = [];
      return graph;
    });
    await rejects((graph) => {
      graph.edges[0].kinds = ["inferred"];
      return graph;
    });
  });

  it("rejects an unresolved reference the graph also established as an edge", async () => {
    await rejects((graph) => {
      graph.unresolved.push({
        path: "src/index.js",
        specifier: "./helper.js",
        kind: "static-import",
        reason: "module-not-observed",
        evidenceId: "evidence:import:import-source:src/index.js",
      });
      graph.unresolved.sort((a, b) =>
        `${a.path}${a.specifier}` < `${b.path}${b.specifier}` ? -1 : 1,
      );
      graph.coverage.unresolved = graph.coverage.unresolved + 1;
      graph.coverage.unresolvedReported = graph.unresolved.length;
      return graph;
    });
  });

  it("rejects an unresolved reference with an unknown reason or a foreign observation", async () => {
    await rejects((graph) => {
      graph.unresolved[0].reason = "probably-not-there";
      return graph;
    });
    await rejects((graph) => {
      graph.unresolved[0].evidenceId = "evidence:inventory:README.md";
      return graph;
    });
    await rejects((graph) => {
      graph.unresolved[0].path = "src/orphan.js";
      return graph;
    });
  });

  it("rejects coverage that disagrees with the graph it summarises", async () => {
    await rejects((graph) => {
      graph.coverage.nodes = graph.coverage.nodes + 1;
      return graph;
    });
    await rejects((graph) => {
      graph.coverage.edges = graph.coverage.edges + 1;
      return graph;
    });
    await rejects((graph) => {
      graph.coverage.state = IMPORT_GRAPH_STATES.COMPLETE;
      return graph;
    });
    await rejects((graph) => {
      graph.coverage.unresolved = graph.coverage.unresolved + 1;
      return graph;
    });
    await rejects((graph) => {
      graph.state = IMPORT_GRAPH_STATES.COMPLETE;
      graph.established = true;
      return graph;
    });
  });

  it("rejects a coverage statement that miscounts the source files it does not read", async () => {
    // The count is cross-checked against the file entities the model contains, so a
    // graph cannot claim to have read everything while the inventory holds files in a
    // language this build does not read.
    const files = { "src/a.js": "export const a = 1;\n", "scripts/build.py": "print('hi')\n" };
    const { model } = await scanOf(files);
    const withCoverage = (coverage) => ({
      ...model,
      imports: {
        ...model.imports,
        graph: { ...model.imports.graph, coverage: { ...model.imports.graph.coverage, ...coverage } },
      },
    });

    const rejectsWith = (coverage, expected) =>
      assert.throws(
        () => validateRepositoryModelGraph(withCoverage(coverage)),
        (error) =>
          error instanceof ValidationError &&
          (error.details?.issues ?? []).some((issue) => issue.includes(expected)),
      );

    rejectsWith(
      { uninterpretedSources: 0 },
      "must count the source files in languages this build does not read",
    );
    rejectsWith(
      { uninterpretedSources: 2 },
      "must count the source files in languages this build does not read",
    );
    rejectsWith({ uninterpretedSources: -1 }, "must be a non-negative integer");
    rejectsWith({ uninterpretedSources: "1" }, "must be a non-negative integer");
    rejectsWith({ uninterpretedExtensions: "py" }, "must be an array");
    rejectsWith({ uninterpretedExtensions: ["py"] }, "lower-case, dot-prefixed");

    // And a graph cannot call itself complete over a repository whose only source
    // files are in a language it never reads, however it states its counts.
    const pythonOnly = await scanOf({ "pkg/main.py": "import os\n" });
    const claimedComplete = {
      ...pythonOnly.model,
      imports: {
        ...pythonOnly.model.imports,
        graph: {
          ...pythonOnly.model.imports.graph,
          state: IMPORT_GRAPH_STATES.COMPLETE,
          established: true,
          coverage: {
            ...pythonOnly.model.imports.graph.coverage,
            state: IMPORT_GRAPH_STATES.COMPLETE,
            established: true,
            complete: true,
          },
        },
      },
    };
    assert.throws(
      () => validateRepositoryModelGraph(claimedComplete),
      (error) =>
        error instanceof ValidationError &&
        (error.details?.issues ?? []).some((issue) =>
          issue.includes("cannot be complete when every source file is in a language"),
        ),
    );
    rejectsWith(
      {
        uninterpretedExtensions: Array.from(
          { length: IMPORT_GRAPH_LIMITS.MAX_UNINTERPRETED_EXTENSIONS + 1 },
          (_, index) => `.e${index}`,
        ),
      },
      "must stay within the graph bound",
    );

    // The same model with a truthful statement still validates, so the assertions
    // above fail for the reason they name and not because the fixture is broken.
    assert.equal(
      validateRepositoryModelGraph(model),
      model,
    );
  });

  it("rejects a source record for a file the inventory never observed", async () => {
    const { model } = await scanOf(fullRepo());
    const tampered = {
      ...model,
      imports: {
        ...model.imports,
        entries: [
          ...model.imports.entries,
          {
            path: "src/ghost.js",
            extension: ".js",
            languageId: "language:javascript",
            status: "parsed",
            reason: null,
            detail: null,
            bytesInspected: 0,
            truncated: false,
            nonStatic: 0,
            problems: [],
            references: [],
            evidenceId: "evidence:import:import-source:src/ghost.js",
          },
        ],
      },
    };
    assert.throws(() => validateRepositoryModelGraph(tampered), ValidationError);
  });

  it("rejects a source record whose status and reason contradict each other", async () => {
    const { model } = await scanOf(fullRepo());
    const breakEntry = (mutate) => {
      const entries = model.imports.entries.map((entry) => ({ ...entry }));
      mutate(entries.find((entry) => entry.path === "src/widget.tsx"));
      return validateRepositoryModelGraph({
        ...model,
        imports: { ...model.imports, entries },
      });
    };

    assert.throws(() => breakEntry((entry) => (entry.reason = null)), ValidationError);
    assert.throws(() => breakEntry((entry) => (entry.status = "guessed")), ValidationError);
    assert.throws(() => breakEntry((entry) => (entry.problems = ["invented"])), ValidationError);
    assert.throws(() => breakEntry((entry) => (entry.extension = ".py")), ValidationError);
    assert.throws(() => breakEntry((entry) => (entry.languageId = "language:cobol")), ValidationError);
    assert.throws(() => breakEntry((entry) => (entry.references = [{ kind: "guess", specifier: "./x" }])), ValidationError);
  });

  it("rejects a reference whose specifier text is unsafe", async () => {
    const { model } = await scanOf(fullRepo());
    const entries = model.imports.entries.map((entry) => ({ ...entry, references: [...entry.references] }));
    const index = entries.find((entry) => entry.path === "src/index.js");
    index.references[0] = { kind: "static-import", specifier: "a\u0000b" };
    assert.throws(
      () => validateRepositoryModelGraph({ ...model, imports: { ...model.imports, entries } }),
      ValidationError,
    );
  });

  it("rejects a module source that was not parsed but states a reference", async () => {
    const { model } = await scanOf(fullRepo());
    const entries = model.imports.entries.map((entry) => ({ ...entry }));
    const widget = entries.find((entry) => entry.path === "src/widget.tsx");
    widget.references = [{ kind: "static-import", specifier: "./index.js" }];
    assert.throws(
      () => validateRepositoryModelGraph({ ...model, imports: { ...model.imports, entries } }),
      ValidationError,
    );
  });

  it("rejects an import graph that does not match the model's own relationships", async () => {
    const { model } = await scanOf(fullRepo());
    const relationships = model.relationships.filter(
      (relationship) => relationship.type !== RELATIONSHIP_TYPES.IMPORTS,
    );
    assert.throws(
      () => validateRepositoryModelGraph({ ...model, relationships }),
      ValidationError,
    );
  });

  it("keeps the acquisition bound declared in the model", async () => {
    const { model } = await scanOf(fullRepo());

    assert.deepEqual(model.imports.graph.coverage.limits, IMPORT_GRAPH_LIMITS);
    assert.equal(IMPORT_ACQUISITION_LIMITS.maxFiles >= 1, true);
    assert.ok(model.imports.graph.coverage.edges <= IMPORT_GRAPH_LIMITS.MAX_EDGES);
    assert.ok(model.imports.graph.coverage.unresolved <= IMPORT_GRAPH_LIMITS.MAX_UNRESOLVED);
  });
});

// ─── Security ────────────────────────────────────────────────────────────────

describe("import graph: security", () => {
  it("never turns a traversal specifier into a target outside the repository", async () => {
    const { model, query } = await scanOf({
      "src/a.js": "const x = require('../../../etc/passwd');\n",
      "etc/passwd.js": "export const outside = 1;\n",
    });

    assert.deepEqual(model.imports.graph.edges, []);
    assert.equal(model.imports.graph.unresolved.length, 1);
    assert.equal(
      model.imports.graph.unresolved[0].reason,
      UNRESOLVED_REFERENCE_REASONS.OUTSIDE_REPOSITORY,
    );
    // The name `etc/passwd.js` is only a repository path here; the point is that
    // `../../../etc/passwd` was refused rather than joined onto the root.
    assert.equal(query.unresolvedImports().unresolved[0].specifier, "../../../etc/passwd");
  });

  it("never resolves an absolute, drive-letter or UNC specifier", async () => {
    const { model } = await scanOf({
      "src/a.js": [
        'const posix = require("/etc/hosts");',
        'const drive = require("C:\\\\\\\\secret\\\\\\\\x");',
        'const unc = require("\\\\\\\\\\\\\\\\server\\\\\\\\share\\\\\\\\x");',
      ].join("\n"),
      "etc/hosts.js": "export const hosts = 1;\n",
    });

    assert.deepEqual(model.imports.graph.edges, []);
    assert.deepEqual(
      model.imports.graph.unresolved.map((record) => record.reason),
      [
        UNRESOLVED_REFERENCE_REASONS.ABSOLUTE_SPECIFIER,
        UNRESOLVED_REFERENCE_REASONS.ABSOLUTE_SPECIFIER,
        UNRESOLVED_REFERENCE_REASONS.ABSOLUTE_SPECIFIER,
      ],
    );
  });

  it("does not treat a symlink as a module source, so it can never be read as one", async () => {
    const root = makeRepo({
      "src/real.js": "export const real = 1;\n",
      "src/consumer.js": 'import "./linked.js";\n',
    });
    symlinkSync(join(root, "src/real.js"), join(root, "src/linked.js"));

    const { model } = await scanModel(root);

    // The link is a symlink entity, not a file entity: nothing read it, and the
    // importer's reference to it is unresolved rather than silently resolved.
    assert.ok(!model.files.entries.some((file) => file.path === "src/linked.js"));
    assert.ok(model.files.symlinks.some((entry) => entry.path === "src/linked.js"));
    assert.deepEqual(model.imports.graph.edges, []);
    assert.equal(
      model.imports.graph.unresolved[0].reason,
      UNRESOLVED_REFERENCE_REASONS.MODULE_NOT_OBSERVED,
    );
  });

  it("refuses an unbounded or control-character specifier at acquisition and in the model", async () => {
    const draftOf = (specifier) =>
      createScanResult({
        root: "C:/repo",
        scannedAt: "2026-01-01T00:00:00.000Z",
        files: [{ path: "a.js", name: "a.js", extension: ".js", depth: 1 }],
        languages: [javascriptLanguage(1, ["a.js"])],
        imports: {
          inspected: true,
          complete: true,
          truncated: false,
          files: [moduleSource("a.js", { references: [{ kind: "require", specifier }] })],
          limits: {},
        },
        scan: { complete: true, truncated: false },
      });

    // Acquisition is the only door a specifier can come through, and it does not let
    // an unbounded string or a control character past the parser projection.
    const malformed = [`./${"x".repeat(600)}`, `./a${String.fromCharCode(0)}b`];
    for (const specifier of malformed) {
      assert.throws(() => validateScanResult(draftOf(specifier)), ValidationError);
    }

    // The model restates the check as a contract, so a specifier smuggled past an
    // unvalidated path is refused before it can reach a path candidate or a report.
    const { model } = await scanOf({ "src/a.js": 'import "./b.js";\n', "src/b.js": "" });
    for (const specifier of malformed) {
      const entries = model.imports.entries.map((entry) => ({
        ...entry,
        references: entry.references.map((reference) => ({ ...reference, specifier })),
      }));
      assert.throws(
        () => validateRepositoryModelGraph({ ...model, imports: { ...model.imports, entries } }),
        (error) =>
          error instanceof ValidationError &&
          (error.details?.issues ?? []).some((issue) =>
            issue.includes("bounded, printable specifier"),
          ),
      );
    }
  });

  it("does not put a reference's text anywhere but its own record", async () => {
    const { model } = await scanOf(fullRepo());
    for (const entry of model.imports.entries) {
      for (const reference of entry.references) {
        assert.ok(!entry.evidenceId.includes(reference.specifier));
      }
    }
    const source = model.indexes.evidenceById["evidence:import:import-source:src/index.js"];
    assert.equal(typeof source, "object");
    assert.equal(source.location.path, "src/index.js");
    const serialized = JSON.stringify(model.imports.graph);
    assert.ok(!serialized.includes("process.env"));
    assert.ok(!serialized.includes("\\\\"));
  });
});

// ─── Rule pack and analyzer integration ──────────────────────────────────────

describe("import graph: rule pack and integration", () => {
  const runRules = async (files, { rules = importRules } = {}) => {
    const { model } = await scanOf(files);
    const engine = createRuleEngine({ registry: createImportRuleRegistry({ rules }) });
    return { model, run: await engine.runAll(contextOf(model)) };
  };

  const inventoryOf = (run) =>
    run.rules.find((entry) => entry.rule.id === IMPORT_RULE_IDS.GRAPH_INVENTORY);

  it("declares its rule in the pack namespace and accepts the shipped pack", () => {
    assert.deepEqual(importRuleSetIssues(importRules), []);
    assert.equal(IMPORT_RULE_IDS.GRAPH_INVENTORY.startsWith("import."), true);
    assert.deepEqual(
      importRules.map((rule) => rule.id),
      [IMPORT_RULE_IDS.GRAPH_INVENTORY],
    );
    assert.equal(createImportRuleRegistry({ rules: importRules }).size, 1);
  });

  it("rejects a rule outside the namespace, or a missing declared rule", () => {
    assert.throws(
      () => createImportRuleRegistry({ rules: [{ ...importRules[0], id: "security.x" }] }),
      (error) => (error.details?.issues ?? []).join(" ").includes("namespace"),
    );
    assert.throws(
      () => createImportRuleRegistry({ rules: [] }),
      (error) => (error.details?.issues ?? []).join(" ").includes("missing from the pack"),
    );
  });

  it("describes every declaration form and unresolved reason the graph can state", () => {
    for (const kind of Object.values(IMPORT_SPECIFIER_KINDS)) {
      assert.equal(typeof KIND_WORDING[kind], "string", `kind "${kind}" has no wording`);
    }
    assert.deepEqual(
      [...Object.keys(KIND_WORDING)].sort(),
      [...Object.values(IMPORT_SPECIFIER_KINDS)].sort(),
    );
    assert.deepEqual(
      [...IMPORT_DESCRIBED_UNRESOLVED_REASONS].sort(),
      [...UNRESOLVED_REFERENCE_REASON_VALUES].sort(),
    );
    assert.deepEqual([...IMPORT_GRAPH_EDGE_TYPE_VALUES], [IMPORT_GRAPH_EDGE_TYPES.IMPORTS]);
  });

  it("reports one finding per established reference, citing its evidence", async () => {
    const { model, run } = await runRules(fullRepo());
    const entry = inventoryOf(run);
    const evidenceIds = new Set(Object.keys(model.indexes.evidenceById));

    assert.equal(entry.status, RULE_OUTCOME_STATUSES.VIOLATION);
    assert.equal(entry.findings.length, model.imports.graph.edges.length);
    assert.equal(entry.metadata.reported, entry.findings.length);
    assert.equal(entry.metadata.basis, IMPORT_BASIS);

    for (const finding of entry.findings) {
      assert.equal(finding.severity, "info");
      assert.ok(finding.evidence.length > 0);
      for (const id of finding.evidence) assert.ok(evidenceIds.has(id));
      assert.equal(finding.metadata.basis, IMPORT_BASIS);
      assert.equal(typeof finding.metadata.fingerprintKey, "string");
      assert.equal(finding.metadata.relationshipType, IMPORT_GRAPH_EDGE_TYPES.IMPORTS);
      assert.ok(KIND_WORDING[finding.metadata.kinds[0]] !== undefined);
    }
  });

  it("names both files, the specifiers and the declaration form", async () => {
    const { run } = await runRules(fullRepo());
    const finding = inventoryOf(run).findings.find(
      (entry) => entry.metadata.fromPath === "src/index.js" && entry.metadata.toPath === "src/helper.js",
    );

    assert.ok(finding !== undefined);
    assert.deepEqual(finding.metadata.specifiers, ["./helper.js"]);
    assert.deepEqual(finding.metadata.sourcePaths, ["src/index.js"]);
    assert.ok(finding.description.includes("`src/index.js` imports `src/helper.js`"));
    assert.ok(finding.description.includes("a static import"));
  });

  it("reports the graph's own coverage and the unresolved references it did not claim", async () => {
    const { run } = await runRules(fullRepo());
    const entry = inventoryOf(run);

    assert.equal(entry.metadata.state, IMPORT_GRAPH_STATES.PARTIAL);
    assert.equal(entry.metadata.established, true);
    assert.equal(entry.metadata.capped, false);
    assert.equal(entry.metadata.unresolved.count, 3);
    assert.deepEqual(Object.keys(entry.metadata.unresolved.byReason).sort(), [
      "bare-specifier",
      "module-not-observed",
    ]);
    assert.equal(entry.metadata.unresolved.truncated, false);
    assert.ok(entry.metadata.nonStatic >= 1);
    assert.equal(entry.metadata.unestablishedSources, 2);
  });

  it("produces deterministic, uniquely fingerprinted findings", async () => {
    const first = await runRules(fullRepo());
    const second = await runRules(fullRepo());
    const engine = createAnalyzerEngine({
      registry: createAnalyzerRegistry([createImportAnalyzer()]),
    });
    const run = await engine.runAll(contextOf(first.model));
    const repeated = await engine.runAll(contextOf(second.model));

    assert.equal(new Set(run.findings.map((finding) => finding.fingerprint)).size, run.findings.length);
    assert.deepEqual(
      run.findings.map((finding) => finding.id),
      repeated.findings.map((finding) => finding.id),
    );
    assert.deepEqual(
      inventoryOf(first.run).findings.map((finding) => finding.metadata.fingerprintKey),
      inventoryOf(second.run).findings.map((finding) => finding.metadata.fingerprintKey),
    );
  });

  it("runs as an ordinary analyzer beside the other packs", async () => {
    const { model } = await scanOf(fullRepo());
    const engine = createAnalyzerEngine({
      registry: createAnalyzerRegistry([createImportAnalyzer()]),
    });
    const result = await engine.runAll(contextOf(model));

    assert.equal(result.analyzers.length, 1);
    assert.equal(result.analyzers[0].analyzer.id, IMPORT_ANALYZER_ID);
    assert.equal(result.analyzers[0].analyzer.scope, IMPORT_ANALYZER_SCOPE);
    assert.ok(result.findings.length > 0);
  });

  it("caps a large inventory and says that it did", async () => {
    const files = {};
    for (let index = 0; index < MAX_IMPORT_FINDINGS + 15; index += 1) {
      const name = String(index).padStart(3, "0");
      files[`src/file-${name}.js`] = `import "./sink.js";\n`;
    }
    files["src/sink.js"] = "export const sink = 1;\n";
    const { run } = await runRules(files);
    const entry = inventoryOf(run);

    assert.equal(entry.findings.length, MAX_IMPORT_FINDINGS);
    assert.equal(entry.metadata.capped, true);
    assert.ok(entry.metadata.edges > MAX_IMPORT_FINDINGS);
  });

  it("abstains rather than reporting a repository whose imports could not be established", async () => {
    const { run } = await runRules({
      "src/widget.tsx": "export const Widget = () => null;\n",
    });
    const entry = inventoryOf(run);

    assert.deepEqual(entry.findings, []);
    assert.notEqual(entry.status, RULE_OUTCOME_STATUSES.PASS);
    assert.equal(entry.status, RULE_OUTCOME_STATUSES.UNKNOWN);
  });

  it("abstains over a repository whose sources are all in a language it does not read", async () => {
    // A Python repository imports a great deal. Reporting `pass` here would be an
    // all-clear over code this build never opened.
    const { run } = await runRules({
      "pkg/main.py": "import os\nfrom . import util\n",
      "pkg/util.py": "def helper():\n    return 1\n",
    });
    const entry = inventoryOf(run);

    assert.deepEqual(entry.findings, []);
    assert.equal(entry.status, RULE_OUTCOME_STATUSES.UNKNOWN);
    assert.equal(entry.metadata.state, IMPORT_GRAPH_STATES.UNSUPPORTED);
    assert.equal(entry.metadata.established, false);
    // The abstention names what was not read, and the metadata states the scope.
    assert.match(entry.applicability.reason, /language this build does not read/);
    assert.equal(entry.metadata.uninterpretedSources, 2);
    assert.deepEqual(entry.metadata.uninterpretedExtensions, [".py"]);
  });

  it("reports a repository that genuinely establishes no reference as a pass", async () => {
    const { run } = await runRules({ "src/a.js": "export const a = 1;\n" });
    const entry = inventoryOf(run);

    assert.deepEqual(entry.findings, []);
    assert.equal(entry.status, RULE_OUTCOME_STATUSES.PASS);
    assert.equal(entry.metadata.state, IMPORT_GRAPH_STATES.COMPLETE);
  });

  it("never reports a reference it could not establish as a finding", async () => {
    const { run } = await runRules({
      "src/a.js": "const x = require('express');\nconst y = require(name);\n",
    });
    const entry = inventoryOf(run);

    assert.deepEqual(entry.findings, []);
    assert.equal(entry.metadata.unresolved.count, 1);
    assert.equal(entry.metadata.unresolved.records[0].specifier, "express");
    assert.equal(entry.metadata.nonStatic >= 1, true);
  });

  it("summarises the graph without re-deriving it", async () => {
    const { model } = await scanOf(fullRepo());
    const query = createRepositoryQuery(model);

    assert.deepEqual(importRelationships(query).map((row) => row.from.length > 0), 
      importRelationships(query).map(() => true));
    assert.equal(importRelationships(query).length, model.imports.graph.edges.length);
    assert.equal(importUnresolved(query).length, model.imports.graph.unresolved.length);
    assert.equal(importCoverage(query).state, model.imports.graph.state);
    assert.equal(importsAbsence(query).established, false);
  });
});

// ─── Architectural boundary ──────────────────────────────────────────────────

describe("import graph: architectural boundary", () => {
  const PACK_DIR = join(dirname(fileURLToPath(import.meta.url)), "..", "src", "rules", "imports");
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
    "../scanner",
    "../../repository/scanner",
    "../../repository/filesystem",
    "../execution",
    "../../execution",
    "tools.js",
    "tool-registry",
  ];

  const packSources = readdirSync(PACK_DIR)
    .filter((name) => name.endsWith(".js"))
    .map((name) => ({ name, text: readFileSync(join(PACK_DIR, name), "utf8") }))
    .concat(
      readdirSync(join(PACK_DIR, "rules"))
        .filter((name) => name.endsWith(".js"))
        .map((name) => ({
          name: `rules/${name}`,
          text: readFileSync(join(PACK_DIR, "rules", name), "utf8"),
        })),
    );

  it("imports nothing but the Core, the analysis framework and its own pack", () => {
    assert.ok(packSources.length >= 6);
    for (const { name, text } of packSources) {
      for (const match of text.matchAll(/from\s+"([^"]+)"/g)) {
        const specifier = match[1];
        const allowed =
          specifier.startsWith("./") ||
          specifier.startsWith("../") ||
          specifier === "../../../core/index.js";
        assert.ok(allowed, `${name} imports "${specifier}"`);
      }
    }
  });

  it("never reaches for the filesystem, a process, the network or the clock", () => {
    for (const { name, text } of packSources) {
      for (const forbidden of FORBIDDEN) {
        assert.ok(!text.includes(`"${forbidden}"`), `${name} references "${forbidden}"`);
      }
      assert.ok(!/\bnew Date\b/.test(text), `${name} must not construct a Date`);
      assert.ok(!/\bDate\.now\b/.test(text), `${name} must not read the clock`);
      assert.ok(!/\bMath\.random\b/.test(text), `${name} must not use randomness`);
      assert.ok(!/\bprocess\.env\b/.test(text), `${name} must not read the environment`);
      assert.ok(!/\brequire\s*\(/.test(text.replace(/`require`/g, "")), `${name} must not call require`);
      assert.ok(!/\beval\s*\(/.test(text), `${name} must not use eval`);
    }
  });

  it("reads the repository only through the query API", () => {
    for (const { name, text } of packSources.filter((entry) => entry.name.startsWith("rules/"))) {
      assert.ok(
        !text.includes("context.repository"),
        `${name} must ask the query API rather than reaching into the model`,
      );
    }
  });

  it("resolves a specifier without ever consulting a package resolver", () => {
    const graphSource = readFileSync(
      join(dirname(fileURLToPath(import.meta.url)), "..", "src", "repository", "model", "import-graph.js"),
      "utf8",
    );
    for (const forbidden of ["node:module", "createRequire", "node:fs", "node:path"]) {
      assert.ok(!graphSource.includes(forbidden), `import-graph.js references "${forbidden}"`);
    }
  });
});

// ─── Hand-built scan helpers ─────────────────────────────────────────────────

/** A language entity for a hand-built ScanResult, with the evidence it needs. */
function javascriptLanguage(fileCount, paths) {
  return {
    id: "javascript",
    fileCount,
    extensions: [".js"],
    evidence: paths.map((path) => ({ path, signal: "source-extension" })),
    evidenceTruncated: false,
  };
}

/**
 * A module source record for a hand-built ScanResult.
 *
 * Defaults to a parsed source with no references, so a test only states the field it
 * is actually about.
 */
function moduleSource(path, extra = {}) {
  const extension = path.slice(path.lastIndexOf("."));
  return {
    path,
    extension,
    language: extension === ".ts" ? "typescript" : "javascript",
    status: "parsed",
    reason: null,
    detail: null,
    bytesInspected: 0,
    truncated: false,
    nonStatic: 0,
    nonStaticReasons: [],
    problems: [],
    references: [],
    ...extra,
  };
}
