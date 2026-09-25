/**
 * Code Guardian — Symbol Graph Tests (Phase 17)
 *
 * Three fixture styles, chosen deliberately:
 *
 *   - **real repositories** written to a temporary directory and scanned through the
 *     accepted Phase 8A boundary, Phase 8C scanner, Phase 8D model builder and Phase 17
 *     projection, so acquisition, model and graph agree end to end. This is the only
 *     way to prove that what a source file literally states is what the graph exposes.
 *   - **hand-built semantic sources** for facts a tiny repository cannot reach on demand
 *     (a lexer that failed, a file whose resolution is not established, a bound that
 *     bit) and for tampering, so the fail-closed behaviour of the graph contract can be
 *     stated exactly.
 *   - **mutation-style tampering** inside the model's own graph area, because the point
 *     of the contract is that a malformed graph fails validation instead of becoming a
 *     finding.
 *
 * The suite's central claim is the phase's central requirement: nothing here may turn a
 * syntactic approximation into semantic certainty. Most of the tests below exist to pin
 * one place where the graph *refuses* to make a claim — a shadowed name, an unestablished
 * callee, a namespace binding, a module nobody read, an `unknown` coverage state.
 *
 * No test spawns a process, contacts a network, installs a package or writes to the
 * repository under test.
 *
 * Run with: node --test tests/symbol-graph.test.js
 */

import { after, describe, it } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { ValidationError } from "../src/core/index.js";

import {
  SEMANTIC_ACQUISITION_LIMITS,
  SEMANTIC_PROBLEMS,
  SEMANTIC_SOURCE_REASONS,
  SEMANTIC_SOURCE_STATUSES,
  SYMBOL_BINDING_KINDS,
  SYMBOL_EXPORT_FORMS,
  SYMBOL_KINDS,
  SYMBOL_OCCURRENCE_FORMS,
  createScanResult,
  detectSemantics,
  isSemanticModuleExtension,
  isUsableSymbolName,
  scanModuleSemantics,
  scanRepository,
  validateScanResult,
} from "../src/repository/scanner/index.js";

import {
  COVERAGE_GUARANTEES,
  RepositoryQueryError,
  SYMBOL_GRAPH_EDGE_TYPES,
  SYMBOL_GRAPH_EDGE_TYPE_VALUES,
  SYMBOL_GRAPH_LIMITS,
  SYMBOL_GRAPH_STATES,
  SYMBOL_GRAPH_STATE_VALUES,
  SYMBOL_GRAPH_VERSION,
  SYMBOL_MODULE_EXTENSIONS,
  // The model boundary re-declares the declaration-kind vocabulary as a list; the scanner
  // boundary exports the same vocabulary as a keyed object. Both are used below, so both
  // names are bound explicitly.
  SYMBOL_KINDS as MODEL_SYMBOL_KINDS,
  SYMBOL_UNRESOLVED_KINDS,
  SYMBOL_UNRESOLVED_REASONS,
  SYMBOL_UNRESOLVED_REASON_VALUES,
  buildRepositoryModel,
  createRepositoryQuery,
  isSymbolSourceEstablished,
  isSymbolSourceResolvable,
  symbolGraphState,
  symbolIdOf,
  validateRepositoryModelGraph,
} from "../src/repository/model/index.js";

import {
  buildAnalysisContext,
  createAnalyzerEngine,
  createAnalyzerRegistry,
} from "../src/analysis/index.js";

import {
  EDGE_TYPE_WORDING,
  MAX_SYMBOL_FINDINGS,
  RULE_OUTCOME_STATUSES,
  SYMBOL_ANALYZER_ID,
  SYMBOL_ANALYZER_SCOPE,
  SYMBOL_BASIS,
  SYMBOL_DESCRIBED_EDGE_TYPES,
  SYMBOL_DESCRIBED_UNRESOLVED_REASONS,
  SYMBOL_KIND_WORDING,
  SYMBOL_RULE_IDS,
  UNRESOLVED_SYMBOL_REASON_WORDING,
  createRuleEngine,
  createSymbolAnalyzer,
  createSymbolRuleRegistry,
  symbolCoverage,
  symbolRelationships,
  symbolRuleSetIssues,
  symbolRules,
  symbolUnresolved,
  symbolsAbsence,
} from "../src/rules/index.js";

// ─── Fixtures ────────────────────────────────────────────────────────────────

const TMP_ROOT = join(tmpdir(), `cg-symbols-${process.pid}-${Date.now()}`);
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
 * A repository that exercises every semantic fact this build extracts.
 *
 * The inventory is deliberately small enough to reason about by hand, and every source
 * statement in it is one this phase claims to understand — the unresolved, shadowed and
 * unsupported statements are here on purpose, so the tests can prove they are *not*
 * turned into resolved relationships.
 */
const fullRepo = () => ({
  "package.json": packageJson({ name: "demo", type: "module" }),
  "src/util.js": [
    "export function helper(x) { return x * 2; }",
    "export const LIMIT = 10;",
    "export class Loader { run() { return helper(1); } }",
    "export default function main() { return helper(LIMIT); }",
    "function privateFn() { return 1; }",
    "export { privateFn as renamed };",
    "",
  ].join("\n"),
  "src/app.js": [
    'import main, { helper, LIMIT } from "./util.js";',
    'import * as ns from "./util.js";',
    "export function run() { return helper(LIMIT); }",
    "function localFn() { return 1; }",
    "export const result = localFn();",
    "const shadow = 1;",
    "function usesShadow() { const shadow = 2; return shadow; }",
    'const missing = require("./nope.js");',
    "",
  ].join("\n"),
  "src/alias.js": ["export const thing = 1;", "export { thing as thingAlias };", ""].join("\n"),
  "src/barrel.js": ['export { thing as relayed } from "./alias.js";', ""].join("\n"),
  "src/user.js": [
    'import { relayed } from "./barrel.js";',
    "export function use() { return relayed; }",
    "",
  ].join("\n"),
  "src/module.ts": [
    "export interface Shape { area(): number; }",
    "export type Alias = string;",
    "export enum Color { Red, Blue }",
    "export namespace Space { export const x = 1; }",
    "let mutable = 1;",
    "mutable = 2;",
    "export function reads() { return mutable; }",
    "",
  ].join("\n"),
  "src/widget.tsx": "export function Widget() { return 1; }\n",
  "scripts/helper.py": "def helper():\n    return 1\n",
});

// ─── Hand-built scan fixtures ────────────────────────────────────────────────

const ISO = "2026-01-01T00:00:00.000Z";
const SCAN_ROOT = "/repo";

/** A language entity for a hand-built scan, so a path has a language to resolve with. */
function javascriptLanguage(fileCount, paths) {
  return {
    id: "javascript",
    fileCount,
    extensions: [".js"],
    evidence: paths.map((path) => ({ path, signal: "source-extension" })),
    evidenceTruncated: false,
  };
}

/** A declaration record for a hand-built semantic source. */
function declaration(name, extra = {}) {
  return {
    name,
    kinds: [SYMBOL_KINDS.FUNCTION],
    keywords: ["function"],
    exported: false,
    exportNames: [],
    callable: true,
    constructable: true,
    shadowed: false,
    reassigned: false,
    binding: null,
    ...extra,
  };
}

/** An export-clause record for a hand-built semantic source. */
function exportClause(name, extra = {}) {
  return {
    name,
    localName: name,
    form: SYMBOL_EXPORT_FORMS.NAMED,
    specifier: null,
    typeOnly: false,
    ...extra,
  };
}

/** An imported-binding declaration for a hand-built semantic source. */
function bindingDeclaration(name, overrides = {}) {
  const has = (key) => Object.prototype.hasOwnProperty.call(overrides, key);
  const { bindingKind, importedName, specifier, typeOnly, ...rest } = overrides;
  return declaration(name, {
    kinds: [SYMBOL_KINDS.IMPORTED_BINDING],
    keywords: ["import:named"],
    callable: null,
    constructable: null,
    binding: {
      bindingKind: bindingKind ?? SYMBOL_BINDING_KINDS.NAMED,
      importedName: importedName ?? name,
      // `null` is a meaningful value here ("this binding names no module"), so it is
      // distinguished from an absent key rather than defaulted away.
      specifier: has("specifier") ? specifier : "./b.js",
      typeOnly: typeOnly === true,
    },
    ...rest,
  });
}

/**
 * A semantic source record for a hand-built ScanResult.
 *
 * Defaults to a fully established parsed source with nothing in it, so a test states
 * only the field it is actually about.
 */
function semanticSource(path, { established, counts, ...extra } = {}) {
  const extension = path.slice(path.lastIndexOf("."));
  return {
    path,
    extension,
    language: extension === ".ts" ? "typescript" : "javascript",
    status: SEMANTIC_SOURCE_STATUSES.PARSED,
    reason: null,
    detail: null,
    bytesInspected: 0,
    truncated: false,
    established: {
      declarations: true,
      resolution: true,
      exports: true,
      ...(established ?? {}),
    },
    counts: {
      declarations: 0,
      exports: 0,
      names: 0,
      references: 0,
      calls: 0,
      constructs: 0,
      tokens: 0,
      ...(counts ?? {}),
    },
    problems: [],
    declarations: [],
    exports: [],
    starExports: [],
    references: [],
    ...extra,
  };
}

/** A validated ScanResult literal carrying only a `semantics` section. */
function scanLiteral({ sources = [], complete = false, truncated = false, scanComplete = true } = {}) {
  // The scan contract requires semantic sources sorted by path, so the fixture sorts
  // rather than making every test state its files in path order.
  const sorted = [...sources].sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  const files = sorted.map((source) => ({
    path: source.path,
    name: source.path.slice(source.path.lastIndexOf("/") + 1),
    extension: source.extension,
    depth: source.path.split("/").length,
  }));
  // Every directory above a source has to be observed too: the model refuses a file
  // whose parent it did not see, which is a real invariant and not a fixture detail.
  const directories = new Set();
  for (const file of files) {
    const parts = file.path.split("/");
    for (let index = 1; index < parts.length; index += 1) {
      directories.add(parts.slice(0, index).join("/"));
    }
  }
  return validateScanResult(
    createScanResult({
      root: SCAN_ROOT,
      scannedAt: ISO,
      files,
      directories: [...directories]
        .sort()
        .map((path) => ({ path, name: path.slice(path.lastIndexOf("/") + 1), depth: path.split("/").length })),
      ...(files.length === 0
        ? {}
        : { languages: [javascriptLanguage(files.length, files.map((file) => file.path))] }),
      semantics: {
        inspected: sorted.length > 0,
        complete,
        truncated,
        files: sorted,
        limits: {},
      },
      scan: { complete: scanComplete, truncated },
    }),
  );
}

/** Build a model (and query handle) from hand-built semantic sources. */
function modelOf(input) {
  const model = buildRepositoryModel(scanLiteral(input));
  return { model, query: createRepositoryQuery(model) };
}

const graphOf = (input) => modelOf(input).model.symbols.graph;

/** Deep-clone a value so a tamper test does not mutate a shared fixture. */
const clone = (value) => JSON.parse(JSON.stringify(value));

/** Every `type` of edge in a graph, deduplicated and sorted. */
const edgeTypesOf = (graph) => [...new Set(graph.edges.map((edge) => edge.type))].sort();

/** All strings anywhere in a value, for leakage checks. */
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

// ─── Acquisition ─────────────────────────────────────────────────────────────

describe("symbol acquisition (real repositories)", () => {
  it("records every declaration kind this build establishes", async () => {
    const { model } = await scanOf(fullRepo());
    const kindsOf = (path) =>
      model.symbols.graph.nodes
        .filter((node) => node.path === path)
        .map((node) => `${node.name}:${node.kinds.join("+")}`);

    assert.deepEqual(kindsOf("src/util.js"), [
      "LIMIT:variable",
      "Loader:class",
      "helper:function",
      "main:function",
      "privateFn:function",
    ]);
    assert.deepEqual(kindsOf("src/module.ts"), [
      "Alias:type-alias",
      "Color:enum",
      "Shape:interface",
      "Space:namespace",
      "mutable:variable",
      "reads:function",
    ]);
  });

  it("records an imported binding with its kind and the module it names", async () => {
    const { model } = await scanOf(fullRepo());
    const helper = model.symbols.graph.nodes.find((node) => node.id === "symbol:src/app.js#helper");

    assert.deepEqual(helper.kinds, [SYMBOL_KINDS.IMPORTED_BINDING]);
    assert.equal(helper.binding.bindingKind, SYMBOL_BINDING_KINDS.NAMED);
    assert.equal(helper.binding.specifier, "./util.js");
    assert.equal(helper.binding.typeOnly, false);
    // A binding's value shape is not established by the clause that binds it.
    assert.equal(helper.callable, null);
    assert.equal(helper.constructable, null);
  });

  it("establishes a reference before the declaration it resolves to", async () => {
    const { model } = await scanOf({
      "package.json": packageJson({ name: "demo", type: "module" }),
      "src/hoist.js": ["export const value = later();", "function later() { return 1; }", ""].join("\n"),
    });
    const graph = model.symbols.graph;

    assert.equal(graph.state, SYMBOL_GRAPH_STATES.COMPLETE);
    assert.deepEqual(
      graph.edges
        .filter((edge) => edge.type === SYMBOL_GRAPH_EDGE_TYPES.CALLS)
        .map((edge) => `${edge.from}->${edge.to}`),
      ["file:src/hoist.js->symbol:src/hoist.js#later"],
    );
  });

  it("does not record a parameter or a block-scoped local as a module-scope symbol", async () => {
    const { model } = await scanOf({
      "package.json": packageJson({ name: "demo", type: "module" }),
      "src/scopes.js": [
        "export function outer(parameter) {",
        "  if (parameter) {",
        "    const blockLocal = 1;",
        "    return blockLocal;",
        "  }",
        "  const functionLocal = 2;",
        "  return functionLocal + parameter;",
        "}",
        "",
      ].join("\n"),
    });
    const graph = model.symbols.graph;

    assert.deepEqual(
      graph.nodes.map((node) => node.name),
      ["outer"],
    );
    // The uses of those names are *recorded* and not resolved: they are not module-scope
    // bindings, and reporting them as references to `outer` would be a false claim.
    for (const name of ["parameter", "blockLocal", "functionLocal"]) {
      const record = graph.unresolved.find((entry) => entry.name === name);
      assert.equal(record?.reason, SYMBOL_UNRESOLVED_REASONS.NAME_NOT_DECLARED);
    }
  });

  it("withholds resolution for a name that could be bound elsewhere in its file", async () => {
    const { model } = await scanOf(fullRepo());
    const graph = model.symbols.graph;

    const shadowed = graph.nodes.find((node) => node.id === "symbol:src/app.js#shadow");
    assert.equal(shadowed.shadowed, true);
    // The outer name is used inside `usesShadow`, where an inner `const shadow` exists,
    // so no *use* of it is resolved. The declaration itself is still a declaration.
    assert.deepEqual(
      graph.edges.filter(
        (edge) =>
          edge.to === shadowed.id &&
          edge.type !== SYMBOL_GRAPH_EDGE_TYPES.DECLARES &&
          edge.type !== SYMBOL_GRAPH_EDGE_TYPES.EXPORTS,
      ),
      [],
    );
    assert.equal(
      graph.unresolved.find((record) => record.name === "shadow" && record.path === "src/app.js")
        .reason,
      SYMBOL_UNRESOLVED_REASONS.NAME_NOT_UNIQUE,
    );
  });

  it("never turns an imported binding into a call target", async () => {
    const { model } = await scanOf(fullRepo());
    const graph = model.symbols.graph;

    // `helper(LIMIT)` in app.js: `helper` is the *local binding*, whose value shape is
    // established by nothing in this file. The file's calls to its own declarations are
    // still established, so the assertion is about the bindings specifically.
    const importedIds = new Set(
      graph.nodes
        .filter((node) => node.kinds.includes(SYMBOL_KINDS.IMPORTED_BINDING))
        .map((node) => node.id),
    );
    assert.deepEqual(
      graph.edges.filter(
        (edge) => edge.type === SYMBOL_GRAPH_EDGE_TYPES.CALLS && importedIds.has(edge.to),
      ),
      [],
    );
    assert.deepEqual(
      graph.edges
        .filter((edge) => edge.type === SYMBOL_GRAPH_EDGE_TYPES.CALLS)
        .map((edge) => edge.to),
      ["symbol:src/app.js#localFn", "symbol:src/util.js#helper"],
    );
    assert.equal(
      graph.unresolved.find(
        (record) => record.path === "src/app.js" && record.kind === "call" && record.name === "helper",
      ).reason,
      SYMBOL_UNRESOLVED_REASONS.CALLEE_NOT_ESTABLISHED,
    );
    // ...while the *reference* to `LIMIT`, which needs no value shape, is established.
    assert.equal(
      graph.edges.some(
        (edge) =>
          edge.type === SYMBOL_GRAPH_EDGE_TYPES.REFERENCES && edge.to === "symbol:src/app.js#LIMIT",
      ),
      true,
    );
  });

  it("never records a method call or a computed call as a call relationship", async () => {
    const { model } = await scanOf({
      "package.json": packageJson({ name: "demo", type: "module" }),
      "src/dispatch.js": [
        "export function target() { return 1; }",
        "export function run(obj, key) {",
        "  obj.target();",
        "  obj[key]();",
        "  this.target();",
        "  return target;",
        "}",
        "",
      ].join("\n"),
    });
    const graph = model.symbols.graph;

    // `obj.target()` and `this.target()` are runtime dispatch; `obj[key]()` is a computed
    // callee. None of them may become a call edge, and none is recorded as a reference to
    // `target` either.
    assert.deepEqual(graph.edges.filter((edge) => edge.type === SYMBOL_GRAPH_EDGE_TYPES.CALLS), []);
  });

  it("reports a JSX/TSX source as unsupported rather than parsing it as JavaScript", async () => {
    const { model } = await scanOf(fullRepo());
    const widget = model.symbols.entries.find((entry) => entry.path === "src/widget.tsx");

    assert.equal(widget.status, SEMANTIC_SOURCE_STATUSES.UNSUPPORTED);
    assert.equal(widget.reason, SEMANTIC_SOURCE_REASONS.FORMAT_NOT_INTERPRETED);
    assert.deepEqual(widget.declarations, []);
    // And the graph says what that costs: something in this repository was not read.
    assert.equal(model.symbols.graph.state, SYMBOL_GRAPH_STATES.PARTIAL);
    assert.ok(model.symbols.graph.coverage.uninterpretedSources > 0);
  });

  it("records a source whose text is not code rather than declaring symbols from it", async () => {
    const { model } = await scanOf({
      "package.json": packageJson({ name: "demo", type: "module" }),
      "src/dynamic.js": [
        "function real() { return real(); }",
        'eval("const injected = 2;");',
        "export { real };",
        "",
      ].join("\n"),
    });
    const source = model.symbols.entries[0];

    // The declaration set is established (the lexer finished), but resolution is not:
    // `eval` can introduce a binding at runtime, so no uniqueness proof in this file holds.
    assert.equal(source.established.declarationsEstablished, true);
    assert.equal(source.established.resolutionEstablished, false);
    assert.equal(source.established.exportsEstablished, true);
    assert.deepEqual(source.problems, [SEMANTIC_PROBLEMS.DYNAMIC_SCOPE_CONSTRUCT]);
    assert.deepEqual(
      model.symbols.graph.nodes.map((node) => node.name),
      ["real"],
    );
    // Declarations are exposed, resolution is withheld — and the graph says so. The
    // occurrence is `real` *calling itself*, which is the sharpest version of the claim:
    // even a name that plainly resolves is not resolved in a file where dynamic scope
    // voids the uniqueness proof.
    // A declaration is *stated* (`declares`, and the export clause that publishes it),
    // but no use of any name in this file is resolved.
    assert.deepEqual(
      model.symbols.graph.edges
        .filter((edge) => edge.type === SYMBOL_GRAPH_EDGE_TYPES.REFERENCES || edge.type === SYMBOL_GRAPH_EDGE_TYPES.CALLS)
        .map((edge) => edge.type),
      [],
    );
    assert.deepEqual(model.symbols.graph.unresolved, [
      {
        path: "src/dynamic.js",
        name: "real",
        kind: SYMBOL_OCCURRENCE_FORMS.CALL,
        reason: SYMBOL_UNRESOLVED_REASONS.RESOLUTION_NOT_ESTABLISHED,
        evidenceId: "evidence:symbol:symbol-source:src/dynamic.js",
      },
    ]);
  });

  it("contributes no symbol from a source the lexer could not read to the end", async () => {
    const { model } = await scanOf({
      "package.json": packageJson({ name: "demo", type: "module" }),
      "src/broken.js": [
        "export function fine() { return 1; }",
        'export const unterminated = "and then the file ends;',
        "",
      ].join("\n"),
    });
    const source = model.symbols.entries.find((entry) => entry.path === "src/broken.js");

    // A lexer that cannot decide what is code cannot decide what is at module scope, so
    // the whole file establishes nothing — the one error that can fabricate a symbol.
    assert.equal(source.established.declarationsEstablished, false);
    assert.equal(source.problems.includes(SEMANTIC_PROBLEMS.UNTERMINATED_STRING), true);
    // The records the scanner did read are kept verbatim (they are statements about the
    // text), and the establishment answer is what stops them becoming symbols.
    assert.equal(source.declarations.length > 0, true);
    assert.deepEqual(
      model.symbols.graph.nodes.map((node) => node.path),
      [],
    );
    assert.equal(model.symbols.graph.state, SYMBOL_GRAPH_STATES.PARTIAL);
    assert.deepEqual(
      model.symbols.graph.coverage.unestablishedSources.map((entry) => entry.path),
      ["src/broken.js"],
    );
  });

  it("does not treat a `let` binding to a function literal as a proven call target", async () => {
    const { model } = await scanOf({
      "package.json": packageJson({ name: "demo", type: "module" }),
      "src/let.js": [
        "let handler = () => 1;",
        "export function run() { return handler(); }",
        "const fixed = () => 2;",
        "export function also() { return fixed(); }",
        "",
      ].join("\n"),
    });
    const graph = model.symbols.graph;
    const node = (name) => graph.nodes.find((entry) => entry.name === name);

    // `let` is reassignable by definition, so its initializer establishes no value shape
    // — the graph states the declaration and withholds the call.
    assert.equal(node("handler").callable, null);
    assert.equal(
      graph.edges.some((edge) => edge.type === SYMBOL_GRAPH_EDGE_TYPES.CALLS && edge.to.endsWith("#handler")),
      false,
    );
    // A `const` bound to a function literal does establish one, and the call is a fact.
    assert.equal(node("fixed").callable, true);
    assert.equal(
      graph.edges.some((edge) => edge.type === SYMBOL_GRAPH_EDGE_TYPES.CALLS && edge.to.endsWith("#fixed")),
      true,
    );
  });

  it("records an unreadable source with a bounded reason instead of declaring nothing", async () => {
    const { model } = modelOf({
      sources: [
        semanticSource("a.js"),
        semanticSource("b.js", {
          status: SEMANTIC_SOURCE_STATUSES.FAILED,
          reason: SEMANTIC_SOURCE_REASONS.UNREADABLE,
          detail: "permission-denied",
          established: { declarations: false, resolution: false, exports: false },
        }),
      ],
    });
    const failed = model.symbols.entries.find((entry) => entry.path === "b.js");

    assert.equal(failed.status, SEMANTIC_SOURCE_STATUSES.FAILED);
    assert.equal(failed.reason, SEMANTIC_SOURCE_REASONS.UNREADABLE);
    assert.equal(model.symbols.graph.state, SYMBOL_GRAPH_STATES.PARTIAL);
    // The failing source is named, so a caller can see *which* file makes the graph
    // partial instead of only being told that it is.
    assert.deepEqual(
      model.symbols.graph.coverage.unestablishedSources.map((entry) => entry.path),
      ["b.js"],
    );
  });

  it("does not treat a template-literal or concatenated specifier as a module", async () => {
    const { model } = await scanOf({
      "package.json": packageJson({ name: "demo", type: "module" }),
      "src/spec.js": [
        'const a = require(`./built.js`);',
        'const b = require("./" + "concat.js");',
        "const c = 1;",
        "export { c };",
        "",
      ].join("\n"),
    });
    const graph = model.symbols.graph;

    // `a` and `b` are ordinary module-scope variables. What must *not* happen is a module
    // reference: no binding is fabricated for a specifier that is not a literal, and no
    // `imports-binding` edge exists because nothing was resolved through one.
    assert.deepEqual(
      graph.nodes.map((node) => `${node.name}:${node.kinds.join("+")}`),
      ["a:variable", "b:variable", "c:variable"],
    );
    assert.equal(
      graph.edges.some((edge) => edge.type === SYMBOL_GRAPH_EDGE_TYPES.IMPORTS_BINDING),
      false,
    );
    assert.equal(
      graph.unresolved.some((record) => record.kind === "import-binding"),
      false,
    );
  });

  it("extracts an export alias and the name it publishes", async () => {
    const { model } = await scanOf(fullRepo());
    const privateFn = model.symbols.graph.nodes.find(
      (node) => node.id === "symbol:src/util.js#privateFn",
    );

    assert.equal(privateFn.exported, true);
    assert.deepEqual(privateFn.exportNames, ["renamed"]);
  });

  it("publishes a TypeScript type alias under the name the file exports", async () => {
    const { model } = await scanOf(fullRepo());
    const alias = model.symbols.graph.nodes.find((node) => node.id === "symbol:src/module.ts#Alias");

    assert.deepEqual(alias.kinds, [SYMBOL_KINDS.TYPE_ALIAS]);
    assert.equal(alias.exported, true);
    assert.deepEqual(alias.exportNames, ["Alias"]);
  });

  it("counts a source's own occurrences without inventing a resolution from them", async () => {
    const { model } = await scanOf(fullRepo());
    const app = model.symbols.entries.find((entry) => entry.path === "src/app.js");

    // The acquisition layer reports the occurrences it saw, including the ones the model
    // then refuses to resolve (`helper(LIMIT)`, the shadowed `shadow`, `require(...)`).
    assert.equal(app.counts.names, 5);
    assert.equal(app.counts.references, 2);
    assert.equal(app.counts.calls, 3);
    assert.equal(app.counts.constructs, 0);
  });

  it("is deterministic: the same repository yields the same graph twice", async () => {
    const first = await scanOf(fullRepo());
    const second = await scanOf(fullRepo());

    assert.deepEqual(
      JSON.parse(JSON.stringify(first.model.symbols.graph)),
      JSON.parse(JSON.stringify(second.model.symbols.graph)),
    );
  });

  it("covers only the extensions it declares, and says which are module sources", () => {
    assert.deepEqual(SYMBOL_MODULE_EXTENSIONS, [".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", ".jsx", ".tsx"]);
    assert.equal(isSemanticModuleExtension(".js"), true);
    assert.equal(isSemanticModuleExtension(".tsx"), true);
    for (const extension of [".py", ".go", ".java", ".rb", ".rs", ".dart", ".json"]) {
      assert.equal(isSemanticModuleExtension(extension), false);
    }
  });

  it("refuses a symbol name that cannot become an identity", () => {
    assert.equal(isUsableSymbolName("ok"), true);
    assert.equal(isUsableSymbolName(""), false);
    // A control character cannot survive a projection into a model field the contract
    // calls an identifier, so it is refused. A space is merely unusual text and is not
    // a name the tokenizer can produce anyway.
    assert.equal(isUsableSymbolName("a\nb"), false);
    assert.equal(isUsableSymbolName("x".repeat(SEMANTIC_ACQUISITION_LIMITS.maxNameLength + 1)), false);
    assert.equal(isUsableSymbolName("x".repeat(SEMANTIC_ACQUISITION_LIMITS.maxNameLength)), true);
    assert.equal(isUsableSymbolName(null), false);
  });
});

// ─── Construction and resolution ─────────────────────────────────────────────

describe("symbol graph construction (hand-built sources)", () => {
  it("states a declaration and the call it establishes", () => {
    const graph = graphOf({
      sources: [
        semanticSource("a.js", {
          declarations: [declaration("run", { exported: true, exportNames: ["run"] })],
          references: [{ name: "run", form: SYMBOL_OCCURRENCE_FORMS.CALL, count: 1 }],
        }),
      ],
    });

    assert.deepEqual(
      graph.edges.map((edge) => `${edge.from}--${edge.type}-->${edge.to}`),
      [
        "file:a.js--calls-->symbol:a.js#run",
        "file:a.js--declares-->symbol:a.js#run",
        "file:a.js--exports-->symbol:a.js#run",
      ],
    );
    assert.equal(graph.nodes[0].callCount, 1);
    assert.equal(graph.nodes[0].referenceCount, 0);
  });

  it("withholds a call whose callee's value shape is not established", () => {
    const graph = graphOf({
      sources: [
        semanticSource("a.js", {
          declarations: [
            declaration("handler", { callable: null, constructable: null }),
            bindingDeclaration("imported", { specifier: "./b.js" }),
          ],
          references: [
            { name: "handler", form: SYMBOL_OCCURRENCE_FORMS.CALL, count: 1 },
            { name: "imported", form: SYMBOL_OCCURRENCE_FORMS.CALL, count: 2 },
          ],
        }),
        semanticSource("b.js", {
          declarations: [declaration("imported", { exported: true, exportNames: ["imported"] })],
        }),
      ],
    });

    assert.deepEqual(
      graph.edges.filter((edge) => edge.type === SYMBOL_GRAPH_EDGE_TYPES.CALLS),
      [],
    );
    assert.deepEqual(
      graph.unresolved.map((record) => `${record.name}:${record.reason}`),
      ["handler:callee-not-established", "imported:callee-not-established"],
    );
    // Counts agree with the edges: an occurrence the graph refuses to state is not
    // counted as if it had been.
    assert.deepEqual(
      graph.nodes.map((node) => node.callCount),
      graph.nodes.map(() => 0),
    );
  });

  it("withholds a reference to a name that is not unique in its file", () => {
    const graph = graphOf({
      sources: [
        semanticSource("a.js", {
          declarations: [declaration("value", { shadowed: true })],
          references: [{ name: "value", form: SYMBOL_OCCURRENCE_FORMS.REFERENCE, count: 3 }],
        }),
      ],
    });

    assert.deepEqual(
      graph.unresolved.map((record) => `${record.name}:${record.reason}`),
      ["value:name-not-unique"],
    );
    assert.deepEqual(
      graph.edges.filter((edge) => edge.type === SYMBOL_GRAPH_EDGE_TYPES.REFERENCES),
      [],
    );
    assert.equal(graph.nodes[0].referenceCount, 0);
  });

  it("uses the scanner's own establishment answer per file", () => {
    const graph = graphOf({
      sources: [
        semanticSource("a.js", {
          declarations: [declaration("kept")],
          established: { declarations: true, resolution: true, exports: true },
        }),
        semanticSource("b.js", {
          problems: [SEMANTIC_PROBLEMS.UNTERMINATED_STRING],
          established: { declarations: false, resolution: false, exports: false },
        }),
      ],
    });

    // The lexer could not decide what is code in `b.js`, so it contributes nothing at
    // all — and the graph names it rather than reporting an empty file.
    assert.deepEqual(
      graph.nodes.map((node) => node.id),
      ["symbol:a.js#kept"],
    );
    assert.equal(graph.state, SYMBOL_GRAPH_STATES.PARTIAL);
    assert.deepEqual(
      graph.coverage.unestablishedSources.map((entry) => entry.path),
      ["b.js"],
    );
  });

  it("keeps declarations while withholding resolution when a problem voids uniqueness", () => {
    const graph = graphOf({
      sources: [
        semanticSource("a.js", {
          problems: [SEMANTIC_PROBLEMS.DYNAMIC_SCOPE_CONSTRUCT],
          declarations: [declaration("one")],
          references: [{ name: "one", form: SYMBOL_OCCURRENCE_FORMS.CALL, count: 1 }],
          established: { declarations: true, resolution: false, exports: true },
        }),
      ],
    });

    assert.deepEqual(graph.nodes.map((node) => node.name), ["one"]);
    assert.deepEqual(
      graph.unresolved.map((record) => record.reason),
      [SYMBOL_UNRESOLVED_REASONS.RESOLUTION_NOT_ESTABLISHED],
    );
    // The loop `eval` forces is the reason the graph is not complete.
    assert.equal(graph.state, SYMBOL_GRAPH_STATES.PARTIAL);
  });

  it("resolves an export alias to the declaration it publishes", () => {
    const graph = graphOf({
      sources: [
        semanticSource("a.js", {
          declarations: [declaration("local")],
          exports: [exportClause("published", { localName: "local" })],
        }),
      ],
    });

    const exported = graph.edges.filter((edge) => edge.type === SYMBOL_GRAPH_EDGE_TYPES.EXPORTS);
    assert.equal(exported.length, 1);
    assert.equal(exported[0].to, "symbol:a.js#local");
    assert.deepEqual(exported[0].names, ["published"]);
  });

  it("follows a re-export chain to the symbol the target declares", () => {
    const graph = graphOf({
      sources: [
        semanticSource("a.js", {
          declarations: [declaration("thing", { exported: true, exportNames: ["thing"] })],
        }),
        semanticSource("b.js", {
          exports: [
            exportClause("relayed", {
              localName: "thing",
              form: SYMBOL_EXPORT_FORMS.RE_EXPORT,
              specifier: "./a.js",
            }),
          ],
        }),
        semanticSource("c.js", {
          declarations: [bindingDeclaration("relayed", { specifier: "./b.js", importedName: "relayed" })],
        }),
      ],
    });

    assert.deepEqual(
      graph.edges
        .filter((edge) => edge.type === SYMBOL_GRAPH_EDGE_TYPES.IMPORTS_BINDING)
        .map((edge) => `${edge.from}->${edge.to}`),
      ["symbol:c.js#relayed->symbol:a.js#thing"],
    );
  });

  it("cannot search a module whose exports are not established, and says which fact that is", () => {
    const graph = graphOf({
      sources: [
        semanticSource("a.js", {
          problems: [SEMANTIC_PROBLEMS.COMMONJS_MODULE_FORM],
          declarations: [declaration("thing", { exported: true, exportNames: ["thing"] })],
          established: { declarations: true, resolution: true, exports: false },
        }),
        semanticSource("b.js", {
          declarations: [bindingDeclaration("thing", { specifier: "./a.js" })],
        }),
      ],
    });

    // Not `export-not-found`: this build did not read the module to the end of what it
    // publishes, so it cannot claim the name is absent.
    assert.deepEqual(
      graph.unresolved.map((record) => `${record.name}:${record.reason}`),
      [`thing:${SYMBOL_UNRESOLVED_REASONS.EXPORT_NOT_ESTABLISHED}`],
    );
    // ...and the declaration `a.js` does establish is still exposed.
    assert.equal(graph.nodes.some((node) => node.id === "symbol:a.js#thing"), true);
  });

  it("records a namespace binding as a module rather than inventing a symbol", () => {
    const graph = graphOf({
      sources: [
        semanticSource("a.js", { declarations: [declaration("thing", { exported: true, exportNames: ["thing"] })] }),
        semanticSource("b.js", {
          declarations: [
            bindingDeclaration("space", {
              bindingKind: SYMBOL_BINDING_KINDS.NAMESPACE,
              importedName: "*",
              specifier: "./a.js",
            }),
          ],
        }),
      ],
    });

    assert.deepEqual(
      graph.unresolved.map((record) => `${record.kind}:${record.name}:${record.reason}`),
      [`import-binding:space:${SYMBOL_UNRESOLVED_REASONS.NAMESPACE_BINDING}`],
    );
  });

  it("records a module the scan did not observe, a bare specifier and an unreadable one", () => {
    const graph = graphOf({
      sources: [
        semanticSource("a.js", {
          declarations: [
            bindingDeclaration("missing", { specifier: "./missing.js" }),
            bindingDeclaration("pkg", { specifier: "express" }),
            bindingDeclaration("unread", { specifier: null }),
          ],
        }),
      ],
    });

    assert.deepEqual(
      graph.unresolved.map((record) => `${record.name}:${record.reason}`),
      [
        "missing:module-not-observed",
        "pkg:bare-specifier",
        `unread:${SYMBOL_UNRESOLVED_REASONS.SPECIFIER_NOT_RECORDED}`,
      ],
    );
  });

  it("records an export the target module does not establish", () => {
    const graph = graphOf({
      sources: [
        semanticSource("a.js", { declarations: [declaration("thing", { exported: true, exportNames: ["thing"] })] }),
        semanticSource("b.js", {
          declarations: [bindingDeclaration("absent", { importedName: "absent", specifier: "./a.js" })],
        }),
      ],
    });

    assert.deepEqual(
      graph.unresolved.map((record) => `${record.name}:${record.reason}`),
      [`absent:${SYMBOL_UNRESOLVED_REASONS.EXPORT_NOT_FOUND}`],
    );
  });

  it("records an ambiguous export instead of choosing one of them", () => {
    const graph = graphOf({
      sources: [
        semanticSource("a.js", {
          declarations: [
            declaration("first", { exported: true, exportNames: ["dup"] }),
            declaration("second", { exported: true, exportNames: ["dup"] }),
          ],
        }),
        semanticSource("b.js", {
          declarations: [bindingDeclaration("dup", { specifier: "./a.js" })],
        }),
      ],
    });

    assert.deepEqual(
      graph.unresolved.map((record) => `${record.name}:${record.reason}`),
      [`dup:${SYMBOL_UNRESOLVED_REASONS.EXPORT_AMBIGUOUS}`],
    );
  });

  it("records an export it cannot name, and one whose local binding it does not establish", () => {
    const graph = graphOf({
      sources: [
        semanticSource("a.js", {
          exports: [
            exportClause("default", { localName: null, form: SYMBOL_EXPORT_FORMS.DEFAULT }),
            exportClause("ghost", { localName: "ghost" }),
            exportClause("relayed", {
              localName: "other",
              form: SYMBOL_EXPORT_FORMS.RE_EXPORT,
              specifier: null,
            }),
          ],
        }),
      ],
    });

    assert.deepEqual(
      graph.unresolved.map((record) => `${record.kind}:${record.name}:${record.reason}`),
      [
        `export:default:${SYMBOL_UNRESOLVED_REASONS.ANONYMOUS_EXPORT}`,
        `export:ghost:${SYMBOL_UNRESOLVED_REASONS.EXPORT_LOCAL_NOT_ESTABLISHED}`,
        `export:relayed:${SYMBOL_UNRESOLVED_REASONS.SPECIFIER_NOT_RECORDED}`,
      ],
    );
  });

  /** A chain `length` re-export hops long, ending in a module that declares `thing`. */
  const reexportChain = (length) => {
    const sources = [
      semanticSource("m0.js", {
        declarations: [declaration("thing", { exported: true, exportNames: ["thing"] })],
      }),
    ];
    for (let index = 1; index <= length; index += 1) {
      sources.push(
        semanticSource(`m${index}.js`, {
          exports: [
            exportClause("thing", {
              localName: "thing",
              form: SYMBOL_EXPORT_FORMS.RE_EXPORT,
              specifier: `./m${index - 1}.js`,
            }),
          ],
        }),
      );
    }
    sources.push(
      semanticSource("import.js", {
        declarations: [bindingDeclaration("thing", { specifier: `./m${length}.js` })],
      }),
    );
    return sources;
  };

  it("follows a re-export chain across several modules", () => {
    const graph = graphOf({ sources: reexportChain(3) });

    assert.deepEqual(
      graph.edges
        .filter((edge) => edge.type === SYMBOL_GRAPH_EDGE_TYPES.IMPORTS_BINDING)
        .map((edge) => `${edge.from}->${edge.to}`),
      ["symbol:import.js#thing->symbol:m0.js#thing"],
    );
  });

  it("bounds the re-export chain it will follow", () => {
    const graph = graphOf({ sources: reexportChain(SYMBOL_GRAPH_LIMITS.MAX_REEXPORT_HOPS + 2) });

    // The chain is bounded, and a chain longer than the bound is *unknown*, never
    // "does not export it".
    assert.deepEqual(
      graph.edges.filter((edge) => edge.type === SYMBOL_GRAPH_EDGE_TYPES.IMPORTS_BINDING),
      [],
    );
    assert.equal(
      graph.unresolved.find((record) => record.path === "import.js").reason,
      SYMBOL_UNRESOLVED_REASONS.EXPORT_NOT_ESTABLISHED,
    );
  });

  it("orders nodes, edges and unresolved records deterministically", () => {
    const graph = graphOf({
      sources: [
        semanticSource("a.js", {
          declarations: [declaration("zulu"), declaration("alpha")],
          // Sorted by `(name, form)`, which is the order the scanner contract requires.
          references: [
            { name: "alpha", form: SYMBOL_OCCURRENCE_FORMS.CALL, count: 1 },
            { name: "missing", form: SYMBOL_OCCURRENCE_FORMS.REFERENCE, count: 1 },
            { name: "zulu", form: SYMBOL_OCCURRENCE_FORMS.CALL, count: 1 },
          ],
        }),
      ],
    });

    const ids = graph.nodes.map((node) => node.id);
    assert.deepEqual(ids, [...ids].sort());
    const keys = graph.edges.map((edge) => `${edge.from}|${edge.to}|${edge.type}`);
    assert.deepEqual(keys, [...keys].sort());
    const unresolvedKeys = graph.unresolved.map((record) => `${record.path}|${record.name}|${record.kind}`);
    assert.deepEqual(unresolvedKeys, [...unresolvedKeys].sort());
  });

  it("keeps a node's counts equal to the occurrences it states as edges", () => {
    const graph = graphOf({
      sources: [
        semanticSource("a.js", {
          declarations: [declaration("one"), declaration("two")],
          references: [
            { name: "one", form: SYMBOL_OCCURRENCE_FORMS.CALL, count: 4 },
            { name: "two", form: SYMBOL_OCCURRENCE_FORMS.REFERENCE, count: 2 },
          ],
        }),
      ],
    });

    const sumOf = (field) => graph.nodes.reduce((total, node) => total + node[field], 0);
    const edgesOf = (type) =>
      graph.edges
        .filter((edge) => edge.type === type)
        .reduce((total, edge) => total + edge.count, 0);

    assert.equal(sumOf("referenceCount"), edgesOf(SYMBOL_GRAPH_EDGE_TYPES.REFERENCES));
    assert.equal(sumOf("callCount") + sumOf("constructCount"), edgesOf(SYMBOL_GRAPH_EDGE_TYPES.CALLS));
  });

  it("does not mutate the sources it is given, and yields the same graph twice", () => {
    const sources = [
      semanticSource("a.js", {
        declarations: [declaration("one")],
        references: [{ name: "one", form: SYMBOL_OCCURRENCE_FORMS.CALL, count: 1 }],
      }),
    ];
    const before = JSON.parse(JSON.stringify(sources));
    const first = graphOf({ sources });
    const second = graphOf({ sources });

    assert.deepEqual(JSON.parse(JSON.stringify(sources)), before);
    assert.deepEqual(JSON.parse(JSON.stringify(first)), JSON.parse(JSON.stringify(second)));
    assert.equal(Object.isFrozen(first), true);
    assert.equal(Object.isFrozen(first.nodes[0]), true);
    assert.equal(Object.isFrozen(first.edges[0].evidenceIds), true);
  });

  it("reports a repository with no module source as complete", () => {
    const graph = graphOf({ sources: [] });

    assert.equal(graph.state, SYMBOL_GRAPH_STATES.COMPLETE);
    assert.equal(graph.established, true);
    assert.deepEqual(graph.nodes, []);
  });

  it("reports a repository whose every module is unsupported as unsupported", () => {
    const graph = graphOf({
      sources: [
        semanticSource("a.tsx", {
          status: SEMANTIC_SOURCE_STATUSES.UNSUPPORTED,
          reason: SEMANTIC_SOURCE_REASONS.FORMAT_NOT_INTERPRETED,
          detail: ".tsx",
          established: { declarations: false, resolution: false, exports: false },
        }),
      ],
    });

    assert.equal(graph.state, SYMBOL_GRAPH_STATES.UNSUPPORTED);
    assert.equal(graph.established, false);
  });

  it("reports a graph the scan could not finish as truncated", () => {
    const graph = graphOf({
      sources: [
        semanticSource("a.js", { declarations: [declaration("one")] }),
        semanticSource("b.js", {
          status: SEMANTIC_SOURCE_STATUSES.NOT_INSPECTED,
          reason: SEMANTIC_SOURCE_REASONS.BUDGET_EXHAUSTED,
          established: { declarations: false, resolution: false, exports: false },
        }),
      ],
      truncated: true,
      scanComplete: false,
    });

    assert.equal(graph.state, SYMBOL_GRAPH_STATES.TRUNCATED);
    assert.equal(graph.coverage.truncated, true);
  });

  it("classifies each coverage state exactly", () => {
    const parsed = { status: "parsed", problems: [], established: { declarationsEstablished: true, resolutionEstablished: true, exportsEstablished: true } };
    const base = { scanComplete: true, scanTruncated: false, hasScanState: true, projectionTruncated: false };

    assert.equal(symbolGraphState({ ...base, sources: [] }), SYMBOL_GRAPH_STATES.COMPLETE);
    assert.equal(
      symbolGraphState({ ...base, sources: [], scanComplete: false }),
      SYMBOL_GRAPH_STATES.UNKNOWN,
    );
    assert.equal(
      symbolGraphState({ ...base, sources: [], uninterpretedSources: 2 }),
      SYMBOL_GRAPH_STATES.UNSUPPORTED,
    );
    assert.equal(symbolGraphState({ ...base, sources: [parsed] }), SYMBOL_GRAPH_STATES.COMPLETE);
    assert.equal(
      symbolGraphState({ ...base, sources: [{ ...parsed, established: { ...parsed.established, resolutionEstablished: false } }] }),
      SYMBOL_GRAPH_STATES.PARTIAL,
    );
    assert.equal(
      symbolGraphState({ ...base, sources: [parsed], scanTruncated: true }),
      SYMBOL_GRAPH_STATES.TRUNCATED,
    );
    assert.equal(
      symbolGraphState({ ...base, sources: [parsed], projectionTruncated: true }),
      SYMBOL_GRAPH_STATES.TRUNCATED,
    );
    assert.equal(
      symbolGraphState({
        ...base,
        sources: [{ status: "unsupported", problems: [], established: {} }],
      }),
      SYMBOL_GRAPH_STATES.UNSUPPORTED,
    );
    assert.equal(
      symbolGraphState({ ...base, sources: [{ status: "failed", problems: [], established: {} }] }),
      SYMBOL_GRAPH_STATES.UNKNOWN,
    );
    // A model that records no scan state at all establishes nothing about the graph, so
    // the only honest answer is `unknown` — never an empty all-clear.
    assert.equal(
      symbolGraphState({
        sources: [parsed],
        scanComplete: false,
        scanTruncated: false,
        hasScanState: false,
        projectionTruncated: false,
      }),
      SYMBOL_GRAPH_STATES.UNKNOWN,
    );
  });

  it("exposes the identity rule the model validates a node against", () => {
    assert.equal(symbolIdOf("src/a.js", "run"), "symbol:src/a.js#run");
    const graph = graphOf({
      sources: [semanticSource("src/a.js", { declarations: [declaration("run")] })],
    });
    assert.equal(graph.nodes[0].id, symbolIdOf("src/a.js", "run"));
    assert.equal(graph.nodes[0].fileId, "file:src/a.js");
    assert.equal(graph.version, SYMBOL_GRAPH_VERSION);
  });

  it("keeps the establishment predicates separate and honest", () => {
    const full = { status: "parsed", established: { declarationsEstablished: true, resolutionEstablished: true, exportsEstablished: true } };
    const cjs = { status: "parsed", established: { declarationsEstablished: true, resolutionEstablished: true, exportsEstablished: false } };
    const lexical = { status: "parsed", established: { declarationsEstablished: false, resolutionEstablished: false, exportsEstablished: false } };

    assert.equal(isSymbolSourceEstablished(full), true);
    assert.equal(isSymbolSourceResolvable(full), true);
    assert.equal(isSymbolSourceEstablished(cjs), true);
    assert.equal(isSymbolSourceResolvable(cjs), true);
    assert.equal(isSymbolSourceEstablished(lexical), false);
    assert.equal(isSymbolSourceResolvable(lexical), false);
    // A source that was never scanned establishes nothing, whatever it claims.
    assert.equal(isSymbolSourceEstablished({ ...full, status: "unsupported" }), false);
  });
});

// ─── Model validation ────────────────────────────────────────────────────────

/**
 * A model whose symbol graph has been altered, for the fail-closed contract tests.
 *
 * Only the `symbols` area is rebuilt, and only shallowly: the rest of the frozen model
 * is shared, so what the validator rejects can only be the tampered area.
 */
function tamperedGraph(sources, mutate, options = {}) {
  const { model } = modelOf({ sources, ...options });
  const graph = model.symbols.graph;
  const area = {
    ...model.symbols,
    graph: {
      ...graph,
      nodes: graph.nodes.map((node) => ({ ...node })),
      edges: graph.edges.map((edge) => ({ ...edge })),
      unresolved: graph.unresolved.map((record) => ({ ...record })),
      coverage: { ...graph.coverage },
    },
  };
  mutate(area.graph, area);
  return { ...model, symbols: area };
}

/** A source that declares one symbol, refers to it and calls it. */
const declarativeSources = () => [
  semanticSource("a.js", {
    declarations: [declaration("run", { exported: true, exportNames: ["run"] })],
    references: [
      { name: "run", form: SYMBOL_OCCURRENCE_FORMS.CALL, count: 1 },
      { name: "run", form: SYMBOL_OCCURRENCE_FORMS.REFERENCE, count: 2 },
    ],
  }),
];

/** Two modules whose bindings resolve to each other, which is a real cycle. */
const cycleSources = () => [
  semanticSource("a.js", {
    declarations: [bindingDeclaration("v", { specifier: "./b.js" })],
    exports: [exportClause("v", { localName: "v" })],
  }),
  semanticSource("b.js", {
    declarations: [bindingDeclaration("v", { specifier: "./a.js" })],
    exports: [exportClause("v", { localName: "v" })],
  }),
];

describe("symbol graph validation", () => {
  const rejects = (mutate) =>
    assert.throws(
      () => validateRepositoryModelGraph(tamperedGraph(declarativeSources(), mutate)),
      ValidationError,
    );

  /**
   * Assert a tampered graph is rejected for a *specific* reason.
   *
   * `rejects` only proves that *some* invariant objected, and several invariants cover
   * the same hole by design — a duplicate node is also an out-of-order node and a
   * mis-counted graph, and a fabricated endpoint is also an edge of the wrong shape.
   * That redundancy is good for the model and bad for a test: if a test accepts whichever
   * invariant happens to fire first, deleting the one it names goes unnoticed. Naming the
   * issue is what makes each invariant independently load-bearing.
   */
  const rejectsWith = (mutate, fragment) => {
    let error;
    try {
      validateRepositoryModelGraph(tamperedGraph(declarativeSources(), mutate));
    } catch (thrown) {
      error = thrown;
    }
    assert.ok(error instanceof ValidationError, "the tampered graph must be rejected");
    const issues = error.details?.issues ?? [];
    assert.ok(
      issues.some((issue) => issue.includes(fragment)),
      `expected an issue naming "${fragment}", got: ${JSON.stringify(issues)}`,
    );
  };

  it("accepts the graph the projection builds", () => {
    const { model } = modelOf({ sources: declarativeSources() });
    assert.equal(validateRepositoryModelGraph(model), model);
  });

  it("accepts a cross-module `exports` edge, because a re-export publishes another module's symbol", () => {
    const graph = graphOf({
      sources: [
        semanticSource("a.js", {
          declarations: [declaration("thing", { exported: true, exportNames: ["thing"] })],
        }),
        semanticSource("b.js", {
          exports: [
            exportClause("relayed", {
              localName: "thing",
              form: SYMBOL_EXPORT_FORMS.RE_EXPORT,
              specifier: "./a.js",
            }),
          ],
        }),
      ],
    });
    const reexport = graph.edges.find(
      (edge) => edge.type === SYMBOL_GRAPH_EDGE_TYPES.EXPORTS && edge.from === "file:b.js",
    );

    assert.equal(reexport.to, "symbol:a.js#thing");
    assert.equal(reexport.to, "symbol:a.js#thing");
    assert.deepEqual(reexport.sourcePaths, ["b.js"]);
  });

  it("rejects a reference attributed to a file other than the one that stated it", () => {
    rejects((graph) => {
      const reference = graph.edges.find(
        (edge) => edge.type === SYMBOL_GRAPH_EDGE_TYPES.REFERENCES,
      );
      assert.ok(reference, "the fixture must state a reference");
      reference.sourcePaths = ["elsewhere.js"];
    });
  });

  it("rejects a symbol whose id is not the identity of its binding", () => {
    rejects((graph) => {
      graph.nodes[0].id = "symbol:a.js#ghost";
    });
    rejectsWith((graph) => {
      graph.nodes[0].id = "symbol:a.js#ghost";
    }, "must be the identity of the binding it describes");
  });

  it("rejects a fabricated symbol id even when every edge is rewritten to match", () => {
    // The case above is caught by whichever invariant notices first, and a rewritten
    // endpoint would hide the id-identity rule behind the endpoint checks. Here the id
    // is renamed *consistently* — every edge that named the old id names the new one —
    // so the only invariant that can reject this graph is the rule that a node's id is
    // the identity of the binding it describes. Without that rule nothing would notice
    // that `symbol:a.js#ghost` is not `symbol:a.js#run`.
    rejectsWith((graph) => {
      const original = graph.nodes[0].id;
      graph.nodes[0].id = "symbol:a.js#ghost";
      assert.notEqual("symbol:a.js#ghost", original, "the fixture must rename the id");
      for (const edge of graph.edges) {
        if (edge.from === original) edge.from = "symbol:a.js#ghost";
        if (edge.to === original) edge.to = "symbol:a.js#ghost";
      }
      assert.ok(
        graph.edges.some((edge) => edge.to === "symbol:a.js#ghost"),
        "the rename must leave the graph otherwise coherent",
      );
    }, "must be the identity of the binding it describes");
  });

  it("rejects a symbol declared in a file the model never observed", () => {
    rejects((graph) => {
      graph.nodes[0].path = "ghost.js";
      graph.nodes[0].id = symbolIdOf("ghost.js", graph.nodes[0].name);
      graph.nodes[0].fileId = "file:ghost.js";
    });
  });

  it("rejects a symbol whose file association disagrees with its path", () => {
    rejects((graph) => {
      graph.nodes[0].fileId = "file:b.js";
    });
  });

  it("rejects a declaration kind the vocabulary does not establish", () => {
    rejects((graph) => {
      graph.nodes[0].kinds = ["telepathy"];
    });
  });

  it("rejects a symbol that states exported names without being exported", () => {
    rejects((graph) => {
      graph.nodes[0].exported = false;
    });
  });

  it("rejects a duplicate symbol id", () => {
    rejects((graph) => {
      graph.nodes.push({ ...graph.nodes[0] });
    });
    // Naming the issue is what pins *this* invariant: a duplicate is also an out-of-order
    // node and a mis-counted graph, so `rejects` alone would accept whichever check fired
    // first and stop noticing if the uniqueness rule itself were removed.
    rejectsWith(
      (graph) => {
        graph.nodes.push({ ...graph.nodes[0] });
      },
      "must be unique within the graph",
    );
  });

  it("rejects unsorted, or unbounded, node and edge lists", () => {
    // A graph with more than one of each, so a reversal is genuinely out of order.
    const twoSymbols = [
      semanticSource("a.js", {
        declarations: [declaration("alpha"), declaration("zulu")],
        references: [
          { name: "alpha", form: SYMBOL_OCCURRENCE_FORMS.CALL, count: 1 },
          { name: "zulu", form: SYMBOL_OCCURRENCE_FORMS.CALL, count: 1 },
        ],
      }),
    ];
    assert.throws(
      () => validateRepositoryModelGraph(tamperedGraph(twoSymbols, (graph) => graph.nodes.reverse())),
      ValidationError,
    );
    assert.throws(
      () => validateRepositoryModelGraph(tamperedGraph(twoSymbols, (graph) => graph.edges.reverse())),
      ValidationError,
    );
    rejects((graph) => {
      graph.nodes = Array.from({ length: SYMBOL_GRAPH_LIMITS.MAX_SYMBOLS + 1 }, () => ({}));
    });
    rejects((graph) => {
      graph.edges = Array.from({ length: SYMBOL_GRAPH_LIMITS.MAX_EDGES + 1 }, () => ({}));
    });
  });

  it("rejects an edge type the graph does not state", () => {
    rejects((graph) => {
      graph.edges[0].type = "inherits";
    });
  });

  it("rejects an edge that names an entity the model does not hold", () => {
    rejects((graph) => {
      graph.edges[0].from = "file:ghost.js";
    });
    rejects((graph) => {
      graph.edges[0].to = "symbol:ghost.js#ghost";
    });
    // The endpoint rule, named. A fabricated `from` is also an edge of the wrong shape, so
    // without this the shape rule would answer for the endpoint rule and hide its removal.
    rejectsWith(
      (graph) => {
        graph.edges[0].from = "file:ghost.js";
      },
      "must name a file the model observed or a symbol in this graph",
    );
  });

  it("rejects an edge whose shape contradicts its type", () => {
    // A `declares` edge joins a file to a symbol; a `references` edge does too.
    rejects((graph) => {
      const declares = graph.edges.find((edge) => edge.type === SYMBOL_GRAPH_EDGE_TYPES.DECLARES);
      declares.to = "file:a.js";
    });
    // An `imports-binding` edge joins two symbols, never a file.
    rejects((graph) => {
      graph.edges[0].type = SYMBOL_GRAPH_EDGE_TYPES.IMPORTS_BINDING;
    });
  });

  it("rejects a relationship stated twice", () => {
    rejects((graph) => {
      graph.edges.splice(1, 0, { ...graph.edges[0] });
    });
    // A repeated relationship is also an out-of-order one, so the ordering rule would
    // otherwise answer for this rule and hide its removal.
    rejectsWith((graph) => {
      graph.edges.splice(1, 0, { ...graph.edges[0] });
    }, "must state each relationship once");
  });

  it("rejects an edge with no count, no provenance or a fabricated observation", () => {
    rejects((graph) => {
      graph.edges[0].count = 0;
    });
    rejects((graph) => {
      graph.edges[0].count = 1.5;
    });
    rejects((graph) => {
      graph.edges[0].sourcePaths = [];
    });
    rejects((graph) => {
      graph.edges[0].evidenceIds = [];
    });
    rejects((graph) => {
      graph.edges[0].evidenceIds = ["evidence:invented"];
    });
  });

  it("rejects an unresolved record with an invented reason or observation", () => {
    const withUnresolved = () =>
      assert.throws(
        () =>
          validateRepositoryModelGraph(
            tamperedGraph(
              [
                semanticSource("a.js", {
                  references: [
                    { name: "nowhere", form: SYMBOL_OCCURRENCE_FORMS.REFERENCE, count: 1 },
                  ],
                }),
              ],
              (graph) => {
                graph.unresolved[0].reason = "because-i-said-so";
              },
            ),
          ),
        ValidationError,
      );

    withUnresolved();
    assert.throws(
      () =>
        validateRepositoryModelGraph(
          tamperedGraph(
            [
              semanticSource("a.js", {
                references: [{ name: "nowhere", form: SYMBOL_OCCURRENCE_FORMS.REFERENCE, count: 1 }],
              }),
            ],
            (graph) => {
              graph.unresolved[0].evidenceId = "evidence:invented";
            },
          ),
        ),
      ValidationError,
    );
    assert.throws(
      () =>
        validateRepositoryModelGraph(
          tamperedGraph(
            [
              semanticSource("a.js", {
                references: [{ name: "nowhere", form: SYMBOL_OCCURRENCE_FORMS.REFERENCE, count: 1 }],
              }),
            ],
            (graph) => {
              graph.unresolved[0].path = "ghost.js";
            },
          ),
        ),
      ValidationError,
    );
  });

  it("rejects a coverage statement that disagrees with the graph it summarises", () => {
    const rejectsCoverage = (mutate) =>
      assert.throws(
        () => validateRepositoryModelGraph(tamperedGraph(declarativeSources(), mutate)),
        ValidationError,
      );

    rejectsCoverage((graph) => {
      graph.coverage.symbols += 1;
    });
    rejectsCoverage((graph) => {
      graph.coverage.edges += 1;
    });
    rejectsCoverage((graph) => {
      graph.coverage.state = SYMBOL_GRAPH_STATES.UNKNOWN;
    });
    rejectsCoverage((graph) => {
      graph.coverage.established = !graph.established;
    });
    rejectsCoverage((graph) => {
      graph.coverage.truncated = true;
    });
    rejectsCoverage((graph) => {
      graph.established = false;
    });
    rejectsCoverage((graph) => {
      graph.coverage.unresolved += 1;
    });
  });

  it("rejects a `complete` state over a repository whose scan did not cover it", () => {
    // The scan this model rests on never finished, so no graph over it is complete — and
    // the projection cannot reach that state on its own, which is why the check has to
    // catch a graph that claims it anyway.
    const { model } = modelOf({ sources: declarativeSources(), scanComplete: false });
    assert.equal(model.symbols.graph.state, SYMBOL_GRAPH_STATES.PARTIAL);

    const area = tamperedGraph(declarativeSources(), (graph) => {
      graph.state = SYMBOL_GRAPH_STATES.COMPLETE;
      graph.established = true;
      graph.coverage.state = SYMBOL_GRAPH_STATES.COMPLETE;
      graph.coverage.established = true;
      graph.coverage.complete = true;
      graph.coverage.truncated = false;
      graph.coverage.unestablishedSources = [];
      graph.coverage.unestablished = 0;
    }, { scanComplete: false });
    // The model itself is the same literal the tamper started from, so only the area
    // differs.
    assert.equal(model.scan.complete, false);
    assert.throws(() => validateRepositoryModelGraph(area), ValidationError);
  });

  it("rejects a symbols area that carries no graph, and one that disagrees with its entries", () => {
    const { model } = modelOf({ sources: declarativeSources() });

    assert.throws(() => validateRepositoryModelGraph({ ...model, symbols: {} }), ValidationError);
    assert.throws(
      () => validateRepositoryModelGraph({ ...model, symbols: { ...model.symbols, graph: null } }),
      ValidationError,
    );
    assert.throws(
      () =>
        validateRepositoryModelGraph({
          ...model,
          symbols: { ...model.symbols, count: model.symbols.count + 1 },
        }),
      ValidationError,
    );
    assert.throws(
      () =>
        validateRepositoryModelGraph({
          ...model,
          symbols: { ...model.symbols, entries: [] },
        }),
      ValidationError,
    );
  });

  it("rejects an entry that names a semantic source the model did not observe", () => {
    const { model } = modelOf({ sources: declarativeSources() });

    assert.throws(
      () =>
        validateRepositoryModelGraph({
          ...model,
          symbols: {
            ...model.symbols,
            entries: [{ ...model.symbols.entries[0], path: "ghost.js" }],
          },
        }),
      ValidationError,
    );
  });
});

// ─── Query API ───────────────────────────────────────────────────────────────

describe("symbol query API", () => {
  const queryOf = async (files) => {
    const { model, query } = await scanOf(files);
    return { model, query };
  };

  it("answers the whole-graph question with an established envelope", async () => {
    const { query } = await queryOf(fullRepo());
    const graph = query.symbolGraph();

    assert.equal(graph.state, SYMBOL_GRAPH_STATES.PARTIAL);
    assert.equal(graph.established, true);
    assert.equal(graph.coverage, COVERAGE_GUARANTEES.PARTIAL);
    assert.equal(graph.truncated, false);
    assert.ok(graph.nodes.length > 0);
    assert.ok(graph.edges.length > 0);
    // Unresolved occurrences are not edges and are not folded into this answer.
    assert.equal("unresolved" in graph, false);
    assert.equal(Object.isFrozen(graph), true);
  });

  it("states the graph's coverage, including why it is not complete", async () => {
    const { model, query } = await queryOf(fullRepo());
    const coverage = query.symbolCoverage();

    assert.deepEqual(coverage, model.symbols.graph.coverage);
    assert.equal(coverage.parsed > 0, true);
    assert.equal(coverage.uninterpretedSources, 1);
    assert.deepEqual(coverage.uninterpretedExtensions, [".py"]);
    assert.ok(coverage.unestablishedSources.length > 0);
  });

  it("filters symbol nodes by the facts the graph recorded", async () => {
    const { query } = await queryOf(fullRepo());

    assert.deepEqual(
      query.symbolNodes({ kind: SYMBOL_KINDS.CLASS }).nodes.map((node) => node.name),
      ["Loader"],
    );
    assert.deepEqual(
      query.symbolNodes({ name: "helper" }).nodes.map((node) => node.path),
      ["src/app.js", "src/util.js"],
    );
    assert.deepEqual(
      query.symbolNodes({ exported: false, kind: SYMBOL_KINDS.FUNCTION }).nodes.map((node) => node.name),
      ["localFn", "usesShadow"],
    );
    assert.deepEqual(
      query.symbolNodes({ path: "src/util.js", exported: true }).nodes.map((node) => node.name),
      ["LIMIT", "Loader", "helper", "main", "privateFn"],
    );
    // Both spellings of a file name the same file, because both are already projected.
    assert.deepEqual(
      query.symbolNodes({ fileId: "src/util.js" }).nodes.map((node) => node.id),
      query.symbolNodes({ fileId: "file:src/util.js" }).nodes.map((node) => node.id),
    );
  });

  it("refuses criteria and bounds the graph cannot honour", async () => {
    const { query } = await queryOf(fullRepo());

    assert.throws(() => query.symbolNodes({ kind: "telepathy" }), RepositoryQueryError);
    assert.throws(() => query.symbolNodes({ nope: 1 }), RepositoryQueryError);
    assert.throws(() => query.symbolNodes({ name: "" }), RepositoryQueryError);
    assert.throws(() => query.symbolNodes({ maxResults: 0 }), RepositoryQueryError);
    assert.throws(() => query.symbolNodes({ maxResults: 100000 }), RepositoryQueryError);
    assert.throws(
      () => query.symbolEdges({ type: "depends-on" }),
      (error) => error instanceof RepositoryQueryError && error.kind === "invalid-relationship-type",
    );
    assert.throws(() => query.unresolvedSymbolReferences({ kind: "telepathy" }), RepositoryQueryError);
    assert.throws(() => query.unresolvedSymbolReferences({ reason: "telepathy" }), RepositoryQueryError);
    assert.throws(() => query.symbolsInFile(""), RepositoryQueryError);
    assert.throws(() => query.symbolPath("a", "b", { maxDepth: -1 }), RepositoryQueryError);
    assert.throws(() => query.symbolPath("a", "b", { nope: 1 }), RepositoryQueryError);
  });

  it("bounds a node list and says that it did", async () => {
    const { query } = await queryOf(fullRepo());
    const nodes = query.symbolNodes({ maxResults: 2 });

    assert.equal(nodes.nodes.length, 2);
    assert.equal(nodes.limited, true);
    assert.equal(nodes.coverage, COVERAGE_GUARANTEES.PARTIAL);
  });

  it("lists the symbols a file declares, and misses an unknown file without erring", async () => {
    const { query } = await queryOf(fullRepo());

    assert.deepEqual(
      query.symbolsInFile("src/app.js").nodes.map((node) => node.name),
      ["LIMIT", "helper", "localFn", "main", "missing", "ns", "result", "run", "shadow", "usesShadow"],
    );
    const missing = query.symbolsInFile("src/nope.js");
    assert.deepEqual(missing.nodes, []);
    assert.equal(missing.coverage, COVERAGE_GUARANTEES.PARTIAL);
    assert.equal(missing.state, SYMBOL_GRAPH_STATES.PARTIAL);
  });

  it("filters edges by endpoint and type, and refuses a foreign type", async () => {
    const { query } = await queryOf(fullRepo());

    // Edges keep the graph's own `(from, to, type)` order: the bindings of `src/app.js`
    // come before the one in `src/user.js`.
    assert.deepEqual(
      query.symbolEdges({ type: SYMBOL_GRAPH_EDGE_TYPES.IMPORTS_BINDING }).edges.map((edge) => edge.to),
      ["symbol:src/util.js#LIMIT", "symbol:src/util.js#helper", "symbol:src/util.js#main", "symbol:src/alias.js#thing"],
    );
    assert.deepEqual(query.symbolEdges({ from: "file:src/nope.js" }).edges, []);
    assert.deepEqual(
      query.symbolEdges({ type: SYMBOL_GRAPH_EDGE_TYPES.CALLS, to: "symbol:src/util.js#helper" }).edges.map(
        (edge) => edge.from,
      ),
      ["file:src/util.js"],
    );
  });

  it("splits what points at a symbol into references and calls", async () => {
    const { query } = await queryOf(fullRepo());
    const result = query.referencesTo("symbol:src/util.js#helper");

    assert.equal(result.symbol.id, "symbol:src/util.js#helper");
    assert.deepEqual(result.references, []);
    assert.deepEqual(result.calls.map((edge) => `${edge.from}:${edge.count}`), ["file:src/util.js:2"]);
    // A reference query is not a call query, and the reverse holds: the graph states each
    // occurrence once, under exactly one type. Note *which* symbol the occurrence in
    // `src/app.js` resolves to: the file's own binding, not the one it was imported from —
    // that connection is the binding edge, not a reference.
    const limit = query.referencesTo("symbol:src/util.js#LIMIT");
    assert.deepEqual(limit.references.map((edge) => edge.from), ["file:src/util.js"]);
    assert.deepEqual(limit.calls, []);
    assert.deepEqual(
      query.referencesTo("symbol:src/app.js#LIMIT").references.map((edge) => `${edge.from}:${edge.count}`),
      ["file:src/app.js:1"],
    );
  });

  it("answers an unknown symbol as an ordinary miss", async () => {
    const { query } = await queryOf(fullRepo());
    const result = query.referencesTo("symbol:ghost.js#ghost");

    assert.equal(result.symbol, null);
    assert.deepEqual(result.references, []);
    assert.deepEqual(result.calls, []);
    assert.deepEqual(query.calledBy("symbol:ghost.js#ghost").edges, []);
  });

  it("answers who calls a symbol, and never who a symbol calls", async () => {
    const { query } = await queryOf(fullRepo());

    assert.deepEqual(query.calledBy("symbol:src/util.js#helper").edges.map((edge) => edge.from), [
      "file:src/util.js",
    ]);
    // The calls a *file* states are the graph's own edges...
    assert.deepEqual(query.callsFrom("src/util.js").edges.map((edge) => edge.to), [
      "symbol:src/util.js#helper",
    ]);
    // ...and a symbol is not a file, so no symbol-scoped "calls from" exists to answer.
    assert.throws(() => query.callsFrom("symbol:src/util.js#helper"), RepositoryQueryError);
    assert.throws(() => query.callsFrom("symbol:src/util.js#helper"), (error) => error.kind === "invalid-query");
  });

  it("lists the symbols a file publishes, resolving a re-export to the declaration", async () => {
    const { query } = await queryOf(fullRepo());

    assert.deepEqual(query.exportsOf("src/alias.js").nodes.map((node) => node.name), ["thing"]);
    assert.deepEqual(query.exportsOf("src/alias.js").nodes[0].exportNames, ["thing", "thingAlias"]);
    // A re-export publishes another module's symbol, so this is where it resolves to.
    assert.deepEqual(query.exportsOf("src/barrel.js").nodes.map((node) => node.path), ["src/alias.js"]);
  });

  it("joins a file's imported bindings to their targets, and keeps the rest apart", async () => {
    const { query } = await queryOf(fullRepo());
    const result = query.importsToSymbols("src/app.js");

    assert.deepEqual(
      result.bindings.map((binding) => `${binding.name}:${binding.resolved}:${binding.targetSymbolId}`),
      [
        "LIMIT:true:symbol:src/util.js#LIMIT",
        "helper:true:symbol:src/util.js#helper",
        "main:true:symbol:src/util.js#main",
        "ns:false:null",
      ],
    );
    // `const missing = require(...)` is an ordinary variable, not an imported binding, so
    // it is not listed here at all — only the binding whose target this build could not
    // establish is.
    assert.deepEqual(
      result.unresolved.map((record) => `${record.name}:${record.reason}`),
      [`ns:${SYMBOL_UNRESOLVED_REASONS.NAMESPACE_BINDING}`],
    );
  });

  it("lists the occurrences the repository could not resolve, by kind and reason", async () => {
    const { query } = await queryOf(fullRepo());
    const all = query.unresolvedSymbolReferences();

    assert.equal(all.unresolved.length > 0, true);
    assert.ok(
      all.unresolved.every((record) => SYMBOL_UNRESOLVED_KINDS.includes(record.kind)),
    );
    const calls = query.unresolvedSymbolReferences({ kind: "call" });
    assert.deepEqual(
      calls.unresolved.map((record) => `${record.name}:${record.reason}`),
      [
        `helper:${SYMBOL_UNRESOLVED_REASONS.CALLEE_NOT_ESTABLISHED}`,
        "require:name-not-declared",
        // `area(): number` in an interface body is a *member signature*, not a call, and
        // this build has no type-aware reading that can tell the two apart. It is recorded
        // as an occurrence and stays unresolved, which is the honest answer: an occurrence
        // the graph refuses to turn into a relationship.
        "area:name-not-declared",
      ],
    );
    assert.deepEqual(
      query.unresolvedSymbolReferences({ path: "src/app.js", name: "shadow" }).unresolved.map(
        (record) => record.reason,
      ),
      [SYMBOL_UNRESOLVED_REASONS.NAME_NOT_UNIQUE],
    );
  });

  it("walks a symbol path along established relationships", async () => {
    const { query } = await queryOf(fullRepo());
    const path = query.symbolPath("symbol:src/user.js#relayed", "symbol:src/alias.js#thing");

    assert.equal(path.found, true);
    assert.deepEqual(path.edges.map((edge) => edge.type), [SYMBOL_GRAPH_EDGE_TYPES.IMPORTS_BINDING]);
    assert.deepEqual(path.nodes.map((node) => node.id), ["symbol:src/user.js#relayed", "symbol:src/alias.js#thing"]);
    assert.deepEqual(path.nodes.map((node) => node.depth), [0, 1]);
    // A file is not a symbol, so a file-to-file path is a different question (`importPath`).
    const filePath = query.symbolPath("file:src/user.js", "file:src/alias.js");
    assert.equal(filePath.found, false);
    assert.deepEqual(filePath.nodes, []);
    // The same symbol is trivially reachable from itself, with no edge invented for it.
    const same = query.symbolPath("symbol:src/util.js#helper", "symbol:src/util.js#helper");
    assert.equal(same.found, true);
    assert.deepEqual(same.edges, []);
  });

  it("bounds a symbol path by depth and by results", async () => {
    const { query } = await queryOf(fullRepo());
    const shallow = query.symbolPath("symbol:src/user.js#relayed", "symbol:src/alias.js#thing", {
      maxDepth: 0,
    });

    assert.equal(shallow.found, false);
    // `maxResults` bounds the nodes the search may visit, so a bound of one cannot describe
    // a two-node path — and it says so rather than answering "not reachable".
    const cut = query.symbolPath("symbol:src/user.js#relayed", "symbol:src/alias.js#thing", {
      maxResults: 1,
    });
    assert.equal(cut.found, false);
    assert.equal(cut.limited, true);
    const room = query.symbolPath("symbol:src/user.js#relayed", "symbol:src/alias.js#thing", {
      maxResults: 2,
    });
    assert.equal(room.found, true);
    assert.equal(room.limited, false);
  });

  it("terminates on a cycle of import bindings", async () => {
    const { query } = modelOf({ sources: cycleSources() });
    const graph = query.symbolGraph();

    // Both directions of the cycle exist, which is what makes the walk interesting.
    assert.deepEqual(
      graph.edges
        .filter((edge) => edge.type === SYMBOL_GRAPH_EDGE_TYPES.IMPORTS_BINDING)
        .map((edge) => `${edge.from}->${edge.to}`),
      ["symbol:a.js#v->symbol:b.js#v", "symbol:b.js#v->symbol:a.js#v"],
    );
    const forward = query.symbolPath("symbol:a.js#v", "symbol:b.js#v");
    assert.equal(forward.found, true);
    const around = query.symbolPath("symbol:b.js#v", "symbol:a.js#v");
    assert.equal(around.found, true);
    // A target outside the cycle is simply not reachable — the walk terminates rather
    // than following the cycle forever.
    const unreachable = query.symbolPath("symbol:a.js#v", "symbol:b.js#ghost");
    assert.equal(unreachable.found, false);
  });

  it("is deterministic across handles, and leaves the model untouched", async () => {
    const { model, query } = await queryOf(fullRepo());
    const second = createRepositoryQuery(model);
    const before = JSON.stringify(model.symbols.graph);

    assert.deepEqual(
      JSON.parse(JSON.stringify(query.symbolGraph())),
      JSON.parse(JSON.stringify(second.symbolGraph())),
    );
    assert.deepEqual(
      JSON.parse(JSON.stringify(query.symbolNodes({ kind: SYMBOL_KINDS.FUNCTION }).nodes)),
      JSON.parse(JSON.stringify(second.symbolNodes({ kind: SYMBOL_KINDS.FUNCTION }).nodes)),
    );
    assert.equal(JSON.stringify(model.symbols.graph), before);
    assert.equal(Object.isFrozen(query.symbolGraph().nodes[0]), true);
  });

  it("reports the scan's guarantee honestly in every envelope", async () => {
    const { query } = await queryOf({
      "package.json": packageJson({ name: "demo", type: "module" }),
      "a.js": "export const one = 1;\n",
    });

    assert.equal(query.symbolGraph().coverage, COVERAGE_GUARANTEES.COMPLETE);
    assert.equal(query.symbolNodes({}).coverage, COVERAGE_GUARANTEES.COMPLETE);
    assert.equal(query.symbolEdges({}).coverage, COVERAGE_GUARANTEES.COMPLETE);
    assert.equal(query.referencesTo("symbol:a.js#one").coverage, COVERAGE_GUARANTEES.COMPLETE);
    assert.equal(query.unresolvedSymbolReferences().coverage, COVERAGE_GUARANTEES.COMPLETE);
    assert.equal(query.callsFrom("a.js").coverage, COVERAGE_GUARANTEES.COMPLETE);
    assert.equal(query.exportsOf("a.js").coverage, COVERAGE_GUARANTEES.COMPLETE);
    assert.equal(query.importsToSymbols("a.js").coverage, COVERAGE_GUARANTEES.COMPLETE);
    assert.equal(query.calledBy("symbol:a.js#one").coverage, COVERAGE_GUARANTEES.COMPLETE);
    assert.equal(query.symbolPath("symbol:a.js#one", "symbol:a.js#one").coverage, COVERAGE_GUARANTEES.COMPLETE);
  });
});

// ─── Rule pack and analyzer ──────────────────────────────────────────────────

describe("symbol rule pack", () => {
  const runOf = async (files) => {
    const { model } = await scanOf(files);
    const engine = createRuleEngine({
      registry: createSymbolRuleRegistry({ rules: symbolRules }),
    });
    return { model, run: await engine.runAll(contextOf(model)) };
  };

  const runOfModel = async (model) => {
    const engine = createRuleEngine({
      registry: createSymbolRuleRegistry({ rules: symbolRules }),
    });
    return engine.runAll(contextOf(model));
  };

  const inventoryOf = (run) => run.rules.find((entry) => entry.rule.id === SYMBOL_RULE_IDS.GRAPH_INVENTORY);

  it("declares its rule in the pack namespace and accepts the shipped pack", () => {
    assert.deepEqual(symbolRuleSetIssues(symbolRules), []);
    assert.equal(SYMBOL_RULE_IDS.GRAPH_INVENTORY.startsWith("symbols."), true);
    assert.deepEqual(
      symbolRules.map((rule) => rule.id),
      [SYMBOL_RULE_IDS.GRAPH_INVENTORY],
    );
    const rule = symbolRules[0];
    assert.equal(rule.severity, "info");
    assert.deepEqual(rule.applicability, {});
    assert.equal(typeof rule.detect, "function");
  });

  it("refuses a rule set that leaves the pack contract", () => {
    assert.deepEqual(symbolRuleSetIssues("nope"), ["symbolRules: must be an array of rules"]);
    assert.equal(
      symbolRuleSetIssues([{ id: "security.analysis.dependencies" }]).length > 0,
      true,
    );
    assert.equal(symbolRuleSetIssues([]).length > 0, true);
    assert.equal(
      symbolRuleSetIssues([symbolRules[0], symbolRules[0]]).some((issue) => issue.includes("twice")),
      true,
    );
    assert.throws(() => createSymbolRuleRegistry({ rules: [] }), Error);
  });

  it("describes every value of every vocabulary the graph can state", () => {
    assert.deepEqual([...SYMBOL_DESCRIBED_EDGE_TYPES].sort(), [...SYMBOL_GRAPH_EDGE_TYPE_VALUES].sort());
    assert.deepEqual(Object.keys(SYMBOL_KIND_WORDING).sort(), [...MODEL_SYMBOL_KINDS].sort());
    assert.deepEqual(
      [...SYMBOL_DESCRIBED_UNRESOLVED_REASONS].sort(),
      [...SYMBOL_UNRESOLVED_REASON_VALUES].sort(),
    );
    assert.deepEqual(Object.keys(EDGE_TYPE_WORDING).sort(), [...SYMBOL_GRAPH_EDGE_TYPE_VALUES].sort());
    assert.deepEqual(
      Object.keys(UNRESOLVED_SYMBOL_REASON_WORDING).sort(),
      [...SYMBOL_UNRESOLVED_REASON_VALUES].sort(),
    );
  });

  it("reports one finding per established relationship, citing the stating file's observation", async () => {
    const { model, run } = await runOf(fullRepo());
    const inventory = inventoryOf(run);
    const evidenceIds = new Set(model.evidence.map((record) => record.id));
    const graph = model.symbols.graph;

    assert.equal(inventory.status, RULE_OUTCOME_STATUSES.VIOLATION);
    assert.equal(inventory.findings.length, graph.edges.length);
    assert.equal(inventory.metadata.basis, SYMBOL_BASIS);
    assert.equal(inventory.metadata.state, graph.state);
    assert.equal(inventory.metadata.reported, graph.edges.length);
    assert.equal(inventory.metadata.capped, false);
    for (const finding of inventory.findings) {
      assert.equal(finding.evidence.length, 1);
      assert.equal(evidenceIds.has(finding.evidence[0]), true);
      assert.equal(finding.metadata.basis, SYMBOL_BASIS);
      assert.equal(SYMBOL_GRAPH_EDGE_TYPE_VALUES.includes(finding.metadata.relationshipType), true);
      assert.equal(typeof finding.metadata.fingerprintKey, "string");
      assert.equal(finding.severity, "info");
    }
  });

  it("states what each relationship is, and what it is not", async () => {
    const { run } = await runOf(fullRepo());
    const findings = inventoryOf(run).findings;
    const described = (type) => findings.filter((finding) => finding.metadata.relationshipType === type);

    assert.equal(described(SYMBOL_GRAPH_EDGE_TYPES.DECLARES).length > 0, true);
    assert.equal(described(SYMBOL_GRAPH_EDGE_TYPES.EXPORTS).length > 0, true);
    assert.equal(described(SYMBOL_GRAPH_EDGE_TYPES.REFERENCES).length > 0, true);
    assert.equal(described(SYMBOL_GRAPH_EDGE_TYPES.CALLS).length > 0, true);
    assert.equal(described(SYMBOL_GRAPH_EDGE_TYPES.IMPORTS_BINDING).length > 0, true);
    for (const finding of findings) {
      assert.ok(finding.description.includes(`\`${finding.metadata.toName}\``));
      assert.ok(finding.description.includes(`\`${finding.metadata.fromPath}\``));
    }
    // A declaration is stated as a declaration, not as a use.
    const declaration = described(SYMBOL_GRAPH_EDGE_TYPES.DECLARES)[0];
    assert.ok(declaration.description.includes("declared at module scope"));
    // A call is stated as a call site, not as an execution.
    const call = described(SYMBOL_GRAPH_EDGE_TYPES.CALLS)[0];
    assert.ok(call.description.includes("not a claim that the call executes"));
  });

  it("keeps an occurrence the graph could not resolve out of the findings", async () => {
    const { model, run } = await runOf(fullRepo());
    const inventory = inventoryOf(run);
    const graph = model.symbols.graph;

    assert.equal(graph.unresolved.length > 0, true);
    assert.equal(inventory.metadata.unresolved.count, graph.unresolved.length);
    assert.equal(
      inventory.metadata.unresolved.count,
      Object.values(inventory.metadata.unresolved.byReason).reduce((total, count) => total + count, 0),
    );
    assert.equal(
      inventory.metadata.unresolved.byKind.call,
      graph.unresolved.filter((record) => record.kind === "call").length,
    );
    // No finding reports an unresolved occurrence as a relationship.
    const words = Object.values(UNRESOLVED_SYMBOL_REASON_WORDING);
    for (const finding of inventory.findings) {
      for (const word of words) assert.ok(!finding.description.includes(word));
    }
  });

  it("caps a large inventory and says that it did", async () => {
    const declarations = [];
    const references = [];
    for (let index = 0; index < MAX_SYMBOL_FINDINGS + 15; index += 1) {
      const name = `fn${String(index).padStart(4, "0")}`;
      declarations.push(declaration(name));
      references.push({ name, form: SYMBOL_OCCURRENCE_FORMS.CALL, count: 1 });
    }
    const { model } = modelOf({ sources: [semanticSource("a.js", { declarations, references })] });
    const run = await runOfModel(model);
    const inventory = inventoryOf(run);

    assert.equal(inventory.findings.length, MAX_SYMBOL_FINDINGS);
    assert.equal(inventory.metadata.capped, true);
    assert.equal(inventory.metadata.edges > MAX_SYMBOL_FINDINGS, true);
  });

  it("produces deterministic, uniquely fingerprinted findings", async () => {
    const first = await runOf(fullRepo());
    const second = await runOf(fullRepo());
    const engine = createAnalyzerEngine({
      registry: createAnalyzerRegistry([createSymbolAnalyzer()]),
    });
    const analyzed = await engine.runAll(contextOf(first.model));

    assert.equal(new Set(analyzed.findings.map((finding) => finding.fingerprint)).size, analyzed.findings.length);
    assert.deepEqual(
      analyzed.findings.map((finding) => finding.id),
      analyzed.findings.map((finding) => finding.id).slice().sort(),
    );
    assert.deepEqual(
      inventoryOf(first.run).findings.map((finding) => finding.metadata.fingerprintKey),
      inventoryOf(second.run).findings.map((finding) => finding.metadata.fingerprintKey),
    );
  });

  it("runs as an ordinary analyzer over the accepted framework", async () => {
    const { model } = await scanOf(fullRepo());
    const engine = createAnalyzerEngine({
      registry: createAnalyzerRegistry([createSymbolAnalyzer()]),
    });
    const result = await engine.runAll(contextOf(model));

    assert.equal(result.analyzers.length, 1);
    assert.equal(result.analyzers[0].analyzer.id, SYMBOL_ANALYZER_ID);
    assert.equal(result.analyzers[0].analyzer.scope, SYMBOL_ANALYZER_SCOPE);
    assert.equal(result.findings.length > 0, true);
  });

  it("abstains instead of reporting a repository it could not read", async () => {
    const { model } = await scanOf({
      "package.json": packageJson({ name: "demo" }),
      "src/widget.tsx": "export function Widget() { return 1; }\n",
    });
    const run = await runOfModel(model);
    const inventory = inventoryOf(run);

    // Findings always win over abstention, so an empty finding list here is the rule
    // saying it could not establish its conclusion — not a clean repository.
    assert.deepEqual(inventory.findings, []);
    assert.equal(inventory.status, RULE_OUTCOME_STATUSES.UNKNOWN);
    assert.equal(inventory.applicability.coverage, "unknown");
    assert.ok(inventory.applicability.reason.includes("format this build interprets"));
  });

  it("says a repository establishes nothing only when it actually established that", async () => {
    const { model } = await scanOf({
      "package.json": packageJson({ name: "demo" }),
      "README.md": "# demo\n",
    });
    const run = await runOfModel(model);
    const inventory = inventoryOf(run);

    // No module source exists, the scan finished and nothing was left unread, so "this
    // repository establishes no semantic relationship" is a claim the model supports.
    assert.equal(model.symbols.graph.state, SYMBOL_GRAPH_STATES.COMPLETE);
    assert.deepEqual(inventory.findings, []);
    assert.equal(inventory.status, RULE_OUTCOME_STATUSES.PASS);
    assert.equal(inventory.metadata.established, true);
  });

  it("names the files that make the absence answer impossible", () => {
    const partial = modelOf({
      sources: [
        semanticSource("a.js", { declarations: [declaration("one")] }),
        semanticSource("b.js", {
          problems: [SEMANTIC_PROBLEMS.UNTERMINATED_STRING],
          established: { declarations: false, resolution: false, exports: false },
        }),
      ],
    }).model;
    const absence = symbolsAbsence(createRepositoryQuery(partial));

    assert.equal(absence.established, false);
    assert.equal(absence.state, SYMBOL_GRAPH_STATES.PARTIAL);
    assert.ok(absence.reason.includes("`b.js`"));
  });

  it("abstains over a repository whose every source is in another language", async () => {
    const { model } = await scanOf({
      "package.json": packageJson({ name: "demo" }),
      "scripts/build.py": "def build():\n    return 1\n",
    });
    const absence = symbolsAbsence(createRepositoryQuery(model));

    assert.equal(model.symbols.graph.state, SYMBOL_GRAPH_STATES.UNSUPPORTED);
    assert.equal(absence.established, false);
    assert.ok(absence.reason.includes("language this build does not read"));
  });
});

// ─── Boundaries ──────────────────────────────────────────────────────────────

describe("symbol graph boundaries", () => {
  const PHASE_17_SOURCES = [
    "src/repository/scanner/policies/semantics.js",
    "src/repository/scanner/detectors/semantics.js",
    "src/repository/model/symbol-graph.js",
    "src/rules/symbols/contracts.js",
    "src/rules/symbols/signals.js",
    "src/rules/symbols/registry.js",
    "src/rules/symbols/analyzer.js",
    "src/rules/symbols/index.js",
    "src/rules/symbols/rules/index.js",
    "src/rules/symbols/rules/inventory.js",
  ];
  const FORBIDDEN = [
    "node:fs",
    "node:fs/promises",
    "fs",
    "child_process",
    "node:child_process",
    "node:net",
    "node:http",
    "node:https",
    "node:dns",
    "node:worker_threads",
    "node:vm",
    "node:module",
    "tools.js",
    "tool-registry",
  ];

  const readPhase17 = () =>
    PHASE_17_SOURCES.map((relative) => ({ relative, text: readFileSync(repoFile(relative), "utf8") }));

  it("imports no filesystem, process, network or tool module", () => {
    for (const { relative, text } of readPhase17()) {
      for (const match of text.matchAll(/from\s+"([^"]+)"/g)) {
        const specifier = match[1];
        assert.ok(
          !FORBIDDEN.includes(specifier),
          `${relative} imports \`${specifier}\``,
        );
      }
      for (const match of text.matchAll(/import\s*\(\s*"([^"]+)"\s*\)/g)) {
        assert.fail(`${relative} uses a dynamic import of \`${match[1]}\``);
      }
    }
  });

  it("keeps the rule pack independent of the acquisition layer", () => {
    for (const { relative, text } of readPhase17()) {
      if (!relative.startsWith("src/rules/symbols")) continue;
      for (const match of text.matchAll(/from\s+"([^"]+)"/g)) {
        const specifier = match[1];
        assert.ok(
          !specifier.includes("scanner") && !specifier.includes("filesystem") && !specifier.includes("execution"),
          `${relative} reaches into \`${specifier}\``,
        );
      }
    }
  });

  it("keeps the projection independent of the analysis and rules layers", () => {
    const projection = readPhase17().find((entry) => entry.relative.endsWith("symbol-graph.js"));

    for (const match of projection.text.matchAll(/from\s+"([^"]+)"/g)) {
      assert.ok(match[1].startsWith("./"), `symbol-graph.js reaches into \`${match[1]}\``);
    }
  });

  it("is a pure function of its input: no clock, no environment, no randomness", () => {
    const text = [
      "export function helper(x) { return x * 2; }",
      "export const LIMIT = 10;",
      "export function run() { return helper(LIMIT); }",
      "",
    ].join("\n");
    const first = scanModuleSemantics(text, { extension: ".js" });
    const second = scanModuleSemantics(text, { extension: ".js" });

    assert.deepEqual(JSON.parse(JSON.stringify(first)), JSON.parse(JSON.stringify(second)));
    assert.equal(Object.isFrozen(first.declarations[0]), true);
    // The same text always yields the same established facts, including its counts.
    assert.deepEqual(first.counts, second.counts);
  });

  it("leaks no absolute host path through the graph, the query surface or a finding", async () => {
    const root = makeRepo(fullRepo());
    const { model } = await scanModel(root);
    const query = createRepositoryQuery(model);
    const engine = createRuleEngine({
      registry: createSymbolRuleRegistry({ rules: symbolRules }),
    });
    const run = await engine.runAll(contextOf(model));

    const serialized = JSON.stringify([
      model.symbols.graph,
      query.symbolGraph(),
      query.symbolCoverage(),
      query.symbolNodes({}).nodes,
      query.symbolEdges({}).edges,
      query.unresolvedSymbolReferences().unresolved,
      query.importsToSymbols("src/app.js").bindings,
      run.findings.map((finding) => ({
        description: finding.description,
        metadata: finding.metadata,
        evidence: finding.evidence,
      })),
    ]);

    assert.equal(serialized.includes(root), false);
    for (const value of stringsIn(JSON.parse(serialized))) {
      assert.equal(value.includes("\\"), false, `a path looks absolute: ${value}`);
    }
  });

  it("records no stack, cause or raw error object in what it exposes", async () => {
    const { model } = await scanOf(fullRepo());
    const query = createRepositoryQuery(model);
    const serialized = JSON.stringify([model.symbols.graph, query.symbolGraph(), query.symbolCoverage()]);

    assert.equal(serialized.includes("stack"), false);
    assert.equal(serialized.includes("cause"), false);
    assert.equal(serialized.includes("Error"), false);
  });
});
