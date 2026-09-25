/**
 * Code Guardian — RepositoryModel Symbol Graph (Phase 17)
 *
 * The semantic projection: module-scope symbols, the references and calls the
 * repository establishes to them, the exports that publish them, and the import
 * bindings that connect one module's export to another module's name. Like the
 * dependency, architecture and import graphs, it is a **deterministic projection of
 * facts the model already holds** — the file entities the inventory observed and the
 * semantic records Phase 17's acquisition layer produced. It is not a parser, not a
 * type checker, not a scope tree, and not a call graph in the compiler sense.
 *
 * ### The resolution rule, stated once
 *
 * A resolution is claimed **only** when the acquisition layer *proved* the name
 * unique in its file and its declaration set established:
 *
 *   reference  `file --references--> symbol` when the name is declared at module
 *              scope in that file and the acquisition layer did not find any other
 *              position in the file where the name could be bound (`shadowed:
 *              false`). That is a proof obligation, not a similarity: since nothing
 *              else in the file can be that name, every non-binding occurrence of it
 *              denotes the module-scope binding — including occurrences inside
 *              function bodies.
 *   call       `file --calls--> symbol` additionally requires the *value shape* to
 *              be established: a function declaration, or a `const` bound to a
 *              function literal, and never a name that is assigned anywhere in the
 *              file. `a.b()` is never a call edge: a method call is runtime dispatch.
 *   export     `file --exports--> symbol` when the file states the name — through an
 *              `export` prefix on the declaration, an `export { … }` clause, or a
 *              re-export whose target the repository establishes.
 *   binding    `symbol --imports-binding--> symbol` when an import clause binds a name
 *              in one file and the module it names exports that name exactly once,
 *              following re-export chains within a bounded number of hops.
 *
 * Everything else is an **unresolved record**, kept apart from the edges with a closed
 * reason: a name that is not declared, a name that is shadowed somewhere in its file,
 * a callee whose value shape is not established (an imported binding, an alias, a
 * `let`), a module the scan did not observe, an export the target does not establish.
 * "Unresolved" is never collapsed into "absent": the occurrence is recorded, it simply
 * makes no claim about where it points.
 *
 * ### What the coverage statement has to carry
 *
 * A semantic graph can be *silent* in ways an import graph cannot: a file whose lexer
 * failed establishes no declaration at all, and a file containing `eval` establishes
 * declarations but no resolution. So the state is computed from the acquisition
 * layer's own three-way establishment answer per file, and the unestablished files are
 * named individually:
 *
 *   complete     every module source was read, its declarations, its resolution and
 *                its exports were all established, and the scan finished — the graph
 *                is whatever the repository establishes, including nothing
 *   partial      the graph is real but incomplete: at least one source establishes
 *                some class of claim only partly
 *   truncated    a bound bit: the inventory was truncated, a byte/file/token budget
 *                stopped acquisition, or this projection reached its own cap
 *   unsupported  no source was scanned because every module source is a format this
 *                build does not interpret (a JSX/TSX-only repository)
 *   unknown      nothing established a graph at all (acquisition never ran, or every
 *                source failed to be read)
 *
 * `established` separates *the repository establishes this symbol graph* — including
 * one with no symbols — from *nothing was established at all*.
 *
 * ### Determinism
 *
 * Symbols are sorted by id, edges by `(from, to, type)`, unresolved records by
 * `(path, name, kind)`. Nothing here reads the clock, the environment, the filesystem
 * or a random source, and no input is iterated in insertion order. The projection
 * parses nothing, resolves no dependency, runs no process and touches no network: it
 * reuses the Phase 16 module resolver for repository-relative paths, and nothing else.
 */

import { resolveModuleReference } from "./import-graph.js";

/** Version of the projection's shape (not of the model). */
export const SYMBOL_GRAPH_VERSION = "1";

/**
 * Symbol graph coverage states.
 *
 * The same five-way vocabulary the import graph uses, for the same reason: an empty
 * symbol list must never be readable as "this repository declares nothing" when the
 * truth is that nothing could be read.
 */
export const SYMBOL_GRAPH_STATES = Object.freeze({
  COMPLETE: "complete",
  PARTIAL: "partial",
  TRUNCATED: "truncated",
  UNSUPPORTED: "unsupported",
  UNKNOWN: "unknown",
});

/** The state vocabulary as a list, for validation. */
export const SYMBOL_GRAPH_STATE_VALUES = Object.freeze(Object.values(SYMBOL_GRAPH_STATES));

/**
 * The relationships the graph states. A closed, five-value vocabulary.
 *
 * `declares` is what makes the graph a graph: a symbol is reachable from the file
 * entity that declared it. `exports` states which name a file publishes, `references`
 * and `calls` state what a file does with a name, and `imports-binding` connects one
 * file's binding to the symbol another file exports. No other relation exists here —
 * there is no `uses`, no `depends-on`, no `implements`, because nothing in this phase
 * can establish one.
 */
export const SYMBOL_GRAPH_EDGE_TYPES = Object.freeze({
  DECLARES: "declares",
  EXPORTS: "exports",
  REFERENCES: "references",
  CALLS: "calls",
  IMPORTS_BINDING: "imports-binding",
});

/** The edge-type vocabulary as a list, for validation. */
export const SYMBOL_GRAPH_EDGE_TYPE_VALUES = Object.freeze(
  Object.values(SYMBOL_GRAPH_EDGE_TYPES),
);

/**
 * Why a reference, call, export or binding produced no edge. Closed vocabulary.
 *
 *   name-not-declared            no module-scope binding of that name exists in the
 *                                file (it may be a parameter, a local, a global or a
 *                                typo)
 *   name-not-unique              the name is bound somewhere else in the file too, so
 *                                the acquisition layer refuses to say which binding
 *                                this occurrence denotes
 *   callee-not-established       the name resolves to a binding whose value shape is
 *                                not established as callable (an imported binding, a
 *                                `let`, an alias, a non-function value)
 *   resolution-not-established   the file contains a dynamic-scope construct (`eval`
 *                                / `with`), which voids every uniqueness proof in it
 *   anonymous-export             an export this build cannot name (a default
 *                                expression)
 *   export-local-not-established the exported local name is not a declaration the
 *                                file establishes
 *   export-not-established       the target module could not be searched to the end
 *                                (a `export *` chain, a module form this build does
 *                                not read)
 *   export-not-found             the target module establishes its exports and does
 *                                not export that name
 *   export-ambiguous             two declarations in the target claim the same name
 *   namespace-binding            a namespace binding names a module, not a symbol
 *   module-not-interpreted       the target module was not scanned as a semantic
 *                                source (unsupported, unreadable, or not inspected)
 *   specifier-not-recorded       the binding states no module this build could read
 *   bare-specifier / absolute-specifier / specifier-not-resolvable /
 *   outside-repository / specifier-invalid / module-not-observed
 *                                the Phase 16 module resolver's own answers, reused
 *                                verbatim so one vocabulary covers both graphs
 */
export const SYMBOL_UNRESOLVED_REASONS = Object.freeze({
  NAME_NOT_DECLARED: "name-not-declared",
  NAME_NOT_UNIQUE: "name-not-unique",
  CALLEE_NOT_ESTABLISHED: "callee-not-established",
  RESOLUTION_NOT_ESTABLISHED: "resolution-not-established",
  ANONYMOUS_EXPORT: "anonymous-export",
  EXPORT_LOCAL_NOT_ESTABLISHED: "export-local-not-established",
  EXPORT_NOT_ESTABLISHED: "export-not-established",
  EXPORT_NOT_FOUND: "export-not-found",
  EXPORT_AMBIGUOUS: "export-ambiguous",
  NAMESPACE_BINDING: "namespace-binding",
  MODULE_NOT_INTERPRETED: "module-not-interpreted",
  SPECIFIER_NOT_RECORDED: "specifier-not-recorded",
});

/** The unresolved-reason vocabulary as a list, for validation. */
export const SYMBOL_UNRESOLVED_REASON_VALUES = Object.freeze([
  ...Object.values(SYMBOL_UNRESOLVED_REASONS),
  "bare-specifier",
  "absolute-specifier",
  "specifier-not-resolvable",
  "outside-repository",
  "specifier-invalid",
  "module-not-observed",
]);

/** What kind of occurrence an unresolved record describes. */
export const SYMBOL_UNRESOLVED_KINDS = Object.freeze([
  "reference",
  "call",
  "construct",
  "export",
  "import-binding",
]);

/**
 * Graph bounds.
 *
 * `MAX_SYMBOLS` and `MAX_EDGES` sit above what acquisition can produce (at most
 * `maxFiles` module sources, each establishing at most `maxDeclarationsPerFile`
 * bindings), so a projection can never describe more than the model's own contract
 * permits while still being an explicit bound rather than an assumption. A cap that
 * does bite is recorded — never silently applied.
 */
export const SYMBOL_GRAPH_LIMITS = Object.freeze({
  MAX_SYMBOLS: 20000,
  MAX_EDGES: 200000,
  MAX_UNRESOLVED: 20000,
  MAX_EXPORT_NAMES_PER_SYMBOL: 16,
  MAX_UNESTABLISHED_SOURCES: 1024,
  MAX_UNINTERPRETED_EXTENSIONS: 32,
  /** Re-export chain hops followed before a target is called unestablished. */
  MAX_REEXPORT_HOPS: 4,
});

/** Extensions that make a file a semantic source, re-declared for the contract test. */
export const SYMBOL_MODULE_EXTENSIONS = Object.freeze([
  ".js",
  ".mjs",
  ".cjs",
  ".ts",
  ".mts",
  ".cts",
  ".jsx",
  ".tsx",
]);

/** Acquisition statuses, re-declared so this module does not import the scanner. */
const PARSED_STATUS = "parsed";
const UNSUPPORTED_STATUS = "unsupported";
const NOT_INSPECTED_STATUS = "not-inspected";

/**
 * Freeze a value and everything reachable from it.
 *
 * Needed here rather than left to the builder: this module returns an already frozen
 * top-level object, and a shallow `Object.freeze` on the outer object would make the
 * builder's own deep freeze stop at it — leaving the symbols, the edges and their
 * provenance arrays mutable inside a model whose contract says deeply frozen.
 *
 * @param {unknown} value
 * @returns {unknown}
 */
function deepFreeze(value) {
  if (value === null || typeof value !== "object" || Object.isFrozen(value)) return value;
  Object.freeze(value);
  for (const key of Object.keys(value)) deepFreeze(value[key]);
  return value;
}

/** Sort by a list of keys, so no two records compare equal. */
function compareByKeys(keys) {
  return (a, b) => {
    for (const key of keys) {
      const left = a?.[key];
      const right = b?.[key];
      if (left === right) continue;
      if (typeof left === "string" && typeof right === "string") {
        return left < right ? -1 : 1;
      }
      return left === undefined || left === null ? 1 : -1;
    }
    return 0;
  };
}

function sortedUnique(values) {
  return [...new Set(values)].sort();
}

/**
 * The identity of one module-scope binding.
 *
 * Deterministic and content-free: the file's repository-relative path and the name.
 * A name may legitimately be declared more than once at module scope (`var` twice, a
 * TypeScript overload set), and those declarations are **one** binding — which is
 * exactly what a symbol node is — so the id carries no ordinal. Both parts are
 * already projected upstream (a repository-relative path, a bounded identifier), so
 * the separator cannot appear inside either.
 *
 * @param {string} path Repository-relative path.
 * @param {string} name Bounded identifier text.
 * @returns {string}
 */
export function symbolIdOf(path, name) {
  return `symbol:${path}#${name}`;
}

/** The file entity id for a repository-relative path. */
function fileIdOf(path) {
  return `file:${path}`;
}

/** Whether a state means a symbol graph was established. */
export function isEstablishedSymbolState(state) {
  return (
    state === SYMBOL_GRAPH_STATES.COMPLETE ||
    state === SYMBOL_GRAPH_STATES.PARTIAL ||
    state === SYMBOL_GRAPH_STATES.TRUNCATED
  );
}

/**
 * Whether a source's *declarations* were established.
 *
 * The scanner answers this per file and the answer is the whole authority: it is
 * `false` exactly when the lexer could not decide what is code (and therefore what is
 * at module scope), which is the only error that can fabricate a symbol. A file that
 * carries *other* problems — `eval` (`dynamic-scope-construct`), an anonymous default
 * export, a declaration limit — still knows its own declarations, and discarding them
 * would trade a real fact for a false emptiness. Those problems cost *resolution* and
 * *exports* instead, which the predicates below check separately.
 */
export function isSymbolSourceEstablished(source) {
  return source.status === PARSED_STATUS && source.established?.declarationsEstablished === true;
}

/**
 * Whether a source's *exports* were established.
 *
 * A module whose export set is not established cannot be searched for an export: a
 * CommonJS module, an `export =` or an `export *` chain may export the very name a
 * lookup asks about, so "this module does not export that name" would be a claim the
 * acquisition layer never made. Those lookups are answered with `export-not-established`
 * instead of `export-not-found`.
 */
export function isSymbolExportEstablished(source) {
  return isSymbolSourceEstablished(source) && source.established?.exportsEstablished === true;
}

/** Whether a source's resolution may be claimed. */
export function isSymbolSourceResolvable(source) {
  return isSymbolSourceEstablished(source) && source.established?.resolutionEstablished === true;
}

/**
 * The graph's coverage state.
 *
 * Read only from facts the model already validated: what each source established,
 * whether a bound was reached, and whether the scan behind them finished. Nothing is
 * inferred from symbol or edge counts — an empty graph is a *result*, not evidence of
 * missing information.
 *
 * @param {object} input
 * @param {object[]} input.sources Semantic source records.
 * @param {boolean} input.scanComplete `scan.complete === true`.
 * @param {boolean} input.scanTruncated `scan.truncated === true`.
 * @param {boolean} input.hasScanState Whether the model records scan state at all.
 * @param {boolean} input.projectionTruncated Whether this projection hit its own cap.
 * @param {number} [input.uninterpretedSources] Source files this graph does not read.
 * @returns {string} One of `SYMBOL_GRAPH_STATES`.
 */
export function symbolGraphState({
  sources,
  scanComplete,
  scanTruncated,
  hasScanState,
  projectionTruncated,
  uninterpretedSources = 0,
}) {
  if (!hasScanState) return SYMBOL_GRAPH_STATES.UNKNOWN;

  if (sources.length === 0) {
    // Nothing to scan. A scan that finished establishes that this repository has no
    // module source — unless it has source files in languages this build does not
    // read, in which case what it establishes is that *nothing here was read*, and
    // calling that complete would be an all-clear over unread code.
    if (scanComplete !== true || scanTruncated === true) return SYMBOL_GRAPH_STATES.UNKNOWN;
    return uninterpretedSources > 0 ? SYMBOL_GRAPH_STATES.UNSUPPORTED : SYMBOL_GRAPH_STATES.COMPLETE;
  }

  if (scanTruncated === true || projectionTruncated === true) return SYMBOL_GRAPH_STATES.TRUNCATED;
  if (
    sources.some(
      (source) =>
        source.truncated === true ||
        source.status === NOT_INSPECTED_STATUS ||
        source.reason === "budget-exhausted",
    )
  ) {
    return SYMBOL_GRAPH_STATES.TRUNCATED;
  }

  const parsed = sources.filter((source) => source.status === PARSED_STATUS);
  if (parsed.length === 0) {
    // Nothing was scanned. Either every module source is a format this build does not
    // interpret, or every one failed to be read — two answers that must not collapse.
    return sources.every((source) => source.status === UNSUPPORTED_STATUS)
      ? SYMBOL_GRAPH_STATES.UNSUPPORTED
      : SYMBOL_GRAPH_STATES.UNKNOWN;
  }

  const everyClaimEstablished = parsed.every(
    (source) =>
      (source.problems ?? []).length === 0 &&
      source.established?.declarationsEstablished === true &&
      source.established?.resolutionEstablished === true &&
      source.established?.exportsEstablished === true,
  );
  if (everyClaimEstablished && parsed.length === sources.length && scanComplete === true) {
    return SYMBOL_GRAPH_STATES.COMPLETE;
  }
  return SYMBOL_GRAPH_STATES.PARTIAL;
}

/** A symbol node's compact summary. Deliberately not the declaration: the id is the link. */
function symbolSummary(source, declaration) {
  return {
    id: symbolIdOf(source.path, declaration.name),
    fileId: fileIdOf(source.path),
    path: source.path,
    name: declaration.name,
    kinds: [...declaration.kinds],
    // Whether the file publishes this binding, and under which names. An empty list
    // means "not exported", which is a fact about the file, not about the name.
    exported: declaration.exported === true,
    exportNames: [...declaration.exportNames].slice(
      0,
      SYMBOL_GRAPH_LIMITS.MAX_EXPORT_NAMES_PER_SYMBOL,
    ),
    // The value shape, three-valued: established-callable, established-not-callable,
    // or not established at all. `null` is what stops a call edge to an alias.
    callable: declaration.callable,
    constructable: declaration.constructable,
    // Whether the name could be bound somewhere else in its file, and whether it is
    // assigned anywhere. Both are *reasons a resolution is withheld*, kept on the node
    // so a consumer can see why a symbol has no references instead of assuming none.
    shadowed: declaration.shadowed === true,
    reassigned: declaration.reassigned === true,
    // For an imported binding: how it was declared and which module it names, exactly
    // as the source wrote it. The resolved target lives on the `imports-binding` edge,
    // because resolution is a relationship and not a property of the name.
    binding:
      declaration.binding === null
        ? null
        : {
            bindingKind: declaration.binding.bindingKind,
            importedName: declaration.binding.importedName,
            specifier: declaration.binding.specifier,
            typeOnly: declaration.binding.typeOnly === true,
          },
    referenceCount: 0,
    callCount: 0,
    constructCount: 0,
  };
}

/**
 * Whether a value shape establishes a call of the given form.
 *
 * @param {object} declaration The declaration record.
 * @param {string} form `call` or `construct`.
 * @returns {boolean}
 */
function isCallableShape(declaration, form) {
  if (declaration.shadowed === true || declaration.reassigned === true) return false;
  return form === "construct"
    ? declaration.constructable === true
    : declaration.callable === true;
}

/**
 * Build the symbol graph from the model's file entities and semantic records.
 *
 * @param {object} input
 * @param {object[]} input.files File entities (`model.files.entries`).
 * @param {object[]} input.sources Semantic source records from `entities.js`.
 * @param {object} input.coverage `{ scanComplete, scanTruncated }`.
 * @param {object} [input.uninterpreted] Source files this graph does not read.
 * @returns {object} Deeply frozen
 *   `{ version, state, established, nodes, edges, unresolved, coverage }`.
 */
export function buildSymbolGraph({ files, sources, coverage, uninterpreted }) {
  const limits = SYMBOL_GRAPH_LIMITS;
  const uninterpretedSources =
    Number.isInteger(uninterpreted?.sources) && uninterpreted.sources > 0
      ? uninterpreted.sources
      : 0;
  const uninterpretedExtensions = sortedUnique(
    (Array.isArray(uninterpreted?.extensions) ? uninterpreted.extensions : []).filter(
      (extension) => typeof extension === "string" && extension !== "",
    ),
  );

  const sourceByPath = new Map(sources.map((source) => [source.path, source]));
  const observedPaths = new Set(files.map((file) => file.path));
  const languageByPath = new Map(
    files.map((file) => [file.path, typeof file.languageId === "string" ? file.languageId : null]),
  );

  // ── Symbols ────────────────────────────────────────────────────────────────
  //
  // A source contributes symbols only when its declaration set is established: a file
  // whose lexer failed may not know what its own top level is, and a symbol read from
  // it could be a token that is not a declaration at all.
  const symbolByKey = new Map();
  const declarationByKey = new Map();
  for (const source of sources) {
    if (!isSymbolSourceEstablished(source)) continue;
    for (const declaration of source.declarations) {
      const key = `${source.path}\u0000${declaration.name}`;
      declarationByKey.set(key, declaration);
      symbolByKey.set(key, symbolSummary(source, declaration));
    }
  }

  // ── Export tables ──────────────────────────────────────────────────────────
  //
  // What each file publishes, by exported name. Built from the exports the source
  // states — a declaration's own `export` prefix and every `export { … }` clause — and
  // used for both `exports` edges and cross-module binding resolution. A name two
  // entries claim is recorded as ambiguous rather than picked.
  const exportTables = new Map();
  const exportEntryFor = (path, name) => {
    let table = exportTables.get(path);
    if (table === undefined) {
      table = new Map();
      exportTables.set(path, table);
    }
    const existing = table.get(name);
    if (existing === undefined) {
      const entry = { name, localName: null, symbolId: null, specifier: null, hops: 0, ambiguous: false };
      table.set(name, entry);
      return entry;
    }
    return existing;
  };

  for (const source of sources) {
    if (!isSymbolSourceEstablished(source)) continue;
    for (const declaration of source.declarations) {
      for (const exportName of declaration.exportNames) {
        const entry = exportEntryFor(source.path, exportName);
        const key = `${source.path}\u0000${declaration.name}`;
        if (entry.symbolId !== null && entry.symbolId !== symbolIdOf(source.path, declaration.name)) {
          entry.ambiguous = true;
          continue;
        }
        entry.symbolId = symbolIdOf(source.path, declaration.name);
        entry.localName = declaration.name;
        entry.symbolKey = key;
        entry.specifier = null;
      }
    }
    for (const clause of source.exports) {
      if (clause.name === null) continue;
      const entry = exportEntryFor(source.path, clause.name);
      if (clause.form === "reexport") {
        if (entry.symbolId !== null || entry.specifier !== null) {
          entry.ambiguous = true;
          continue;
        }
        entry.specifier = clause.specifier;
        entry.localName = clause.localName;
        entry.importedName = clause.localName;
        continue;
      }
      if (clause.localName === null) {
        // An export this build cannot name: recorded as an entry so a consumer sees
        // that the name exists, with no symbol behind it.
        entry.unestablished = true;
        continue;
      }
      if (entry.symbolId !== null || entry.specifier !== null || entry.unestablished === true) {
        entry.ambiguous = true;
        continue;
      }
      const key = `${source.path}\u0000${clause.localName}`;
      if (declarationByKey.has(key)) {
        entry.symbolId = symbolIdOf(source.path, clause.localName);
        entry.localName = clause.localName;
        entry.symbolKey = key;
        entry.specifier = null;
      } else {
        entry.unestablished = true;
        entry.localName = clause.localName;
      }
    }
  }

  const edges = [];
  const unresolvedAll = [];
  const noteUnresolved = (path, name, kind, reason, evidenceId) => {
    unresolvedAll.push({ path, name, kind, reason, evidenceId: evidenceId ?? null });
  };

  /**
   * Resolve an exported name in a module, following re-export chains.
   *
   * Bounded by `MAX_REEXPORT_HOPS` and cycle-safe through `visited`, so a barrel chain
   * that loops terminates. Only a module this graph interpreted can be searched: an
   * unscanned module is *unknown*, never "does not export it".
   */
  const resolveExport = (fromPath, modulePath, name, visited) => {
    if (visited.has(`${modulePath}\u0000${name}`)) {
      return { symbolId: null, reason: SYMBOL_UNRESOLVED_REASONS.EXPORT_NOT_ESTABLISHED };
    }
    visited.add(`${modulePath}\u0000${name}`);

    const moduleSource = sourceByPath.get(modulePath);
    if (moduleSource === undefined || !isSymbolSourceEstablished(moduleSource)) {
      return { symbolId: null, reason: SYMBOL_UNRESOLVED_REASONS.MODULE_NOT_INTERPRETED };
    }
    if (!isSymbolExportEstablished(moduleSource)) {
      // The module was read, but not to the end of what it publishes. Searching it would
      // turn "we did not read this" into "it does not export that".
      return { symbolId: null, reason: SYMBOL_UNRESOLVED_REASONS.EXPORT_NOT_ESTABLISHED };
    }

    const table = exportTables.get(modulePath);
    const entry = table === undefined ? undefined : table.get(name);
    if (entry === undefined) {
      const couldComeFromElsewhere =
        (moduleSource.starExports ?? []).length > 0 ||
        moduleSource.established?.exportsEstablished !== true;
      return {
        symbolId: null,
        reason: couldComeFromElsewhere
          ? SYMBOL_UNRESOLVED_REASONS.EXPORT_NOT_ESTABLISHED
          : SYMBOL_UNRESOLVED_REASONS.EXPORT_NOT_FOUND,
      };
    }
    if (entry.ambiguous === true) {
      return { symbolId: null, reason: SYMBOL_UNRESOLVED_REASONS.EXPORT_AMBIGUOUS };
    }
    if (entry.specifier === null || entry.specifier === undefined) {
      if (entry.symbolId === null || entry.symbolId === undefined) {
        return { symbolId: null, reason: SYMBOL_UNRESOLVED_REASONS.EXPORT_LOCAL_NOT_ESTABLISHED };
      }
      return { symbolId: entry.symbolId, reason: null };
    }
    if (visited.size > limits.MAX_REEXPORT_HOPS) {
      return { symbolId: null, reason: SYMBOL_UNRESOLVED_REASONS.EXPORT_NOT_ESTABLISHED };
    }

    const resolvedModule = resolveModuleReference({
      fromPath: modulePath,
      specifier: entry.specifier,
      languageId: languageByPath.get(modulePath) ?? null,
      observedPaths,
    });
    if (resolvedModule.resolvedPath === null) {
      return { symbolId: null, reason: resolvedModule.reason };
    }
    return resolveExport(
      modulePath,
      resolvedModule.resolvedPath,
      entry.importedName ?? name,
      visited,
    );
  };

  // ── References, calls and exports ──────────────────────────────────────────
  //
  // Per file, because every one of these is a statement about one file's own text:
  // what it refers to, what it calls, and what it publishes.
  const edgeIndex = new Map();
  const addEdge = (partial) => {
    const key = `${partial.from}\u0000${partial.to}\u0000${partial.type}`;
    let edge = edgeIndex.get(key);
    if (edge === undefined) {
      edge = { ...partial, count: 0, names: new Set(), sourcePaths: new Set(), evidenceIds: new Set() };
      edgeIndex.set(key, edge);
      edges.push(edge);
      return edge;
    }
    return edge;
  };

  for (const source of sources) {
    const resolvable = isSymbolSourceResolvable(source);
    const established = isSymbolSourceEstablished(source);

    for (const reference of source.references) {
      const key = `${source.path}\u0000${reference.name}`;
      const declaration = declarationByKey.get(key);
      const kind = reference.form;

      if (declaration === undefined) {
        noteUnresolved(
          source.path,
          reference.name,
          kind,
          resolvable
            ? SYMBOL_UNRESOLVED_REASONS.NAME_NOT_DECLARED
            : SYMBOL_UNRESOLVED_REASONS.RESOLUTION_NOT_ESTABLISHED,
          source.evidenceId,
        );
        continue;
      }
      if (!resolvable) {
        noteUnresolved(
          source.path,
          reference.name,
          kind,
          SYMBOL_UNRESOLVED_REASONS.RESOLUTION_NOT_ESTABLISHED,
          source.evidenceId,
        );
        continue;
      }
      if (declaration.shadowed === true) {
        noteUnresolved(
          source.path,
          reference.name,
          kind,
          SYMBOL_UNRESOLVED_REASONS.NAME_NOT_UNIQUE,
          source.evidenceId,
        );
        continue;
      }

      const to = symbolIdOf(source.path, reference.name);

      if (reference.form !== "reference" && !isCallableShape(declaration, reference.form)) {
        noteUnresolved(
          source.path,
          reference.name,
          kind,
          SYMBOL_UNRESOLVED_REASONS.CALLEE_NOT_ESTABLISHED,
          source.evidenceId,
        );
        continue;
      }

      // A node's counts describe the occurrences the graph actually *states* as edges, so
      // the increment happens only on the path that adds one. An occurrence withheld
      // above (a name that is not declared, a name that is not unique, a callee whose
      // value shape is not established) contributes no edge and is therefore not counted
      // here — which is what keeps `sum(node.referenceCount)` equal to the reference-edge
      // occurrences, instead of silently counting occurrences the graph refuses to state.
      const node = symbolByKey.get(key);
      if (node !== undefined) {
        if (reference.form === "reference") node.referenceCount += reference.count;
        else if (reference.form === "call") node.callCount += reference.count;
        else node.constructCount += reference.count;
      }

      const edge = addEdge({
        from: fileIdOf(source.path),
        to,
        type:
          reference.form === "reference"
            ? SYMBOL_GRAPH_EDGE_TYPES.REFERENCES
            : SYMBOL_GRAPH_EDGE_TYPES.CALLS,
      });
      edge.count += reference.count;
      edge.sourcePaths.add(source.path);
      edge.evidenceIds.add(source.evidenceId);
    }

    if (!established) continue;

    // `declares`: one edge per symbol, so a symbol is reachable from its file.
    for (const declaration of source.declarations) {
      const edge = addEdge({
        from: fileIdOf(source.path),
        to: symbolIdOf(source.path, declaration.name),
        type: SYMBOL_GRAPH_EDGE_TYPES.DECLARES,
      });
      edge.count += 1;
      edge.sourcePaths.add(source.path);
      edge.evidenceIds.add(source.evidenceId);
    }

    // `exports`: which names the file publishes, from the declarations and the clauses
    // alike, so the edge states the published names rather than the local ones.
    for (const declaration of source.declarations) {
      if (declaration.exportNames.length === 0) continue;
      const edge = addEdge({
        from: fileIdOf(source.path),
        to: symbolIdOf(source.path, declaration.name),
        type: SYMBOL_GRAPH_EDGE_TYPES.EXPORTS,
      });
      edge.count += 1;
      for (const name of declaration.exportNames) edge.names.add(name);
      edge.sourcePaths.add(source.path);
      edge.evidenceIds.add(source.evidenceId);
    }

    for (const clause of source.exports) {
      if (clause.name === null) continue;
      if (clause.form === "reexport") {
        if (clause.specifier === null) {
          noteUnresolved(
            source.path,
            clause.name,
            "export",
            SYMBOL_UNRESOLVED_REASONS.SPECIFIER_NOT_RECORDED,
            source.evidenceId,
          );
          continue;
        }
        const resolvedModule = resolveModuleReference({
          fromPath: source.path,
          specifier: clause.specifier,
          languageId: languageByPath.get(source.path) ?? null,
          observedPaths,
        });
        if (resolvedModule.resolvedPath === null) {
          noteUnresolved(source.path, clause.name, "export", resolvedModule.reason, source.evidenceId);
          continue;
        }
        const resolved = resolveExport(
          source.path,
          resolvedModule.resolvedPath,
          clause.localName ?? clause.name,
          new Set([`${source.path}\u0000${clause.name}`]),
        );
        if (resolved.symbolId === null) {
          noteUnresolved(source.path, clause.name, "export", resolved.reason, source.evidenceId);
          continue;
        }
        const edge = addEdge({
          from: fileIdOf(source.path),
          to: resolved.symbolId,
          type: SYMBOL_GRAPH_EDGE_TYPES.EXPORTS,
        });
        edge.count += 1;
        edge.names.add(clause.name);
        edge.sourcePaths.add(source.path);
        edge.evidenceIds.add(source.evidenceId);
        continue;
      }

      if (clause.localName === null) {
        noteUnresolved(
          source.path,
          clause.name,
          "export",
          SYMBOL_UNRESOLVED_REASONS.ANONYMOUS_EXPORT,
          source.evidenceId,
        );
        continue;
      }
      const key = `${source.path}\u0000${clause.localName}`;
      if (!declarationByKey.has(key)) {
        noteUnresolved(
          source.path,
          clause.name,
          "export",
          SYMBOL_UNRESOLVED_REASONS.EXPORT_LOCAL_NOT_ESTABLISHED,
          source.evidenceId,
        );
        continue;
      }
      const edge = addEdge({
        from: fileIdOf(source.path),
        to: symbolIdOf(source.path, clause.localName),
        type: SYMBOL_GRAPH_EDGE_TYPES.EXPORTS,
      });
      edge.count += 1;
      edge.names.add(clause.name);
      edge.sourcePaths.add(source.path);
      edge.evidenceIds.add(source.evidenceId);
    }

    // `imports-binding`: what each imported binding points at, resolved against the
    // observed inventory and the target module's own export table.
    for (const declaration of source.declarations) {
      if (declaration.binding === null) continue;
      const to = symbolIdOf(source.path, declaration.name);
      const specifier = declaration.binding.specifier;
      if (specifier === null) {
        noteUnresolved(
          source.path,
          declaration.name,
          "import-binding",
          SYMBOL_UNRESOLVED_REASONS.SPECIFIER_NOT_RECORDED,
          source.evidenceId,
        );
        continue;
      }
      const resolvedModule = resolveModuleReference({
        fromPath: source.path,
        specifier,
        languageId: languageByPath.get(source.path) ?? null,
        observedPaths,
      });
      if (resolvedModule.resolvedPath === null) {
        noteUnresolved(
          source.path,
          declaration.name,
          "import-binding",
          resolvedModule.reason,
          source.evidenceId,
        );
        continue;
      }
      if (declaration.binding.bindingKind === "namespace") {
        // A namespace import (binding a module, not a name) names a *module*, not a
        // symbol: there is nothing
        // for an edge to point at, and inventing a module node here would duplicate
        // the import graph's own nodes.
        noteUnresolved(
          source.path,
          declaration.name,
          "import-binding",
          SYMBOL_UNRESOLVED_REASONS.NAMESPACE_BINDING,
          source.evidenceId,
        );
        continue;
      }

      const targetName =
        declaration.binding.bindingKind === "default"
          ? "default"
          : (declaration.binding.importedName ?? declaration.name);
      const resolved = resolveExport(
        source.path,
        resolvedModule.resolvedPath,
        targetName,
        new Set([`${source.path}\u0000${declaration.name}`]),
      );
      if (resolved.symbolId === null) {
        noteUnresolved(
          source.path,
          declaration.name,
          "import-binding",
          resolved.reason,
          source.evidenceId,
        );
        continue;
      }
      const edge = addEdge({
        from: to,
        to: resolved.symbolId,
        type: SYMBOL_GRAPH_EDGE_TYPES.IMPORTS_BINDING,
      });
      edge.count += 1;
      edge.names.add(targetName);
      edge.sourcePaths.add(source.path);
      edge.evidenceIds.add(source.evidenceId);
    }
  }

  // ── Materialize ────────────────────────────────────────────────────────────
  const allNodes = [...symbolByKey.values()].sort(compareByKeys(["id"]));
  const nodesTruncated = allNodes.length > limits.MAX_SYMBOLS;
  const nodes = nodesTruncated ? allNodes.slice(0, limits.MAX_SYMBOLS) : allNodes;
  const nodeIds = new Set(nodes.map((node) => node.id));

  // An edge that names a node the projection dropped is dropped with it, rather than
  // left pointing at a symbol the graph does not describe.
  const knownEndpoint = (id) => nodeIds.has(id) || observedPaths.has(id.slice("file:".length));
  const allEdges = edges
    .filter((edge) => knownEndpoint(edge.from) && knownEndpoint(edge.to))
    .map((edge) => {
      const merged = {
        from: edge.from,
        to: edge.to,
        type: edge.type,
        count: edge.count,
        sourcePaths: sortedUnique([...edge.sourcePaths]),
        evidenceIds: sortedUnique([...edge.evidenceIds]),
      };
      if (edge.type === SYMBOL_GRAPH_EDGE_TYPES.EXPORTS || edge.type === SYMBOL_GRAPH_EDGE_TYPES.IMPORTS_BINDING) {
        const names = sortedUnique([...edge.names]);
        return {
          ...merged,
          names: names.slice(0, limits.MAX_EXPORT_NAMES_PER_SYMBOL),
          namesTruncated: names.length > limits.MAX_EXPORT_NAMES_PER_SYMBOL,
        };
      }
      return merged;
    })
    .sort(compareByKeys(["from", "to", "type"]));

  const edgesTruncated = allEdges.length > limits.MAX_EDGES;
  const finalEdges = edgesTruncated ? allEdges.slice(0, limits.MAX_EDGES) : allEdges;

  const sortedUnresolved = unresolvedAll
    .slice()
    .sort(compareByKeys(["path", "name", "kind"]))
    .map((record) => Object.freeze({ ...record }));
  const unresolvedTruncated = sortedUnresolved.length > limits.MAX_UNRESOLVED;
  const unresolved = unresolvedTruncated
    ? sortedUnresolved.slice(0, limits.MAX_UNRESOLVED)
    : sortedUnresolved;

  const state = symbolGraphState({
    sources,
    scanComplete: coverage?.scanComplete === true,
    scanTruncated: coverage?.scanTruncated === true,
    hasScanState:
      typeof coverage?.scanComplete === "boolean" && typeof coverage?.scanTruncated === "boolean",
    projectionTruncated: nodesTruncated || edgesTruncated || unresolvedTruncated,
    uninterpretedSources,
  });
  const established = isEstablishedSymbolState(state);

  // Why the graph is not complete, named file by file: every source whose declarations
  // or resolution could not be established. Each is a place a symbol or a reference
  // could exist and is not known to.
  const unestablished = sources
    .filter((source) => !isSymbolSourceEstablished(source))
    .map((source) =>
      Object.freeze({
        path: source.path,
        status: source.status,
        reason: source.reason ?? null,
        problems: Object.freeze([...(source.problems ?? [])]),
        declarationsEstablished: source.established?.declarationsEstablished === true,
        resolutionEstablished: source.established?.resolutionEstablished === true,
        truncated: source.truncated === true,
        evidenceId: source.evidenceId ?? null,
      }),
    )
    .sort(compareByKeys(["path"]))
    .slice(0, limits.MAX_UNESTABLISHED_SOURCES);

  const unresolvedByReason = {};
  for (const reason of SYMBOL_UNRESOLVED_REASON_VALUES) unresolvedByReason[reason] = 0;
  for (const record of unresolvedAll) {
    unresolvedByReason[record.reason] = (unresolvedByReason[record.reason] ?? 0) + 1;
  }
  const unestablishedCount = sources.filter((source) => !isSymbolSourceEstablished(source)).length;

  const countByStatus = (status) => sources.filter((source) => source.status === status).length;
  const countEdges = (type) => finalEdges.filter((edge) => edge.type === type).length;

  return deepFreeze({
    version: SYMBOL_GRAPH_VERSION,
    state,
    established,
    nodes,
    edges: finalEdges,
    // Occurrences that are not edges: "the file says this and we cannot establish what
    // it denotes" is a different fact from *these two entities are connected*.
    unresolved,
    coverage: {
      state,
      established,
      complete: state === SYMBOL_GRAPH_STATES.COMPLETE,
      truncated: state === SYMBOL_GRAPH_STATES.TRUNCATED,
      inspected: sources.some((source) => source.status === PARSED_STATUS),
      // Counts of what the graph contains, never a claim that the repository has no
      // more. `references` counts established reference occurrences across all call
      // sites, so `resolved + unresolved === references` holds over what was acquired.
      symbols: nodes.length,
      edges: finalEdges.length,
      sources: sources.length,
      moduleFiles: nodes.length === 0 ? 0 : new Set(nodes.map((node) => node.path)).size,
      declaredSymbols: countEdges(SYMBOL_GRAPH_EDGE_TYPES.DECLARES),
      exportedSymbols: countEdges(SYMBOL_GRAPH_EDGE_TYPES.EXPORTS),
      referenceEdges: countEdges(SYMBOL_GRAPH_EDGE_TYPES.REFERENCES),
      callEdges: countEdges(SYMBOL_GRAPH_EDGE_TYPES.CALLS),
      bindingEdges: countEdges(SYMBOL_GRAPH_EDGE_TYPES.IMPORTS_BINDING),
      parsed: countByStatus(PARSED_STATUS),
      unsupported: countByStatus(UNSUPPORTED_STATUS),
      failed: sources.filter(
        (source) =>
          source.status !== PARSED_STATUS &&
          source.status !== UNSUPPORTED_STATUS &&
          source.status !== NOT_INSPECTED_STATUS,
      ).length,
      notInspected: countByStatus(NOT_INSPECTED_STATUS),
      // The other half of the coverage statement: source files the repository has that
      // this graph does not read at all.
      uninterpretedSources,
      uninterpretedExtensions: Object.freeze(
        uninterpretedExtensions.slice(0, limits.MAX_UNINTERPRETED_EXTENSIONS),
      ),
      uninterpretedExtensionsTruncated:
        uninterpretedExtensions.length > limits.MAX_UNINTERPRETED_EXTENSIONS,
      references: sources.reduce(
        (total, source) => total + (source.counts?.references ?? 0) + (source.counts?.calls ?? 0) + (source.counts?.constructs ?? 0),
        0,
      ),
      unresolved: unresolvedAll.length,
      unresolvedReported: unresolved.length,
      unresolvedByReason: Object.freeze(unresolvedByReason),
      shadowedSymbols: nodes.filter((node) => node.shadowed === true).length,
      // How many sources establish no declaration at all — the count behind the
      // (bounded) list below, so a truncated list is never mistaken for all of them.
      unestablished: unestablishedCount,
      // Why the graph is not complete, named file by file.
      unestablishedSources: Object.freeze(unestablished),
      // Every bound that bit, stated rather than implied.
      nodesTruncated,
      edgesTruncated,
      unresolvedTruncated,
      limits,
    },
  });
}
