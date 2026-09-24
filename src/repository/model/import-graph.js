/**
 * Code Guardian — RepositoryModel Import Graph (Phase 16)
 *
 * The import graph is a **deterministic projection** of two things the model
 * already holds: the file entities the inventory observed, and the module
 * references the Phase 16 acquisition layer extracted from supported source. It is
 * not a second parser, not a symbol table and not a call graph — it adds the two
 * things neither the entity list nor the raw acquisition records can express,
 * **per-edge provenance** and an explicit **coverage statement**, and nothing else.
 *
 * ### What an edge means, exactly
 *
 *   `from --imports--> to`
 *
 * means *the file `from` literally states a module reference that the repository's
 * own inventory establishes as the file `to`*. It is never inferred from:
 *
 *   - two files sharing a directory or a name,
 *   - a path-naming convention (`x.test.js`, `x.spec.ts`),
 *   - a framework's routing or auto-loading convention,
 *   - a symbol, an export, a call or a type,
 *   - package configuration (tsconfig `paths`, webpack/Vite/Babel aliases).
 *
 * Nothing about execution order, call direction, ownership or runtime use is
 * claimed: an import edge is a *static reference*, and the reverse edge is not
 * stated twice — `importsOf` follows edges forward, `importedBy` follows them
 * backward, and both read the same one-directional edges.
 *
 * ### Resolution is repository-relative and refuses to guess
 *
 * A specifier is resolved only against the files the scan actually observed:
 * `./x` and `../x` are joined lexically to the importing file's directory, then
 * looked up as an exact path, then with a documented extension appended, then as
 * `index.<ext>`. Everything else is an **unresolved reference**, not an edge, with
 * a closed reason:
 *
 *   bare-specifier           an npm package or a path alias — this build resolves
 *                            neither, because doing so needs configuration it must
 *                            not read
 *   absolute-specifier       a POSIX, drive-letter or UNC absolute path
 *   specifier-not-resolvable a bundler-only specifier (a query or fragment, a
 *                            backslash path)
 *   outside-repository       the joined path leaves the repository root
 *   specifier-invalid        empty, over-long or control-character text
 *   module-not-observed      the repository-relative path is not a file the scan
 *                            observed (whether because it does not exist or because
 *                            the ignore policy excluded it is the query layer's
 *                            question, not this module's)
 *
 * A path that leaves the root is refused *before* lookup, so a traversal can never
 * name a candidate outside the repository even in principle.
 *
 * ### Declared, referenced and orphaned are three different facts
 *
 * A node's presence says only that the file exists and takes part in the graph. It
 * says nothing about being "used", "reachable" or "dead": reachability is a
 * traversal result, and this module reports topology, not significance. That is why
 * the query layer's `entryPointCandidates()` and `orphanModules()` return
 * *candidates* and carry the coverage statement with them — on a partial graph,
 * "no incoming edge" is not the same claim as on a complete one.
 *
 * ### Coverage is five-way, and empty is not unknown
 *
 *   complete     every module source in the repository was read and interpreted
 *                without truncation or problems — the graph is whatever the
 *                repository establishes, including nothing
 *   partial      the graph is real but incomplete: a source could not be parsed, or
 *                its parse was cut short, or it contained module-shaped references
 *                that cannot be established statically
 *   truncated    a bound bit: the inventory was truncated, or a file, byte or token
 *                budget stopped acquisition, or the projection's own edge or
 *                unresolved cap was reached
 *   unsupported  no source was parsed because every module source is a format this
 *                build does not interpret (a JSX/TSX-only repository)
 *   unknown      nothing established a graph at all (acquisition never ran, or every
 *                source failed to be read)
 *
 * `established` separates *the repository establishes this import graph* —
 * including one with no edges — from *nothing was established at all*. An empty
 * edge list is never reported as an all-clear on its own.
 *
 * ### Determinism
 *
 * Nodes are sorted by id, edges by `(from, to, type)`, unresolved references by
 * `(path, specifier, kind)`. Nothing here reads the clock, the environment, the
 * filesystem or a random source, and no input is iterated in insertion order.
 */

/** Version of the projection's shape (not of the model). */
export const IMPORT_GRAPH_VERSION = "1";

/**
 * Import graph coverage states.
 *
 * The vocabulary extends Phase 14's and Phase 15's four states with `truncated`,
 * because for this graph a bound being reached is the single most common way for
 * knowledge to stop, and a consumer asking "is this answer complete?" deserves that
 * answer rather than a generic `partial`.
 */
export const IMPORT_GRAPH_STATES = Object.freeze({
  /** Every module source was read and interpreted. The graph is complete. */
  COMPLETE: "complete",
  /** The graph is real but incomplete: an uninterpreted or partially-read source. */
  PARTIAL: "partial",
  /** A bound was reached: the inventory, a budget, or this projection's own cap. */
  TRUNCATED: "truncated",
  /** No source was interpreted because every module source is an unparsed format. */
  UNSUPPORTED: "unsupported",
  /** Nothing established a graph: acquisition never ran, or every source failed. */
  UNKNOWN: "unknown",
});

/** The state vocabulary as a list, for validation. */
export const IMPORT_GRAPH_STATE_VALUES = Object.freeze(Object.values(IMPORT_GRAPH_STATES));

/**
 * Import graph edge types.
 *
 * One value, on purpose: the model's own relationship vocabulary has no import
 * relation (nothing could establish one before this phase), and inventing a family
 * of near-synonyms (`import-edge`, `module-edge`, `require-edge`) would make
 * "imports" mean six different things depending on who asked.
 */
export const IMPORT_GRAPH_EDGE_TYPES = Object.freeze({
  IMPORTS: "imports",
});

/** The edge-type vocabulary as a list, for validation. */
export const IMPORT_GRAPH_EDGE_TYPE_VALUES = Object.freeze(Object.values(IMPORT_GRAPH_EDGE_TYPES));

/**
 * Why a module reference is not an edge.
 *
 * Closed vocabulary: a reason is an identifier, never free text, so a hostile
 * specifier can never travel through this field.
 */
export const UNRESOLVED_REFERENCE_REASONS = Object.freeze({
  BARE_SPECIFIER: "bare-specifier",
  ABSOLUTE_SPECIFIER: "absolute-specifier",
  SPECIFIER_NOT_RESOLVABLE: "specifier-not-resolvable",
  OUTSIDE_REPOSITORY: "outside-repository",
  SPECIFIER_INVALID: "specifier-invalid",
  MODULE_NOT_OBSERVED: "module-not-observed",
});

/** The unresolved-reason vocabulary as a list, for validation. */
export const UNRESOLVED_REFERENCE_REASON_VALUES = Object.freeze(
  Object.values(UNRESOLVED_REFERENCE_REASONS),
);

/**
 * Graph bounds.
 *
 * `MAX_NODES` and `MAX_EDGES` sit above what the acquisition layer can produce
 * (at most `maxFiles` module sources, each stating at most
 * `maxReferencesPerFile` references), so a projection can never describe more than
 * the model's own contract permits while still being an explicit bound rather than
 * an assumption. A cap that does bite is recorded — never silently applied.
 */
export const IMPORT_GRAPH_LIMITS = Object.freeze({
  MAX_NODES: 24000,
  MAX_EDGES: 200000,
  MAX_UNRESOLVED: 20000,
  MAX_SPECIFIERS_PER_EDGE: 16,
  MAX_UNESTABLISHED_SOURCES: 1024,
  MAX_UNINTERPRETED_EXTENSIONS: 32,
});

/**
 * Extensions that make a file a module source, re-declared here rather than
 * imported from the scanner (the model must not depend on the acquisition layer).
 *
 * A contract test in `tests/import-graph.test.js` pins this list against the
 * scanner's own, so a rename on either side fails the suite.
 */
export const MODULE_EXTENSIONS = Object.freeze([
  ".js",
  ".mjs",
  ".cjs",
  ".ts",
  ".mts",
  ".cts",
  ".jsx",
  ".tsx",
]);

/**
 * Extensions tried when a specifier omits one, in the documented order.
 *
 * The order depends on the *importing* file's language, which is a deliberate,
 * documented tie-break rather than a guess about intent: a TypeScript file that says
 * `./x` is resolved to `x.ts` before `x.js`, and a JavaScript file to `x.js` before
 * `x.ts`, because that is what each ecosystem's own resolver does. `.json` is
 * included last because `require("./data.json")` is a real, common reference to a
 * real, observed file.
 */
export const RESOLUTION_EXTENSIONS = Object.freeze({
  typescript: Object.freeze([
    ".ts",
    ".mts",
    ".cts",
    ".tsx",
    ".js",
    ".mjs",
    ".cjs",
    ".jsx",
    ".json",
  ]),
  javascript: Object.freeze([
    ".js",
    ".mjs",
    ".cjs",
    ".jsx",
    ".ts",
    ".mts",
    ".cts",
    ".tsx",
    ".json",
  ]),
});

/** The directory basename tried last, so `./utils` can reach `utils/index.ts`. */
export const INDEX_BASENAME = "index";

/**
 * Language entity id that selects the TypeScript resolution order.
 * Re-declared rather than imported from `entities.js`'s caller for clarity.
 */
const TYPESCRIPT_LANGUAGE_ID = "language:typescript";

/**
 * The languages this graph interprets.
 *
 * A file whose *observed* language is not one of these is counted as an
 * **uninterpreted source**: this build reads no Python, Go, Java, Rust or Dart import
 * statement, and saying nothing about those files is not the same as saying they
 * declare nothing. A repository whose every source file is in an uninterpreted
 * language therefore has no module source at all, and that is `unsupported` rather
 * than `complete` — "every module source was read" and "there was nothing here this
 * build could read" are different answers, and the second must never be reported as
 * an all-clear.
 */
export const INTERPRETED_LANGUAGE_IDS = Object.freeze([
  "language:javascript",
  TYPESCRIPT_LANGUAGE_ID,
]);

/** Whether an observed language is one this graph interprets. */
export function isInterpretedLanguage(languageId) {
  return INTERPRETED_LANGUAGE_IDS.includes(languageId);
}

/** Acquisition statuses, re-declared so this module does not import the scanner. */
const PARSED_STATUS = "parsed";
const UNSUPPORTED_STATUS = "unsupported";
const NOT_INSPECTED_STATUS = "not-inspected";

/**
 * Freeze a value and everything reachable from it.
 *
 * Needed here rather than left to the builder: this module returns an already frozen
 * top-level object, and a shallow `Object.freeze` on the outer object would make the
 * builder's own deep freeze stop at it — leaving the nodes, the edges and their
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

/** Whether a specifier is usable resolver input: bounded, printable, non-empty. */
function isUsableSpecifier(specifier) {
  if (typeof specifier !== "string" || specifier === "") return false;
  if (specifier.length > 512) return false;
  for (let index = 0; index < specifier.length; index += 1) {
    const code = specifier.charCodeAt(index);
    if (code < 0x20 || code === 0x7f) return false;
  }
  return true;
}

/**
 * Classify a specifier without looking anything up.
 *
 * Kept separate from resolution so *this cannot be a repository path at all* is a
 * different answer from *this path is not one the scan observed*.
 *
 * @param {string} specifier
 * @returns {{kind: string, reason: string|null}}
 */
export function classifySpecifier(specifier) {
  if (!isUsableSpecifier(specifier)) {
    return { kind: "invalid", reason: UNRESOLVED_REFERENCE_REASONS.SPECIFIER_INVALID };
  }
  if (specifier.startsWith("/")) {
    return { kind: "absolute", reason: UNRESOLVED_REFERENCE_REASONS.ABSOLUTE_SPECIFIER };
  }
  if (/^[A-Za-z]:[\\/]/.test(specifier) || specifier.startsWith("\\\\")) {
    return { kind: "absolute", reason: UNRESOLVED_REFERENCE_REASONS.ABSOLUTE_SPECIFIER };
  }
  if (specifier.startsWith("#")) {
    return { kind: "bare", reason: UNRESOLVED_REFERENCE_REASONS.BARE_SPECIFIER };
  }
  if (
    specifier.includes("\\") ||
    specifier.includes("?") ||
    specifier.includes("#")
  ) {
    return { kind: "unresolvable", reason: UNRESOLVED_REFERENCE_REASONS.SPECIFIER_NOT_RESOLVABLE };
  }
  if (specifier.startsWith("./") || specifier.startsWith("../")) {
    return { kind: "relative", reason: null };
  }
  return { kind: "bare", reason: UNRESOLVED_REFERENCE_REASONS.BARE_SPECIFIER };
}

/**
 * Join a relative specifier onto a directory, lexically.
 *
 * Segments are resolved by the same rules a path normalizer uses, but the result is
 * never allowed above the repository root: a `..` that would pop past it returns
 * `null`, which the caller reports as `outside-repository`. That refusal happens
 * before any lookup, so a traversal cannot even name a candidate path.
 *
 * @param {string} baseDirectory Repository-relative directory ('' at the root).
 * @param {string} specifier A `./` or `../` specifier.
 * @returns {string|null} The repository-relative path, or `null` when it escapes.
 */
export function joinRelativePath(baseDirectory, specifier) {
  const segments = baseDirectory === "" ? [] : baseDirectory.split("/");
  for (const segment of specifier.split("/")) {
    if (segment === "" || segment === ".") continue;
    if (segment === "..") {
      if (segments.length === 0) return null;
      segments.pop();
      continue;
    }
    segments.push(segment);
  }
  return segments.join("/");
}

/**
 * Resolve one module reference against the observed files.
 *
 * @param {object} input
 * @param {string} input.fromPath Importing file's repository-relative path.
 * @param {string} input.specifier Specifier exactly as written.
 * @param {string} input.languageId Importing file's language entity id.
 * @param {Set<string>} input.observedPaths Repository-relative paths the scan observed.
 * @returns {{resolvedPath: string|null, reason: string|null, candidates: number}}
 */
export function resolveModuleReference({ fromPath, specifier, languageId, observedPaths }) {
  const classified = classifySpecifier(specifier);
  if (classified.kind !== "relative") {
    return { resolvedPath: null, reason: classified.reason, candidates: 0 };
  }

  const slash = fromPath.lastIndexOf("/");
  const baseDirectory = slash === -1 ? "" : fromPath.slice(0, slash);
  const joined = joinRelativePath(baseDirectory, specifier);
  if (joined === null) {
    return { resolvedPath: null, reason: UNRESOLVED_REFERENCE_REASONS.OUTSIDE_REPOSITORY, candidates: 0 };
  }

  const extensions =
    languageId === TYPESCRIPT_LANGUAGE_ID
      ? RESOLUTION_EXTENSIONS.typescript
      : RESOLUTION_EXTENSIONS.javascript;

  const candidatePaths = [joined];
  for (const extension of extensions) candidatePaths.push(`${joined}${extension}`);
  const indexPrefix = joined === "" ? "" : `${joined}/`;
  for (const extension of extensions) {
    candidatePaths.push(`${indexPrefix}${INDEX_BASENAME}${extension}`);
  }

  for (const candidate of candidatePaths) {
    if (observedPaths.has(candidate)) {
      return { resolvedPath: candidate, reason: null, candidates: candidatePaths.length };
    }
  }

  return {
    resolvedPath: null,
    reason: UNRESOLVED_REFERENCE_REASONS.MODULE_NOT_OBSERVED,
    candidates: candidatePaths.length,
  };
}

/**
 * The graph's coverage state.
 *
 * Read only from facts the model already validated: which sources were acquired and
 * how, whether a bound was reached, and whether the scan behind them finished.
 * Nothing is inferred from node or edge counts — an empty graph is a *result*, not
 * evidence of missing information.
 *
 * @param {object} input
 * @param {object[]} input.sources Module source records.
 * @param {boolean} input.scanComplete `scan.complete === true`.
 * @param {boolean} input.scanTruncated `scan.truncated === true`.
 * @param {boolean} input.hasScanState Whether the model records scan state at all.
 * @param {boolean} input.projectionTruncated Whether this projection hit its own cap.
 * @param {number} [input.uninterpretedSources] Source files whose observed language
 *   this graph does not interpret.
 * @returns {string} One of `IMPORT_GRAPH_STATES`.
 */
export function importGraphState({
  sources,
  scanComplete,
  scanTruncated,
  hasScanState,
  projectionTruncated,
  uninterpretedSources = 0,
}) {
  if (!hasScanState) return IMPORT_GRAPH_STATES.UNKNOWN;

  if (sources.length === 0) {
    // Nothing to interpret. A scan that finished establishes that this repository has
    // no module source — unless it has source files in languages this build does not
    // read, in which case what it establishes is that *nothing here was read*, and
    // calling that complete would be an all-clear over unread code. A scan that did
    // not finish establishes nothing at all.
    if (scanComplete !== true || scanTruncated === true) return IMPORT_GRAPH_STATES.UNKNOWN;
    return uninterpretedSources > 0
      ? IMPORT_GRAPH_STATES.UNSUPPORTED
      : IMPORT_GRAPH_STATES.COMPLETE;
  }

  if (scanTruncated === true || projectionTruncated === true) {
    return IMPORT_GRAPH_STATES.TRUNCATED;
  }
  if (
    sources.some(
      (source) =>
        source.truncated === true ||
        source.status === NOT_INSPECTED_STATUS ||
        source.reason === "budget-exhausted",
    )
  ) {
    return IMPORT_GRAPH_STATES.TRUNCATED;
  }

  const parsed = sources.filter((source) => source.status === PARSED_STATUS);
  if (parsed.length === 0) {
    // Nothing was interpreted. That is either "every module source is a format this
    // build does not parse" or "every module source failed to be read" — two
    // different answers that must not collapse.
    return sources.every((source) => source.status === UNSUPPORTED_STATUS)
      ? IMPORT_GRAPH_STATES.UNSUPPORTED
      : IMPORT_GRAPH_STATES.UNKNOWN;
  }

  const fullyInterpreted = parsed.every((source) => (source.problems ?? []).length === 0);
  if (fullyInterpreted && parsed.length === sources.length && scanComplete === true) {
    return IMPORT_GRAPH_STATES.COMPLETE;
  }
  return IMPORT_GRAPH_STATES.PARTIAL;
}

/** Whether a state means an import graph was established. */
export function isEstablishedState(state) {
  return (
    state === IMPORT_GRAPH_STATES.COMPLETE ||
    state === IMPORT_GRAPH_STATES.PARTIAL ||
    state === IMPORT_GRAPH_STATES.TRUNCATED
  );
}

/** Whether a status means the source's references were established. */
export function isSourceEstablished(source) {
  return source.status === PARSED_STATUS && (source.problems ?? []).length === 0;
}

/** A node's compact summary. Deliberately not the file entity: the id is the link. */
function nodeSummary(file, source) {
  return {
    id: file.id,
    path: file.path,
    extension: typeof file.extension === "string" ? file.extension : "",
    languageId: typeof file.languageId === "string" ? file.languageId : null,
    // Whether this file is itself a module source for this graph, as opposed to a
    // file only reached by a reference (`require("./data.json")`, `import
    // "./style.css"`). A non-module node is a real target, never a module.
    module: MODULE_EXTENSIONS.includes(file.extension),
    status: source === undefined ? null : source.status,
  };
}

/**
 * Build the import graph from the model's file entities and acquisition records.
 *
 * @param {object} input
 * @param {object[]} input.files File entities (`model.files.entries`).
 * @param {object[]} input.sources Module source records from `entities.js`.
 * @param {object} input.coverage `{ scanComplete, scanTruncated }`.
 * @param {object} [input.uninterpreted] Source files whose observed language this
 *   graph does not interpret, as `{ sources, extensions }`. Derived by the builder
 *   from the file entities the model already holds, so the projection invents no
 *   language knowledge of its own.
 * @returns {object} Deeply frozen
 *   `{ version, state, established, nodes, edges, unresolved, coverage }`.
 */
export function buildImportGraph({ files, sources, coverage, uninterpreted }) {
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
  const fileByPath = new Map(files.map((file) => [file.path, file]));

  // ── Resolution ─────────────────────────────────────────────────────────────
  //
  // Every reference is resolved here, against the observed inventory only, into
  // either an edge (a file the repository establishes) or an unresolved record (a
  // reference the repository does not establish a target for). Nothing is resolved
  // by convention, and a path leaving the repository is refused before lookup.
  const edgeRecords = new Map();
  const unresolvedAll = [];
  let resolvedCount = 0;
  let nonStaticCount = 0;

  for (const source of sources) {
    nonStaticCount += Number.isInteger(source.nonStatic) ? source.nonStatic : 0;
    if (source.status !== PARSED_STATUS) continue;

    for (const reference of source.references ?? []) {
      const resolution = resolveModuleReference({
        fromPath: source.path,
        specifier: reference.specifier,
        languageId: source.languageId,
        observedPaths,
      });

      if (resolution.resolvedPath === null) {
        unresolvedAll.push({
          path: source.path,
          specifier: reference.specifier,
          kind: reference.kind,
          reason: resolution.reason,
          evidenceId: source.evidenceId,
        });
        continue;
      }

      resolvedCount += 1;
      const from = `file:${source.path}`;
      const to = `file:${resolution.resolvedPath}`;
      const key = `${from}\u0000${to}`;
      let record = edgeRecords.get(key);
      if (record === undefined) {
        record = {
          from,
          to,
          specifiers: new Set(),
          kinds: new Set(),
          evidenceIds: new Set(),
          sourcePaths: new Set(),
        };
        edgeRecords.set(key, record);
      }
      record.specifiers.add(reference.specifier);
      record.kinds.add(reference.kind);
      record.evidenceIds.add(source.evidenceId);
      record.sourcePaths.add(source.path);
    }
  }

  // ── Nodes ──────────────────────────────────────────────────────────────────
  //
  // Every module source the inventory observed, plus every file a reference
  // resolved to. A node therefore always names a file the scan saw: the graph can
  // describe no file that was not observed, which is what stops resolution from
  // inventing an entity.
  const nodeIds = new Set();
  for (const file of files) {
    if (MODULE_EXTENSIONS.includes(file.extension)) nodeIds.add(file.id);
  }
  for (const record of edgeRecords.values()) {
    nodeIds.add(record.to);
  }

  const nodes = [...nodeIds]
    .map((id) => {
      const path = id.slice("file:".length);
      const file = fileByPath.get(path);
      if (file === undefined) return null;
      return nodeSummary(file, sourceByPath.get(path));
    })
    .filter((node) => node !== null)
    .sort(compareByKeys(["id"]));

  const graphNodeIds = new Set(nodes.map((node) => node.id));

  // ── Edges ──────────────────────────────────────────────────────────────────
  const allEdges = [...edgeRecords.values()]
    .filter((record) => graphNodeIds.has(record.from) && graphNodeIds.has(record.to))
    .map((record) => {
      const specifiers = [...record.specifiers].sort();
      return {
        from: record.from,
        to: record.to,
        type: IMPORT_GRAPH_EDGE_TYPES.IMPORTS,
        // The specifier(s) exactly as written, sorted and bounded — the reference
        // itself, so a consumer can see what the file said without re-reading it.
        specifiers: specifiers.slice(0, IMPORT_GRAPH_LIMITS.MAX_SPECIFIERS_PER_EDGE),
        specifiersTruncated: specifiers.length > IMPORT_GRAPH_LIMITS.MAX_SPECIFIERS_PER_EDGE,
        // Which declaration forms established it (a static import, a re-export, a
        // require, a dynamic import), so "how is this file imported?" is answerable.
        kinds: [...record.kinds].sort(),
        // Provenance: the importing file's own import observation, and the
        // repository-relative path whose observation stated it. File-level, because
        // the acquisition layer records no line positions — a fabricated line number
        // would be provenance that does not exist.
        evidenceIds: [...record.evidenceIds].sort(),
        sourcePaths: [...record.sourcePaths].sort(),
      };
    })
    .sort(compareByKeys(["from", "to", "type"]));

  const edgesTruncated = allEdges.length > IMPORT_GRAPH_LIMITS.MAX_EDGES;
  const edges = edgesTruncated ? allEdges.slice(0, IMPORT_GRAPH_LIMITS.MAX_EDGES) : allEdges;

  const sortedUnresolved = unresolvedAll
    .slice()
    .sort(compareByKeys(["path", "specifier", "kind"]))
    .map((record) => Object.freeze({ ...record }));
  const unresolvedTruncated = sortedUnresolved.length > IMPORT_GRAPH_LIMITS.MAX_UNRESOLVED;
  const unresolved = unresolvedTruncated
    ? sortedUnresolved.slice(0, IMPORT_GRAPH_LIMITS.MAX_UNRESOLVED)
    : sortedUnresolved;

  const specifiersTruncated = edges.some((edge) => edge.specifiersTruncated === true);

  const state = importGraphState({
    sources,
    scanComplete: coverage?.scanComplete === true,
    scanTruncated: coverage?.scanTruncated === true,
    hasScanState:
      typeof coverage?.scanComplete === "boolean" && typeof coverage?.scanTruncated === "boolean",
    projectionTruncated: edgesTruncated || unresolvedTruncated,
    uninterpretedSources,
  });
  const established = isEstablishedState(state);

  const countByStatus = (status) => sources.filter((source) => source.status === status).length;

  // Why the graph is not complete, named file by file: every module source whose
  // references were not fully established. Each is a place an import could exist and
  // is not known to.
  const unestablished = sources
    .filter((source) => !isSourceEstablished(source))
    .map((source) =>
      Object.freeze({
        path: source.path,
        status: source.status,
        reason: source.reason ?? null,
        problems: Object.freeze([...(source.problems ?? [])]),
        truncated: source.truncated === true,
        evidenceId: source.evidenceId ?? null,
      }),
    )
    .sort(compareByKeys(["path"]))
    .slice(0, IMPORT_GRAPH_LIMITS.MAX_UNESTABLISHED_SOURCES);

  const unresolvedByReason = {};
  for (const reason of UNRESOLVED_REFERENCE_REASON_VALUES) {
    unresolvedByReason[reason] = 0;
  }
  for (const record of unresolvedAll) {
    unresolvedByReason[record.reason] = (unresolvedByReason[record.reason] ?? 0) + 1;
  }

  return deepFreeze({
    version: IMPORT_GRAPH_VERSION,
    state,
    established,
    nodes,
    edges,
    // References that are not edges. Kept apart from the edges on purpose: an
    // unresolved reference is "the file said this and we cannot establish what it
    // points at", which is a different fact from *these two files are connected*.
    unresolved,
    coverage: {
      state,
      established,
      complete: state === IMPORT_GRAPH_STATES.COMPLETE,
      truncated: state === IMPORT_GRAPH_STATES.TRUNCATED,
      inspected: sources.some((source) => source.status === PARSED_STATUS),
      // Counts of what the graph contains, never a claim that the repository has no
      // more. `references` counts established references, so `resolved +
      // unresolved === references` holds over what was acquired, not over what
      // exists.
      nodes: nodes.length,
      edges: edges.length,
      sources: sources.length,
      moduleFiles: nodes.filter((node) => node.module === true).length,
      // The other half of the coverage statement: source files the repository has
      // that this graph does not read at all. A consumer asking "is this the whole
      // import story?" needs both numbers, and neither is inferred from the other.
      uninterpretedSources,
      uninterpretedExtensions: Object.freeze(
        uninterpretedExtensions.slice(0, IMPORT_GRAPH_LIMITS.MAX_UNINTERPRETED_EXTENSIONS),
      ),
      uninterpretedExtensionsTruncated:
        uninterpretedExtensions.length > IMPORT_GRAPH_LIMITS.MAX_UNINTERPRETED_EXTENSIONS,
      parsed: countByStatus(PARSED_STATUS),
      unsupported: countByStatus(UNSUPPORTED_STATUS),
      failed: sources.filter((source) => source.status !== PARSED_STATUS && source.status !== UNSUPPORTED_STATUS && source.status !== NOT_INSPECTED_STATUS).length,
      notInspected: countByStatus(NOT_INSPECTED_STATUS),
      references: resolvedCount + unresolvedAll.length,
      resolved: resolvedCount,
      unresolved: unresolvedAll.length,
      unresolvedReported: unresolved.length,
      unresolvedByReason: Object.freeze(unresolvedByReason),
      nonStatic: nonStaticCount,
      // Why the graph is not complete, named file by file.
      unestablishedSources: Object.freeze(unestablished),
      // Every bound that bit, stated rather than implied.
      edgesTruncated,
      unresolvedTruncated,
      specifiersTruncated,
      limits: IMPORT_GRAPH_LIMITS,
    },
  });
}
