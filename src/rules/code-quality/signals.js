/**
 * Code Guardian — Code Quality Repository Signals (Official Roadmap Phase 12)
 *
 * The one place the code-quality rules ask the repository questions. Every read goes through
 * the query API over the frozen RepositoryModel: no filesystem, no `node:path`, no process,
 * no network, no scan. A rule that cannot answer a question from the model reports `unknown`
 * rather than going to look for itself.
 *
 * ### Absence is a claim, not an observation
 *
 * The gap-shaped rules can only conclude "not present", and `sourceAbsence()` decides whether
 * the model supports it. It mirrors the Phase 10/11 rule: the scan must have covered the
 * repository completely (the query envelope's `coverage: "complete"`) and no path may have
 * failed to read. Anything else leaves the answer `unknown`.
 *
 * ### Three qualities of evidence
 *
 *   - **Configuration / script / dependency** evidence is a *declaration*: the repository
 *     says a tool is set up. It is `detected`, never `verified`.
 *   - **CI content** evidence is an *invocation*: a workflow's bytes contain the tool's
 *     command. Configuration + invocation is what this phase calls `verified`.
 *   - **Graph** evidence (import and symbol graphs) is a *shape*: an export with no
 *     established references, a module nothing imports. It is an `indicator`, and the graph's
 *     own coverage decides whether the absence of edges means anything at all.
 */

import {
  COVERAGE_GUARANTEES,
  ENTITY_KINDS,
  IMPORT_GRAPH_STATES,
  SYMBOL_GRAPH_STATES,
  SYMBOL_SIGNALS,
  createRepositoryQuery,
} from "../../repository/model/index.js";

import { QUALITY_CONFIGURATION_SIGNALS } from "./contracts.js";

/** Build the read-only query handle for an AnalysisContext. */
export function queryFor(context) {
  return createRepositoryQuery(context.repository);
}

/** Configuration entities the scanner reported with one signal, in id order. */
export function configurationBySignal(query, signal) {
  return query
    .listEntities(ENTITY_KINDS.CONFIGURATION)
    .entities.filter((entity) => entity.signal === signal);
}

/** Every configuration entity, in id order. */
export function configurationInventory(query) {
  return query.listEntities(ENTITY_KINDS.CONFIGURATION);
}

/** The basename of a repository-relative path (POSIX, no `node:path`). */
export function basenameOf(path) {
  const parts = String(path ?? "").split("/");
  return parts.length === 0 ? "" : parts[parts.length - 1];
}

/**
 * The observed manifests and their declared script facts.
 *
 * Returns one record per observed manifest: the path, the manifest entity, whether its
 * metadata was parsed, and the declared script *names*. A manifest whose metadata was not
 * parsed is returned too — the absence of a script it *might* have declared is `unknown`,
 * never "declared no script".
 */
export function manifestFacts(query) {
  const records = [];
  for (const entity of query.listEntities(ENTITY_KINDS.MANIFEST).entities) {
    const metadata = entity.parse?.metadata ?? null;
    records.push({
      entity,
      path: entity.path,
      parseStatus: entity.parse?.status ?? null,
      parsed: entity.parse?.status === "parsed" && metadata !== null,
      scripts: Array.isArray(metadata?.scripts) ? metadata.scripts : [],
      scriptsTruncated: metadata?.scriptsTruncated === true,
    });
  }
  return records.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
}

/** Every declared script name across observed manifests, sorted and de-duplicated. */
export function declaredScriptNames(query) {
  const names = new Set();
  for (const record of manifestFacts(query)) {
    if (!record.parsed) continue;
    for (const name of record.scripts) if (typeof name === "string") names.add(name);
  }
  return [...names].sort();
}

/**
 * Whether a script whose *name* names a quality tool was declared.
 *
 * Name-based on purpose: the manifest metadata keeps script names, not commands, so this is
 * the fact the model actually has. It says a script exists; it does not say what the script
 * runs, and the finding is worded accordingly.
 *
 * @param {string[]} declaredNames Sorted script names.
 * @param {string[]} words Vocabulary words a script name may contain.
 * @returns {string[]} The matching names, sorted.
 */
export function scriptNamesMatching(declaredNames, words) {
  const vocabulary = new Set(words.map((word) => word.toLowerCase()));
  const out = [];
  for (const name of declaredNames) {
    for (const word of String(name).toLowerCase().split(/[^a-z0-9]+/)) {
      if (word !== "" && vocabulary.has(word)) {
        out.push(name);
        break;
      }
    }
  }
  return out.sort();
}

/** Dependency entities for one ecosystem, in id order. */
export function dependenciesInEcosystem(query, ecosystem) {
  return query
    .listEntities(ENTITY_KINDS.DEPENDENCY)
    .entities.filter((entity) => entity.ecosystem === ecosystem);
}

/** Every observed dependency name across ecosystems, sorted and de-duplicated. */
export function declaredDependencyNames(query) {
  const names = new Set();
  for (const entity of query.listEntities(ENTITY_KINDS.DEPENDENCY).entities) {
    if (typeof entity.name === "string") names.add(entity.name);
  }
  return [...names].sort();
}

/** Whether a dependency with this exact name is declared anywhere. */
export function declaresDependency(query, name) {
  return declaredDependencyNames(query).includes(name);
}

/** The observed language entities, in id order. */
export function languageEntities(query) {
  return query.listEntities(ENTITY_KINDS.LANGUAGE).entities;
}

/** The observed language ids, sorted and de-duplicated. */
export function languageIds(query) {
  const ids = new Set();
  for (const entity of languageEntities(query)) {
    if (typeof entity.languageId === "string") ids.add(entity.languageId);
  }
  return [...ids].sort();
}

/** Every observed file entity, in id order. */
export function fileEntities(query) {
  return query.listEntities(ENTITY_KINDS.FILE).entities;
}

/**
 * The evidence ids the model recorded for one repository-relative file path.
 *
 * Used by the structural rules, whose graph nodes name a module *path*: the evidence a
 * finding must cite is the file's own inventory observation, read from the model rather than
 * re-derived.
 *
 * @param {object} query
 * @param {string} path A repository-relative path.
 * @returns {string[]} Sorted evidence ids (empty when the path is unknown to the model).
 */
export function fileEvidenceIds(query, path) {
  if (typeof path !== "string" || path === "") return [];
  const result = query.getEvidenceForEntity(`${ENTITY_KINDS.FILE}:${path}`);
  return (result.evidence ?? [])
    .map((record) => record?.id)
    .filter((id) => typeof id === "string")
    .sort();
}

/** Whether the repository has any source-bearing artifact (a resolved language). */
export function hasSourceSubject(query) {
  return languageIds(query).length > 0;
}

/** Every CI entity the model observed, in id order. */
export function ciInventory(query) {
  return query.listEntities(ENTITY_KINDS.CICD);
}

/**
 * What CI establishes about code-quality tooling.
 *
 * The union of the `qualityCommands` the acquisition layer classified from each readable
 * workflow, plus the workflows it could **not** read. An unread workflow is reported
 * separately because "we read it and it runs no linter" and "we could not read it" are
 * different facts: a rule that concludes "no linter runs in CI" over an unread workflow would
 * be exactly the false certainty this architecture exists to prevent.
 *
 * @param {object} query
 * @returns {{tools: string[], readEntries: number, unreadEntries: number, providers: string[]}}
 */
export function ciQualityObservation(query) {
  const entries = ciInventory(query).entities;
  const tools = new Set();
  const providers = new Set();
  let readEntries = 0;
  let unreadEntries = 0;

  for (const entity of entries) {
    if (entity.provider !== undefined && entity.provider !== null) providers.add(entity.provider);
    if (entity.testExecution === "unknown") {
      // The content pass could not interpret this workflow (see the acquisition
      // contract): its quality commands are not established.
      unreadEntries += 1;
      continue;
    }
    readEntries += 1;
    for (const id of entity.qualityCommands ?? []) {
      if (typeof id === "string") tools.add(id);
    }
  }

  return Object.freeze({
    tools: [...tools].sort(),
    readEntries,
    unreadEntries,
    providers: [...providers].sort(),
  });
}

/** Whether an import-graph state establishes an edge absence (Phase 16's own rule). */
function isImportStateEstablished(state) {
  return (
    state === IMPORT_GRAPH_STATES.COMPLETE ||
    state === IMPORT_GRAPH_STATES.PARTIAL ||
    state === IMPORT_GRAPH_STATES.TRUNCATED
  );
}

/**
 * The import graph's orphan-module candidates and the state behind them.
 *
 * `orphans` are module files no established import edge touches in either direction. They are
 * *candidates* — an executable script, a dynamically loaded plugin, or a file whose importer
 * could not be parsed all look the same — so the rule reports an indicator and the graph's
 * own state decides whether it is worth reporting at all.
 *
 * @param {object} query
 * @returns {{orphans: object[], state: string, established: boolean, limited: boolean,
 *   coverage: string}}
 */
export function importGraphEvidence(query) {
  const orphans = query.orphanModules();
  const graph = query.importGraph();
  return Object.freeze({
    orphans: orphans.nodes ?? [],
    limited: orphans.limited === true,
    state: graph.state,
    established: isImportStateEstablished(graph.state),
    coverage: graph.coverage,
  });
}

/**
 * The model's own symbol-source observations, one per source the semantic layer read.
 *
 * This is the only place a per-source *problem* is recorded. The symbol graph's coverage
 * detail carries `unestablishedSources`, but that list means "this source's semantic
 * claims could not be established" — a `declaration-limit` or an unlexable file — and a
 * dynamic-scope construct sets a *different* flag (`resolutionEstablished: false`) that
 * never reaches it. So the fact is read from the observation the builder recorded for the
 * source, not re-derived and not guessed from the graph's edges.
 *
 * @param {object} query
 * @returns {Array<{path: string, status: string|null, established: {declarations: boolean,
 *   resolution: boolean, exports: boolean}, problems: string[], truncated: boolean,
 *   evidenceId: string}>} Sorted by path.
 */
export function symbolSourceObservations(query) {
  const records = [];
  for (const file of fileEntities(query)) {
    const evidence = query.getEvidenceForEntity(file.id).evidence ?? [];
    for (const record of evidence) {
      if (record?.data?.signal !== SYMBOL_SIGNALS.SOURCE) continue;
      records.push(
        Object.freeze({
          path: file.path,
          status: typeof record.data.status === "string" ? record.data.status : null,
          established: Object.freeze({
            declarations: record.data.declarationsEstablished === true,
            resolution: record.data.resolutionEstablished === true,
            exports: record.data.exportsEstablished === true,
          }),
          problems: Object.freeze([...(record.data.problems ?? [])]),
          truncated: record.data.truncated === true,
          evidenceId: record.id,
        }),
      );
      break;
    }
  }
  return records.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
}

/**
 * The symbol graph's quality-relevant shapes and the state behind them.
 *
 *   `unusedExports`        exported bindings with **no established reference** in this
 *                          repository's own sources. A library's public API is consumed
 *                          outside the repository and still looks identical here, which is
 *                          why the rule reports an *indicator*.
 *   `dynamicScopeSources`  the model's own symbol-source observations whose bounded read
 *                          recorded a dynamic-scope construct (`eval`, `with`) — a
 *                          code-quality unsafe-pattern indicator, read from the
 *                          observation rather than re-derived from source.
 *   `moduleSymbolCounts`   module path → module-scope declaration count, the structural fact
 *                          behind the large-module indicator.
 *
 * `coverage` is the graph's own coverage *detail* (`symbolCoverage()`), not the state
 * string `symbolGraph()` repeats: the detail is what names the sources whose claims were not
 * established and the bounds that bit.
 *
 * @param {object} query
 * @returns {object} Frozen.
 */
export function symbolGraphEvidence(query) {
  const graph = query.symbolGraph();
  const coverage = query.symbolCoverage();
  const nodes = Array.isArray(graph.nodes) ? graph.nodes : [];

  const moduleSymbolCounts = new Map();
  for (const node of nodes) {
    if (typeof node.path !== "string") continue;
    moduleSymbolCounts.set(node.path, (moduleSymbolCounts.get(node.path) ?? 0) + 1);
  }

  const unusedExports = nodes.filter(
    (node) =>
      node.exported === true &&
      (node.referenceCount ?? 0) === 0 &&
      node.shadowed !== true &&
      node.reassigned !== true,
  );

  const unestablishedSources = Array.isArray(coverage.unestablishedSources)
    ? coverage.unestablishedSources
    : [];
  const dynamicScopeSources = symbolSourceObservations(query).filter((source) =>
    source.problems.includes("dynamic-scope-construct"),
  );

  return Object.freeze({
    state: graph.state,
    established: graph.established === true,
    complete: graph.state === SYMBOL_GRAPH_STATES.COMPLETE,
    truncated: graph.truncated === true,
    coverage: coverage.state ?? graph.coverage ?? null,
    nodes,
    moduleSymbolCounts,
    unusedExports,
    dynamicScopeSources,
    unestablishedReported: unestablishedSources.length,
    unestablishedTotal: Number.isInteger(coverage.unestablished) ? coverage.unestablished : 0,
  });
}

/**
 * Whether the model supports an absence claim over the file inventory.
 *
 * This is the file-inventory answer *plus* the configuration-inventory cap: the scanner caps
 * configuration evidence per signal, so a repository with more quality configurations than
 * the cap carries a `configuration` inventory that is complete as far as it goes but not
 * complete as a *set*. An absence-shaped quality claim over such an inventory is `unknown`.
 *
 * @param {object} context A validated AnalysisContext.
 * @returns {{established: boolean, reason: string|null, observedFiles: number, ignoredPaths: number}}
 */
export function sourceAbsence(context) {
  const query = createRepositoryQuery(context.repository);
  const inventory = query.listEntities(ENTITY_KINDS.FILE);
  const summary = query.coverage();
  const reasons = [];

  if (inventory.coverage !== COVERAGE_GUARANTEES.COMPLETE) {
    reasons.push(
      summary.truncated === true
        ? "the scan stopped at a limit before the inventory was complete"
        : "the scan did not cover the repository completely",
    );
  }
  if (summary.unreadableCount > 0) {
    reasons.push(`${summary.unreadableCount} path(s) could not be read`);
  }
  if (context.repository?.configuration?.evidenceTruncated === true) {
    reasons.push("the configuration inventory was truncated at the evidence cap");
  }

  return Object.freeze({
    established: reasons.length === 0,
    reason: reasons.length === 0 ? null : reasons.join("; "),
    observedFiles: inventory.entities.length,
    ignoredPaths: summary.ignoredCount,
  });
}

/** The quality configuration signals this pack reads, re-exported for rule authors. */
export const QUALITY_SIGNALS = QUALITY_CONFIGURATION_SIGNALS;
