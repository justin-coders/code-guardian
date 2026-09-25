/**
 * Code Guardian — Symbol Repository Signals (Phase 17)
 *
 * The one place symbol rules ask the repository questions. Every read goes through
 * the Phase 11 query API over the frozen RepositoryModel: no filesystem, no
 * `node:path`, no source parsing, no scope analysis, no process, no clock. A rule that
 * cannot answer a question from the model reports `unknown` rather than going to look
 * for itself — which is the whole point of building the symbol graph once, in the
 * model.
 *
 * ### Relationships are flattened here, provenance is not
 *
 * A graph edge already carries the observation that established it and the
 * repository-relative path whose observation stated it, so flattening adds only what a
 * description needs — the endpoints' paths, names and kinds — and never re-derives the
 * relationship itself.
 *
 * ### What this module refuses to add
 *
 * It does not attribute a call site to an enclosing symbol: the acquisition layer
 * attributes an occurrence to the *file* that states it and to nothing finer, so a
 * flattening that claimed "function `a` calls function `b`" would be inventing scope
 * information the substrate does not have. `edges` therefore always read
 * `file --type--> symbol`, exactly as the graph states them.
 */

import {
  SYMBOL_GRAPH_STATES,
  createRepositoryQuery,
  stabilityHash,
} from "../../repository/model/index.js";

import { EDGE_TYPE_WORDING, UNRESOLVED_SYMBOL_REASON_WORDING } from "./contracts.js";

/**
 * Build the read-only query handle for an AnalysisContext.
 *
 * @param {object} context A validated AnalysisContext.
 * @returns {object} A frozen query handle.
 */
export function queryFor(context) {
  return createRepositoryQuery(context.repository);
}

/** The repository-relative path an entity id names, or `null`. */
function pathOfId(id) {
  if (typeof id !== "string") return null;
  if (id.startsWith("file:")) return id.slice(5);
  return null;
}

/**
 * Every established semantic relationship, with provenance.
 *
 * Sorted by `(from, type, to)` locally, so the order never depends on a model
 * internal — the same repository always yields the same list. Each row carries a
 * `fingerprintKey` naming the relationship: a finding's canonical fingerprint is
 * derived from its rule, category and evidence set, and *every* relationship a file
 * states cites that file's single semantic observation, so without a disambiguator two
 * edges would collapse into one finding and the run would fail as a duplicate. The key
 * is a stability hash of the endpoints and the edge type — never an index, which would
 * shift every fingerprint when an unrelated file is added.
 *
 * @param {object} query
 * @returns {Array<{from: string, fromPath: string|null, fromName: string|null,
 *   to: string, toPath: string|null, toName: string|null, toKinds: string[],
 *   toShadowed: boolean, type: string, wording: string, count: number,
 *   names: string[], evidenceIds: string[], sourcePaths: string[],
 *   fingerprintKey: string}>}
 */
export function symbolRelationships(query) {
  const graph = query.symbolGraph();
  const nodeById = new Map(graph.nodes.map((node) => [node.id, node]));

  const rows = graph.edges.map((edge) => {
    const from = nodeById.get(edge.from);
    const to = nodeById.get(edge.to);
    return {
      from: edge.from,
      fromPath: from?.path ?? pathOfId(edge.from),
      fromName: from?.name ?? null,
      to: edge.to,
      toPath: to?.path ?? pathOfId(edge.to),
      // The target symbol's own established identity. `null` when the edge points at a
      // file entity (a `declares`/`exports`/`references`/`calls` edge's target is always
      // a symbol, so this is the symbol summary).
      toName: to?.name ?? null,
      toKinds: [...(to?.kinds ?? [])],
      // Whether the target's name could be bound elsewhere in its file. Kept on the row
      // because it is *why* an occurrence was withheld from the target, which is the
      // difference between "nothing uses this" and "this build cannot say".
      toShadowed: to?.shadowed === true,
      type: edge.type,
      wording: EDGE_TYPE_WORDING[edge.type] ?? edge.type,
      count: typeof edge.count === "number" ? edge.count : 1,
      names: [...(edge.names ?? [])],
      // The stating file's own observation. Citing it is what makes the finding
      // traceable after the Finding Engine canonicalizes it.
      evidenceIds: [...(edge.evidenceIds ?? [])],
      sourcePaths: [...(edge.sourcePaths ?? [])],
      fingerprintKey: `symbol:${stabilityHash(`${edge.from}|${edge.type}|${edge.to}`)}`,
    };
  });

  return rows.sort((a, b) => {
    if (a.from !== b.from) return a.from < b.from ? -1 : 1;
    if (a.type !== b.type) return a.type < b.type ? -1 : 1;
    return a.to < b.to ? -1 : a.to > b.to ? 1 : 0;
  });
}

/**
 * The occurrences the repository does **not** establish a target for.
 *
 * Kept separate from `symbolRelationships` on purpose: a name a file refers to whose
 * binding is not established is a different fact from a resolved relationship, and a
 * rule that mixed them would report a non-fact as a relationship. Each record carries a
 * closed `kind` and `reason`, so the reasons can be summarised without rendering raw
 * source text as prose.
 *
 * @param {object} query
 * @returns {Array<{path: string, name: string, kind: string, reason: string,
 *   evidenceId: string|null}>}
 */
export function symbolUnresolved(query) {
  return query.unresolvedSymbolReferences({ maxResults: 1000 }).unresolved.map((record) => ({
    path: record.path,
    name: record.name,
    kind: record.kind,
    reason: record.reason,
    evidenceId: record.evidenceId ?? null,
  }));
}

/**
 * The graph's own coverage statement: its five-way state, the sources whose semantic
 * claims could not be established, and the bounds it was built under.
 *
 * @param {object} query
 * @returns {object} Frozen coverage statement.
 */
export function symbolCoverage(query) {
  return query.symbolCoverage();
}

/**
 * Whether the model supports a claim that the repository establishes no semantic
 * relationship at all.
 *
 * Two separate things have to hold, and neither is inferred from an empty edge list: a
 * graph must actually have been established (`unsupported` and `unknown` are not "no
 * symbols", they are "no answer"), and the scan behind it must have covered the
 * repository. A partial graph can be missing exactly the reference a caller would
 * conclude does not exist — and the commonest causes, a source whose lexer failed and a
 * source whose `eval` voided resolution, are named here rather than left implicit.
 *
 * @param {object} query
 * @returns {{established: boolean, reason: string|null, state: string}}
 */
export function symbolsAbsence(query) {
  const graph = symbolCoverage(query);
  const inventory = query.coverage();
  const reasons = [];

  if (graph.established !== true) {
    // Two ways for "unsupported" to be true, and they read differently to a human:
    // every module source is a format this build does not interpret (JSX/TSX), or there
    // is no module source at all because every source file is written in a language it
    // does not read (Python, Go, Java, ...).
    const unreadLanguage =
      graph.state === SYMBOL_GRAPH_STATES.UNSUPPORTED &&
      graph.sources === 0 &&
      (graph.uninterpretedSources ?? 0) > 0;
    reasons.push(
      unreadLanguage
        ? "every source file in this repository is in a language this build does not read"
        : graph.state === SYMBOL_GRAPH_STATES.UNSUPPORTED
          ? "no module source in this repository is a format this build interprets"
          : "the model did not establish a symbol graph",
    );
  } else if (graph.state !== SYMBOL_GRAPH_STATES.COMPLETE) {
    const unestablished = graph.unestablishedSources ?? [];
    if (graph.state === SYMBOL_GRAPH_STATES.TRUNCATED) {
      reasons.push(
        "a resource bound stopped semantic acquisition before every source's declarations and resolution were established",
      );
    } else if (unestablished.length > 0) {
      reasons.push(
        `symbols could not be fully established for ${unestablished
          .slice(0, 5)
          .map((entry) => `\`${entry.path}\``)
          .join(", ")}${unestablished.length > 5 ? " and others" : ""}`,
      );
    } else {
      reasons.push("the graph judged the repository only partly established");
    }
  }
  if (inventory.complete !== true) {
    reasons.push(
      inventory.truncated === true
        ? "the scan stopped at a limit before the inventory was complete"
        : "the scan did not cover the repository completely",
    );
  }

  return Object.freeze({
    established: reasons.length === 0,
    reason: reasons.length === 0 ? null : reasons.join("; "),
    state: graph.state,
  });
}

/** The edge-type vocabulary this module can describe, for tests. */
export const SYMBOL_DESCRIBED_EDGE_TYPES = Object.freeze(Object.keys(EDGE_TYPE_WORDING));

/** The unresolved-reason vocabulary this module can describe, for tests. */
export const SYMBOL_DESCRIBED_UNRESOLVED_REASONS = Object.freeze(
  Object.keys(UNRESOLVED_SYMBOL_REASON_WORDING),
);

export { SYMBOL_GRAPH_STATES };
