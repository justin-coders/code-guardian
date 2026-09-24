/**
 * Code Guardian — Import Repository Signals (Phase 16)
 *
 * The one place import rules ask the repository questions. Every read goes through
 * the Phase 11 query API over the frozen RepositoryModel: no filesystem, no
 * `node:path`, no source parsing, no resolver, no process, no clock. A rule that
 * cannot answer a question from the model reports `unknown` rather than going to look
 * for itself — which is the whole point of building the import graph once, in the
 * model.
 *
 * ### Relationships are flattened here, provenance is not
 *
 * A graph edge already carries the observation that established it and the
 * repository-relative path whose observation stated it, so flattening adds only what
 * a description needs — the endpoints' paths, languages and kinds — and never
 * re-derives the reference itself.
 */

import {
  IMPORT_GRAPH_STATES,
  createRepositoryQuery,
  stabilityHash,
} from "../../repository/model/index.js";

import { KIND_WORDING, UNRESOLVED_REASON_WORDING } from "./contracts.js";

/**
 * Build the read-only query handle for an AnalysisContext.
 *
 * @param {object} context A validated AnalysisContext.
 * @returns {object} A frozen query handle.
 */
export function queryFor(context) {
  return createRepositoryQuery(context.repository);
}

/**
 * Every established import reference, with provenance.
 *
 * Sorted by `(from, to)` locally, so the order never depends on a model internal —
 * the same repository always yields the same list.
 *
 * Each row also carries a `fingerprintKey`: a finding's canonical fingerprint is
 * derived from its rule, category and evidence set, and *every* reference from one
 * file cites that file's single import observation. Without a disambiguator, two
 * imports from the same file would collapse into one finding and the run would fail
 * as a duplicate. The key is a stability hash of the endpoints — never an index,
 * which would shift every fingerprint when an unrelated file is added — and it is
 * deterministic and bounded.
 *
 * @param {object} query
 * @returns {Array<{from: string, fromPath: string|null, fromLanguage: string|null,
 *   to: string, toPath: string|null, toLanguage: string|null, toIsModule: boolean,
 *   type: string, specifiers: string[], kinds: string[],
 *   kindWording: string[], evidenceIds: string[], sourcePaths: string[],
 *   fingerprintKey: string}>}
 */
export function importRelationships(query) {
  const graph = query.importGraph();
  const nodeById = new Map(graph.nodes.map((node) => [node.id, node]));

  const rows = graph.edges.map((edge) => {
    const from = nodeById.get(edge.from);
    const to = nodeById.get(edge.to);
    return {
      from: edge.from,
      fromPath: from?.path ?? null,
      fromLanguage: from?.languageId ?? null,
      to: edge.to,
      toPath: to?.path ?? null,
      toLanguage: to?.languageId ?? null,
      toIsModule: to?.module === true,
      type: edge.type,
      specifiers: [...(edge.specifiers ?? [])],
      kinds: [...(edge.kinds ?? [])],
      kindWording: (edge.kinds ?? []).map((kind) => KIND_WORDING[kind] ?? kind),
      // The importing file's own observation. Citing it is what makes the finding
      // traceable after the Finding Engine canonicalizes it.
      evidenceIds: [...(edge.evidenceIds ?? [])],
      sourcePaths: [...(edge.sourcePaths ?? [])],
      fingerprintKey: `import:${stabilityHash(`${edge.from}|${edge.type}|${edge.to}`)}`,
    };
  });

  return rows.sort((a, b) => {
    if (a.from !== b.from) return a.from < b.from ? -1 : 1;
    return a.to < b.to ? -1 : a.to > b.to ? 1 : 0;
  });
}

/**
 * The module references the repository does **not** establish a target for.
 *
 * Kept separate from `importRelationships` on purpose: a reference whose target the
 * scan did not observe is a different fact from a file-to-file reference, and a rule
 * that mixed them would report a non-fact as a relationship. Each record carries a
 * closed `reason`, so the reasons can be summarised without rendering raw specifier
 * text as prose.
 *
 * @param {object} query
 * @returns {Array<{path: string, specifier: string, kind: string, reason: string,
 *   evidenceId: string|null}>}
 */
export function importUnresolved(query) {
  return query.unresolvedImports({ maxResults: 1000 }).unresolved.map((record) => ({
    path: record.path,
    specifier: record.specifier,
    kind: record.kind,
    reason: record.reason,
    evidenceId: record.evidenceId ?? null,
  }));
}

/**
 * The graph's own coverage statement: its five-way state, the sources whose
 * references could not be fully established, and the bounds it was built under.
 *
 * @param {object} query
 * @returns {object} Frozen coverage statement.
 */
export function importCoverage(query) {
  return query.importCoverage();
}

/**
 * Whether the model supports a claim that the repository establishes no import
 * reference at all.
 *
 * Two separate things have to hold, and neither is inferred from an empty edge list:
 * a graph must actually have been established (`unsupported` and `unknown` are not
 * "no imports", they are "no answer"), and the scan behind it must have covered the
 * repository. A partial graph can be missing exactly the reference a caller would
 * conclude does not exist — and the commonest cause, a source whose parse was cut
 * short, is named here rather than left implicit.
 *
 * @param {object} query
 * @returns {{established: boolean, reason: string|null, state: string}}
 */
export function importsAbsence(query) {
  const graph = importCoverage(query);
  const inventory = query.coverage();
  const reasons = [];

  if (graph.established !== true) {
    // Two ways for "unsupported" to be true, and they read differently to a human:
    // every module source is a format this build does not parse (JSX/TSX), or there is
    // no module source at all because every source file is written in a language it
    // does not read (Python, Go, Java, ...).
    const unreadLanguage =
      graph.state === IMPORT_GRAPH_STATES.UNSUPPORTED &&
      graph.sources === 0 &&
      (graph.uninterpretedSources ?? 0) > 0;
    reasons.push(
      unreadLanguage
        ? "every source file in this repository is in a language this build does not read"
        : graph.state === IMPORT_GRAPH_STATES.UNSUPPORTED
          ? "no module source in this repository is a format this build interprets"
          : "the model did not establish an import graph",
    );
  } else if (graph.state !== IMPORT_GRAPH_STATES.COMPLETE) {
    const unestablished = graph.unestablishedSources ?? [];
    if (graph.state === IMPORT_GRAPH_STATES.TRUNCATED) {
      reasons.push(
        "a resource bound stopped module acquisition before every source was read",
      );
    } else if (unestablished.length > 0) {
      reasons.push(
        `module references could not be fully established for ${unestablished
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

/** The unresolved-reason vocabulary this module can describe, for tests. */
export const IMPORT_DESCRIBED_UNRESOLVED_REASONS = Object.freeze(
  Object.keys(UNRESOLVED_REASON_WORDING),
);

export { IMPORT_GRAPH_STATES };
