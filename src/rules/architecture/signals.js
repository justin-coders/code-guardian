/**
 * Code Guardian — Architecture Repository Signals (Phase 15)
 *
 * The one place architecture rules ask the repository questions. Every read goes
 * through the Phase 11 query API over the frozen RepositoryModel: no filesystem, no
 * `node:path`, no source parsing, no AST, no process, no clock. A rule that cannot
 * answer a question from the model reports `unknown` rather than going to look for
 * itself — which is the whole point of building the architecture graph once, in the
 * model.
 *
 * ### Relationships are flattened here, provenance is not
 *
 * A graph edge already carries the observations that established it and the
 * repository-relative paths whose observations stated it, so flattening adds only
 * what a description needs — the endpoints' kinds, names and paths — and never
 * re-derives the relationship itself.
 */

import {
  ARCHITECTURE_EDGE_TYPES,
  ARCHITECTURE_GRAPH_STATES,
  createRepositoryQuery,
  stabilityHash,
} from "../../repository/model/index.js";

import { EDGE_WORDING } from "./contracts.js";

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
 * Every architectural relationship the repository establishes, with provenance.
 *
 * Sorted by `(from, type, to)` locally, so the order never depends on a model
 * internal — the same repository always yields the same list.
 *
 * Each row also carries a `fingerprintKey`: a finding's canonical fingerprint is
 * derived from its rule, category and evidence set, and several containment edges
 * legitimately cite the same observations (a file is inventoried once, and its
 * directory's observation states the containment too). Without a disambiguator two
 * edges could collapse into one finding. The key is a stability hash of the
 * endpoints and the type — never an index, which would shift every fingerprint when
 * an unrelated entity is added — and it is deterministic and bounded.
 *
 * @param {object} query
 * @returns {Array<{from: string, fromKind: string|null, fromName: string|null,
 *   fromPath: string|null, to: string, toKind: string|null, toName: string|null,
 *   toPath: string|null, type: string, wording: string, evidenceIds: string[],
 *   sourcePaths: string[], services: string[], fingerprintKey: string}>}
 */
export function architectureRelationships(query) {
  const graph = query.architectureGraph();
  const nodeById = new Map(graph.nodes.map((node) => [node.id, node]));

  const rows = graph.edges.map((edge) => {
    const from = nodeById.get(edge.from);
    const to = nodeById.get(edge.to);
    return {
      from: edge.from,
      fromKind: from?.kind ?? null,
      fromName: from?.name ?? null,
      fromPath: from?.path ?? null,
      to: edge.to,
      toKind: to?.kind ?? null,
      toName: to?.name ?? null,
      toPath: to?.path ?? null,
      type: edge.type,
      wording: EDGE_WORDING[edge.type] ?? null,
      evidenceIds: [...(edge.evidenceIds ?? [])],
      sourcePaths: [...(edge.sourcePaths ?? [])],
      services: [...(edge.services ?? [])],
      fingerprintKey: `architecture:${stabilityHash(`${edge.from}|${edge.type}|${edge.to}`)}`,
    };
  });

  return rows.sort((a, b) => {
    if (a.from !== b.from) return a.from < b.from ? -1 : 1;
    if (a.type !== b.type) return a.type < b.type ? -1 : 1;
    return a.to < b.to ? -1 : a.to > b.to ? 1 : 0;
  });
}

/**
 * The graph's own coverage statement: its four-way state, the container sources
 * whose declarations could not be established, and the bounds it was built under.
 *
 * @param {object} query
 * @returns {object} Frozen coverage statement.
 */
export function architectureCoverage(query) {
  return query.architectureCoverage();
}

/**
 * Whether the model supports a claim that the repository establishes no
 * architectural relationship at all.
 *
 * Two separate things have to hold, and neither is inferred from an empty edge list:
 * a graph must actually have been established (`unsupported` and `unknown` are not
 * "no relationships", they are "no answer"), and the scan behind it must have
 * covered the repository. A partial graph can be missing exactly the relationship a
 * caller would conclude does not exist.
 *
 * @param {object} query
 * @returns {{established: boolean, reason: string|null, state: string}}
 */
export function architectureAbsence(query) {
  const graph = architectureCoverage(query);
  const inventory = query.coverage();
  const reasons = [];

  if (graph.established !== true) {
    reasons.push(
      graph.state === ARCHITECTURE_GRAPH_STATES.UNSUPPORTED
        ? "the inventory establishes no architectural entity"
        : "the model did not establish an architecture",
    );
  } else if (graph.state !== ARCHITECTURE_GRAPH_STATES.COMPLETE) {
    reasons.push(
      (graph.unestablishedSources ?? []).length > 0
        ? `container build declarations could not be established for ${(graph.unestablishedSources ?? [])
            .map((entry) => `\`${entry.path}\``)
            .join(", ")}`
        : "the scan judged the repository only partly covered",
    );
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

/** The edge vocabulary this module can describe, exported for tests and consumers. */
export const ARCHITECTURE_DESCRIBED_EDGE_TYPES = Object.freeze(Object.keys(EDGE_WORDING));

export { ARCHITECTURE_EDGE_TYPES };
