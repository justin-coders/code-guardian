/**
 * Code Guardian — Dependency Graph Inventory Rule (Phase 14)
 *
 * The integration proof for Phase 14's dependency graph, and deliberately an
 * **inventory** rule: it reports the dependency relationships a supported lockfile
 * established, one finding per edge, naming both packages, the ecosystem and the
 * lockfile that stated the relationship.
 *
 * ### Why this is not a "circular dependency" rule
 *
 * A cycle, a deep tree, a wide fan-out and a large closure are all *properties*, not
 * problems — and this phase has no evidence that any of them is undesirable in the
 * repository being analysed. Turning graph shape into a verdict would be exactly the
 * fabricated judgment the architecture forbids, so the rule reports structure and
 * stops. Health, advisories, freshness and circularity belong to later phases.
 *
 * ### What it proves about the graph substrate
 *
 *   - it reads the graph **only** through the Phase 11 query API (`dependencyGraph`,
 *     `dependencyGraphCoverage`) — never `model.dependencies.graph`, never a lockfile;
 *   - every finding cites the observation that established the edge, so provenance
 *     survives fingerprinting;
 *   - it never infers directness from topology: an edge says "the lockfile recorded
 *     this relationship", and nothing about whether the target is a direct or
 *     transitive dependency;
 *   - an empty graph is only reported as `pass` when the graph was actually
 *     established *and* complete, so "no relationships" is never claimed over a
 *     repository whose lockfile could not be read;
 *   - output is deterministic: edges are flattened and ordered by `(from, to, type)`.
 *
 * ### Boundedness
 *
 * A large lockfile can establish tens of thousands of relationships. The rule stops
 * at `MAX_GRAPH_FINDINGS` and records that it did (`metadata.capped`), so a capped
 * run is never silently partial.
 */

import { createRule } from "../../../core/index.js";

import { APPLICABILITY_COVERAGE } from "../../contracts.js";
import { createRuleDetection } from "../../evaluation.js";

import {
  DEPENDENCY_CATEGORY,
  DEPENDENCY_CONFIDENCE,
  DEPENDENCY_GRAPH_BASIS,
  DEPENDENCY_RULE_IDS,
  DEPENDENCY_RULE_VERSION,
  MAX_GRAPH_FINDINGS,
} from "../contracts.js";
import {
  dependencyGraphAbsence,
  dependencyGraphCoverage,
  dependencyGraphEdges,
  queryFor,
} from "../signals.js";

/** How an edge type reads in a finding description. */
const EDGE_TYPE_WORDING = Object.freeze({
  "depends-on": "records that it depends on",
});

/** A human-readable statement of one established relationship. */
function describe(edge) {
  const from = edge.fromName ?? edge.from;
  const to = edge.toName ?? edge.to;
  const lockfiles =
    edge.manifestPaths.length === 0
      ? "a lockfile"
      : `\`${edge.manifestPaths.join("`, `")}\``;
  const wording = EDGE_TYPE_WORDING[edge.type] ?? "is recorded as related to";

  return `\`${from}\` ${wording} \`${to}\` according to ${lockfiles}, in the \`${edge.ecosystem}\` ecosystem. This finding states the relationship the lockfile recorded; it does not infer a requirement from a version range, and it says nothing about whether either package is a direct dependency, current, or safe.`;
}

/**
 * Detect established dependency relationships across the repository model.
 *
 * @param {object} context A validated AnalysisContext.
 * @returns {object} A detection object.
 */
function detectDependencyGraph(context) {
  const query = queryFor(context);
  const edges = dependencyGraphEdges(query);
  const coverage = dependencyGraphCoverage(query);

  const findings = [];
  for (const edge of edges) {
    if (findings.length >= MAX_GRAPH_FINDINGS) break;
    findings.push({
      confidence: DEPENDENCY_CONFIDENCE.OBSERVED_RELATIONSHIP,
      description: describe(edge),
      // The lockfile observation that established the relationship. Citing it is what
      // makes the finding traceable after the Finding Engine canonicalizes it.
      evidence: [...edge.evidenceIds],
      metadata: {
        from: edge.from,
        fromName: edge.fromName,
        to: edge.to,
        toName: edge.toName,
        ecosystem: edge.ecosystem,
        type: edge.type,
        manifestPaths: [...edge.manifestPaths],
        // One file-level observation per lockfile means several relationships cite the
        // same evidence, and a canonical fingerprint is derived from the evidence set.
        // Without this key two edges of one lockfile would fingerprint identically and
        // the run would fail as a duplicate. The key names the edge, not its order.
        fingerprintKey: edge.fingerprintKey,
        basis: DEPENDENCY_GRAPH_BASIS,
      },
    });
  }

  const metadata = {
    basis: DEPENDENCY_GRAPH_BASIS,
    state: coverage.state,
    established: coverage.established,
    nodes: coverage.nodes,
    edges: coverage.edges,
    relationships: edges.length,
    reported: findings.length,
    capped: findings.length < edges.length,
    versionAmbiguous: coverage.versionInstances?.ambiguous === true,
  };

  if (findings.length > 0) {
    // Findings always win over abstention: an established relationship was observed,
    // so reporting it does not depend on how complete the rest of the graph is.
    return { findings, evidence: [], metadata };
  }

  // No relationship was observed. That is a claim, so it needs the coverage to
  // support it: a graph that was never established, or was only partly
  // established, must abstain rather than report a clean repository.
  const absence = dependencyGraphAbsence(query);
  if (!absence.established) {
    // The counts travel with the abstention too: a reader can see that the graph was
    // partial (or never established) rather than that it was empty.
    return {
      ...createRuleDetection({
        findings: [],
        coverage: APPLICABILITY_COVERAGE.UNKNOWN,
        reason: `no dependency relationship was observed, but ${absence.reason}`,
      }),
      metadata,
    };
  }

  return { findings, evidence: [], metadata };
}

export const dependencyGraphRules = Object.freeze([
  createRule({
    id: DEPENDENCY_RULE_IDS.GRAPH_INVENTORY,
    version: DEPENDENCY_RULE_VERSION,
    category: DEPENDENCY_CATEGORY,
    title: "Dependency relationship recorded in a lockfile",
    description:
      "A supported lockfile records that one dependency depends on another. The finding names both packages, the ecosystem they belong to and the lockfile that stated the relationship, and cites the observation that established it. It is an inventory statement: the relationship was read, not inferred from a version range, and no judgment is made about directness, circularity, freshness, licensing or vulnerability.",
    severity: "info",
    // Every repository whose dependencies were acquired is in scope; a rule with no
    // selectors is universally applicable (Core Rule contract).
    applicability: {},
    detect: (context) => detectDependencyGraph(context),
    remediation: {},
    metadata: {
      basis: DEPENDENCY_GRAPH_BASIS,
      tags: ["dependency", "graph", "lockfile", "inventory"],
      falsePositives: [
        "a lockfile relationship that the installed tree never resolves to",
        "an optional or peer relationship a package states but does not require",
      ],
    },
  }),
]);
