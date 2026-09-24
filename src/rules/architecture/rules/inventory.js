/**
 * Code Guardian — Architecture Inventory Rule (Phase 15)
 *
 * The integration proof for Phase 15's architecture graph, and deliberately an
 * **inventory** rule: it reports the architectural relationships the repository
 * establishes, one finding per relationship, naming both endpoints, the relationship
 * itself, and the path whose observation stated it.
 *
 * ### Why this is not a layering or coupling rule
 *
 * "This directory contains those files", "this manifest declares that package",
 * "this test artifact uses that framework" and "this Compose service builds that
 * Dockerfile" are *facts about the repository's shape*. Whether the shape is good,
 * layered, cohesive, over-coupled or production-ready needs a model of what the
 * project is trying to be — and this architecture has no such model, so the rule
 * reports structure and stops. There is no graph score, no cycle verdict and no
 * readiness statement anywhere in it.
 *
 * ### What it proves about the graph substrate
 *
 *   - it reads the graph **only** through the Phase 11 query API
 *     (`architectureGraph`, `architectureCoverage`) — never the raw model area,
 *     never a file;
 *   - every finding cites the observations that established the relationship, so
 *     provenance survives fingerprinting;
 *   - it never claims an import, a call, an inheritance or a tested-by relation: those
 *     edges do not exist in the graph, because nothing in this architecture can
 *     establish them;
 *   - an empty graph is only reported as `pass` when the graph was actually
 *     established *and* complete, so "no relationships" is never claimed over a
 *     repository whose scan was incomplete or whose container configuration could not
 *     be read;
 *   - output is deterministic: relationships are flattened and sorted by
 *     `(from, type, to)`.
 *
 * ### Boundedness
 *
 * A large repository has one containment edge per entity. The rule stops at
 * `MAX_ARCHITECTURE_FINDINGS` and records that it did (`metadata.capped`), so a
 * capped run is never silently partial.
 */

import { createRule } from "../../../core/index.js";

import { APPLICABILITY_COVERAGE } from "../../contracts.js";
import { createRuleDetection } from "../../evaluation.js";

import {
  ARCHITECTURE_BASIS,
  ARCHITECTURE_CATEGORY,
  ARCHITECTURE_CONFIDENCE,
  ARCHITECTURE_RULE_IDS,
  ARCHITECTURE_RULE_VERSION,
  MAX_ARCHITECTURE_FINDINGS,
} from "../contracts.js";
import {
  architectureAbsence,
  architectureCoverage,
  architectureRelationships,
  queryFor,
} from "../signals.js";

/** A short label for an endpoint: its path, its name, or its id. */
function endpointLabel(kind, name, path, id) {
  if (typeof path === "string") return `\`${path}\``;
  if (typeof name === "string") return `\`${name}\` (${kind})`;
  return `\`${id}\``;
}

/** A human-readable statement of one established relationship. */
function describe(relationship) {
  const from = endpointLabel(
    relationship.fromKind,
    relationship.fromName,
    relationship.fromPath,
    relationship.from,
  );
  const to = endpointLabel(
    relationship.toKind,
    relationship.toName,
    relationship.toPath,
    relationship.to,
  );
  const wording = relationship.wording ?? "is related to";

  const stated =
    relationship.sourcePaths.length === 0
      ? ""
      : ` The observation behind it is at ${relationship.sourcePaths
          .map((path) => `\`${path}\``)
          .join(", ")}.`;
  const services =
    relationship.services.length === 0
      ? ""
      : ` The declaration names the container service(s) ${relationship.services
          .map((service) => `\`${service}\``)
          .join(", ")}.`;

  return `${from} ${wording} ${to}, according to the repository structure the scan observed.${stated}${services} This finding states a relationship the repository establishes; it is not an import, a call, an inheritance or a test-coverage claim, and it makes no judgment about layering, coupling, ownership or quality.`;
}

/**
 * Detect architecture relationships across the repository model.
 *
 * @param {object} context A validated AnalysisContext.
 * @returns {object} A detection object.
 */
function detectArchitecture(context) {
  const query = queryFor(context);
  const relationships = architectureRelationships(query);
  const coverage = architectureCoverage(query);

  const findings = [];
  for (const relationship of relationships) {
    if (findings.length >= MAX_ARCHITECTURE_FINDINGS) break;
    findings.push({
      confidence: ARCHITECTURE_CONFIDENCE.OBSERVED_RELATIONSHIP,
      description: describe(relationship),
      // The observation that established the relationship. Citing it is what makes
      // the finding traceable after the Finding Engine canonicalizes it.
      evidence: [...relationship.evidenceIds],
      metadata: {
        from: relationship.from,
        fromKind: relationship.fromKind,
        fromPath: relationship.fromPath,
        to: relationship.to,
        toKind: relationship.toKind,
        toPath: relationship.toPath,
        relationshipType: relationship.type,
        sourcePaths: [...relationship.sourcePaths],
        services: [...relationship.services],
        // One entity observation can support several edges, and a canonical
        // fingerprint is derived from the evidence set. Without this key two edges of
        // one entity would fingerprint identically and the run would fail as a
        // duplicate. The key names the relationship, not its order.
        fingerprintKey: relationship.fingerprintKey,
        basis: ARCHITECTURE_BASIS,
      },
    });
  }

  const metadata = {
    basis: ARCHITECTURE_BASIS,
    state: coverage.state,
    established: coverage.established === true,
    nodes: coverage.nodes,
    edges: coverage.edges,
    buildContexts: coverage.buildContexts,
    reported: findings.length,
    capped: findings.length < relationships.length,
    unestablishedSources: (coverage.unestablishedSources ?? []).length,
  };

  if (findings.length > 0) {
    // Findings always win over abstention: an established relationship was observed,
    // so reporting it does not depend on how complete the rest of the graph is.
    return { findings, evidence: [], metadata };
  }

  // No relationship was observed. That is a claim, so it needs the coverage to
  // support it: a graph that was never established, or was only partly established,
  // must abstain rather than report a repository whose structure is unimpeachable.
  const absence = architectureAbsence(query);
  if (!absence.established) {
    return {
      ...createRuleDetection({
        findings: [],
        coverage: APPLICABILITY_COVERAGE.UNKNOWN,
        reason: `no architectural relationship was observed, but ${absence.reason}`,
      }),
      metadata,
    };
  }

  return { findings, evidence: [], metadata };
}

export const architectureRules = Object.freeze([
  createRule({
    id: ARCHITECTURE_RULE_IDS.GRAPH_INVENTORY,
    version: ARCHITECTURE_RULE_VERSION,
    category: ARCHITECTURE_CATEGORY,
    title: "Architectural relationship established by the repository",
    description:
      "The repository establishes an architectural relationship the scan observed: an entity sitting in a container, a manifest declaring a dependency, a test artifact using a framework, or a Compose service building a Dockerfile from a context root. The finding names both endpoints, the relationship, the file whose observation stated it and — for container wiring — the declaring services, and cites the observation that established it. It is an inventory statement: no import, call, inheritance or test-coverage relation is claimed, and no layering, coupling or quality judgment is made.",
    severity: "info",
    // Every repository that was scanned is in scope; a rule with no selectors is
    // universally applicable (Core Rule contract).
    applicability: {},
    detect: (context) => detectArchitecture(context),
    remediation: {},
    metadata: {
      basis: ARCHITECTURE_BASIS,
      tags: ["architecture", "structure", "inventory"],
      falsePositives: [
        "a containment relation between two artifacts that happen to share a directory",
        "a declared dependency the project does not actually use",
      ],
    },
  }),
]);
