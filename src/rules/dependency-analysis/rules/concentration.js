/**
 * Code Guardian — Dependency Concentration Rule (Official Roadmap Phase 15)
 *
 * The "dependency concentration" domain — a **measurement**, not a score. It reports packages
 * that many other packages depend on in the recorded dependency graph, naming the measured
 * in-degree and the documented threshold. It never says the concentration is risky, and there is
 * no dependency risk score anywhere.
 *
 * The graph must be established; over a partial graph an empty result is `unknown`, not "no
 * concentration".
 */

import { createRule } from "../../../core/index.js";

import {
  DEPENDENCY_ANALYSIS_BASES,
  DEPENDENCY_ANALYSIS_CATEGORY,
  DEPENDENCY_ANALYSIS_CONFIDENCE,
  DEPENDENCY_ANALYSIS_LIMITS,
  DEPENDENCY_ANALYSIS_RULE_IDS,
  DEPENDENCY_ANALYSIS_RULE_VERSION,
  DEPENDENCY_ANALYSIS_STATES,
} from "../contracts.js";
import {
  dependencyGraphEdges,
  dependencyGraphEstablished,
  queryFor,
} from "../signals.js";

import { capFindings, keyFragment, unknownDetection } from "./shared.js";

const CATEGORY = DEPENDENCY_ANALYSIS_CATEGORY;
const VERSION = DEPENDENCY_ANALYSIS_RULE_VERSION;
const IDS = DEPENDENCY_ANALYSIS_RULE_IDS;
const BASES = DEPENDENCY_ANALYSIS_BASES;
const STATES = DEPENDENCY_ANALYSIS_STATES;

export const dependencyConcentrationRules = Object.freeze([
  createRule({
    id: IDS.CONCENTRATION,
    version: VERSION,
    category: CATEGORY,
    title: "A package is depended on by many recorded packages",
    description:
      "A package's in-degree in the recorded dependency graph reaches the analyzer's documented concentration threshold — that many distinct packages depend on it. The finding states the measured in-degree, the threshold and a bounded sample of the packages that depend on it. It is a structural measurement over lockfile evidence, never a risk verdict.",
    severity: "info",
    applicability: {},
    detect: (context) => {
      const query = queryFor(context);
      const graph = dependencyGraphEstablished(query);

      if (!graph.established) {
        return unknownDetection(
          `the dependency graph is "${graph.state}", so concentration is not established`,
        );
      }

      const edges = dependencyGraphEdges(query);
      const dependentsByNode = new Map();
      const nodeById = new Map();
      for (const edge of edges) {
        nodeById.set(edge.to, { name: edge.toName, ecosystem: edge.ecosystem });
        const set = dependentsByNode.get(edge.to);
        if (set === undefined) dependentsByNode.set(edge.to, new Set([edge.from]));
        else set.add(edge.from);
      }

      const threshold = DEPENDENCY_ANALYSIS_LIMITS.CONCENTRATION_INDEGREE;
      const candidates = [...dependentsByNode.entries()]
        .map(([id, dependents]) => ({
          id,
          name: nodeById.get(id)?.name ?? id,
          ecosystem: nodeById.get(id)?.ecosystem ?? null,
          dependents: [...dependents].sort(),
          evidenceIds: [
            ...new Set(
              edges.filter((edge) => edge.to === id).flatMap((edge) => edge.evidenceIds),
            ),
          ].sort(),
        }))
        .filter((entry) => entry.dependents.length >= threshold)
        .sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));

      if (edges.length === 0) {
        return {
          findings: [],
          evidence: [],
          metadata: { basis: BASES.DEPENDENCY_GRAPH, state: STATES.NOT_APPLICABLE, edges: 0 },
        };
      }

      const { entries, truncated } = capFindings(candidates.filter((entry) => entry.evidenceIds.length > 0));
      const findings = entries.map((entry) => ({
        confidence: DEPENDENCY_ANALYSIS_CONFIDENCE.MEASURED_RELATIONSHIP,
        description: `\`${entry.name}\` (${entry.ecosystem ?? "unknown ecosystem"}) is depended on by ${entry.dependents.length} distinct packages in the recorded dependency graph (threshold ${threshold}). This is a measured concentration of relationships; it does not state that the package is risky or unwanted.`,
        evidence: [...entry.evidenceIds],
        metadata: {
          basis: BASES.DEPENDENCY_GRAPH,
          state: STATES.DETECTED,
          fingerprintKey: `concentration:${keyFragment(entry.id)}`,
          node: entry.id,
          package: entry.name,
          ecosystem: entry.ecosystem,
          dependents: entry.dependents.length,
          threshold,
        },
      }));

      return {
        findings,
        evidence: [],
        metadata: {
          basis: BASES.DEPENDENCY_GRAPH,
          state: findings.length > 0 ? STATES.DETECTED : STATES.ESTABLISHED,
          graphState: graph.state,
          edges: edges.length,
          threshold,
          reported: findings.length,
          truncated,
        },
      };
    },
    remediation: {},
    metadata: {
      tags: ["dependency", "concentration", "measurement"],
      falsePositives: ["a widely used utility that a project legitimately depends on everywhere"],
    },
  }),
]);
