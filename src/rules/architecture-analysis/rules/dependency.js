/**
 * Code Guardian — Architecture Dependency Rules (Official Roadmap Phase 14)
 *
 * Two of the nine official domains, both about the module-level dependency graph:
 *
 *   dependency direction    the measured direction `A → B` between established modules, one
 *                           finding per direction, citing the underlying import edges. It is a
 *                           measurement, not a stereotype: no controllers→services→repositories
 *                           ordering is ever assumed.
 *   circular dependencies   actual cycles in the module graph, computed as strongly connected
 *                           components with at least two members. A finding is emitted only for
 *                           a real cycle and names the participating modules and edges; an empty
 *                           result is an answer only when the graph was complete, otherwise the
 *                           rule answers `unknown`.
 */

import { createRule } from "../../../core/index.js";

import {
  ARCHITECTURE_ANALYSIS_BASES,
  ARCHITECTURE_ANALYSIS_CATEGORY,
  ARCHITECTURE_ANALYSIS_CONFIDENCE,
  ARCHITECTURE_ANALYSIS_LIMITS,
  ARCHITECTURE_ANALYSIS_RULE_IDS,
  ARCHITECTURE_ANALYSIS_RULE_VERSION,
  ARCHITECTURE_ANALYSIS_STATES,
} from "../contracts.js";
import { findModuleCycles } from "../graph.js";
import { buildModuleGraph, queryFor } from "../signals.js";

import { capFindings, keyFragment, unknownDetection } from "./shared.js";

const CATEGORY = ARCHITECTURE_ANALYSIS_CATEGORY;
const VERSION = ARCHITECTURE_ANALYSIS_RULE_VERSION;
const IDS = ARCHITECTURE_ANALYSIS_RULE_IDS;
const LIMITS = ARCHITECTURE_ANALYSIS_LIMITS;
const BASES = ARCHITECTURE_ANALYSIS_BASES;
const STATES = ARCHITECTURE_ANALYSIS_STATES;
const CONFIDENCE = ARCHITECTURE_ANALYSIS_CONFIDENCE;

export const architectureDependencyRules = Object.freeze([
  createRule({
    id: IDS.DEPENDENCY_DIRECTION,
    version: VERSION,
    category: CATEGORY,
    title: "Dependency direction between established modules",
    description:
      "A module depends on another module when at least one of its files states an import the repository establishes as a file in the other. The finding names both modules, the number of import edges and the files whose observations stated them. It is a measured direction: no universal ordering (controllers → services → repositories) is assumed, and no direction is called correct.",
    severity: "info",
    applicability: {},
    detect: (context) => {
      const query = queryFor(context);
      const graph = buildModuleGraph(query);

      if (!graph.established) {
        return unknownDetection(
          `the import graph is "${graph.state}", so dependency directions are not established`,
        );
      }

      if (graph.edges.length === 0) {
        if (graph.complete) {
          return {
            findings: [],
            evidence: [],
            metadata: {
              basis: BASES.IMPORT_GRAPH,
              state: STATES.NOT_APPLICABLE,
              graphState: graph.state,
              directions: 0,
            },
          };
        }
        return unknownDetection(
          `no module dependency was observed, but the import graph is "${graph.state}"`,
        );
      }

      const candidates = graph.edges.filter((edge) => edge.evidenceIds.length > 0);
      const { entries, truncated } = capFindings(candidates);
      const findings = entries.map((edge) => ({
        confidence: CONFIDENCE.OBSERVED_RELATIONSHIP,
        description: `Module \`${edge.from || "(repository root)"}\` depends on module \`${edge.to || "(repository root)"}\` through ${edge.count} established import edge(s)${edge.sourcePaths.length === 0 ? "" : `, stated in ${edge.sourcePaths.map((path) => `\`${path}\``).join(", ")}`}. This is a measured direction the repository establishes; it makes no claim that the direction is desirable or undesirable.`,
        evidence: edge.evidenceIds,
        metadata: {
          basis: BASES.IMPORT_GRAPH,
          state: STATES.ESTABLISHED,
          fingerprintKey: `direction:${keyFragment(edge.from)}::${keyFragment(edge.to)}`,
          from: edge.from,
          to: edge.to,
          count: edge.count,
          sourcePaths: [...edge.sourcePaths],
        },
      }));

      return {
        findings,
        evidence: [],
        metadata: {
          basis: BASES.IMPORT_GRAPH,
          state: findings.length > 0 ? STATES.ESTABLISHED : STATES.NOT_APPLICABLE,
          graphState: graph.state,
          directions: graph.edges.length,
          reported: findings.length,
          truncated,
        },
      };
    },
    remediation: {},
    metadata: {
      tags: ["architecture", "dependency-direction"],
      falsePositives: [],
    },
  }),

  createRule({
    id: IDS.DEPENDENCY_CYCLE,
    version: VERSION,
    category: CATEGORY,
    title: "Circular dependency between modules",
    description:
      "The module-level dependency graph contains a cycle: a strongly connected component with at least two modules, each reachable from the others through established import edges. The finding names the participating modules and the edges that form the cycle, and cites their observations. It is derived only from a real graph cycle; an empty result is reported as clean only when the import graph was complete.",
    severity: "medium",
    applicability: {},
    detect: (context) => {
      const query = queryFor(context);
      const graph = buildModuleGraph(query);

      if (!graph.established) {
        return unknownDetection(
          `the import graph is "${graph.state}", so cycles are not established`,
        );
      }

      const cycles = findModuleCycles(graph);

      if (cycles.length === 0) {
        if (graph.complete) {
          return {
            findings: [],
            evidence: [],
            metadata: {
              basis: BASES.IMPORT_GRAPH,
              state: STATES.NOT_APPLICABLE,
              graphState: graph.state,
              modules: graph.modules.length,
              cycles: 0,
            },
          };
        }
        return unknownDetection(
          `no cycle was observed, but the import graph is "${graph.state}", so the absence is not established`,
        );
      }

      // Deterministic cycle order and a bounded cycle description.
      const ordered = cycles
        .slice()
        .sort((a, b) => (a.join("\u0000") < b.join("\u0000") ? -1 : 1));

      const { entries, truncated } = capFindings(ordered);
      const findings = entries.map((component) => {
        const members = new Set(component);
        const cycleEdges = graph.edges.filter(
          (edge) => members.has(edge.from) && members.has(edge.to),
        );
        const evidence = [...new Set(cycleEdges.flatMap((edge) => edge.evidenceIds))].sort();
        const named = component.slice(0, LIMITS.MAX_CYCLE_MEMBERS).map((path) => `\`${path}\``);
        const extra = component.length - named.length;
        return {
          confidence: CONFIDENCE.OBSERVED_RELATIONSHIP,
          description: `A circular dependency connects ${component.length} modules: ${named.join(", ")}${extra > 0 ? `, and ${extra} more` : ""}. Each is reachable from the others through established import edges. This finding reports the cycle the repository's own imports form; it does not say the cycle is intentional or a defect.`,
          evidence,
          metadata: {
            basis: BASES.IMPORT_GRAPH,
            state: STATES.ESTABLISHED,
            fingerprintKey: `cycle:${keyFragment(component.join("|"))}`,
            modules: [...component].slice(0, LIMITS.MAX_CYCLE_MEMBERS),
            moduleCount: component.length,
            edges: cycleEdges.length,
          },
        };
      }).filter((finding) => finding.evidence.length > 0);

      return {
        findings,
        evidence: [],
        metadata: {
          basis: BASES.IMPORT_GRAPH,
          state: findings.length > 0 ? STATES.ESTABLISHED : STATES.UNKNOWN,
          graphState: graph.state,
          modules: graph.modules.length,
          cycles: cycles.length,
          reported: findings.length,
          truncated,
        },
      };
    },
    remediation: {},
    metadata: {
      tags: ["architecture", "circular-dependency"],
      falsePositives: [],
    },
  }),
]);
