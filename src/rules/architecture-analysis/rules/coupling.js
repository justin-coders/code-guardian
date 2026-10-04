/**
 * Code Guardian — Architecture Coupling and Cohesion Rules (Official Roadmap Phase 14)
 *
 * Two of the nine official domains, both **indicators over measured structure** rather than
 * verdicts:
 *
 *   coupling            a module that depends on at least `COUPLING_OUTGOING` distinct modules.
 *                       The finding states the measured counts; it never says the coupling is
 *                       "too high" — the roadmap asks for measured coupling, and a threshold is
 *                       a documented reporting choice, not taste.
 *   cohesion indicators a module large enough to have internal structure (at least
 *                       `COHESION_MIN_MEMBERS` module sources) whose members never import one
 *                       another while the module still participates in the graph. It reports an
 *                       interpretable shape, never an opaque cohesion score.
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
import { buildModuleGraph, queryFor } from "../signals.js";

import { capFindings, edgeEvidenceIds, keyFragment, unknownDetection } from "./shared.js";

const CATEGORY = ARCHITECTURE_ANALYSIS_CATEGORY;
const VERSION = ARCHITECTURE_ANALYSIS_RULE_VERSION;
const IDS = ARCHITECTURE_ANALYSIS_RULE_IDS;
const LIMITS = ARCHITECTURE_ANALYSIS_LIMITS;
const BASES = ARCHITECTURE_ANALYSIS_BASES;
const STATES = ARCHITECTURE_ANALYSIS_STATES;
const CONFIDENCE = ARCHITECTURE_ANALYSIS_CONFIDENCE;

export const architectureCouplingRules = Object.freeze([
  createRule({
    id: IDS.COUPLING_MEASURED,
    version: VERSION,
    category: CATEGORY,
    title: "A module depends on many other modules",
    description:
      "A module whose outgoing module dependency count reaches the analyzer's documented threshold is reported with the measured counts: how many distinct modules it depends on, how many depend on it, and how many import edges it holds internally. This is a measured relationship, not a judgment that the coupling is wrong; the threshold is a documented, deterministic reporting line.",
    severity: "info",
    applicability: {},
    detect: (context) => {
      const query = queryFor(context);
      const graph = buildModuleGraph(query);

      if (!graph.established) {
        return unknownDetection(
          `the import graph is "${graph.state}", so coupling is not established`,
        );
      }

      if (graph.modules.length === 0) {
        if (graph.complete) {
          return {
            findings: [],
            evidence: [],
            metadata: { basis: BASES.IMPORT_GRAPH, state: STATES.NOT_APPLICABLE, measuredModules: 0 },
          };
        }
        return unknownDetection(`no module was measured, but the import graph is "${graph.state}"`);
      }

      const threshold = LIMITS.COUPLING_OUTGOING;
      const outgoingByModule = new Map();
      for (const edge of graph.edges) {
        const list = outgoingByModule.get(edge.from);
        if (list === undefined) outgoingByModule.set(edge.from, [edge]);
        else list.push(edge);
      }

      const candidates = graph.modules
        .filter((module) => module.outgoingModuleCount >= threshold)
        .map((module) => ({
          module,
          edges: outgoingByModule.get(module.path) ?? [],
        }))
        .sort((a, b) => (a.module.path < b.module.path ? -1 : a.module.path > b.module.path ? 1 : 0));

      if (candidates.length === 0) {
        return {
          findings: [],
          evidence: [],
          metadata: {
            basis: BASES.IMPORT_GRAPH,
            state: STATES.NOT_APPLICABLE,
            graphState: graph.state,
            threshold,
            measuredModules: graph.modules.length,
          },
        };
      }

      const { entries, truncated } = capFindings(candidates);
      const findings = entries.map(({ module, edges }) => ({
        confidence: CONFIDENCE.MEASURED_RELATIONSHIP,
        description: `Module \`${module.label}\` depends on ${module.outgoingModuleCount} distinct modules (threshold ${threshold}) across ${module.outgoingEdges} import edge(s), and is depended on by ${module.incomingModuleCount}. This is a measured relationship; it does not state that the module is badly designed.`,
        evidence: edgeEvidenceIds(edges),
        metadata: {
          basis: BASES.IMPORT_GRAPH,
          state: STATES.DETECTED,
          fingerprintKey: `coupling:${keyFragment(module.label)}`,
          module: module.label,
          modulePath: module.path,
          outgoingModules: module.outgoingModuleCount,
          incomingModules: module.incomingModuleCount,
          outgoingEdges: module.outgoingEdges,
          internalEdges: module.internalEdges,
          threshold,
        },
      })).filter((finding) => finding.evidence.length > 0);

      return {
        findings,
        evidence: [],
        metadata: {
          basis: BASES.IMPORT_GRAPH,
          state: findings.length > 0 ? STATES.DETECTED : STATES.UNKNOWN,
          graphState: graph.state,
          threshold,
          measuredModules: graph.modules.length,
          reported: findings.length,
          truncated,
        },
      };
    },
    remediation: {},
    metadata: {
      tags: ["architecture", "coupling"],
      falsePositives: ["a module that legitimately aggregates many small dependencies"],
    },
  }),

  createRule({
    id: IDS.COHESION_INDICATOR,
    version: VERSION,
    category: CATEGORY,
    title: "A module's own sources do not import one another",
    description:
      "A module with at least the configured number of module sources whose members establish no internal import edge, while the module still participates in the graph, is a cohesion indicator. The finding states the member count, the internal edge count and the module's external connectivity; it is an interpretable shape, not an opaque cohesion score and not a claim that the module is wrongly designed.",
    severity: "info",
    applicability: {},
    detect: (context) => {
      const query = queryFor(context);
      const graph = buildModuleGraph(query);

      if (!graph.established) {
        return unknownDetection(
          `the import graph is "${graph.state}", so cohesion indicators are not established`,
        );
      }

      if (graph.modules.length === 0) {
        if (graph.complete) {
          return {
            findings: [],
            evidence: [],
            metadata: { basis: BASES.IMPORT_GRAPH, state: STATES.NOT_APPLICABLE, measuredModules: 0 },
          };
        }
        return unknownDetection(`no module was measured, but the import graph is "${graph.state}"`);
      }

      const minMembers = LIMITS.COHESION_MIN_MEMBERS;
      const candidates = graph.modules
        .filter(
          (module) =>
            module.fileCount >= minMembers &&
            module.internalEdges === 0 &&
            module.outgoingModuleCount + module.incomingModuleCount > 0,
        )
        .sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));

      if (candidates.length === 0) {
        return {
          findings: [],
          evidence: [],
          metadata: {
            basis: BASES.IMPORT_GRAPH,
            state: STATES.NOT_APPLICABLE,
            graphState: graph.state,
            minMembers,
            measuredModules: graph.modules.length,
          },
        };
      }

      const { entries, truncated } = capFindings(
        candidates.filter((module) => module.evidenceIds.length > 0),
      );
      const findings = entries.map((module) => ({
        confidence: CONFIDENCE.STRUCTURAL_INDICATOR,
        description: `Module \`${module.label}\` holds ${module.fileCount} module sources, none of which establishes an import edge to another source in the same module, while it depends on ${module.outgoingModuleCount} module(s) and is depended on by ${module.incomingModuleCount}. This is a cohesion indicator over measured structure; it does not say the module is wrongly designed.`,
        evidence: module.evidenceIds,
        metadata: {
          basis: BASES.IMPORT_GRAPH,
          state: STATES.DETECTED,
          fingerprintKey: `cohesion:${keyFragment(module.label)}`,
          module: module.label,
          modulePath: module.path,
          files: module.fileCount,
          internalEdges: module.internalEdges,
          outgoingModules: module.outgoingModuleCount,
          incomingModules: module.incomingModuleCount,
          minMembers,
        },
      }));

      return {
        findings,
        evidence: [],
        metadata: {
          basis: BASES.IMPORT_GRAPH,
          state: findings.length > 0 ? STATES.DETECTED : STATES.UNKNOWN,
          graphState: graph.state,
          minMembers,
          measuredModules: graph.modules.length,
          reported: findings.length,
          truncated,
        },
      };
    },
    remediation: {},
    metadata: {
      tags: ["architecture", "cohesion"],
      falsePositives: ["a module of independent scripts that intentionally share only a folder"],
    },
  }),
]);
