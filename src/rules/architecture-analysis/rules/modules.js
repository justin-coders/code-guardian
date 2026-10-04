/**
 * Code Guardian — Architecture Module Rules (Official Roadmap Phase 14)
 *
 * Two of the nine official domains, both about the module as a unit:
 *
 *   module boundaries   what the repository's own structure establishes as a module, and what
 *                       it contains — an inventory of modules, each cited to the files that
 *                       established it. A directory name is never read.
 *   large modules       a module whose member count (or module-scope declaration total, when the
 *                       symbol graph establishes it) crosses a documented threshold. It reports
 *                       the measured counts and the threshold; it is a size *indicator*, never a
 *                       verdict about the module's quality.
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

import { capFindings, keyFragment, unknownDetection } from "./shared.js";

const CATEGORY = ARCHITECTURE_ANALYSIS_CATEGORY;
const VERSION = ARCHITECTURE_ANALYSIS_RULE_VERSION;
const IDS = ARCHITECTURE_ANALYSIS_RULE_IDS;
const LIMITS = ARCHITECTURE_ANALYSIS_LIMITS;
const BASES = ARCHITECTURE_ANALYSIS_BASES;
const STATES = ARCHITECTURE_ANALYSIS_STATES;
const CONFIDENCE = ARCHITECTURE_ANALYSIS_CONFIDENCE;

/** Whether the import graph establishes module boundaries at all, and how completely. */
function boundaryGraph(query) {
  return buildModuleGraph(query);
}

export const architectureModuleRules = Object.freeze([
  createRule({
    id: IDS.MODULE_BOUNDARY,
    version: VERSION,
    category: CATEGORY,
    title: "Module boundary established by the repository structure",
    description:
      "A directory that the repository's own import graph establishes as a container of module sources is an architectural module. The finding names the module, how many module sources it holds, its internal import count and how many other modules it depends on and is depended on by, and cites the observations of the files that established it. It is an inventory of the repository's boundaries: it never claims a module is well- or badly-bounded and never reads a directory name.",
    severity: "info",
    applicability: {},
    detect: (context) => {
      const query = queryFor(context);
      const graph = boundaryGraph(query);

      if (!graph.established) {
        return unknownDetection(
          `the import graph is "${graph.state}", so module boundaries are not established`,
        );
      }

      if (graph.modules.length === 0) {
        if (graph.complete) {
          return {
            findings: [],
            evidence: [],
            metadata: { basis: BASES.IMPORT_GRAPH, state: STATES.NOT_APPLICABLE, modules: 0 },
          };
        }
        return unknownDetection(
          `no module boundary was observed, but the import graph is "${graph.state}"`,
        );
      }

      const candidates = graph.modules.filter((module) => module.evidenceIds.length > 0);
      const { entries, truncated } = capFindings(candidates);
      const findings = entries.map((module) => ({
        confidence: CONFIDENCE.OBSERVED_RELATIONSHIP,
        description: `Module \`${module.label}\` is established by ${module.fileCount} module source(s) the repository's import graph read. It holds ${module.internalEdges} internal import edge(s), depends on ${module.outgoingModuleCount} other module(s) and is depended on by ${module.incomingModuleCount}. This finding states a boundary the repository establishes; it is not an import-order, ownership or quality judgment.`,
        evidence: module.evidenceIds,
        metadata: {
          basis: BASES.IMPORT_GRAPH,
          state: STATES.ESTABLISHED,
          fingerprintKey: `boundary:${keyFragment(module.label)}`,
          module: module.label,
          modulePath: module.path,
          files: module.fileCount,
          internalEdges: module.internalEdges,
          outgoingModules: module.outgoingModuleCount,
          incomingModules: module.incomingModuleCount,
        },
      }));

      return {
        findings,
        evidence: [],
        metadata: {
          basis: BASES.IMPORT_GRAPH,
          state: findings.length > 0 ? STATES.ESTABLISHED : STATES.NOT_APPLICABLE,
          graphState: graph.state,
          modules: graph.modules.length,
          reported: findings.length,
          truncated,
        },
      };
    },
    remediation: {},
    metadata: {
      tags: ["architecture", "module-boundaries"],
      falsePositives: [
        "a directory that holds only a single re-export and is still a valid module",
      ],
    },
  }),

  createRule({
    id: IDS.MODULE_LARGE,
    version: VERSION,
    category: CATEGORY,
    title: "A module is large by the analyzer's documented thresholds",
    description:
      "A module whose module-source count reaches the file threshold, or whose total module-scope declaration count reaches the declaration threshold (when the symbol graph establishes it), is reported as large. The finding states the measured counts and the thresholds it crossed. It is a size indicator the repository can check, not a complexity measurement and not a statement that a large module is wrong.",
    severity: "info",
    applicability: {},
    detect: (context) => {
      const query = queryFor(context);
      const graph = boundaryGraph(query);

      if (!graph.established) {
        return unknownDetection(
          `the import graph is "${graph.state}", so module sizes are not established`,
        );
      }

      const fileThreshold = LIMITS.LARGE_MODULE_FILES;
      const declarationThreshold = LIMITS.LARGE_MODULE_DECLARATIONS;

      const candidates = graph.modules
        .filter((module) => {
          if (module.fileCount >= fileThreshold) return true;
          return module.declarationsComplete && module.declarations >= declarationThreshold;
        })
        .map((module) => ({
          module,
          byFiles: module.fileCount >= fileThreshold,
          byDeclarations:
            module.declarationsComplete && module.declarations >= declarationThreshold,
        }))
        .sort((a, b) => (a.module.path < b.module.path ? -1 : a.module.path > b.module.path ? 1 : 0));

      if (candidates.length === 0) {
        if (graph.modules.length === 0) {
          if (graph.complete) {
            return {
              findings: [],
              evidence: [],
              metadata: {
                basis: BASES.IMPORT_GRAPH,
                state: STATES.NOT_APPLICABLE,
                measuredModules: 0,
              },
            };
          }
          return unknownDetection(
            `no module was measured, but the import graph is "${graph.state}"`,
          );
        }
        return {
          findings: [],
          evidence: [],
          metadata: {
            basis: BASES.IMPORT_GRAPH,
            state: STATES.NOT_APPLICABLE,
            graphState: graph.state,
            fileThreshold,
            declarationThreshold,
            measuredModules: graph.modules.length,
          },
        };
      }

      const { entries, truncated } = capFindings(
        candidates.filter((entry) => entry.module.evidenceIds.length > 0),
      );
      const findings = entries.map(({ module, byFiles, byDeclarations }) => ({
        confidence: CONFIDENCE.STRUCTURAL_INDICATOR,
        description: `Module \`${module.label}\` holds ${module.fileCount} module source(s)${module.declarationsComplete ? ` and ${module.declarations} module-scope declaration(s)` : ""}, crossing the ${byFiles ? `module-source threshold of ${fileThreshold}` : ""}${byFiles && byDeclarations ? " and the " : ""}${byDeclarations ? `declaration threshold of ${declarationThreshold}` : ""}. This is a size indicator over measured counts, not a complexity measurement and not a statement that the module is wrong.`,
        evidence: module.evidenceIds,
        metadata: {
          basis: BASES.IMPORT_GRAPH,
          state: STATES.DETECTED,
          fingerprintKey: `large:${keyFragment(module.label)}`,
          module: module.label,
          modulePath: module.path,
          files: module.fileCount,
          declarations: module.declarations,
          declarationsComplete: module.declarationsComplete,
          fileThreshold,
          declarationThreshold,
        },
      }));

      return {
        findings,
        evidence: [],
        metadata: {
          basis: BASES.IMPORT_GRAPH,
          state: findings.length > 0 ? STATES.DETECTED : STATES.NOT_APPLICABLE,
          graphState: graph.state,
          fileThreshold,
          declarationThreshold,
          measuredModules: graph.modules.length,
          reported: findings.length,
          truncated,
        },
      };
    },
    remediation: {},
    metadata: {
      tags: ["architecture", "large-module"],
      falsePositives: ["a generated barrel file with many re-exports"],
    },
  }),
]);
