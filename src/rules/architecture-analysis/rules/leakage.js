/**
 * Code Guardian — Architecture Boundary Leakage Rule (Official Roadmap Phase 14)
 *
 * The "boundary leakage" domain, gated on the boundary actually existing.
 *
 * The roadmap's rule is absolute here: *no established boundary → no boundary-leakage
 * violation*. So a boundary is established only when the repository itself shows one: a module
 * that publishes an **entry file** (`index.<ext>`) which other modules import. That module has
 * an interface. Leakage is then a measured import edge that reaches *past* that interface — an
 * outside file importing one of the module's internal, non-entry files.
 *
 * A module with no imported entry file has no interface to leak, so it is never reported. When
 * no module establishes such a boundary, the rule answers `not_applicable` over complete
 * coverage (there is genuinely no subject) and `unknown` otherwise. It never manufactures a
 * boundary to produce a finding.
 */

import { createRule } from "../../../core/index.js";

import {
  ARCHITECTURE_ANALYSIS_BASES,
  ARCHITECTURE_ANALYSIS_CATEGORY,
  ARCHITECTURE_ANALYSIS_CONFIDENCE,
  ARCHITECTURE_ANALYSIS_RULE_IDS,
  ARCHITECTURE_ANALYSIS_RULE_VERSION,
  ARCHITECTURE_ANALYSIS_STATES,
} from "../contracts.js";
import { isEntryFile } from "../graph.js";
import { buildModuleGraph, modulePathOf, queryFor } from "../signals.js";

import { capFindings, keyFragment, unknownDetection } from "./shared.js";

const CATEGORY = ARCHITECTURE_ANALYSIS_CATEGORY;
const VERSION = ARCHITECTURE_ANALYSIS_RULE_VERSION;
const IDS = ARCHITECTURE_ANALYSIS_RULE_IDS;
const BASES = ARCHITECTURE_ANALYSIS_BASES;
const STATES = ARCHITECTURE_ANALYSIS_STATES;
const CONFIDENCE = ARCHITECTURE_ANALYSIS_CONFIDENCE;

const label = (path) => (path === "" ? "(repository root)" : path);

export const architectureLeakageRules = Object.freeze([
  createRule({
    id: IDS.BOUNDARY_LEAKAGE,
    version: VERSION,
    category: CATEGORY,
    title: "An import reaches past a module's published entry file",
    description:
      "A module that publishes an entry file (`index.<ext>`) which other modules import has an established interface. This finding reports an outside import that bypasses that interface by targeting one of the module's internal, non-entry files. It is reported only where the boundary itself is established by a real imported entry file; a module with no imported entry has no interface to leak.",
    severity: "medium",
    applicability: {},
    detect: (context) => {
      const query = queryFor(context);
      const graph = buildModuleGraph(query);

      if (!graph.established) {
        return unknownDetection(
          `the import graph is "${graph.state}", so boundary leakage is not established`,
        );
      }

      const entryFilesByModule = new Map();
      for (const module of graph.modules) {
        const entries = module.files.filter((path) => isEntryFile(path));
        if (entries.length > 0) entryFilesByModule.set(module.path, new Set(entries));
      }

      // A boundary exists only when an entry file is actually imported from another module.
      const boundaries = new Set();
      for (const edge of graph.edges) {
        for (const fileEdge of edge.fileEdges) {
          const targetModule = modulePathOf(fileEdge.to);
          if (targetModule !== edge.to) continue;
          const entries = entryFilesByModule.get(edge.to);
          if (entries !== undefined && entries.has(fileEdge.to)) boundaries.add(edge.to);
        }
      }

      if (boundaries.size === 0) {
        if (graph.complete) {
          return {
            findings: [],
            evidence: [],
            metadata: {
              basis: BASES.IMPORT_GRAPH,
              state: STATES.NOT_APPLICABLE,
              graphState: graph.state,
              boundaries: 0,
            },
          };
        }
        return unknownDetection(
          `no published entry file was observed, but the import graph is "${graph.state}"`,
        );
      }

      const leaks = [];
      for (const edge of graph.edges) {
        if (!boundaries.has(edge.to)) continue;
        const entries = entryFilesByModule.get(edge.to) ?? new Set();
        const leaked = edge.fileEdges
          .filter((fileEdge) => !entries.has(fileEdge.to))
          .map((fileEdge) => fileEdge.to);
        if (leaked.length === 0) continue;
        leaks.push({
          from: edge.from,
          to: edge.to,
          leaked: [...new Set(leaked)].sort(),
          entries: [...entries].sort(),
          evidence: [...edge.evidenceIds].sort(),
        });
      }

      if (leaks.length === 0) {
        return {
          findings: [],
          evidence: [],
          metadata: {
            basis: BASES.IMPORT_GRAPH,
            state: STATES.NOT_APPLICABLE,
            graphState: graph.state,
            boundaries: boundaries.size,
          },
        };
      }

      leaks.sort((a, b) => (a.from < b.from ? -1 : a.from > b.from ? 1 : a.to < b.to ? -1 : 1));
      const { entries: bounded, truncated } = capFindings(
        leaks.filter((leak) => leak.evidence.length > 0),
      );
      const findings = bounded.map((leak) => ({
        confidence: CONFIDENCE.OBSERVED_RELATIONSHIP,
        description: `Module \`${label(leak.from)}\` imports \`${leak.leaked.map((path) => `\`${path}\``).join(", ")}\` inside module \`${label(leak.to)}\`, which publishes its interface through ${leak.entries.map((path) => `\`${path}\``).join(", ")}. The import bypasses that entry file. This is a bypass of a boundary the repository establishes, not of a boundary the analyzer assumed.`,
        evidence: leak.evidence,
        metadata: {
          basis: BASES.IMPORT_GRAPH,
          state: STATES.ESTABLISHED,
          fingerprintKey: `leakage:${keyFragment(leak.from)}::${keyFragment(leak.to)}`,
          from: leak.from,
          to: leak.to,
          leakedFiles: leak.leaked,
          entryFiles: leak.entries,
        },
      }));

      return {
        findings,
        evidence: [],
        metadata: {
          basis: BASES.IMPORT_GRAPH,
          state: findings.length > 0 ? STATES.ESTABLISHED : STATES.UNKNOWN,
          graphState: graph.state,
          boundaries: boundaries.size,
          reported: findings.length,
          truncated,
        },
      };
    },
    remediation: {},
    metadata: {
      tags: ["architecture", "boundary-leakage"],
      falsePositives: ["a module that has not adopted a barrel interface yet"],
    },
  }),
]);
