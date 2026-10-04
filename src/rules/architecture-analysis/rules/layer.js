/**
 * Code Guardian — Architecture Layer Rule (Official Roadmap Phase 14)
 *
 * The "layer violations" domain, implemented against the only layer model this build can
 * honestly test: a **repository-declared** direction between its own local packages.
 *
 * The roadmap is explicit that the analyzer "should not impose one universal architecture on
 * every repository". So there is no presentation/application/domain/infrastructure stack here.
 * Instead, a layer model exists only when the repository *declares* one: a manifest stating a
 * `workspace:`/`file:`/`link:` dependency on a package the repository itself defines is a
 * declared direction `A → B`. A violation is then a measured import edge that goes the other
 * way — `B` imports `A` — which is evidence, not an opinion.
 *
 * When the repository declares no local-package direction, there is no model to test and the
 * rule answers `unknown`. It never invents a violation to have something to report.
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
import { buildModuleGraph, declaredLocalDirections, isUnder, queryFor } from "../signals.js";

import { capFindings, keyFragment, unknownDetection } from "./shared.js";

const CATEGORY = ARCHITECTURE_ANALYSIS_CATEGORY;
const VERSION = ARCHITECTURE_ANALYSIS_RULE_VERSION;
const IDS = ARCHITECTURE_ANALYSIS_RULE_IDS;
const BASES = ARCHITECTURE_ANALYSIS_BASES;
const STATES = ARCHITECTURE_ANALYSIS_STATES;
const CONFIDENCE = ARCHITECTURE_ANALYSIS_CONFIDENCE;

const label = (path) => (path === "" ? "(repository root)" : path);

export const architectureLayerRules = Object.freeze([
  createRule({
    id: IDS.LAYER_VIOLATION,
    version: VERSION,
    category: CATEGORY,
    title: "A dependency goes against a direction the repository declares",
    description:
      "The repository declares a local-package dependency direction (a manifest stating a workspace, file or link dependency on a package the repository itself defines). This finding reports an established import edge that goes the reverse way: the depended-on module imports the module that declares the dependency. It is a violation of the repository's own declared direction, never of a universal architecture, and it is reported only where such a direction exists.",
    severity: "medium",
    applicability: {},
    detect: (context) => {
      const query = queryFor(context);
      const graph = buildModuleGraph(query);

      if (!graph.established) {
        return unknownDetection(
          `the import graph is "${graph.state}", so a declared direction cannot be tested`,
        );
      }

      const directions = declaredLocalDirections(query);
      if (directions.length === 0) {
        return unknownDetection(
          "the repository declares no local-package dependency direction, so no layer model is established",
        );
      }

      const violations = [];
      for (const edge of graph.edges) {
        for (const direction of directions) {
          const forward = isUnder(edge.from, direction.from) && isUnder(edge.to, direction.to);
          const reverse = isUnder(edge.from, direction.to) && isUnder(edge.to, direction.from);
          if (!reverse || forward) continue;
          violations.push({
            edge,
            reverse: direction,
            evidence: [...new Set([...(edge.evidenceIds ?? []), ...(direction.evidenceIds ?? [])])].sort(),
          });
          break;
        }
      }

      if (violations.length === 0) {
        return {
          findings: [],
          evidence: [],
          metadata: {
            basis: BASES.DECLARED_DEPENDENCY,
            state: STATES.ESTABLISHED,
            graphState: graph.state,
            declaredDirections: directions.length,
            violations: 0,
          },
        };
      }

      violations.sort((a, b) =>
        a.edge.from === b.edge.from
          ? a.edge.to < b.edge.to
            ? -1
            : 1
          : a.edge.from < b.edge.from
            ? -1
            : 1,
      );

      const { entries, truncated } = capFindings(
        violations.filter((entry) => entry.evidence.length > 0),
      );
      const findings = entries.map((entry) => ({
        confidence: CONFIDENCE.OBSERVED_RELATIONSHIP,
        description: `Module \`${label(entry.edge.from)}\` imports module \`${label(entry.edge.to)}\`, but the package \`${label(entry.reverse.from)}\` declares a \`${entry.reverse.specKind}\` dependency on \`${entry.reverse.dependencyName}\` (package \`${label(entry.reverse.to)}\`) — that is, the repository declares \`${label(entry.reverse.from)}\` depends on \`${label(entry.reverse.to)}\`, while the import runs the other way. This is a violation of the direction the repository itself declares, not of a universal architecture.`,
        evidence: entry.evidence,
        metadata: {
          basis: BASES.DECLARED_DEPENDENCY,
          state: STATES.ESTABLISHED,
          fingerprintKey: `layer:${keyFragment(entry.edge.from)}::${keyFragment(entry.edge.to)}`,
          from: entry.edge.from,
          to: entry.edge.to,
          dependencyName: entry.reverse.dependencyName,
          specKind: entry.reverse.specKind,
          importEdges: entry.edge.count,
        },
      }));

      return {
        findings,
        evidence: [],
        metadata: {
          basis: BASES.DECLARED_DEPENDENCY,
          state: findings.length > 0 ? STATES.ESTABLISHED : STATES.UNKNOWN,
          graphState: graph.state,
          declaredDirections: directions.length,
          violations: violations.length,
          reported: findings.length,
          truncated,
        },
      };
    },
    remediation: {},
    metadata: {
      tags: ["architecture", "layer-violation"],
      falsePositives: [],
    },
  }),
]);
