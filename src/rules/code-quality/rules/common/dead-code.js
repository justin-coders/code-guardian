/**
 * Code Guardian — Dead-Code Indicator Rules (Official Roadmap Phase 12)
 *
 * Two rules for the roadmap's "dead code indicators" domain. Both report **indicators** and
 * say so in their own words: the analyzer does not claim code is dead, and this phase builds
 * no reachability engine (that is later static-analysis work).
 *
 *   unused-export   an exported binding with **no established reference** in this
 *                   repository's own sources. A library's public API is consumed outside the
 *                   repository and looks identical here, which is why the finding is an
 *                   indicator and why it cites the symbol graph's coverage.
 *   orphan-module   a module file no established import edge touches in either direction.
 *                   An executable script, a dynamically loaded plugin, or a file whose
 *                   importer could not be parsed all look the same.
 *
 * Both are **graph-gated**: when the graph's own state does not establish edges, the rule
 * abstains with `unknown` rather than reporting every module as an orphan.
 */

import { createRule } from "../../../../core/index.js";

import {
  CODE_QUALITY_BASES,
  CODE_QUALITY_CATEGORY,
  CODE_QUALITY_CONFIDENCE,
  CODE_QUALITY_LIMITS,
  CODE_QUALITY_RULE_IDS,
  CODE_QUALITY_RULE_VERSION,
} from "../../contracts.js";
import { fileEvidenceIds, importGraphEvidence, queryFor, symbolGraphEvidence } from "../../signals.js";

import { capFindings, keyFragment } from "../shared.js";

/** Whether a symbol-graph state establishes that an absent reference is meaningful. */
function symbolGraphMeasurable(evidence) {
  return evidence.established === true;
}

export const deadCodeRules = Object.freeze([
  createRule({
    id: CODE_QUALITY_RULE_IDS.DEAD_CODE_UNUSED_EXPORT,
    version: CODE_QUALITY_RULE_VERSION,
    category: CODE_QUALITY_CATEGORY,
    title: "An exported binding has no established references",
    description:
      "The symbol graph established an exported binding with no reference edge in this repository's own sources. This is a *dead-code indicator*, not a verdict: a public API consumed by another repository, a framework entrypoint invoked by name, or a binding referenced only through a construct this build does not parse all look identical here. The finding cites the module and the exported name so the observation can be checked, and the rule abstains entirely when the graph's own state does not establish references.",
    severity: "low",
    applicability: {},
    detect: (context) => {
      const query = queryFor(context);
      const graph = symbolGraphEvidence(query);

      if (!symbolGraphMeasurable(graph)) {
        return {
          findings: [],
          evidence: [],
          coverage: "unknown",
          reason: `the symbol graph is "${graph.state}", so an export's absent references are not established`,
        };
      }

      const candidates = [...graph.unusedExports]
        .filter((node) => typeof node.path === "string")
        .sort((a, b) =>
          a.path === b.path
            ? String(a.name) < String(b.name)
              ? -1
              : 1
            : a.path < b.path
              ? -1
              : 1,
        );

      const { entries, truncated } = capFindings(candidates, CODE_QUALITY_LIMITS.MAX_STRUCTURAL_FINDINGS);
      const findings = entries.map((node) => ({
        confidence: CODE_QUALITY_CONFIDENCE.STRUCTURAL_INDICATOR,
        evidence: fileEvidenceIds(query, node.path),
        metadata: {
          basis: CODE_QUALITY_BASES.SYMBOL_GRAPH,
          state: "detected",
          fingerprintKey: `unused-export:${keyFragment(node.path)}:${keyFragment(node.name)}`,
          path: node.path,
          name: node.name,
          exportNames: Array.isArray(node.exportNames) ? [...node.exportNames] : [],
        },
      }));

      return {
        findings,
        evidence: [],
        metadata: {
          basis: CODE_QUALITY_BASES.SYMBOL_GRAPH,
          state: findings.length > 0 ? "detected" : "not_applicable",
          graphState: graph.state,
          reported: findings.length,
          truncated,
        },
      };
    },
    remediation: {},
    metadata: {
      tags: ["code-quality", "dead-code"],
      falsePositives: ["a public API consumed outside the repository", "a binding referenced only dynamically"],
    },
  }),

  createRule({
    id: CODE_QUALITY_RULE_IDS.DEAD_CODE_ORPHAN_MODULE,
    version: CODE_QUALITY_RULE_VERSION,
    category: CODE_QUALITY_CATEGORY,
    title: "A module has no established import edges",
    description:
      "The import graph established no import edge touching this module in either direction. This is a *dead-code indicator*, not a verdict: an executable script, a dynamically loaded plugin, a build entry, or a file whose importer could not be parsed all look the same. The rule abstains entirely when the graph's own state does not establish edges, so a partial graph never turns into a list of orphans.",
    severity: "info",
    applicability: {},
    detect: (context) => {
      const query = queryFor(context);
      const graph = importGraphEvidence(query);

      if (!graph.established) {
        return {
          findings: [],
          evidence: [],
          coverage: "unknown",
          reason: `the import graph is "${graph.state}", so a module's absent edges are not established`,
        };
      }

      const candidates = [...graph.orphans]
        .filter((node) => typeof node.path === "string")
        .sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));

      const { entries, truncated } = capFindings(candidates, CODE_QUALITY_LIMITS.MAX_STRUCTURAL_FINDINGS);
      const findings = entries.map((node) => ({
        confidence: CODE_QUALITY_CONFIDENCE.STRUCTURAL_INDICATOR,
        evidence: fileEvidenceIds(query, node.path),
        metadata: {
          basis: CODE_QUALITY_BASES.IMPORT_GRAPH,
          state: "detected",
          fingerprintKey: `orphan-module:${keyFragment(node.path)}`,
          path: node.path,
        },
      }));

      return {
        findings,
        evidence: [],
        metadata: {
          basis: CODE_QUALITY_BASES.IMPORT_GRAPH,
          state: findings.length > 0 ? "detected" : "not_applicable",
          graphState: graph.state,
          limited: graph.limited,
          reported: findings.length,
          truncated,
        },
      };
    },
    remediation: {},
    metadata: {
      tags: ["code-quality", "dead-code"],
      falsePositives: ["an executable script or build entry", "a dynamically loaded plugin"],
    },
  }),
]);
