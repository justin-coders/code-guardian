/**
 * Code Guardian — Complexity Indicator Rule (Official Roadmap Phase 12)
 *
 * The roadmap's "complexity" domain, implemented **within what the model can actually
 * measure**. This build has no AST, no control-flow graph and no line count: building one
 * would be the later "advanced static analysis" phase, not this one. What the symbol graph
 * does establish is how many module-scope declarations a module contains, and a module with a
 * very large number of them is a **module-size** indicator the repository can check.
 *
 * The rule says so explicitly. It never calls this "cyclomatic complexity", never attaches a
 * number to a function, and abstains (`unknown`) whenever the graph's own state does not
 * establish the counts.
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
import { fileEvidenceIds, queryFor, symbolGraphEvidence } from "../../signals.js";

import { capFindings, keyFragment } from "../shared.js";

export const complexityRules = Object.freeze([
  createRule({
    id: CODE_QUALITY_RULE_IDS.COMPLEXITY_LARGE_MODULE,
    version: CODE_QUALITY_RULE_VERSION,
    category: CODE_QUALITY_CATEGORY,
    title: "A module declares an unusually large number of bindings",
    description:
      "The symbol graph established a module whose module-scope declaration count reaches the analyzer's large-module threshold. This is a **module-size** indicator, not a cyclomatic-complexity measurement: this build has no AST or control-flow metric, and a module with many small functions is not the same as one deeply branching function. The finding states the declaration count it observed and the threshold it crossed, so the observation can be checked, and the rule abstains entirely when the graph's own state does not establish the counts.",
    severity: "info",
    applicability: {},
    detect: (context) => {
      const query = queryFor(context);
      const graph = symbolGraphEvidence(query);

      if (!graph.established) {
        return {
          findings: [],
          evidence: [],
          coverage: "unknown",
          reason: `the symbol graph is "${graph.state}", so module-scope declaration counts are not established`,
        };
      }

      const threshold = CODE_QUALITY_LIMITS.LARGE_MODULE_SYMBOLS;
      const candidates = [...graph.moduleSymbolCounts.entries()]
        .filter(([, count]) => count >= threshold)
        .map(([path, count]) => ({ path, count }))
        .sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));

      const { entries, truncated } = capFindings(candidates, CODE_QUALITY_LIMITS.MAX_STRUCTURAL_FINDINGS);
      const findings = entries.map((entry) => ({
        confidence: CODE_QUALITY_CONFIDENCE.STRUCTURAL_INDICATOR,
        evidence: fileEvidenceIds(query, entry.path),
        metadata: {
          basis: CODE_QUALITY_BASES.SYMBOL_GRAPH,
          state: "detected",
          fingerprintKey: `large-module:${keyFragment(entry.path)}`,
          path: entry.path,
          declarations: entry.count,
          threshold,
          measure: "module-scope-declarations",
        },
      }));

      return {
        findings,
        evidence: [],
        metadata: {
          basis: CODE_QUALITY_BASES.SYMBOL_GRAPH,
          state: findings.length > 0 ? "detected" : "not_applicable",
          graphState: graph.state,
          threshold,
          measuredModules: graph.moduleSymbolCounts.size,
          reported: findings.length,
          truncated,
        },
      };
    },
    remediation: {},
    metadata: {
      tags: ["code-quality", "complexity"],
      falsePositives: ["a large but simple module (a manifest of constants, a generated table)"],
    },
  }),
]);
