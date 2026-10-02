/**
 * Code Guardian — Unsafe-Pattern Rule (Official Roadmap Phase 12)
 *
 * The roadmap's "unsafe patterns" domain, kept strictly distinct from the Security Analyzer:
 * a secret, an authorization bypass or an exposed endpoint belongs to Official Phase 10, and
 * this rule reports none of them. What it reports is a **code-quality** construct the
 * repository's own bounded read already established — a module source that uses a
 * dynamic-scope construct (`eval`, `with`).
 *
 * The fact comes from the semantic acquisition layer, which marks such a source because
 * dynamic scope voids every uniqueness proof it would otherwise make; the symbol graph exposes
 * it as a per-source problem. Nothing is re-read here, and the rule abstains when the graph's
 * own state does not establish the sources.
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

/** The bounded problem id the semantics acquisition records for `eval` / `with`. */
const DYNAMIC_SCOPE_PROBLEM = "dynamic-scope-construct";

export const unsafePatternRules = Object.freeze([
  createRule({
    id: CODE_QUALITY_RULE_IDS.UNSAFE_PATTERN_DYNAMIC_SCOPE,
    version: CODE_QUALITY_RULE_VERSION,
    category: CODE_QUALITY_CATEGORY,
    title: "A module source uses a dynamic-scope construct",
    description:
      "A bounded read of a module source observed `eval(...)` or a `with (...)` statement. This is a code-quality unsafe pattern — dynamic scope defeats static reasoning about the module's bindings — and it is deliberately not a security finding: no secret, authorization or exposure is claimed. The finding names the module the acquisition layer recorded it for, and the rule abstains when the semantic graph's own state does not establish the sources.",
    severity: "low",
    applicability: {},
    detect: (context) => {
      const query = queryFor(context);
      const graph = symbolGraphEvidence(query);

      if (!graph.established) {
        return {
          findings: [],
          evidence: [],
          coverage: "unknown",
          reason: `the symbol graph is "${graph.state}", so a module's dynamic-scope constructs are not established`,
        };
      }

      const candidates = [...graph.dynamicScopeSources].sort((a, b) =>
        String(a.path) < String(b.path) ? -1 : String(a.path) > String(b.path) ? 1 : 0,
      );

      const { entries, truncated } = capFindings(candidates, CODE_QUALITY_LIMITS.MAX_STRUCTURAL_FINDINGS);
      const findings = [];
      for (const source of entries) {
        const evidence =
          typeof source.evidenceId === "string" && source.evidenceId !== ""
            ? [source.evidenceId]
            : fileEvidenceIds(query, source.path);
        findings.push({
          confidence: CODE_QUALITY_CONFIDENCE.OBSERVED_CONTENT,
          evidence,
          metadata: {
            basis: CODE_QUALITY_BASES.SYMBOL_GRAPH,
            state: "detected",
            fingerprintKey: `dynamic-scope:${keyFragment(source.path)}`,
            path: source.path,
            problem: DYNAMIC_SCOPE_PROBLEM,
          },
        });
      }

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
      tags: ["code-quality", "unsafe-pattern"],
      falsePositives: ["a source whose only `eval` occurrence is inside a string or a comment the bounded read matched"],
    },
  }),
]);
