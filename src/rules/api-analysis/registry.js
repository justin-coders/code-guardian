/**
 * Code Guardian — API Analysis Rule Registry (Official Roadmap Phase 16)
 *
 * The generic registry plus one domain guarantee: the pack's declared rules are present. A rule
 * id is a long-term identity — it appears in every fingerprint the rule produces — so a renamed
 * or dropped rule would silently retire fingerprints with no failing test of the remaining
 * rules, and a pack that quietly stopped covering one of the thirteen official domains would
 * look identical to one that covered them all.
 *
 * The namespace is `api.`, shared with the existing API substrate rule (`api.graph.inventory`),
 * which stays in its own pack and registry.
 */

import { RuleRegistrationError } from "../errors.js";
import { createRuleRegistry } from "../registry.js";

import { API_ANALYSIS_RULE_ID_PREFIX, API_ANALYSIS_RULE_IDS } from "./contracts.js";

/** Collect everything wrong with a proposed api-analysis rule set. */
export function apiAnalysisRuleSetIssues(rules) {
  if (!Array.isArray(rules)) return ["apiAnalysisRules: must be an array of rules"];

  const issues = [];
  const seen = new Set();

  rules.forEach((rule, index) => {
    const id = rule?.id;
    if (typeof id !== "string" || !id.startsWith(API_ANALYSIS_RULE_ID_PREFIX)) {
      issues.push(
        `apiAnalysisRules[${index}].id: must be declared in the "${API_ANALYSIS_RULE_ID_PREFIX}" namespace`,
      );
      return;
    }
    if (seen.has(id)) issues.push(`apiAnalysisRules[${index}].id: "${id}" is declared twice`);
    seen.add(id);
  });

  for (const declared of Object.values(API_ANALYSIS_RULE_IDS)) {
    if (!seen.has(declared)) {
      issues.push(`apiAnalysisRules: the declared rule "${declared}" is missing from the pack`);
    }
  }

  return issues;
}

/** Build the pack's registry. */
export function createApiAnalysisRuleRegistry({ rules }) {
  const issues = apiAnalysisRuleSetIssues(rules);
  if (issues.length > 0) throw new RuleRegistrationError(issues);
  return createRuleRegistry(rules);
}
