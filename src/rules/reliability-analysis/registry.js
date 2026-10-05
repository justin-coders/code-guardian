/**
 * Code Guardian — Reliability Analysis Rule Registry (Official Roadmap Phase 17)
 *
 * The generic registry plus one domain guarantee: the pack's declared rules are present. A rule id
 * is a long-term identity — it appears in every fingerprint the rule produces — so a renamed or
 * dropped rule would silently retire fingerprints with no failing test of the remaining rules, and
 * a pack that quietly stopped covering one of the ten official domains would look identical to one
 * that covered them all.
 *
 * The namespace is `reliability.`, owned entirely by this pack.
 */

import { RuleRegistrationError } from "../errors.js";
import { createRuleRegistry } from "../registry.js";

import {
  RELIABILITY_ANALYSIS_RULE_ID_PREFIX,
  RELIABILITY_ANALYSIS_RULE_IDS,
} from "./contracts.js";

/** Collect everything wrong with a proposed reliability-analysis rule set. */
export function reliabilityAnalysisRuleSetIssues(rules) {
  if (!Array.isArray(rules)) return ["reliabilityAnalysisRules: must be an array of rules"];

  const issues = [];
  const seen = new Set();

  rules.forEach((rule, index) => {
    const id = rule?.id;
    if (typeof id !== "string" || !id.startsWith(RELIABILITY_ANALYSIS_RULE_ID_PREFIX)) {
      issues.push(
        `reliabilityAnalysisRules[${index}].id: must be declared in the "${RELIABILITY_ANALYSIS_RULE_ID_PREFIX}" namespace`,
      );
      return;
    }
    if (seen.has(id)) issues.push(`reliabilityAnalysisRules[${index}].id: "${id}" is declared twice`);
    seen.add(id);
  });

  for (const declared of Object.values(RELIABILITY_ANALYSIS_RULE_IDS)) {
    if (!seen.has(declared)) {
      issues.push(`reliabilityAnalysisRules: the declared rule "${declared}" is missing from the pack`);
    }
  }

  return issues;
}

/** Build the pack's registry. */
export function createReliabilityAnalysisRuleRegistry({ rules }) {
  const issues = reliabilityAnalysisRuleSetIssues(rules);
  if (issues.length > 0) throw new RuleRegistrationError(issues);
  return createRuleRegistry(rules);
}
