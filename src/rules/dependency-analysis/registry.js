/**
 * Code Guardian — Dependency Analysis Rule Registry (Official Roadmap Phase 15)
 *
 * The generic registry plus one domain guarantee: the pack's declared rules are present. A rule
 * id is a long-term identity — it appears in every fingerprint the rule produces — so a renamed
 * or dropped rule would silently shrink the pack with no failing test of the remaining rules.
 *
 * The namespace is `dependency.`, shared with the existing inventory rules (`dependency.inventory
 * .declarations`, `dependency.graph.inventory`), which stay in their own pack and registry.
 */

import { RuleRegistrationError } from "../errors.js";
import { createRuleRegistry } from "../registry.js";

import {
  DEPENDENCY_ANALYSIS_RULE_ID_PREFIX,
  DEPENDENCY_ANALYSIS_RULE_IDS,
} from "./contracts.js";

/** Collect everything wrong with a proposed dependency-analysis rule set. */
export function dependencyAnalysisRuleSetIssues(rules) {
  if (!Array.isArray(rules)) return ["dependencyAnalysisRules: must be an array of rules"];

  const issues = [];
  const seen = new Set();

  rules.forEach((rule, index) => {
    const id = rule?.id;
    if (typeof id !== "string" || !id.startsWith(DEPENDENCY_ANALYSIS_RULE_ID_PREFIX)) {
      issues.push(
        `dependencyAnalysisRules[${index}].id: must be declared in the "${DEPENDENCY_ANALYSIS_RULE_ID_PREFIX}" namespace`,
      );
      return;
    }
    if (seen.has(id)) issues.push(`dependencyAnalysisRules[${index}].id: "${id}" is declared twice`);
    seen.add(id);
  });

  for (const declared of Object.values(DEPENDENCY_ANALYSIS_RULE_IDS)) {
    if (!seen.has(declared)) {
      issues.push(`dependencyAnalysisRules: the declared rule "${declared}" is missing from the pack`);
    }
  }

  return issues;
}

/** Build the pack's registry. */
export function createDependencyAnalysisRuleRegistry({ rules }) {
  const issues = dependencyAnalysisRuleSetIssues(rules);
  if (issues.length > 0) throw new RuleRegistrationError(issues);
  return createRuleRegistry(rules);
}
