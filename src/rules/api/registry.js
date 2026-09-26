/**
 * Code Guardian — API Rule Registry (Phase 18)
 *
 * The generic Phase 10 registry plus one domain guarantee: the pack's declared rules are
 * actually present. The reasoning is the same as every other pack's — a rule id appears in
 * every fingerprint the rule produces, so a silently renamed or dropped rule retires
 * fingerprints without any remaining test noticing.
 *
 * Rules beyond the declared set are allowed, so a caller can register a fixture or a
 * project-local API rule without editing the pack contract.
 */

import { RuleRegistrationError } from "../errors.js";
import { createRuleRegistry } from "../registry.js";

import { API_RULE_ID_PREFIX, API_RULE_IDS } from "./contracts.js";

/**
 * Collect everything wrong with a proposed API rule set.
 *
 * @param {unknown} rules
 * @returns {string[]} Empty when the set satisfies the pack contract.
 */
export function apiRuleSetIssues(rules) {
  if (!Array.isArray(rules)) return ["apiRules: must be an array of rules"];

  const issues = [];
  const seen = new Set();

  rules.forEach((rule, index) => {
    const id = rule?.id;
    if (typeof id !== "string" || !id.startsWith(API_RULE_ID_PREFIX)) {
      issues.push(`apiRules[${index}].id: must be declared in the "${API_RULE_ID_PREFIX}" namespace`);
      return;
    }
    if (seen.has(id)) issues.push(`apiRules[${index}].id: "${id}" is declared twice`);
    seen.add(id);
  });

  for (const declared of Object.values(API_RULE_IDS)) {
    if (!seen.has(declared)) {
      issues.push(`apiRules: the declared rule "${declared}" is missing from the pack`);
    }
  }

  return issues;
}

/**
 * Build the pack's registry.
 *
 * @param {object} [input]
 * @param {object[]} [input.rules] Rules to register.
 * @returns {object} A frozen Phase 10 registry handle.
 * @throws {RuleRegistrationError} When the set violates the pack contract, or a rule
 *   descriptor violates the Core/framework contract.
 */
export function createApiRuleRegistry({ rules }) {
  const issues = apiRuleSetIssues(rules);
  if (issues.length > 0) throw new RuleRegistrationError(issues);
  return createRuleRegistry(rules);
}
