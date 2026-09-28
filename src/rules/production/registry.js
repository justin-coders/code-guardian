/**
 * Code Guardian — Production Rule Registry (Phase 20)
 *
 * The generic Phase 10 registry plus one domain guarantee: the pack's declared rules are
 * actually present. The reasoning is the same as every other pack's — a rule id appears in
 * every fingerprint the rule produces, so a silently renamed or dropped rule retires
 * fingerprints without any remaining test noticing. Here the guarantee covers six ids, one
 * per audit domain, so a missing domain fails loudly instead of quietly reducing the report
 * to five inventories.
 *
 * Rules beyond the declared set are allowed, so a caller can register a fixture or a
 * project-local production rule without editing the pack contract.
 */

import { RuleRegistrationError } from "../errors.js";
import { createRuleRegistry } from "../registry.js";

import { PRODUCTION_RULE_ID_PREFIX, PRODUCTION_RULE_IDS } from "./contracts.js";

/**
 * Collect everything wrong with a proposed production rule set.
 *
 * @param {unknown} rules
 * @returns {string[]} Empty when the set satisfies the pack contract.
 */
export function productionRuleSetIssues(rules) {
  if (!Array.isArray(rules)) return ["productionRules: must be an array of rules"];

  const issues = [];
  const seen = new Set();

  rules.forEach((rule, index) => {
    const id = rule?.id;
    if (typeof id !== "string" || !id.startsWith(PRODUCTION_RULE_ID_PREFIX)) {
      issues.push(
        `productionRules[${index}].id: must be declared in the "${PRODUCTION_RULE_ID_PREFIX}" namespace`,
      );
      return;
    }
    if (seen.has(id)) issues.push(`productionRules[${index}].id: "${id}" is declared twice`);
    seen.add(id);
  });

  for (const declared of Object.values(PRODUCTION_RULE_IDS)) {
    if (!seen.has(declared)) {
      issues.push(`productionRules: the declared rule "${declared}" is missing from the pack`);
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
export function createProductionRuleRegistry({ rules }) {
  const issues = productionRuleSetIssues(rules);
  if (issues.length > 0) throw new RuleRegistrationError(issues);
  return createRuleRegistry(rules);
}
