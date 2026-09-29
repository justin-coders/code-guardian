/**
 * Code Guardian — Compliance Rule Registry (Phase 22)
 *
 * The generic Phase 10 registry plus one domain guarantee: the pack's declared rules are actually
 * present. The reasoning is the same as every other pack's — a rule id appears in every fingerprint
 * the rule produces, so a silently renamed or dropped rule retires fingerprints without any
 * remaining test noticing. Here the guarantee covers six ids, one per policy domain, so a missing
 * domain fails loudly instead of quietly reducing compliance to five domains.
 *
 * Rules beyond the declared set are allowed, so a caller can register a fixture or a
 * project-local compliance rule without editing the pack contract.
 */

import { RuleRegistrationError } from "../errors.js";
import { createRuleRegistry } from "../registry.js";

import { COMPLIANCE_RULE_ID_PREFIX, COMPLIANCE_RULE_IDS } from "./contracts.js";

/**
 * Collect everything wrong with a proposed compliance rule set.
 *
 * @param {unknown} rules
 * @returns {string[]} Empty when the set satisfies the pack contract.
 */
export function complianceRuleSetIssues(rules) {
  if (!Array.isArray(rules)) return ["complianceRules: must be an array of rules"];

  const issues = [];
  const seen = new Set();

  rules.forEach((rule, index) => {
    const id = rule?.id;
    if (typeof id !== "string" || !id.startsWith(COMPLIANCE_RULE_ID_PREFIX)) {
      issues.push(
        `complianceRules[${index}].id: must be declared in the "${COMPLIANCE_RULE_ID_PREFIX}" namespace`,
      );
      return;
    }
    if (seen.has(id)) issues.push(`complianceRules[${index}].id: "${id}" is declared twice`);
    seen.add(id);
  });

  for (const declared of Object.values(COMPLIANCE_RULE_IDS)) {
    if (!seen.has(declared)) {
      issues.push(`complianceRules: the declared rule "${declared}" is missing from the pack`);
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
 * @throws {RuleRegistrationError} When the set violates the pack contract, or a rule descriptor
 *   violates the Core/framework contract.
 */
export function createComplianceRuleRegistry({ rules }) {
  const issues = complianceRuleSetIssues(rules);
  if (issues.length > 0) throw new RuleRegistrationError(issues);
  return createRuleRegistry(rules);
}
