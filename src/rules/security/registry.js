/**
 * Code Guardian — Security Rule Registry (Phase 12)
 *
 * The generic Phase 10 registry plus one domain guarantee: the pack's declared rules
 * are actually present.
 *
 * A rule id is a long-term identity — it appears in every fingerprint the rule
 * produces — so "the security analyzer silently evaluates seven rules instead of
 * eight because someone renamed one" is a security regression that no test of the
 * remaining rules would catch. `securityRuleSetIssues()` turns that into a
 * registration failure:
 *
 *   - every rule must live in the `security.` namespace, so a copy-pasted rule
 *     cannot quietly join the pack under another domain's id, and
 *   - every id declared in `SECURITY_RULE_IDS` must be registered, so a rename or a
 *     deletion fails loudly instead of shrinking the pack.
 *
 * Rules beyond the declared set are allowed: a caller may add a fixture or a
 * project-local rule without editing the pack contract, which is what makes the pack
 * composable while still unforgiving about its own content.
 */

import { RuleRegistrationError } from "../errors.js";
import { createRuleRegistry } from "../registry.js";

import { SECURITY_RULE_ID_PREFIX, SECURITY_RULE_IDS } from "./contracts.js";

/**
 * Collect everything wrong with a proposed security rule set.
 *
 * @param {unknown} rules
 * @returns {string[]} Empty when the set satisfies the pack contract.
 */
export function securityRuleSetIssues(rules) {
  if (!Array.isArray(rules)) return ["securityRules: must be an array of rules"];

  const issues = [];
  const seen = new Set();

  rules.forEach((rule, index) => {
    const id = rule?.id;
    if (typeof id !== "string" || !id.startsWith(SECURITY_RULE_ID_PREFIX)) {
      issues.push(
        `securityRules[${index}].id: must be declared in the "${SECURITY_RULE_ID_PREFIX}" namespace`,
      );
      return;
    }
    if (seen.has(id)) issues.push(`securityRules[${index}].id: "${id}" is declared twice`);
    seen.add(id);
  });

  for (const declared of Object.values(SECURITY_RULE_IDS)) {
    if (!seen.has(declared)) {
      issues.push(`securityRules: the declared rule "${declared}" is missing from the pack`);
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
export function createSecurityRuleRegistry({ rules }) {
  const issues = securityRuleSetIssues(rules);
  if (issues.length > 0) throw new RuleRegistrationError(issues);
  return createRuleRegistry(rules);
}
