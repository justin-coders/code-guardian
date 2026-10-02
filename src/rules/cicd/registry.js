/**
 * Code Guardian — CI/CD Rule Registry (Official Roadmap Phase 13)
 *
 * The generic registry plus one domain guarantee: the pack's declared rules are actually
 * present. A rule id is a long-term identity — it appears in every fingerprint the rule produces
 * and maps to exactly one roadmap domain — so a renamed or dropped rule would silently shrink
 * the pack with no failing test of the *remaining* rules.
 *
 * `cicdRuleSetIssues()` turns that into a registration failure:
 *
 *   - every rule must live in the `cicd.` namespace,
 *   - every id declared in `CICD_RULE_IDS` must be registered, and
 *   - every registered rule must map to a declared roadmap domain.
 *
 * Rules beyond the declared set are allowed, so a caller can add a fixture rule without editing
 * the pack contract.
 */

import { RuleRegistrationError } from "../errors.js";
import { createRuleRegistry } from "../registry.js";

import { CICD_DOMAIN_IDS, CICD_RULE_DOMAINS, CICD_RULE_ID_PREFIX, CICD_RULE_IDS } from "./contracts.js";

/**
 * Collect everything wrong with a proposed CI/CD rule set.
 *
 * @param {unknown} rules
 * @returns {string[]} Empty when the set satisfies the pack contract.
 */
export function cicdRuleSetIssues(rules) {
  if (!Array.isArray(rules)) return ["cicdRules: must be an array of rules"];

  const issues = [];
  const seen = new Set();

  rules.forEach((rule, index) => {
    const id = rule?.id;
    if (typeof id !== "string" || !id.startsWith(CICD_RULE_ID_PREFIX)) {
      issues.push(`cicdRules[${index}].id: must be declared in the "${CICD_RULE_ID_PREFIX}" namespace`);
      return;
    }
    if (seen.has(id)) issues.push(`cicdRules[${index}].id: "${id}" is declared twice`);
    seen.add(id);

    // A rule that reports a roadmap domain must report a *declared* one.
    const domain = CICD_RULE_DOMAINS[id];
    if (domain !== undefined && !CICD_DOMAIN_IDS.includes(domain)) {
      issues.push(`cicdRules[${index}].id: "${id}" maps to the undeclared domain "${domain}"`);
    }
  });

  for (const declared of Object.values(CICD_RULE_IDS)) {
    if (!seen.has(declared)) {
      issues.push(`cicdRules: the declared rule "${declared}" is missing from the pack`);
    }
  }

  return issues;
}

/**
 * Build the pack's registry.
 *
 * @param {object} [input]
 * @param {object[]} [input.rules] Rules to register.
 * @returns {object} A frozen registry handle.
 * @throws {RuleRegistrationError} When the set violates the pack contract.
 */
export function createCicdRuleRegistry({ rules }) {
  const issues = cicdRuleSetIssues(rules);
  if (issues.length > 0) throw new RuleRegistrationError(issues);
  return createRuleRegistry(rules);
}
