/**
 * Code Guardian — Testing Rule Registry (Official Roadmap Phase 11)
 *
 * The generic Phase 10 registry plus one domain guarantee: the pack's declared rules
 * are actually present.
 *
 * A rule id is a long-term identity — it appears in every fingerprint the rule
 * produces — so a renamed or dropped rule would silently shrink the pack with no
 * failing test of the *remaining* rules. `testingRuleSetIssues()` turns that into a
 * registration failure:
 *
 *   - every rule must live in the `testing.` namespace, and
 *   - every id declared in `TESTING_RULE_IDS` must be registered.
 *
 * Rules beyond the declared set are allowed, so a caller can add a fixture rule
 * without editing the pack contract.
 */

import { RuleRegistrationError } from "../errors.js";
import { createRuleRegistry } from "../registry.js";

import { TESTING_RULE_ID_PREFIX, TESTING_RULE_IDS } from "./contracts.js";

/**
 * Collect everything wrong with a proposed testing rule set.
 *
 * @param {unknown} rules
 * @returns {string[]} Empty when the set satisfies the pack contract.
 */
export function testingRuleSetIssues(rules) {
  if (!Array.isArray(rules)) return ["testingRules: must be an array of rules"];

  const issues = [];
  const seen = new Set();

  rules.forEach((rule, index) => {
    const id = rule?.id;
    if (typeof id !== "string" || !id.startsWith(TESTING_RULE_ID_PREFIX)) {
      issues.push(
        `testingRules[${index}].id: must be declared in the "${TESTING_RULE_ID_PREFIX}" namespace`,
      );
      return;
    }
    if (seen.has(id)) issues.push(`testingRules[${index}].id: "${id}" is declared twice`);
    seen.add(id);
  });

  for (const declared of Object.values(TESTING_RULE_IDS)) {
    if (!seen.has(declared)) {
      issues.push(`testingRules: the declared rule "${declared}" is missing from the pack`);
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
 * @throws {RuleRegistrationError} When the set violates the pack contract.
 */
export function createTestingRuleRegistry({ rules }) {
  const issues = testingRuleSetIssues(rules);
  if (issues.length > 0) throw new RuleRegistrationError(issues);
  return createRuleRegistry(rules);
}
