/**
 * Code Guardian — Middleware Rule Registry (Phase 19)
 *
 * The generic Phase 10 registry plus one domain guarantee: the pack's declared rules are
 * actually present. The reasoning is the same as every other pack's — a rule id appears in
 * every fingerprint the rule produces, so a silently renamed or dropped rule retires
 * fingerprints without any remaining test noticing.
 *
 * Rules beyond the declared set are allowed, so a caller can register a fixture or a
 * project-local middleware rule without editing the pack contract.
 */

import { RuleRegistrationError } from "../errors.js";
import { createRuleRegistry } from "../registry.js";

import { MIDDLEWARE_RULE_ID_PREFIX, MIDDLEWARE_RULE_IDS } from "./contracts.js";

/**
 * Collect everything wrong with a proposed middleware rule set.
 *
 * @param {unknown} rules
 * @returns {string[]} Empty when the set satisfies the pack contract.
 */
export function middlewareRuleSetIssues(rules) {
  if (!Array.isArray(rules)) return ["middlewareRules: must be an array of rules"];

  const issues = [];
  const seen = new Set();

  rules.forEach((rule, index) => {
    const id = rule?.id;
    if (typeof id !== "string" || !id.startsWith(MIDDLEWARE_RULE_ID_PREFIX)) {
      issues.push(
        `middlewareRules[${index}].id: must be declared in the "${MIDDLEWARE_RULE_ID_PREFIX}" namespace`,
      );
      return;
    }
    if (seen.has(id)) issues.push(`middlewareRules[${index}].id: "${id}" is declared twice`);
    seen.add(id);
  });

  for (const declared of Object.values(MIDDLEWARE_RULE_IDS)) {
    if (!seen.has(declared)) {
      issues.push(`middlewareRules: the declared rule "${declared}" is missing from the pack`);
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
export function createMiddlewareRuleRegistry({ rules }) {
  const issues = middlewareRuleSetIssues(rules);
  if (issues.length > 0) throw new RuleRegistrationError(issues);
  return createRuleRegistry(rules);
}
