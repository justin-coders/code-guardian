/**
 * Code Guardian — Symbol Rule Registry (Phase 17)
 *
 * The generic Phase 10 registry plus one domain guarantee: the pack's declared rules
 * are actually present. The reasoning is the same as the security, dependency,
 * architecture and import packs' — a rule id appears in every fingerprint the rule
 * produces, so a silently renamed or dropped rule retires fingerprints without any
 * remaining test noticing.
 *
 * Rules beyond the declared set are allowed, so a caller can register a fixture or a
 * project-local symbol rule without editing the pack contract.
 */

import { RuleRegistrationError } from "../errors.js";
import { createRuleRegistry } from "../registry.js";

import { SYMBOL_RULE_ID_PREFIX, SYMBOL_RULE_IDS } from "./contracts.js";

/**
 * Collect everything wrong with a proposed symbol rule set.
 *
 * @param {unknown} rules
 * @returns {string[]} Empty when the set satisfies the pack contract.
 */
export function symbolRuleSetIssues(rules) {
  if (!Array.isArray(rules)) return ["symbolRules: must be an array of rules"];

  const issues = [];
  const seen = new Set();

  rules.forEach((rule, index) => {
    const id = rule?.id;
    if (typeof id !== "string" || !id.startsWith(SYMBOL_RULE_ID_PREFIX)) {
      issues.push(
        `symbolRules[${index}].id: must be declared in the "${SYMBOL_RULE_ID_PREFIX}" namespace`,
      );
      return;
    }
    if (seen.has(id)) issues.push(`symbolRules[${index}].id: "${id}" is declared twice`);
    seen.add(id);
  });

  for (const declared of Object.values(SYMBOL_RULE_IDS)) {
    if (!seen.has(declared)) {
      issues.push(`symbolRules: the declared rule "${declared}" is missing from the pack`);
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
export function createSymbolRuleRegistry({ rules }) {
  const issues = symbolRuleSetIssues(rules);
  if (issues.length > 0) throw new RuleRegistrationError(issues);
  return createRuleRegistry(rules);
}
