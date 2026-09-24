/**
 * Code Guardian — Import Rule Registry (Phase 16)
 *
 * The generic Phase 10 registry plus one domain guarantee: the pack's declared rules
 * are actually present. The reasoning is the same as the security, dependency and
 * architecture packs' — a rule id appears in every fingerprint the rule produces, so
 * a silently renamed or dropped rule retires fingerprints without any remaining test
 * noticing.
 *
 * Rules beyond the declared set are allowed, so a caller can register a fixture or a
 * project-local import rule without editing the pack contract.
 */

import { RuleRegistrationError } from "../errors.js";
import { createRuleRegistry } from "../registry.js";

import { IMPORT_RULE_ID_PREFIX, IMPORT_RULE_IDS } from "./contracts.js";

/**
 * Collect everything wrong with a proposed import rule set.
 *
 * @param {unknown} rules
 * @returns {string[]} Empty when the set satisfies the pack contract.
 */
export function importRuleSetIssues(rules) {
  if (!Array.isArray(rules)) return ["importRules: must be an array of rules"];

  const issues = [];
  const seen = new Set();

  rules.forEach((rule, index) => {
    const id = rule?.id;
    if (typeof id !== "string" || !id.startsWith(IMPORT_RULE_ID_PREFIX)) {
      issues.push(
        `importRules[${index}].id: must be declared in the "${IMPORT_RULE_ID_PREFIX}" namespace`,
      );
      return;
    }
    if (seen.has(id)) issues.push(`importRules[${index}].id: "${id}" is declared twice`);
    seen.add(id);
  });

  for (const declared of Object.values(IMPORT_RULE_IDS)) {
    if (!seen.has(declared)) {
      issues.push(`importRules: the declared rule "${declared}" is missing from the pack`);
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
export function createImportRuleRegistry({ rules }) {
  const issues = importRuleSetIssues(rules);
  if (issues.length > 0) throw new RuleRegistrationError(issues);
  return createRuleRegistry(rules);
}
