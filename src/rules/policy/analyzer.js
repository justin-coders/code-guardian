/**
 * Code Guardian — Policy Preset Analyzer (Phase 23)
 *
 * The preset domain's entry point into the accepted analyzer framework: build the pack's registry,
 * hand it to the Phase 10 `RuleAnalyzer` adapter, expose the result. Nothing here re-implements
 * orchestration, applicability, evidence validation or fingerprinting, and the descriptor is an
 * ordinary Analyzer, so it works with `createAnalyzerRegistry` alongside every other pack's
 * analyzer without a special case.
 *
 * `failFast` defaults to `false`, uniformly with every other pack.
 */

import { createRuleAnalyzer } from "../analyzer.js";

import {
  POLICY_ANALYZER_ID,
  POLICY_ANALYZER_NAME,
  POLICY_ANALYZER_SCOPE,
  POLICY_RULE_PACK_VERSION,
} from "./contracts.js";
import { createPolicyRuleRegistry } from "./registry.js";
import { policyRules } from "./rules/index.js";

/**
 * Build the Policy Preset Audit Analyzer.
 *
 * @param {object} [options]
 * @param {object[]} [options.rules] The rules to evaluate (defaults to the shipped pack).
 * @param {boolean} [options.failFast] Stop at the first rule failure (opt-in).
 * @returns {object} An Analyzer descriptor for `createAnalyzerRegistry`.
 * @throws {RuleRegistrationError} When the rule set violates the pack contract.
 */
export function createPolicyAnalyzer({ rules = policyRules, failFast = false } = {}) {
  return createRuleAnalyzer({
    id: POLICY_ANALYZER_ID,
    name: POLICY_ANALYZER_NAME,
    version: POLICY_RULE_PACK_VERSION,
    scope: POLICY_ANALYZER_SCOPE,
    rules: createPolicyRuleRegistry({ rules }),
    failFast,
  });
}
