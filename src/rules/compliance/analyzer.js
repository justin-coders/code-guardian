/**
 * Code Guardian — Compliance Analyzer (Phase 22)
 *
 * The policy domain's entry point into the accepted analyzer framework: build the pack's registry,
 * hand it to the Phase 10 `RuleAnalyzer` adapter, expose the result. Nothing here re-implements
 * orchestration, applicability, evidence validation or fingerprinting, and the descriptor is an
 * ordinary Analyzer, so it works with `createAnalyzerRegistry` alongside every other pack's
 * analyzer without a special case.
 *
 * `failFast` defaults to `false`: one domain rule that throws or returns malformed output must not
 * stop the other five from reporting.
 */

import { createRuleAnalyzer } from "../analyzer.js";

import {
  COMPLIANCE_ANALYZER_ID,
  COMPLIANCE_ANALYZER_NAME,
  COMPLIANCE_ANALYZER_SCOPE,
  COMPLIANCE_RULE_PACK_VERSION,
} from "./contracts.js";
import { createComplianceRuleRegistry } from "./registry.js";
import { complianceRules } from "./rules/index.js";

/**
 * Build the Compliance Analyzer.
 *
 * @param {object} [options]
 * @param {object[]} [options.rules] The rules to evaluate (defaults to the shipped pack).
 * @param {boolean} [options.failFast] Stop at the first rule failure (opt-in).
 * @returns {object} An Analyzer descriptor for `createAnalyzerRegistry`.
 * @throws {RuleRegistrationError} When the rule set violates the pack contract.
 */
export function createComplianceAnalyzer({ rules = complianceRules, failFast = false } = {}) {
  return createRuleAnalyzer({
    id: COMPLIANCE_ANALYZER_ID,
    name: COMPLIANCE_ANALYZER_NAME,
    version: COMPLIANCE_RULE_PACK_VERSION,
    scope: COMPLIANCE_ANALYZER_SCOPE,
    rules: createComplianceRuleRegistry({ rules }),
    failFast,
  });
}
