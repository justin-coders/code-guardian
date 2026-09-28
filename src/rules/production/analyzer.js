/**
 * Code Guardian — Production Analyzer (Phase 20)
 *
 * The production domain's entry point into the accepted analyzer framework: build the pack's
 * registry, hand it to the Phase 10 `RuleAnalyzer` adapter, expose the result. Nothing here
 * re-implements orchestration, applicability, evidence validation or fingerprinting, and the
 * descriptor is an ordinary Analyzer, so it works with `createAnalyzerRegistry` alongside
 * every other pack's analyzer without a special case.
 *
 * `failFast` defaults to `false`: one domain rule that throws or returns malformed output
 * must not stop the other five from reporting.
 */

import { createRuleAnalyzer } from "../analyzer.js";

import {
  PRODUCTION_ANALYZER_ID,
  PRODUCTION_ANALYZER_NAME,
  PRODUCTION_ANALYZER_SCOPE,
  PRODUCTION_RULE_PACK_VERSION,
} from "./contracts.js";
import { createProductionRuleRegistry } from "./registry.js";
import { productionRules } from "./rules/index.js";

/**
 * Build the Production Analyzer.
 *
 * @param {object} [options]
 * @param {object[]} [options.rules] The rules to evaluate (defaults to the shipped pack).
 * @param {boolean} [options.failFast] Stop at the first rule failure (opt-in).
 * @returns {object} An Analyzer descriptor for `createAnalyzerRegistry`.
 * @throws {RuleRegistrationError} When the rule set violates the pack contract.
 */
export function createProductionAnalyzer({ rules = productionRules, failFast = false } = {}) {
  return createRuleAnalyzer({
    id: PRODUCTION_ANALYZER_ID,
    name: PRODUCTION_ANALYZER_NAME,
    version: PRODUCTION_RULE_PACK_VERSION,
    scope: PRODUCTION_ANALYZER_SCOPE,
    rules: createProductionRuleRegistry({ rules }),
    failFast,
  });
}
