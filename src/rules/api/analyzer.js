/**
 * Code Guardian — API Analyzer (Phase 18)
 *
 * The API domain's entry point into the accepted analyzer framework: build the pack's
 * registry, hand it to the Phase 10 `RuleAnalyzer` adapter, expose the result. Nothing
 * here re-implements orchestration, applicability, evidence validation or fingerprinting,
 * and the descriptor is an ordinary Analyzer, so it works with `createAnalyzerRegistry`
 * alongside every other pack's analyzer without a special case.
 *
 * `failFast` defaults to `false`: one API rule that throws or returns malformed output
 * must not stop the others from reporting.
 */

import { createRuleAnalyzer } from "../analyzer.js";

import {
  API_ANALYZER_ID,
  API_ANALYZER_NAME,
  API_ANALYZER_SCOPE,
  API_RULE_PACK_VERSION,
} from "./contracts.js";
import { createApiRuleRegistry } from "./registry.js";
import { apiRules } from "./rules/index.js";

/**
 * Build the API Analyzer.
 *
 * @param {object} [options]
 * @param {object[]} [options.rules] The rules to evaluate (defaults to the shipped pack).
 * @param {boolean} [options.failFast] Stop at the first rule failure (opt-in).
 * @returns {object} An Analyzer descriptor for `createAnalyzerRegistry`.
 * @throws {RuleRegistrationError} When the rule set violates the pack contract.
 */
export function createApiAnalyzer({ rules = apiRules, failFast = false } = {}) {
  return createRuleAnalyzer({
    id: API_ANALYZER_ID,
    name: API_ANALYZER_NAME,
    version: API_RULE_PACK_VERSION,
    scope: API_ANALYZER_SCOPE,
    rules: createApiRuleRegistry({ rules }),
    failFast,
  });
}
