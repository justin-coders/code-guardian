/**
 * Code Guardian — Symbol Analyzer (Phase 17)
 *
 * The semantic domain's entry point into the accepted analyzer framework: build the
 * pack's registry, hand it to the Phase 10 `RuleAnalyzer` adapter, expose the result.
 * Nothing here re-implements orchestration, applicability, evidence validation or
 * fingerprinting, and the descriptor is an ordinary Analyzer, so it works with
 * `createAnalyzerRegistry` alongside the security, dependency, architecture and import
 * analyzers without a special case.
 *
 * `failFast` defaults to `false`: one symbol rule that throws or returns malformed
 * output must not stop the others from reporting.
 */

import { createRuleAnalyzer } from "../analyzer.js";

import {
  SYMBOL_ANALYZER_ID,
  SYMBOL_ANALYZER_NAME,
  SYMBOL_ANALYZER_SCOPE,
  SYMBOL_RULE_PACK_VERSION,
} from "./contracts.js";
import { createSymbolRuleRegistry } from "./registry.js";
import { symbolRules } from "./rules/index.js";

/**
 * Build the Symbol Analyzer.
 *
 * @param {object} [options]
 * @param {object[]} [options.rules] The rules to evaluate (defaults to the shipped
 *   pack). A caller-supplied set is still checked against the pack contract.
 * @param {boolean} [options.failFast] Stop at the first rule failure (opt-in).
 * @returns {object} An Analyzer descriptor for `createAnalyzerRegistry`.
 * @throws {RuleRegistrationError} When the rule set violates the pack contract or a
 *   descriptor is malformed.
 */
export function createSymbolAnalyzer({ rules = symbolRules, failFast = false } = {}) {
  return createRuleAnalyzer({
    id: SYMBOL_ANALYZER_ID,
    name: SYMBOL_ANALYZER_NAME,
    version: SYMBOL_RULE_PACK_VERSION,
    scope: SYMBOL_ANALYZER_SCOPE,
    rules: createSymbolRuleRegistry({ rules }),
    failFast,
  });
}
