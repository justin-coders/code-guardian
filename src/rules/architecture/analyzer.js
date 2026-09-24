/**
 * Code Guardian — Architecture Analyzer (Phase 15)
 *
 * The architecture domain's entry point into the accepted analyzer framework: build
 * the pack's registry, hand it to the Phase 10 `RuleAnalyzer` adapter, expose the
 * result. Nothing here re-implements orchestration, applicability, evidence
 * validation or fingerprinting, and the descriptor is an ordinary Analyzer, so it
 * works with `createAnalyzerRegistry` alongside the security and dependency analyzers
 * without a special case.
 *
 * `failFast` defaults to `false`: one architecture rule that throws or returns
 * malformed output must not stop the others from reporting.
 */

import { createRuleAnalyzer } from "../analyzer.js";

import {
  ARCHITECTURE_ANALYZER_ID,
  ARCHITECTURE_ANALYZER_NAME,
  ARCHITECTURE_ANALYZER_SCOPE,
  ARCHITECTURE_RULE_PACK_VERSION,
} from "./contracts.js";
import { createArchitectureRuleRegistry } from "./registry.js";
import { architectureRules } from "./rules/index.js";

/**
 * Build the Architecture Analyzer.
 *
 * @param {object} [options]
 * @param {object[]} [options.rules] The rules to evaluate (defaults to the shipped
 *   pack). A caller-supplied set is still checked against the pack contract.
 * @param {boolean} [options.failFast] Stop at the first rule failure (opt-in).
 * @returns {object} An Analyzer descriptor for `createAnalyzerRegistry`.
 * @throws {RuleRegistrationError} When the rule set violates the pack contract or a
 *   descriptor is malformed.
 */
export function createArchitectureAnalyzer({ rules = architectureRules, failFast = false } = {}) {
  return createRuleAnalyzer({
    id: ARCHITECTURE_ANALYZER_ID,
    name: ARCHITECTURE_ANALYZER_NAME,
    version: ARCHITECTURE_RULE_PACK_VERSION,
    scope: ARCHITECTURE_ANALYZER_SCOPE,
    rules: createArchitectureRuleRegistry({ rules }),
    failFast,
  });
}
