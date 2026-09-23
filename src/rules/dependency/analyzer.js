/**
 * Code Guardian — Dependency Analyzer (Phase 13)
 *
 * The dependency domain's entry point into the accepted analyzer framework: build the
 * pack's registry, hand it to the Phase 10 `RuleAnalyzer` adapter, expose the result.
 * Nothing here re-implements orchestration, applicability, evidence validation or
 * fingerprinting, and the descriptor is an ordinary Analyzer, so it works with
 * `createAnalyzerRegistry` alongside the security analyzer without a special case.
 *
 * `failFast` defaults to `false`: one dependency rule that throws or returns
 * malformed output must not stop the others from reporting.
 */

import { createRuleAnalyzer } from "../analyzer.js";

import {
  DEPENDENCY_ANALYZER_ID,
  DEPENDENCY_ANALYZER_NAME,
  DEPENDENCY_ANALYZER_SCOPE,
  DEPENDENCY_RULE_PACK_VERSION,
} from "./contracts.js";
import { createDependencyRuleRegistry } from "./registry.js";
import { dependencyRules } from "./rules/index.js";

/**
 * Build the Dependency Analyzer.
 *
 * @param {object} [options]
 * @param {object[]} [options.rules] The rules to evaluate (defaults to the shipped
 *   pack). A caller-supplied set is still checked against the pack contract.
 * @param {boolean} [options.failFast] Stop at the first rule failure (opt-in).
 * @returns {object} An Analyzer descriptor for `createAnalyzerRegistry`.
 * @throws {RuleRegistrationError} When the rule set violates the pack contract or a
 *   descriptor is malformed.
 */
export function createDependencyAnalyzer({ rules = dependencyRules, failFast = false } = {}) {
  return createRuleAnalyzer({
    id: DEPENDENCY_ANALYZER_ID,
    name: DEPENDENCY_ANALYZER_NAME,
    version: DEPENDENCY_RULE_PACK_VERSION,
    scope: DEPENDENCY_ANALYZER_SCOPE,
    rules: createDependencyRuleRegistry({ rules }),
    failFast,
  });
}
