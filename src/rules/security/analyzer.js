/**
 * Code Guardian — Security Analyzer (Phase 12)
 *
 * The security domain's entry point into the accepted analyzer framework. It is a
 * thin composition — build the pack's registry, hand it to the Phase 10
 * `RuleAnalyzer` adapter, and expose the result — because everything an analyzer
 * needs already exists: the adapter turns rules into an Analyzer, the Phase 9 engine
 * runs analyzers with isolation and fail-fast, and the Phase 9 Finding Engine
 * canonicalizes the raw drafts the rules produce.
 *
 * Nothing here re-implements orchestration, applicability, evidence validation or
 * fingerprinting. `createSecurityAnalyzer()` returns a normal Analyzer descriptor,
 * so it works with `createAnalyzerRegistry` and any future registry of analyzers
 * without a special case.
 *
 * `failFast` defaults to `false`: one security rule that throws or returns malformed
 * output must not stop the other seven from reporting.
 */

import { createRuleAnalyzer } from "../analyzer.js";

import {
  SECURITY_ANALYZER_ID,
  SECURITY_ANALYZER_NAME,
  SECURITY_ANALYZER_SCOPE,
  SECURITY_RULE_PACK_VERSION,
} from "./contracts.js";
import { createSecurityRuleRegistry } from "./registry.js";
import { securityRules } from "./rules/index.js";

/**
 * Build the Security Analyzer.
 *
 * @param {object} [options]
 * @param {object[]} [options.rules] The rules to evaluate (defaults to the shipped
 *   pack). A caller-supplied set is still checked against the pack contract, so a
 *   renamed or dropped rule fails rather than silently changing what "the security
 *   analyzer" means.
 * @param {boolean} [options.failFast] Stop at the first rule failure (opt-in).
 * @returns {object} An Analyzer descriptor for `createAnalyzerRegistry`.
 * @throws {RuleRegistrationError} When the rule set violates the pack contract or a
 *   descriptor is malformed.
 */
export function createSecurityAnalyzer({ rules = securityRules, failFast = false } = {}) {
  return createRuleAnalyzer({
    id: SECURITY_ANALYZER_ID,
    name: SECURITY_ANALYZER_NAME,
    version: SECURITY_RULE_PACK_VERSION,
    scope: SECURITY_ANALYZER_SCOPE,
    rules: createSecurityRuleRegistry({ rules }),
    failFast,
  });
}
