/**
 * Code Guardian — Middleware Analyzer (Phase 19)
 *
 * The middleware domain's entry point into the accepted analyzer framework: build the pack's
 * registry, hand it to the Phase 10 `RuleAnalyzer` adapter, expose the result. Nothing here
 * re-implements orchestration, applicability, evidence validation or fingerprinting, and the
 * descriptor is an ordinary Analyzer, so it works with `createAnalyzerRegistry` alongside
 * every other pack's analyzer without a special case.
 *
 * `failFast` defaults to `false`: one middleware rule that throws or returns malformed output
 * must not stop the others from reporting.
 */

import { createRuleAnalyzer } from "../analyzer.js";

import {
  MIDDLEWARE_ANALYZER_ID,
  MIDDLEWARE_ANALYZER_NAME,
  MIDDLEWARE_ANALYZER_SCOPE,
  MIDDLEWARE_RULE_PACK_VERSION,
} from "./contracts.js";
import { createMiddlewareRuleRegistry } from "./registry.js";
import { middlewareRules } from "./rules/index.js";

/**
 * Build the Middleware Analyzer.
 *
 * @param {object} [options]
 * @param {object[]} [options.rules] The rules to evaluate (defaults to the shipped pack).
 * @param {boolean} [options.failFast] Stop at the first rule failure (opt-in).
 * @returns {object} An Analyzer descriptor for `createAnalyzerRegistry`.
 * @throws {RuleRegistrationError} When the rule set violates the pack contract.
 */
export function createMiddlewareAnalyzer({ rules = middlewareRules, failFast = false } = {}) {
  return createRuleAnalyzer({
    id: MIDDLEWARE_ANALYZER_ID,
    name: MIDDLEWARE_ANALYZER_NAME,
    version: MIDDLEWARE_RULE_PACK_VERSION,
    scope: MIDDLEWARE_ANALYZER_SCOPE,
    rules: createMiddlewareRuleRegistry({ rules }),
    failFast,
  });
}
