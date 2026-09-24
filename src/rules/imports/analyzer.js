/**
 * Code Guardian — Import Analyzer (Phase 16)
 *
 * The import domain's entry point into the accepted analyzer framework: build the
 * pack's registry, hand it to the Phase 10 `RuleAnalyzer` adapter, expose the result.
 * Nothing here re-implements orchestration, applicability, evidence validation or
 * fingerprinting, and the descriptor is an ordinary Analyzer, so it works with
 * `createAnalyzerRegistry` alongside the security, dependency and architecture
 * analyzers without a special case.
 *
 * `failFast` defaults to `false`: one import rule that throws or returns malformed
 * output must not stop the others from reporting.
 */

import { createRuleAnalyzer } from "../analyzer.js";

import {
  IMPORT_ANALYZER_ID,
  IMPORT_ANALYZER_NAME,
  IMPORT_ANALYZER_SCOPE,
  IMPORT_RULE_PACK_VERSION,
} from "./contracts.js";
import { createImportRuleRegistry } from "./registry.js";
import { importRules } from "./rules/index.js";

/**
 * Build the Import Analyzer.
 *
 * @param {object} [options]
 * @param {object[]} [options.rules] The rules to evaluate (defaults to the shipped
 *   pack). A caller-supplied set is still checked against the pack contract.
 * @param {boolean} [options.failFast] Stop at the first rule failure (opt-in).
 * @returns {object} An Analyzer descriptor for `createAnalyzerRegistry`.
 * @throws {RuleRegistrationError} When the rule set violates the pack contract or a
 *   descriptor is malformed.
 */
export function createImportAnalyzer({ rules = importRules, failFast = false } = {}) {
  return createRuleAnalyzer({
    id: IMPORT_ANALYZER_ID,
    name: IMPORT_ANALYZER_NAME,
    version: IMPORT_RULE_PACK_VERSION,
    scope: IMPORT_ANALYZER_SCOPE,
    rules: createImportRuleRegistry({ rules }),
    failFast,
  });
}
