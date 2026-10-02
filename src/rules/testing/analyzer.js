/**
 * Code Guardian — Testing Analyzer (Official Roadmap Phase 11)
 *
 * The testing domain's entry point into the accepted analyzer framework:
 *
 *   Repository → RepositoryModel → TestingAnalyzer → applicable rules → evidence → findings
 *
 * It is a thin composition. Everything an analyzer needs already exists: the rule
 * layer's `RuleAnalyzer` adapter turns rules into an Analyzer, the analyzer engine
 * runs analyzers with isolation and fail-fast, and the Finding Engine canonicalizes
 * the raw drafts the rules produce. This module adds exactly one thing on top — the
 * structured **testing summary** (`summarizeTesting`), the deterministic map of the
 * nine roadmap domains to the five official states, attached as result metadata so
 * a consumer can read the domain states without re-deriving them from findings.
 *
 * Nothing here re-implements orchestration, applicability, evidence validation or
 * fingerprinting. `createTestingAnalyzer()` returns a normal Analyzer descriptor, so
 * it works with `createAnalyzerRegistry` without a special case.
 *
 * `failFast` defaults to `false`: one testing rule that throws must not stop the
 * other rules from reporting.
 */

import { createAnalysisResult } from "../../core/index.js";

import { createRuleAnalyzer } from "../analyzer.js";

import {
  TESTING_ANALYZER_ID,
  TESTING_ANALYZER_NAME,
  TESTING_ANALYZER_SCOPE,
  TESTING_RULE_PACK_VERSION,
} from "./contracts.js";
import { createTestingRuleRegistry } from "./registry.js";
import { testingRules } from "./rules/index.js";
import { summarizeTesting } from "./summary.js";

/**
 * Build the Testing Analyzer.
 *
 * @param {object} [options]
 * @param {object[]} [options.rules] The rules to evaluate (defaults to the shipped
 *   pack). A caller-supplied set is still checked against the pack contract, so a
 *   renamed or dropped rule fails rather than silently changing what "the testing
 *   analyzer" means.
 * @param {boolean} [options.failFast] Stop at the first rule failure (opt-in).
 * @param {Function} [options.summarize] Summary builder (defaults to the shipped one).
 * @returns {object} An Analyzer descriptor for `createAnalyzerRegistry`.
 * @throws {RuleRegistrationError} When the rule set violates the pack contract.
 */
export function createTestingAnalyzer({
  rules = testingRules,
  failFast = false,
  summarize = summarizeTesting,
} = {}) {
  const ruleAnalyzer = createRuleAnalyzer({
    id: TESTING_ANALYZER_ID,
    name: TESTING_ANALYZER_NAME,
    version: TESTING_RULE_PACK_VERSION,
    scope: TESTING_ANALYZER_SCOPE,
    rules: createTestingRuleRegistry({ rules }),
    failFast,
  });

  return {
    id: ruleAnalyzer.id,
    name: ruleAnalyzer.name,
    version: ruleAnalyzer.version,
    scope: ruleAnalyzer.scope,
    description: ruleAnalyzer.description,
    canAnalyze: ruleAnalyzer.canAnalyze,
    async analyze(context) {
      const result = await ruleAnalyzer.analyze(context);
      return createAnalysisResult({
        findings: result.findings,
        evidence: result.evidence,
        metrics: result.metrics,
        metadata: { ...result.metadata, testingSummary: summarize(context) },
      });
    },
  };
}
