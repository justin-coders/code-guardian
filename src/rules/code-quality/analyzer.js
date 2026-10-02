/**
 * Code Guardian — Code Quality Analyzer (Official Roadmap Phase 12)
 *
 * The code-quality domain's entry point into the accepted analyzer framework:
 *
 *   Repository → RepositoryModel → CodeQualityAnalyzer → applicable rules → evidence → findings
 *
 * It is a thin composition. Everything an analyzer needs already exists: the rule layer's
 * `RuleAnalyzer` adapter turns rules into an Analyzer, the analyzer engine runs analyzers with
 * isolation and fail-fast, and the Finding Engine canonicalizes the raw drafts the rules
 * produce. This module adds exactly one thing on top — the structured **code-quality summary**
 * (`summarizeCodeQuality`), the deterministic map of the nine roadmap domains to the five
 * official states, attached as result metadata so a consumer can read the domain states without
 * re-deriving them from findings.
 *
 * Nothing here re-implements orchestration, applicability, evidence validation or
 * fingerprinting. `createCodeQualityAnalyzer()` returns a normal Analyzer descriptor, so it
 * works with `createAnalyzerRegistry` without a special case. `failFast` defaults to `false`:
 * one rule that throws must not stop the other rules from reporting.
 */

import { createAnalysisResult } from "../../core/index.js";

import { createRuleAnalyzer } from "../analyzer.js";

import {
  CODE_QUALITY_ANALYZER_ID,
  CODE_QUALITY_ANALYZER_NAME,
  CODE_QUALITY_ANALYZER_SCOPE,
  CODE_QUALITY_RULE_PACK_VERSION,
} from "./contracts.js";
import { createCodeQualityRuleRegistry } from "./registry.js";
import { codeQualityRules } from "./rules/index.js";
import { summarizeCodeQuality } from "./summary.js";

/**
 * Build the Code Quality Analyzer.
 *
 * @param {object} [options]
 * @param {object[]} [options.rules] The rules to evaluate (defaults to the shipped pack). A
 *   caller-supplied set is still checked against the pack contract, so a renamed or dropped
 *   rule fails rather than silently changing what "the code-quality analyzer" means.
 * @param {boolean} [options.failFast] Stop at the first rule failure (opt-in).
 * @param {Function} [options.summarize] Summary builder (defaults to the shipped one).
 * @returns {object} An Analyzer descriptor for `createAnalyzerRegistry`.
 * @throws {RuleRegistrationError} When the rule set violates the pack contract.
 */
export function createCodeQualityAnalyzer({
  rules = codeQualityRules,
  failFast = false,
  summarize = summarizeCodeQuality,
} = {}) {
  const ruleAnalyzer = createRuleAnalyzer({
    id: CODE_QUALITY_ANALYZER_ID,
    name: CODE_QUALITY_ANALYZER_NAME,
    version: CODE_QUALITY_RULE_PACK_VERSION,
    scope: CODE_QUALITY_ANALYZER_SCOPE,
    rules: createCodeQualityRuleRegistry({ rules }),
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
        metadata: { ...result.metadata, codeQualitySummary: summarize(context) },
      });
    },
  };
}
