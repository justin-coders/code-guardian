/**
 * Code Guardian — API Analysis Analyzer (Official Roadmap Phase 16)
 *
 * The API domain's entry point into the accepted analyzer framework:
 *
 *   Repository → Scanner(facts) → RepositoryModel → APIAnalyzer → api-analysis rules
 *              → evidence → findings
 *
 * It is a thin composition over the existing rule layer and Finding Engine. It adds exactly one
 * thing on top — the structured **API summary** (`summarizeApiAnalysis`), the deterministic map
 * of the thirteen official domains to their states, attached as result metadata.
 *
 * Nothing here re-implements orchestration, applicability, evidence validation or
 * fingerprinting, and the descriptor is an ordinary Analyzer, so it works with
 * `createAnalyzerRegistry` alongside every other pack's analyzer without a special case.
 * `failFast` defaults to `false`: one API rule that throws or returns malformed output must not
 * stop the others from reporting.
 */

import { createAnalysisResult } from "../../core/index.js";

import { createRuleAnalyzer } from "../analyzer.js";

import {
  API_ANALYSIS_ANALYZER_ID,
  API_ANALYSIS_ANALYZER_NAME,
  API_ANALYSIS_ANALYZER_SCOPE,
  API_ANALYSIS_RULE_PACK_VERSION,
} from "./contracts.js";
import { createApiAnalysisRuleRegistry } from "./registry.js";
import { apiAnalysisRules } from "./rules/index.js";
import { summarizeApiAnalysis } from "./summary.js";

/**
 * Build the API Analysis Analyzer.
 *
 * @param {object} [options]
 * @param {object[]} [options.rules] The rules to evaluate (defaults to the shipped pack).
 * @param {boolean} [options.failFast] Stop at the first rule failure (opt-in).
 * @param {Function} [options.summarize] Summary builder (defaults to the shipped one).
 * @returns {object} An Analyzer descriptor for `createAnalyzerRegistry`.
 * @throws {RuleRegistrationError} When the rule set violates the pack contract.
 */
export function createApiAnalysisAnalyzer({
  rules = apiAnalysisRules,
  failFast = false,
  summarize = summarizeApiAnalysis,
} = {}) {
  const ruleAnalyzer = createRuleAnalyzer({
    id: API_ANALYSIS_ANALYZER_ID,
    name: API_ANALYSIS_ANALYZER_NAME,
    version: API_ANALYSIS_RULE_PACK_VERSION,
    scope: API_ANALYSIS_ANALYZER_SCOPE,
    rules: createApiAnalysisRuleRegistry({ rules }),
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
        metadata: { ...result.metadata, apiAnalysisSummary: summarize(context) },
      });
    },
  };
}
