/**
 * Code Guardian — Reliability Analysis Analyzer (Official Roadmap Phase 17)
 *
 * The reliability domain's entry point into the accepted analyzer framework:
 *
 *   Repository → Scanner(facts) → RepositoryModel → ReliabilityAnalyzer → reliability-analysis rules
 *              → evidence → findings
 *
 * It is a thin composition over the existing rule layer and Finding Engine. It adds exactly one
 * thing on top — the structured **reliability summary** (`summarizeReliabilityAnalysis`), the
 * deterministic map of the ten official domains to their states, attached as result metadata.
 *
 * Nothing here re-implements orchestration, applicability, evidence validation or fingerprinting,
 * and the descriptor is an ordinary Analyzer, so it works with `createAnalyzerRegistry` alongside
 * every other pack's analyzer without a special case. `failFast` defaults to `false`: one
 * reliability rule that throws or returns malformed output must not stop the others from reporting.
 */

import { createAnalysisResult } from "../../core/index.js";

import { createRuleAnalyzer } from "../analyzer.js";

import {
  RELIABILITY_ANALYSIS_ANALYZER_ID,
  RELIABILITY_ANALYSIS_ANALYZER_NAME,
  RELIABILITY_ANALYSIS_ANALYZER_SCOPE,
  RELIABILITY_ANALYSIS_RULE_PACK_VERSION,
} from "./contracts.js";
import { createReliabilityAnalysisRuleRegistry } from "./registry.js";
import { reliabilityAnalysisRules } from "./rules/index.js";
import { summarizeReliabilityAnalysis } from "./summary.js";

/**
 * Build the Reliability Analysis Analyzer.
 *
 * @param {object} [options]
 * @param {object[]} [options.rules] The rules to evaluate (defaults to the shipped pack).
 * @param {boolean} [options.failFast] Stop at the first rule failure (opt-in).
 * @param {Function} [options.summarize] Summary builder (defaults to the shipped one).
 * @returns {object} An Analyzer descriptor for `createAnalyzerRegistry`.
 * @throws {RuleRegistrationError} When the rule set violates the pack contract.
 */
export function createReliabilityAnalysisAnalyzer({
  rules = reliabilityAnalysisRules,
  failFast = false,
  summarize = summarizeReliabilityAnalysis,
} = {}) {
  const ruleAnalyzer = createRuleAnalyzer({
    id: RELIABILITY_ANALYSIS_ANALYZER_ID,
    name: RELIABILITY_ANALYSIS_ANALYZER_NAME,
    version: RELIABILITY_ANALYSIS_RULE_PACK_VERSION,
    scope: RELIABILITY_ANALYSIS_ANALYZER_SCOPE,
    rules: createReliabilityAnalysisRuleRegistry({ rules }),
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
        metadata: { ...result.metadata, reliabilityAnalysisSummary: summarize(context) },
      });
    },
  };
}
