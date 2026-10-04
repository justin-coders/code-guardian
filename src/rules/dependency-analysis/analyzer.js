/**
 * Code Guardian — Dependency Analysis Analyzer (Official Roadmap Phase 15)
 *
 * The dependency domain's entry point into the accepted analyzer framework:
 *
 *   Repository → Scanner(facts) → RepositoryModel → DependencyAnalyzer → dependency rules
 *              → evidence → findings
 *
 * It is a thin composition over the existing rule layer and Finding Engine. It adds exactly one
 * thing on top — the structured **dependency summary** (`summarizeDependencyAnalysis`), the
 * deterministic map of the eight roadmap domains to their states, attached as result metadata.
 *
 * External dependency intelligence is supplied through `context.options.dependencyIntelligence`
 * and is never fetched here: a rule performs no network access, and the dataset's own state is
 * reported so a missing dataset yields `unknown`, not a clean result.
 */

import { createAnalysisResult } from "../../core/index.js";

import { createRuleAnalyzer } from "../analyzer.js";

import {
  DEPENDENCY_ANALYSIS_ANALYZER_ID,
  DEPENDENCY_ANALYSIS_ANALYZER_NAME,
  DEPENDENCY_ANALYSIS_ANALYZER_SCOPE,
  DEPENDENCY_ANALYSIS_RULE_PACK_VERSION,
} from "./contracts.js";
import { createDependencyAnalysisRuleRegistry } from "./registry.js";
import { dependencyAnalysisRules } from "./rules/index.js";
import { summarizeDependencyAnalysis } from "./summary.js";

/**
 * Build the Dependency Analysis Analyzer.
 *
 * @param {object} [options]
 * @param {object[]} [options.rules] The rules to evaluate (defaults to the shipped pack).
 * @param {boolean} [options.failFast] Stop at the first rule failure (opt-in).
 * @param {Function} [options.summarize] Summary builder (defaults to the shipped one).
 * @returns {object} An Analyzer descriptor for `createAnalyzerRegistry`.
 * @throws {RuleRegistrationError} When the rule set violates the pack contract.
 */
export function createDependencyAnalysisAnalyzer({
  rules = dependencyAnalysisRules,
  failFast = false,
  summarize = summarizeDependencyAnalysis,
} = {}) {
  const ruleAnalyzer = createRuleAnalyzer({
    id: DEPENDENCY_ANALYSIS_ANALYZER_ID,
    name: DEPENDENCY_ANALYSIS_ANALYZER_NAME,
    version: DEPENDENCY_ANALYSIS_RULE_PACK_VERSION,
    scope: DEPENDENCY_ANALYSIS_ANALYZER_SCOPE,
    rules: createDependencyAnalysisRuleRegistry({ rules }),
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
        metadata: { ...result.metadata, dependencySummary: summarize(context) },
      });
    },
  };
}
