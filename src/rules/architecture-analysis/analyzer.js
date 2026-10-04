/**
 * Code Guardian — Architecture Analysis Analyzer (Official Roadmap Phase 14)
 *
 * The architecture domain's entry point into the accepted analyzer framework:
 *
 *   Repository → Scanner(facts) → RepositoryModel → ArchitectureAnalyzer → architecture rules
 *              → evidence → findings
 *
 * It is a thin composition. Everything an analyzer needs already exists: the rule layer's
 * `RuleAnalyzer` adapter turns rules into an Analyzer, the analyzer engine runs analyzers with
 * isolation and fail-fast, and the Finding Engine canonicalizes the raw drafts the rules
 * produce. This module adds exactly one thing on top — the structured **architecture summary**
 * (`summarizeArchitecture`), the deterministic map of the nine roadmap domains to their states,
 * attached as result metadata.
 *
 * Nothing here re-implements orchestration, applicability, evidence validation or
 * fingerprinting. `createArchitectureAnalysisAnalyzer()` returns a normal Analyzer descriptor,
 * so it works with `createAnalyzerRegistry` without a special case. `failFast` defaults to
 * `false`: one rule that throws must not stop the other rules from reporting.
 */

import { createAnalysisResult } from "../../core/index.js";

import { createRuleAnalyzer } from "../analyzer.js";

import {
  ARCHITECTURE_ANALYSIS_ANALYZER_ID,
  ARCHITECTURE_ANALYSIS_ANALYZER_NAME,
  ARCHITECTURE_ANALYSIS_ANALYZER_SCOPE,
  ARCHITECTURE_ANALYSIS_RULE_PACK_VERSION,
} from "./contracts.js";
import { createArchitectureAnalysisRuleRegistry } from "./registry.js";
import { architectureAnalysisRules } from "./rules/index.js";
import { summarizeArchitecture } from "./summary.js";

/**
 * Build the Architecture Analysis Analyzer.
 *
 * @param {object} [options]
 * @param {object[]} [options.rules] The rules to evaluate (defaults to the shipped pack). A
 *   caller-supplied set is still checked against the pack contract, so a renamed or dropped rule
 *   fails rather than silently changing what "the architecture analyzer" means.
 * @param {boolean} [options.failFast] Stop at the first rule failure (opt-in).
 * @param {Function} [options.summarize] Summary builder (defaults to the shipped one).
 * @returns {object} An Analyzer descriptor for `createAnalyzerRegistry`.
 * @throws {RuleRegistrationError} When the rule set violates the pack contract.
 */
export function createArchitectureAnalysisAnalyzer({
  rules = architectureAnalysisRules,
  failFast = false,
  summarize = summarizeArchitecture,
} = {}) {
  const ruleAnalyzer = createRuleAnalyzer({
    id: ARCHITECTURE_ANALYSIS_ANALYZER_ID,
    name: ARCHITECTURE_ANALYSIS_ANALYZER_NAME,
    version: ARCHITECTURE_ANALYSIS_RULE_PACK_VERSION,
    scope: ARCHITECTURE_ANALYSIS_ANALYZER_SCOPE,
    rules: createArchitectureAnalysisRuleRegistry({ rules }),
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
        metadata: { ...result.metadata, architectureSummary: summarize(context) },
      });
    },
  };
}
