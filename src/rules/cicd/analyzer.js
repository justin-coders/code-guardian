/**
 * Code Guardian — CI/CD Analyzer (Official Roadmap Phase 13)
 *
 * The CI/CD domain's entry point into the accepted analyzer framework:
 *
 *   Repository → RepositoryModel → CICDAnalyzer → applicable rules → evidence → findings
 *
 * It is a thin composition. Everything an analyzer needs already exists: the rule layer's
 * `RuleAnalyzer` adapter turns rules into an Analyzer, the analyzer engine runs analyzers with
 * isolation and fail-fast, and the Finding Engine canonicalizes the raw drafts the rules produce.
 * This module adds exactly one thing on top — the structured **CI/CD summary**
 * (`summarizeCicd`), the deterministic map of the twelve roadmap domains to the five official
 * states, attached as result metadata so a consumer can read the domain states without
 * re-deriving them from findings.
 *
 * Nothing here re-implements orchestration, applicability, evidence validation or
 * fingerprinting, and nothing here runs a workflow, a command or a provider API.
 * `createCicdAnalyzer()` returns a normal Analyzer descriptor, so it works with
 * `createAnalyzerRegistry` without a special case; `failFast` defaults to `false`, so one rule
 * that throws cannot stop the other eleven from reporting.
 */

import { createAnalysisResult } from "../../core/index.js";

import { createRuleAnalyzer } from "../analyzer.js";

import {
  CICD_ANALYZER_ID,
  CICD_ANALYZER_NAME,
  CICD_ANALYZER_SCOPE,
  CICD_RULE_PACK_VERSION,
} from "./contracts.js";
import { createCicdRuleRegistry } from "./registry.js";
import { cicdRules } from "./rules/index.js";
import { summarizeCicd } from "./summary.js";

/**
 * Build the CI/CD Analyzer.
 *
 * @param {object} [options]
 * @param {object[]} [options.rules] The rules to evaluate (defaults to the shipped pack). A
 *   caller-supplied set is still checked against the pack contract, so a renamed or dropped rule
 *   fails rather than silently changing what "the CI/CD analyzer" means.
 * @param {boolean} [options.failFast] Stop at the first rule failure (opt-in).
 * @param {Function} [options.summarize] Summary builder (defaults to the shipped one).
 * @returns {object} An Analyzer descriptor for `createAnalyzerRegistry`.
 * @throws {RuleRegistrationError} When the rule set violates the pack contract.
 */
export function createCicdAnalyzer({
  rules = cicdRules,
  failFast = false,
  summarize = summarizeCicd,
} = {}) {
  const ruleAnalyzer = createRuleAnalyzer({
    id: CICD_ANALYZER_ID,
    name: CICD_ANALYZER_NAME,
    version: CICD_RULE_PACK_VERSION,
    scope: CICD_ANALYZER_SCOPE,
    rules: createCicdRuleRegistry({ rules }),
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
        metadata: { ...result.metadata, cicdSummary: summarize(context) },
      });
    },
  };
}
