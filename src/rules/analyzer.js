/**
 * Code Guardian — RuleAnalyzer Adapter (Phase 10)
 *
 * The Rule Engine is not an analyzer, and the Analyzer Engine is not a rule engine.
 * This adapter is the single seam between them: it wraps a set of rules as a Phase 9
 * `Analyzer`, so the accepted analyzer pipeline (selection → applicability →
 * isolation → deduplication → aggregate result) runs rules without either engine
 * learning about the other.
 *
 * What it deliberately does **not** do:
 *
 *   - it does not canonicalize findings. It returns the Rule Engine's raw finding
 *     drafts and evidence to the Phase 9 engine, which owns the Finding Engine
 *     (fingerprinting, id assignment, evidence re-resolution). The two pipelines
 *     therefore compose instead of duplicating.
 *   - it does not swallow rule failures. Failed and unknown rules are recorded in
 *     the analyzer's metadata, and `throwOnRuleFailure` promotes a failure to an
 *     analyzer failure when a caller wants the strict behaviour.
 *   - it does not grant capabilities. Rules receive the same AnalysisContext an
 *     analyzer does: the frozen RepositoryModel and declarative data only.
 */

import { createAnalysisResult, createApplicability } from "../core/index.js";

import { createRuleRegistry } from "./registry.js";
import { createRuleEngine } from "./engine.js";
import { ABNORMAL_RULE_STATUSES, RULE_OUTCOME_STATUSES } from "./contracts.js";
import { sanitizeRuleFailure } from "./errors.js";

/**
 * Create an analyzer that evaluates a set of rules.
 *
 * @param {object} input
 * @param {string} input.id Analyzer id (`security.rules`, `testing.rules`, ...).
 * @param {string} input.name Human-readable name.
 * @param {string} input.version Analyzer version.
 * @param {string} input.scope Domain namespace.
 * @param {object[]|object} input.rules Rules to evaluate, or a rule registry.
 * @param {boolean} [input.failFast] Forwarded to the Rule Engine.
 * @param {boolean} [input.throwOnRuleFailure] Fail the analyzer when a rule fails.
 * @param {Function} [input.clock] Millisecond clock.
 * @returns {object} An Analyzer descriptor usable with `createAnalyzerRegistry`.
 */
export function createRuleAnalyzer({
  id,
  name,
  version,
  scope,
  rules = [],
  failFast = false,
  throwOnRuleFailure = false,
  clock,
} = {}) {
  const registry =
    rules !== null && typeof rules === "object" && typeof rules.list === "function"
      ? rules
      : createRuleRegistry(rules);

  const engine = createRuleEngine({ registry, failFast, ...(clock === undefined ? {} : { clock }) });

  return {
    id,
    name,
    version,
    scope,
    description: `Evaluates ${registry.size} rule${registry.size === 1 ? "" : "s"}`,
    canAnalyze: () =>
      createApplicability(
        registry.size === 0
          ? { applicable: false, reason: "no rules registered" }
          : { applicable: true },
      ),
    async analyze(context) {
      const run = await engine.runAll(context);

      const ruleFailures = run.rules
        .filter((result) => result.status === RULE_OUTCOME_STATUSES.FAILED)
        .flatMap((result) => result.errors.map(sanitizeRuleFailure));
      const unavailable = run.rules
        .filter((result) => result.status === RULE_OUTCOME_STATUSES.UNKNOWN)
        .map((result) => ({
          ruleId: result.rule.id,
          reason: result.applicability?.reason ?? null,
        }));

      if (throwOnRuleFailure && ruleFailures.length > 0) {
        const first = ruleFailures[0];
        const error = new Error(`rule "${first.ruleId}" failed: ${first.message}`);
        error.code = first.code;
        error.details = { ruleFailures };
        throw error;
      }

      const violations = run.rules.filter(
        (result) => result.status === RULE_OUTCOME_STATUSES.VIOLATION,
      ).length;

      // Only *derived* evidence crosses into the analyzer result. Model evidence is
      // already available to the Finding Engine, and re-emitting it would make the
      // Phase 9 engine correctly reject the id as a duplicate of the model's own.
      const modelEvidenceIds = new Set(
        Object.keys(context.repository.indexes?.evidenceById ?? {}),
      );
      const derivedEvidence = run.evidence.filter((record) => !modelEvidenceIds.has(record.id));

      return createAnalysisResult({
        findings: run.findings,
        evidence: derivedEvidence,
        metrics: {
          rulesSelected: run.metadata.selectedCount,
          rulesEvaluated: run.metadata.evaluated,
          rulesViolated: violations,
          rulesUnknown: run.metadata.unknown,
        },
        metadata: {
          ruleSet: registry.ids(),
          ruleFailures,
          unavailableRules: unavailable,
          abnormal: run.rules
            .filter((result) => ABNORMAL_RULE_STATUSES.includes(result.status))
            .map((result) => ({ ruleId: result.rule.id, status: result.status })),
        },
      });
    },
  };
}
