/**
 * Code Guardian — Rule Engine (Phase 10)
 *
 * The engine owns the *rule pipeline*, and nothing else. It knows nothing about
 * security, testing or architecture; it knows how to take a validated
 * AnalysisContext, decide which rules apply, evaluate them without letting one
 * corrupt another, and report exactly what happened.
 *
 *   AnalysisContext
 *         │
 *         ▼
 *   selection ──► applicability ──► detect() ──► raw findings / evidence
 *         │            │                │                    │
 *         │     not-applicable /     failure            raw drafts
 *         │        unknown              │                    │
 *         ▼            ▼                ▼                    ▼
 *      skipped      result           result               result
 *         └────────────┴────────────────┴────────────────────┘
 *                              │
 *                              ▼
 *                        rule run result
 *
 * Invariants the engine enforces:
 *
 *   - **Isolation.** Every rule runs inside its own boundary: one throwing, one
 *     returning nonsense and one producing a malformed finding do not stop the
 *     others, and each failure is recorded against the rule that caused it.
 *     `failFast` is opt-in and reports the rules it never reached as `skipped`, so
 *     an aborted run never looks complete.
 *   - **No fabrication.** Findings may only cite evidence that exists in the
 *     RepositoryModel or that the *same* rule emitted in this run. Reference scope
 *     is per rule, and emitted evidence ids are unique for the whole run.
 *   - **No false certainty.** A rule whose applicability depends on something the
 *     scan did not cover is `unknown`, not `not-applicable` and not clean.
 *   - **Determinism.** Selection, execution, results, findings, evidence and errors
 *     all have documented orderings that do not depend on object key order, rule
 *     scheduling or discovery order.
 *
 * The engine performs no I/O, spawns nothing and never touches the filesystem: the
 * only repository knowledge available to a rule is the frozen RepositoryModel
 * inside the context.
 */

import { validateAnalysisContext } from "../core/index.js";

import { deepFreeze } from "../analysis/index.js";

import {
  ABNORMAL_RULE_STATUSES,
  RULE_ENGINE_VERSION,
  RULE_FAILURE_KINDS,
  RULE_OUTCOME_STATUSES,
} from "./contracts.js";
import { RuleFrameworkError, ruleFailureEntry } from "./errors.js";
import { evaluateRule, ruleSummary } from "./evaluation.js";
import {
  createRuleEvaluationResult,
  createRuleRunResult,
  stableAnalysisView,
  validateRuleEvaluationResult,
  validateRuleRunResult,
} from "./results.js";

/** Default engine options. */
export const DEFAULT_RULE_ENGINE_OPTIONS = Object.freeze({
  /** Stop after the first rule failure (opt-in). */
  failFast: false,
  /** Millisecond clock. Injected so runs can be made fully deterministic. */
  clock: () => Date.now(),
});

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

/** A compact, serializable description of the analysed repository. */
function repositorySummary(model) {
  return {
    repositoryId: model.identity.repositoryId,
    root: model.identity.root,
    coverage: {
      complete: model.scan.coverage.guarantee === "complete",
      truncated: model.scan.truncated === true,
      guarantee: model.scan.coverage.guarantee,
    },
  };
}

/**
 * Create a rule engine bound to a registry.
 *
 * @param {object} options
 * @param {object} options.registry A registry from `createRuleRegistry`.
 * @param {boolean} [options.failFast] Default fail-fast behaviour for runs.
 * @param {Function} [options.clock] Millisecond clock (metadata only).
 * @returns {object} A frozen engine handle with `run` and `runAll`.
 */
export function createRuleEngine({
  registry,
  failFast = false,
  clock = DEFAULT_RULE_ENGINE_OPTIONS.clock,
} = {}) {
  if (registry === null || typeof registry !== "object" || typeof registry.list !== "function") {
    throw new RuleFrameworkError(
      RULE_FAILURE_KINDS.UNKNOWN_RULE,
      "createRuleEngine requires a rule registry",
    );
  }

  const engine = {
    /** Evaluate every registered rule. */
    async runAll(context, options = {}) {
      return engine.run(registry.ids(), context, options);
    },

    /**
     * Evaluate the selected rules, sorted by id.
     *
     * @param {string[]} ids Rule ids to evaluate.
     * @param {object} context A validated AnalysisContext.
     * @param {object} [options]
     * @param {boolean} [options.failFast] Overrides the engine default.
     * @returns {Promise<object>} A validated, frozen rule run result.
     * @throws {RuleConfigurationError} When an id is not registered.
     */
    async run(ids, context, options = {}) {
      const selected = registry.select(ids);
      const effectiveFailFast = options.failFast ?? failFast;
      // Validated here as well as in `buildAnalysisContext`: an engine called with
      // a hand-built context must fail closed rather than hand rules something that
      // is not a contract instance.
      const validatedContext = validateAnalysisContext(context);
      return runSelected({
        selected,
        context: validatedContext,
        failFast: effectiveFailFast,
        clock,
      });
    },
  };

  return Object.freeze(engine);
}

/** Execute one selection. */
async function runSelected({ selected, context, failFast, clock }) {
  const startedAt = clock();
  const repository = context.repository;

  // Run-global evidence-id registry, seeded with the model's reserved ids before
  // any rule executes. An id accepted from one rule is reserved for the rest of
  // the run.
  const runEvidenceIds = new Set(Object.keys(repository.indexes?.evidenceById ?? {}));

  const ruleResults = [];
  let aborted = false;

  for (const rule of selected) {
    if (aborted) {
      ruleResults.push(skippedResult(rule));
      continue;
    }

    const ruleStartedAt = clock();
    const result = await evaluateRule(rule, context, {
      runEvidenceIds,
      durationMs: () => clock() - ruleStartedAt,
    });
    ruleResults.push(result);
    if (failFast && result.status === RULE_OUTCOME_STATUSES.FAILED) aborted = true;
  }

  const findings = ruleResults.flatMap((result) => result.findings);
  const evidenceById = new Map();
  for (const result of ruleResults) {
    for (const record of result.evidence) evidenceById.set(record.id, record);
  }
  const evidence = [...evidenceById.keys()].sort().map((id) => evidenceById.get(id));

  const abnormal = ruleResults.filter((result) =>
    ABNORMAL_RULE_STATUSES.includes(result.status),
  );

  const aggregate = createRuleRunResult({
    version: RULE_ENGINE_VERSION,
    repository: repositorySummary(repository),
    rules: ruleResults,
    findings,
    evidence,
    errors: collectErrors(ruleResults),
    metadata: {
      engineVersion: RULE_ENGINE_VERSION,
      selectedRules: selected.map((rule) => rule.id),
      selectedCount: selected.length,
      evaluated: ruleResults.filter(
        (result) => result.status === RULE_OUTCOME_STATUSES.VIOLATION || result.status === RULE_OUTCOME_STATUSES.PASS,
      ).length,
      notApplicable: ruleResults.filter(
        (result) => result.status === RULE_OUTCOME_STATUSES.NOT_APPLICABLE,
      ).length,
      unknown: ruleResults.filter((result) => result.status === RULE_OUTCOME_STATUSES.UNKNOWN)
        .length,
      failed: ruleResults.filter((result) => result.status === RULE_OUTCOME_STATUSES.FAILED)
        .length,
      skipped: ruleResults.filter((result) => result.status === RULE_OUTCOME_STATUSES.SKIPPED)
        .length,
      failFast,
      repositoryCoverage: repository.scan.coverage.guarantee,
    },
    durationMs: clock() - startedAt,
    complete: abnormal.length === 0,
  });

  const validated = validateRuleRunResult(aggregate);
  return deepFreeze(validated);
}

/** A defined outcome for a rule the run never reached. */
function skippedResult(rule) {
  const result = createRuleEvaluationResult({
    rule: ruleSummary(rule),
    status: RULE_OUTCOME_STATUSES.SKIPPED,
    applicability: null,
    findings: [],
    evidence: [],
    metrics: {},
    metadata: {},
    errors: [
      ruleFailureEntry("skipped because an earlier rule failed and fail-fast is enabled", {
        kind: RULE_FAILURE_KINDS.FAIL_FAST_ABORT,
        ruleId: rule.id,
      }),
    ],
    durationMs: 0,
  });
  validateRuleEvaluationResult(result);
  return deepFreeze(result);
}

/** Aggregate every rule failure into one deterministically ordered list. */
function collectErrors(ruleResults) {
  const errors = [];
  for (const result of ruleResults) {
    for (const entry of result.errors) errors.push(entry);
  }
  return errors.sort((a, b) => {
    const keyA = `${a.ruleId ?? ""}\u0000${a.kind}\u0000${a.code}\u0000${a.message}`;
    const keyB = `${b.ruleId ?? ""}\u0000${b.kind}\u0000${b.code}\u0000${b.message}`;
    return keyA < keyB ? -1 : keyA > keyB ? 1 : 0;
  });
}

/** Convenience predicate: did every selected rule produce a clean outcome? */
export function isRuleRunComplete(result) {
  return isPlainObject(result) && result.complete === true;
}

/** The findings one rule contributed to an aggregate result. */
export function findingsForRule(result, ruleId) {
  const entry = result.rules.find((candidate) => candidate.rule.id === ruleId);
  return entry === undefined ? [] : [...entry.findings];
}

export { stableAnalysisView };
