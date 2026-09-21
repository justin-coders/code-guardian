/**
 * Code Guardian — Rule Engine Contracts (Phase 10)
 *
 * Vocabulary for the rule *engine*: what a rule evaluation can conclude, and why
 * one failed. Domain vocabulary (severities, categories, rule metadata) belongs
 * to the Core contracts, and nothing here redefines it.
 *
 * ### The Core Rule contract is the authority
 *
 * Phase 7 already defines a Rule (`src/core/contracts/rule.js`): identity and
 * metadata plus an `applicability` selector object and a `detect(context)`
 * function. That shape matches the architecture specification (Rule Engine §13,
 * Rule Applicability §14) exactly, so Phase 10 does **not** redesign it. The Rule
 * Engine adds the parts Core deliberately left to a later phase:
 *
 *   - a registry that validates and orders rules;
 *   - an evaluator that turns a rule's declarative applicability selectors into an
 *     explicit `{ applicable, reason }` decision against the RepositoryModel;
 *   - a structured outcome around `detect`'s return value (`pass`, `violation`,
 *     `not-applicable`, `unknown`, `failed`);
 *   - isolation and deterministic ordering for a whole rule run.
 *
 * ### Statuses are a different axis from Phase 9 analyzer statuses
 *
 * `ANALYZER_RUN_STATUSES` (Phase 9) describes what happened to an *analyzer* in a
 * run. `RULE_OUTCOME_STATUSES` here describes what an *evaluation* concluded. They
 * are not competing vocabularies: a RuleAnalyzer is `completed` while the rules it
 * ran report `pass`, `violation` or `unknown`.
 */

import { RULE_APPLICABILITY_KEYS } from "../core/index.js";

/** Version of the rule engine (result shapes, ordering, semantics). */
export const RULE_ENGINE_VERSION = "1.0.0";

/**
 * The outcome of evaluating one rule against one AnalysisContext.
 *
 *   pass            the rule applied and its condition did not hold
 *   violation       the rule applied and its condition held (findings produced)
 *   not-applicable  the rule does not apply to this repository, and the model
 *                   coverage is complete enough to establish that
 *   unknown         the rule could not be evaluated — applicability depends on
 *                   something the scan did not cover. This is deliberately *not*
 *                   `not-applicable`: "not observed" is not "absent".
 *   failed          the rule (or its output) violated the contract
 *   skipped         the run stopped before reaching it (fail-fast only)
 */
export const RULE_OUTCOME_STATUSES = Object.freeze({
  PASS: "pass",
  VIOLATION: "violation",
  NOT_APPLICABLE: "not-applicable",
  UNKNOWN: "unknown",
  FAILED: "failed",
  SKIPPED: "skipped",
});

/** Terminal statuses a rule evaluation can reach. */
export const RULE_OUTCOME_STATUS_VALUES = Object.freeze(Object.values(RULE_OUTCOME_STATUSES));

/** Statuses that make a rule run incomplete. */
export const ABNORMAL_RULE_STATUSES = Object.freeze([
  RULE_OUTCOME_STATUSES.FAILED,
  RULE_OUTCOME_STATUSES.UNKNOWN,
  RULE_OUTCOME_STATUSES.SKIPPED,
]);

/**
 * Why a rule did not produce a clean outcome.
 *
 * The failure semantics Phase 10 must keep apart (not-applicable and unknown are
 * *statuses*, not kinds, and never appear here):
 *
 *   invalid-rule            the registered descriptor was corrupted after
 *                           registration, or a descriptor is malformed
 *   duplicate-rule          a rule id is already registered
 *   unknown-rule            an id was selected that is not registered
 *   invalid-applicability   `rule.applicability` is not the contracted selector
 *                           object, or applicability evaluation returned nonsense
 *   rule-failure            `detect()` threw or rejected
 *   invalid-rule-result     `detect()` returned something that is not a finding
 *                           list or a rule detection object
 *   invalid-finding         a produced finding violated the Finding draft contract
 *   invalid-evidence        a rule emitted evidence that is not a valid Evidence
 *   unsafe-evidence-path    a rule emitted evidence outside the repository
 *   duplicate-evidence-id   a rule emitted evidence reusing another id in this run
 *   fail-fast-abort         recorded on rules skipped because a previous rule
 *                           failed and fail-fast was requested
 */
export const RULE_FAILURE_KINDS = Object.freeze({
  INVALID_RULE: "invalid-rule",
  DUPLICATE_RULE: "duplicate-rule",
  UNKNOWN_RULE: "unknown-rule",
  INVALID_APPLICABILITY: "invalid-applicability",
  RULE_FAILURE: "rule-failure",
  INVALID_RULE_RESULT: "invalid-rule-result",
  INVALID_FINDING: "invalid-finding",
  INVALID_EVIDENCE: "invalid-evidence",
  UNSAFE_EVIDENCE_PATH: "unsafe-evidence-path",
  DUPLICATE_EVIDENCE_ID: "duplicate-evidence-id",
  FAIL_FAST_ABORT: "fail-fast-abort",
});

/**
 * Stable codes carried by recorded rule failures.
 *
 * `analysis` codes mean a rule produced bad output; `configuration` codes mean
 * the engine was asked to do something impossible (an unknown or duplicate id).
 * The split mirrors the Core error categories and the Phase 9 convention.
 */
export const RULE_FAILURE_CODES = Object.freeze({
  invalidRule: "CG_RULE_INVALID",
  duplicateRule: "CG_RULE_DUPLICATE",
  unknownRule: "CG_RULE_UNKNOWN",
  invalidApplicability: "CG_RULE_APPLICABILITY_INVALID",
  threw: "CG_RULE_THREW",
  invalidRuleResult: "CG_RULE_RESULT_INVALID",
  invalidFinding: "CG_RULE_FINDING_INVALID",
  invalidEvidence: "CG_RULE_EVIDENCE_INVALID",
  unsafeEvidencePath: "CG_RULE_EVIDENCE_PATH_UNSAFE",
  duplicateEvidenceId: "CG_RULE_EVIDENCE_ID_DUPLICATE",
  failFastAbort: "CG_RULE_SKIPPED",
});

/**
 * Rule id shape: lower-case, dot-separated namespaces (`security.hardcoded-secret`,
 * `testing.missing-test`). Enforced at registration so ids stay stable, sortable
 * and usable as namespaced selectors — never random, never host-derived.
 */
export const RULE_ID_PATTERN = /^[a-z0-9][a-z0-9-]*(?:\.[a-z0-9][a-z0-9-]*)*$/;

/**
 * The selector keys a rule's `applicability` object may declare.
 *
 * Re-exported from the Core contract rather than redefined: a rule that Core
 * accepts must not be rejected by the engine for using a documented selector, and
 * a selector added to Core becomes available here automatically.
 */
export const RULE_SELECTOR_KEYS = RULE_APPLICABILITY_KEYS;

/**
 * Model-derived capabilities.
 *
 * A rule may declare `applicability.capabilities` (Core vocabulary). The
 * RepositoryModel does not carry a capability list, so the engine derives the
 * capabilities it can establish **from observed entities only**:
 *
 *   source-code   at least one observed file carries a resolved language
 *
 * A capability the model cannot establish is reported as `unknown` coverage, never
 * as an absent capability, so a rule requiring it is skipped rather than run
 * against an incomplete inventory. Capability ids are validated for shape only —
 * the vocabulary is open, so a later phase can teach the engine new capabilities
 * without a contract change.
 */
export const RULE_CAPABILITIES = Object.freeze({
  SOURCE_CODE: "source-code",
});

/** How much the model lets the engine conclude about an applicability selector. */
export const APPLICABILITY_COVERAGE = Object.freeze({
  COMPLETE: "complete",
  UNKNOWN: "unknown",
});

/** Bounds applied to rule-supplied identity text. */
export const MAX_IDENTIFIER_LENGTH = 120;
export const MAX_ERROR_MESSAGE_LENGTH = 500;
