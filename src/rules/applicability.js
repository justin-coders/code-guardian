/**
 * Code Guardian — Rule Applicability (Phase 10)
 *
 * Applicability answers one question: *should this rule be evaluated against this
 * repository?* It is deliberately separate from detection, so a Python rule on a Go
 * repository is skipped rather than run and reported clean.
 *
 * ### The Core selector object is the declaration
 *
 * Core gives a Rule an `applicability` object of declarative selectors
 * (`languages`, `frameworks`, `files`, `capabilities`). This module evaluates those
 * selectors against the **RepositoryModel** — never the filesystem — and returns an
 * explicit `{ applicable, reason, coverage }` decision, which is the Phase 9
 * `{ applicable, reason }` convention plus one honest extra fact: whether the
 * model's coverage was good enough to conclude.
 *
 * ### `unknown` is not `absent`
 *
 * A selector is evaluated three ways, not two:
 *
 *   satisfied    the model observed (or the selector was established)
 *   unsatisfied  the scan was complete and covered the subject, and found nothing
 *   unknown      the scan did not cover the subject, so the engine cannot conclude
 *
 * A rule whose selector is unresolved because coverage is incomplete is reported
 * `unknown`, never `not-applicable`. Treating "not observed" as "absent" is exactly
 * the false-certainty Phase 8C/8D exist to prevent, and it would let a rule make an
 * absence-based claim about an inventory that was never complete.
 *
 * Multiple selector keys are combined with **AND**; multiple values inside one key
 * are combined with **OR** — the standard reading of a selector object.
 */

import {
  COVERAGE_CLASSES,
  ENTITY_KINDS,
  coverageClass,
  listEntitiesByKind,
} from "../repository/model/index.js";

import { deepFreeze } from "../analysis/index.js";

import {
  APPLICABILITY_COVERAGE,
  RULE_CAPABILITIES,
  RULE_FAILURE_KINDS,
  RULE_SELECTOR_KEYS,
} from "./contracts.js";
import { RuleFrameworkError } from "./errors.js";

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

/** Whether the model's scan covered the repository completely. */
function isComplete(model) {
  return model.scan.complete === true && model.scan.truncated !== true;
}

/** The language ids the model observed. */
function observedLanguages(model) {
  const ids = new Set();
  for (const entity of listEntitiesByKind(model, ENTITY_KINDS.LANGUAGE)) {
    if (typeof entity.languageId === "string") ids.add(entity.languageId);
  }
  return ids;
}

/** The framework names the model observed. */
function observedFrameworks(model) {
  const names = new Set();
  for (const entity of listEntitiesByKind(model, ENTITY_KINDS.FRAMEWORK)) {
    if (typeof entity.name === "string") names.add(entity.name);
  }
  return names;
}

/** Model-derived capability facts: `source-code` iff a file has a resolved language. */
function observedCapabilities(model) {
  const capabilities = new Set();
  for (const entity of listEntitiesByKind(model, ENTITY_KINDS.FILE)) {
    if (typeof entity.languageId === "string" && entity.languageId !== null) {
      capabilities.add(RULE_CAPABILITIES.SOURCE_CODE);
      break;
    }
  }
  return capabilities;
}

const SATISFIED = "satisfied";
const UNSATISFIED = "unsatisfied";
const UNKNOWN = "unknown";

function evaluateLanguages(values, model, complete) {
  const observed = observedLanguages(model);
  if (values.some((id) => observed.has(id))) return { state: SATISFIED };
  const list = values.join(", ");
  if (complete) {
    return { state: UNSATISFIED, reason: `requires language: ${list}; none observed` };
  }
  return {
    state: UNKNOWN,
    reason: `requires language: ${list}; scan coverage is incomplete`,
  };
}

function evaluateFrameworks(values, model, complete) {
  const observed = observedFrameworks(model);
  if (values.some((name) => observed.has(name))) return { state: SATISFIED };
  const list = values.join(", ");
  if (complete) {
    return { state: UNSATISFIED, reason: `requires framework: ${list}; none observed` };
  }
  return {
    state: UNKNOWN,
    reason: `requires framework: ${list}; scan coverage is incomplete`,
  };
}

function evaluateFiles(values, model) {
  const absent = [];
  const unknown = [];
  for (const path of values) {
    const coverage = coverageClass(model, path);
    if (coverage === COVERAGE_CLASSES.OBSERVED) return { state: SATISFIED };
    if (coverage === COVERAGE_CLASSES.ABSENT) absent.push(path);
    else unknown.push(path);
  }
  if (unknown.length > 0) {
    return {
      state: UNKNOWN,
      reason: `requires path: ${unknown.join(", ")}; not covered by the scan`,
    };
  }
  return { state: UNSATISFIED, reason: `requires path: ${absent.join(", ")}; absent` };
}

function evaluateCapabilities(values, model, complete) {
  const observed = observedCapabilities(model);
  if (values.some((id) => observed.has(id))) return { state: SATISFIED };
  const unrecognized = values.filter((id) => id !== RULE_CAPABILITIES.SOURCE_CODE);
  if (unrecognized.length > 0 || !complete) {
    return {
      state: UNKNOWN,
      reason: `requires capability: ${values.join(", ")}; not established by the model`,
    };
  }
  return {
    state: UNSATISFIED,
    reason: `requires capability: ${values.join(", ")}; absent`,
  };
}

const EVALUATORS = Object.freeze({
  languages: evaluateLanguages,
  frameworks: evaluateFrameworks,
  files: evaluateFiles,
  capabilities: evaluateCapabilities,
});

/** Declared selector keys, in the Core vocabulary's order, for deterministic reasons. */
function declaredSelectors(applicability) {
  const declared = [];
  for (const key of RULE_SELECTOR_KEYS) {
    const value = applicability[key];
    if (Array.isArray(value) && value.length > 0) declared.push(key);
  }
  return declared;
}

/**
 * Evaluate a rule's applicability against the model.
 *
 * @param {object} rule A registered rule.
 * @param {object} context A validated AnalysisContext.
 * @returns {{applicable: boolean, reason: string|null, coverage: string}} Frozen.
 * @throws {RuleFrameworkError} kind `invalid-applicability` when the rule's
 *   `applicability` is not the contracted selector object.
 */
export function evaluateRuleApplicability(rule, context) {
  const applicability = rule?.applicability;
  if (!isPlainObject(applicability)) {
    throw new RuleFrameworkError(
      RULE_FAILURE_KINDS.INVALID_APPLICABILITY,
      "rule.applicability must be a selector object",
      { ruleId: rule?.id ?? null, returned: applicability === null ? "null" : typeof applicability },
    );
  }

  const model = context.repository;
  const complete = isComplete(model);
  const declared = declaredSelectors(applicability);
  if (declared.length === 0) {
    return deepFreeze({
      applicable: true,
      reason: null,
      coverage: APPLICABILITY_COVERAGE.COMPLETE,
    });
  }

  let definitive = false;
  let unknown = false;
  const reasons = [];

  for (const key of declared) {
    const outcome = EVALUATORS[key](applicability[key], model, complete);
    if (outcome.state === UNSATISFIED) {
      definitive = true;
      reasons.push(outcome.reason);
    } else if (outcome.state === UNKNOWN) {
      unknown = true;
      reasons.push(outcome.reason);
    }
  }

  if (definitive) {
    return deepFreeze({
      applicable: false,
      reason: reasons.join("; "),
      coverage: APPLICABILITY_COVERAGE.COMPLETE,
    });
  }
  if (unknown) {
    return deepFreeze({
      applicable: false,
      reason: reasons.join("; "),
      coverage: APPLICABILITY_COVERAGE.UNKNOWN,
    });
  }
  return deepFreeze({
    applicable: true,
    reason: null,
    coverage: APPLICABILITY_COVERAGE.COMPLETE,
  });
}
