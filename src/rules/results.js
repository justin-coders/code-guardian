/**
 * Code Guardian — Rule Results (Phase 10)
 *
 * Two result contracts, both shape/draft factories validated by a matching
 * validator — the same Core convention used throughout this codebase:
 *
 *   rule evaluation result  what one rule concluded: its status, the applicability
 *                           decision that gated it, the findings it produced, the
 *                           evidence those findings cite, its metrics and failures.
 *   rule run result         the aggregate: which repository was evaluated, every
 *                           rule result, the collected findings and evidence, and
 *                           the run metadata.
 *
 * Both carry **raw finding drafts**, not canonical findings. Canonicalization
 * (fingerprinting, id assignment, evidence re-resolution) is the Phase 9 Finding
 * Engine's job, and the Rule Engine deliberately does not duplicate it: a rule
 * result is exactly the information that pipeline needs.
 *
 * Neither result can express a judgment. There is no score, grade, verdict or
 * readiness field anywhere, and the validator keeps it that way.
 *
 * `durationMs` is the only non-deterministic field. It is metadata: it never
 * participates in an identity or an ordering, and `stableAnalysisView` (shared with
 * Phase 9) removes it so two runs of the same model and rules compare byte for byte.
 */

import { ValidationError, validateEvidence } from "../core/index.js";

import { stableAnalysisView } from "../analysis/index.js";

import {
  ABNORMAL_RULE_STATUSES,
  APPLICABILITY_COVERAGE,
  RULE_ENGINE_VERSION,
  RULE_FAILURE_KINDS,
  RULE_OUTCOME_STATUSES,
  RULE_OUTCOME_STATUS_VALUES,
} from "./contracts.js";

const FAILURE_KINDS = Object.freeze(Object.values(RULE_FAILURE_KINDS));
const COVERAGE_VALUES = Object.freeze(Object.values(APPLICABILITY_COVERAGE));

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isNonEmptyString(value) {
  return typeof value === "string" && value.trim() !== "";
}

function isNonNegativeNumber(value) {
  return typeof value === "number" && Number.isFinite(value) && value >= 0;
}

/** Fields every rule evaluation result declares. */
export const RULE_EVALUATION_FIELDS = Object.freeze([
  "rule",
  "status",
  "applicability",
  "findings",
  "evidence",
  "metrics",
  "metadata",
  "errors",
  "durationMs",
]);

/** Fields the aggregate rule run result declares. */
export const RULE_RUN_FIELDS = Object.freeze([
  "version",
  "repository",
  "rules",
  "findings",
  "evidence",
  "errors",
  "metadata",
  "durationMs",
  "complete",
]);

/**
 * Build a rule evaluation result draft.
 *
 * Defaults are semantically neutral: a draft describes a rule that produced
 * nothing, and never claims a status the caller did not set.
 *
 * @param {object} [input]
 * @returns {object} A RuleEvaluationResult-shaped draft; run the validator first.
 */
export function createRuleEvaluationResult(input = {}) {
  return {
    rule: input.rule ?? {},
    status: input.status,
    applicability: input.applicability ?? null,
    findings: input.findings ?? [],
    evidence: input.evidence ?? [],
    metrics: input.metrics ?? {},
    metadata: input.metadata ?? {},
    errors: input.errors ?? [],
    durationMs: input.durationMs ?? 0,
  };
}

/**
 * Build an aggregate rule run result draft.
 *
 * @param {object} [input]
 * @returns {object} A RuleRunResult-shaped draft; run the validator first.
 */
export function createRuleRunResult(input = {}) {
  return {
    version: input.version ?? RULE_ENGINE_VERSION,
    repository: input.repository ?? {},
    rules: input.rules ?? [],
    findings: input.findings ?? [],
    evidence: input.evidence ?? [],
    errors: input.errors ?? [],
    metadata: input.metadata ?? {},
    durationMs: input.durationMs ?? 0,
    complete: input.complete ?? false,
  };
}

function collectFailureEntryIssues(entry, fail, path) {
  if (!isPlainObject(entry)) {
    fail(path, "must be a plain object");
    return;
  }
  if (!FAILURE_KINDS.includes(entry.kind)) {
    fail(`${path}.kind`, `must be one of: ${FAILURE_KINDS.join(", ")}`);
  }
  if (!isNonEmptyString(entry.code)) fail(`${path}.code`, "must be a stable non-empty code");
  if (!isNonEmptyString(entry.message)) fail(`${path}.message`, "must be a non-empty message");
  if (entry.ruleId !== null && !isNonEmptyString(entry.ruleId)) {
    fail(`${path}.ruleId`, "must be a non-empty string or null");
  }
  if ("details" in entry && !isPlainObject(entry.details)) {
    fail(`${path}.details`, "must be a plain object");
  }
}

function collectEvidenceIssues(value, fail, path) {
  if (!Array.isArray(value)) {
    fail(path, "must be an array of Evidence records");
    return;
  }
  value.forEach((record, index) => {
    try {
      validateEvidence(record);
    } catch (error) {
      const reported = error?.details?.issues ?? ["must be a valid Evidence record"];
      for (const issue of reported) fail(`${path}[${index}]`, issue);
    }
  });
}

function collectApplicabilityIssues(value, fail, path) {
  if (value === null) return;
  if (!isPlainObject(value)) {
    fail(path, "must be null or { applicable: boolean, reason: string|null, coverage }");
    return;
  }
  if (typeof value.applicable !== "boolean") {
    fail(`${path}.applicable`, "must be a boolean");
  }
  if (value.reason !== null && typeof value.reason !== "string") {
    fail(`${path}.reason`, "must be a string or null");
  }
  if (!COVERAGE_VALUES.includes(value.coverage)) {
    fail(`${path}.coverage`, `must be one of: ${COVERAGE_VALUES.join(", ")}`);
  }
}

/**
 * Validate a rule evaluation result.
 *
 * @param {unknown} value
 * @returns {object} The same value when valid.
 * @throws {ValidationError} Listing every violation.
 */
export function validateRuleEvaluationResult(value) {
  const issues = [];
  const fail = (path, message) => issues.push(`${path}: ${message}`);

  if (!isPlainObject(value)) {
    throw new ValidationError("Invalid rule evaluation result", {
      details: { contract: "RuleEvaluationResult", issues: ["result: must be a plain object"] },
    });
  }

  for (const field of RULE_EVALUATION_FIELDS) {
    if (!(field in value)) fail(`ruleEvaluationResult.${field}`, "is required");
  }

  const rule = value.rule;
  if (!isPlainObject(rule)) {
    fail("ruleEvaluationResult.rule", "must be a plain object");
  } else {
    for (const field of ["id", "version", "category", "severity", "title"]) {
      if (!isNonEmptyString(rule[field])) {
        fail(`ruleEvaluationResult.rule.${field}`, "must be a non-empty string");
      }
    }
  }

  if (!RULE_OUTCOME_STATUS_VALUES.includes(value.status)) {
    fail("ruleEvaluationResult.status", `must be one of: ${RULE_OUTCOME_STATUS_VALUES.join(", ")}`);
  }

  collectApplicabilityIssues(value.applicability, fail, "ruleEvaluationResult.applicability");

  if (!Array.isArray(value.findings)) {
    fail("ruleEvaluationResult.findings", "must be an array of raw finding drafts");
  } else {
    value.findings.forEach((finding, index) => {
      if (!isPlainObject(finding)) {
        fail(`ruleEvaluationResult.findings[${index}]`, "must be a plain object");
      }
    });
  }

  collectEvidenceIssues(value.evidence, fail, "ruleEvaluationResult.evidence");

  for (const field of ["metrics", "metadata"]) {
    if (!isPlainObject(value[field])) {
      fail(`ruleEvaluationResult.${field}`, "must be a plain object");
    }
  }

  if (!Array.isArray(value.errors)) {
    fail("ruleEvaluationResult.errors", "must be an array");
  } else {
    value.errors.forEach((entry, index) =>
      collectFailureEntryIssues(entry, fail, `ruleEvaluationResult.errors[${index}]`),
    );
  }

  if (!isNonNegativeNumber(value.durationMs)) {
    fail("ruleEvaluationResult.durationMs", "must be a non-negative number (metadata only)");
  }

  // Status/result coherence: a status must not overstate what the rule did.
  const applicability = value.applicability;
  if (value.status === RULE_OUTCOME_STATUSES.NOT_APPLICABLE) {
    if (!isPlainObject(applicability) || applicability.applicable !== false) {
      fail("ruleEvaluationResult.applicability", "a not-applicable rule must record applicable === false");
    }
    if (Array.isArray(value.findings) && value.findings.length > 0) {
      fail("ruleEvaluationResult.findings", "a not-applicable rule cannot produce findings");
    }
  }
  if (value.status === RULE_OUTCOME_STATUSES.UNKNOWN) {
    if (!isPlainObject(applicability) || applicability.coverage !== APPLICABILITY_COVERAGE.UNKNOWN) {
      fail(
        "ruleEvaluationResult.applicability",
        "an unknown rule must record unknown coverage",
      );
    }
    if (Array.isArray(value.findings) && value.findings.length > 0) {
      fail("ruleEvaluationResult.findings", "an unknown rule cannot produce findings");
    }
  }
  if (
    value.status === RULE_OUTCOME_STATUSES.PASS &&
    Array.isArray(value.findings) &&
    value.findings.length > 0
  ) {
    fail("ruleEvaluationResult.findings", "a passing rule cannot produce findings");
  }
  if (
    value.status === RULE_OUTCOME_STATUSES.VIOLATION &&
    Array.isArray(value.findings) &&
    value.findings.length === 0
  ) {
    fail("ruleEvaluationResult.findings", "a violation must produce at least one finding");
  }
  if (
    value.status === RULE_OUTCOME_STATUSES.FAILED &&
    Array.isArray(value.errors) &&
    value.errors.length === 0
  ) {
    fail("ruleEvaluationResult.errors", "a failed rule must record at least one failure");
  }
  if (value.status === RULE_OUTCOME_STATUSES.SKIPPED) {
    if (applicability !== null) {
      fail("ruleEvaluationResult.applicability", "a skipped rule was never evaluated");
    }
    if (Array.isArray(value.findings) && value.findings.length > 0) {
      fail("ruleEvaluationResult.findings", "a skipped rule cannot produce findings");
    }
    if (Array.isArray(value.errors) && value.errors.length === 0) {
      fail("ruleEvaluationResult.errors", "a skipped rule must record why it was skipped");
    }
  }

  if (issues.length > 0) {
    throw new ValidationError("Invalid rule evaluation result", {
      details: { contract: "RuleEvaluationResult", issues },
    });
  }

  return value;
}

/**
 * Validate the aggregate rule run result.
 *
 * @param {unknown} value
 * @returns {object} The same value when valid.
 * @throws {ValidationError} Listing every violation.
 */
export function validateRuleRunResult(value) {
  const issues = [];
  const fail = (path, message) => issues.push(`${path}: ${message}`);

  if (!isPlainObject(value)) {
    throw new ValidationError("Invalid rule run result", {
      details: { contract: "RuleRunResult", issues: ["result: must be a plain object"] },
    });
  }

  for (const field of RULE_RUN_FIELDS) {
    if (!(field in value)) fail(`ruleRunResult.${field}`, "is required");
  }

  if (!isNonEmptyString(value.version)) {
    fail("ruleRunResult.version", "must be a non-empty version string");
  }

  const repository = value.repository;
  if (!isPlainObject(repository)) {
    fail("ruleRunResult.repository", "must be a plain object");
  } else {
    if (!isNonEmptyString(repository.repositoryId)) {
      fail("ruleRunResult.repository.repositoryId", "must be a non-empty string");
    }
    if (!isNonEmptyString(repository.root)) {
      fail("ruleRunResult.repository.root", "must be a non-empty string");
    }
    if (!isPlainObject(repository.coverage)) {
      fail("ruleRunResult.repository.coverage", "must be a plain object");
    }
  }

  if (!Array.isArray(value.rules)) {
    fail("ruleRunResult.rules", "must be an array");
  } else {
    const ruleIds = [];
    value.rules.forEach((result, index) => {
      const path = `ruleRunResult.rules[${index}]`;
      if (!isPlainObject(result)) {
        fail(path, "must be a rule evaluation result");
        return;
      }
      try {
        validateRuleEvaluationResult(result);
      } catch (error) {
        const reported = error?.details?.issues ?? ["invalid rule evaluation result"];
        for (const issue of reported) fail(path, issue);
      }
      if (isNonEmptyString(result.rule?.id)) ruleIds.push(result.rule.id);
    });
    const sorted = [...ruleIds].sort();
    if (ruleIds.join("\u0000") !== sorted.join("\u0000")) {
      fail("ruleRunResult.rules", "must be sorted by rule id");
    }
    if (new Set(ruleIds).size !== ruleIds.length) {
      fail("ruleRunResult.rules", "must not contain a rule twice");
    }
  }

  if (!Array.isArray(value.findings)) {
    fail("ruleRunResult.findings", "must be an array of raw finding drafts");
  } else {
    value.findings.forEach((finding, index) => {
      if (!isPlainObject(finding)) {
        fail(`ruleRunResult.findings[${index}]`, "must be a plain object");
      }
    });
  }

  collectEvidenceIssues(value.evidence, fail, "ruleRunResult.evidence");

  if (!Array.isArray(value.errors)) {
    fail("ruleRunResult.errors", "must be an array");
  } else {
    value.errors.forEach((entry, index) =>
      collectFailureEntryIssues(entry, fail, `ruleRunResult.errors[${index}]`),
    );
    const keys = value.errors.map(
      (entry) => `${entry?.ruleId ?? ""}\u0000${entry?.kind ?? ""}\u0000${entry?.code ?? ""}`,
    );
    const sorted = [...keys].sort();
    if (keys.join("\u0002") !== sorted.join("\u0002")) {
      fail("ruleRunResult.errors", "must be sorted deterministically");
    }
  }

  if (!isPlainObject(value.metadata)) {
    fail("ruleRunResult.metadata", "must be a plain object");
  }
  if (!isNonNegativeNumber(value.durationMs)) {
    fail("ruleRunResult.durationMs", "must be a non-negative number (metadata only)");
  }
  if (typeof value.complete !== "boolean") {
    fail("ruleRunResult.complete", "must be a boolean");
  }

  if (Array.isArray(value.rules) && typeof value.complete === "boolean") {
    const abnormal = value.rules.filter((result) =>
      ABNORMAL_RULE_STATUSES.includes(result?.status),
    );
    if (value.complete === true && abnormal.length > 0) {
      fail("ruleRunResult.complete", "cannot be true while a rule failed or is unknown");
    }
    if (value.complete === false && abnormal.length === 0) {
      fail("ruleRunResult.complete", "must be false when a rule failed or is unknown");
    }
  }

  if (issues.length > 0) {
    throw new ValidationError("Invalid rule run result", {
      details: { contract: "RuleRunResult", issues },
    });
  }

  return value;
}

export { stableAnalysisView };
