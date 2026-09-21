/**
 * Code Guardian — Rule Evaluation (Phase 10)
 *
 * This module is the isolation boundary for one rule. Nothing a rule does — throw,
 * return nonsense, produce a malformed finding, try to cite evidence it does not
 * own — escapes as an exception that would stop a rule run. Every possible outcome
 * becomes a structured, validated rule evaluation result.
 *
 * ### The Core `detect` contract, interpreted
 *
 * Core says a rule's `detect(context)` returns `Finding[] | Promise<Finding[]>`. The
 * engine honours that, and additionally accepts a small structured form
 * (`{ findings, evidence }`) so a rule can record a *derived* observation using the
 * Phase 9 Evidence contract rather than inventing a second evidence system.
 *
 * What the engine does with the return value:
 *
 *   - **applicability gates detection.** A rule that does not apply is never run;
 *     its status is `not-applicable`, or `unknown` when the model's coverage was
 *     too limited to conclude.
 *   - **findings stay raw.** The engine fills the rule's static identity
 *     (`ruleId`, `category`, `severity`, `title`, `description`) so the draft is
 *     self-contained, and requires the rule to supply `confidence` — an assertion
 *     of certainty is the rule's to make, never the engine's. It never fingerprints:
 *     canonicalization belongs to the Phase 9 Finding Engine.
 *   - **evidence is provenance-safe.** A finding may cite the RepositoryModel's own
 *     evidence or evidence this rule emitted in this evaluation, and nothing else.
 *     Emitted evidence must be a valid Evidence record, must locate a
 *     repository-relative path, and must not reuse an id already reserved in the
 *     run (the same run-global uniqueness Phase 9 enforces).
 *
 * ### Statuses
 *
 *   not-applicable  applicability was false and coverage was complete
 *   unknown         applicability could not be decided because coverage is incomplete
 *   pass            the rule applied and produced no findings
 *   violation       the rule applied and produced at least one finding
 *   failed          the rule, or its output, violated the contract
 */

import {
  FINDING_SEVERITIES,
  isValidConfidence,
  validateEvidence,
  validateRule,
} from "../core/index.js";
import { isRepositoryRelativePath } from "../repository/model/index.js";

import { deepFreeze, sanitizeDeclarativeValue } from "../analysis/index.js";

import { evaluateRuleApplicability } from "./applicability.js";
import {
  APPLICABILITY_COVERAGE,
  MAX_IDENTIFIER_LENGTH,
  RULE_FAILURE_KINDS,
  RULE_OUTCOME_STATUSES,
} from "./contracts.js";
import { RuleFrameworkError, ruleFailureEntry } from "./errors.js";
import { createRuleEvaluationResult, validateRuleEvaluationResult } from "./results.js";

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

/** The identity fields a rule result records for attribution. */
export function ruleSummary(rule) {
  return {
    id: rule.id,
    version: rule.version,
    category: rule.category,
    severity: rule.severity,
    title: rule.title,
  };
}

function invalidFinding(rule, message, details = {}) {
  return new RuleFrameworkError(RULE_FAILURE_KINDS.INVALID_FINDING, message, {
    ruleId: rule?.id ?? null,
    ...details,
  });
}

/** Build a `{ findings, evidence }` detection object a rule may return. */
export function createRuleDetection(input = {}) {
  return {
    findings: input.findings ?? [],
    evidence: input.evidence ?? [],
  };
}

/**
 * Interpret a rule's `detect()` return value.
 *
 * Accepts the Core shape (an array of findings) and the structured detection
 * object. Absent collections are empty; anything else is a contract violation
 * rather than a rule that quietly did nothing.
 */
function interpretDetection(raw, rule) {
  if (raw === undefined || raw === null) return { findings: [], evidence: [] };
  if (Array.isArray(raw)) return { findings: raw, evidence: [] };
  if (isPlainObject(raw)) {
    const findings = raw.findings ?? [];
    const evidence = raw.evidence ?? [];
    if (!Array.isArray(findings)) {
      throw new RuleFrameworkError(
        RULE_FAILURE_KINDS.INVALID_RULE_RESULT,
        "detect() returned a detection object whose findings is not an array",
        { ruleId: rule.id },
      );
    }
    if (!Array.isArray(evidence)) {
      throw new RuleFrameworkError(
        RULE_FAILURE_KINDS.INVALID_RULE_RESULT,
        "detect() returned a detection object whose evidence is not an array",
        { ruleId: rule.id },
      );
    }
    return { findings, evidence };
  }
  throw new RuleFrameworkError(
    RULE_FAILURE_KINDS.INVALID_RULE_RESULT,
    "detect() must return an array of findings or a { findings, evidence } detection object",
    { ruleId: rule.id },
  );
}

/**
 * Resolve the evidence a rule emitted, enforcing the run-global evidence-id rules.
 *
 * `ownEvidence` is the rule's local set (duplicate diagnostics and reference
 * scope); `runEvidence` is the run-global registry, seeded with the model's ids.
 * An id accepted from one rule is reserved for the remainder of the run, so a later
 * rule reusing it fails.
 */
function resolveRuleEvidence(records, rule, ownEvidence, runEvidence) {
  const accepted = [];
  for (const record of records) {
    let validated;
    try {
      validated = validateEvidence(record);
    } catch (error) {
      throw new RuleFrameworkError(
        RULE_FAILURE_KINDS.INVALID_EVIDENCE,
        "a rule emitted something that is not a valid Evidence record",
        { ruleId: rule.id, issues: error?.details?.issues ?? [] },
      );
    }

    const id = validated.id;
    if (ownEvidence.has(id) || runEvidence.has(id)) {
      throw new RuleFrameworkError(
        RULE_FAILURE_KINDS.DUPLICATE_EVIDENCE_ID,
        "a rule emitted evidence reusing an existing evidence id",
        { ruleId: rule.id, evidenceId: String(id) },
      );
    }
    if (!isRepositoryRelativePath(validated.location?.path)) {
      throw new RuleFrameworkError(
        RULE_FAILURE_KINDS.UNSAFE_EVIDENCE_PATH,
        "rule-emitted evidence must locate a repository-relative path",
        { ruleId: rule.id, evidenceId: String(id) },
      );
    }

    ownEvidence.add(id);
    runEvidence.add(id);
    accepted.push(validated);
  }
  return accepted;
}

/**
 * Turn rule-produced findings into self-contained raw finding drafts.
 *
 * The engine fills the rule's static identity and refuses to invent confidence, so
 * a draft carries everything the Phase 9 Finding Engine needs and nothing it could
 * misread.
 */
function normalizeRuleFindings(findings, rule, allowedEvidenceIds) {
  const out = [];
  for (const finding of findings) {
    if (!isPlainObject(finding)) {
      throw invalidFinding(rule, "a rule finding must be a plain object");
    }

    if (!isValidConfidence(finding.confidence)) {
      throw invalidFinding(
        rule,
        "a rule finding must declare confidence; the engine never asserts certainty on the rule's behalf",
      );
    }

    const category = finding.category ?? rule.category;
    if (typeof category !== "string" || category.trim() === "") {
      throw invalidFinding(rule, "a rule finding must declare a category (or inherit its rule's)");
    }

    const severity = finding.severity ?? rule.severity;
    if (!FINDING_SEVERITIES.includes(severity)) {
      throw invalidFinding(rule, `severity must be one of ${FINDING_SEVERITIES.join(", ")}`);
    }

    const title = finding.title ?? rule.title;
    if (
      typeof title !== "string" ||
      title.trim() === "" ||
      title.length > MAX_IDENTIFIER_LENGTH
    ) {
      throw invalidFinding(rule, "a rule finding must declare a bounded title (or inherit its rule's)");
    }

    const references = finding.evidence ?? [];
    if (!Array.isArray(references)) {
      throw invalidFinding(rule, "finding.evidence must be an array of evidence reference ids");
    }
    const evidence = [];
    for (const reference of references) {
      if (typeof reference !== "string" || reference.trim() === "") {
        throw invalidFinding(
          rule,
          "evidence entries must be evidence reference ids (strings), not embedded objects",
        );
      }
      if (!allowedEvidenceIds.has(reference)) {
        throw invalidFinding(
          rule,
          "a finding cites evidence that is neither in the repository model nor produced by this rule",
          { evidence: [reference] },
        );
      }
      if (!evidence.includes(reference)) evidence.push(reference);
    }
    evidence.sort();

    out.push({
      ruleId: finding.ruleId ?? rule.id,
      category,
      severity,
      title,
      description: finding.description ?? rule.description ?? "",
      confidence: finding.confidence,
      evidence,
      status: finding.status,
      metadata: isPlainObject(finding.metadata) ? finding.metadata : {},
      impact: finding.impact,
      remediation: finding.remediation ?? rule.remediation,
    });
  }
  return out;
}

/** Assemble one evaluation result and validate it. */
function buildResult(input) {
  const result = createRuleEvaluationResult(input);
  validateRuleEvaluationResult(result);
  return deepFreeze(result);
}

/** A failed outcome for a rule the engine could not evaluate. */
function failedResult(summary, { kind, error, ruleId, details = {}, durationMs }) {
  return buildResult({
    rule: summary,
    status: RULE_OUTCOME_STATUSES.FAILED,
    applicability: null,
    findings: [],
    evidence: [],
    metrics: {},
    metadata: {},
    errors: [ruleFailureEntry(error, { kind, ruleId, details })],
    durationMs,
  });
}

/**
 * Evaluate one rule, converting every possible outcome into a result object.
 *
 * @param {object} rule A registered rule.
 * @param {object} context A validated AnalysisContext.
 * @param {object} [options]
 * @param {Set<string>} [options.runEvidenceIds] Run-global reserved evidence ids.
 * @param {Function} [options.durationMs] Reads elapsed time for this rule.
 * @returns {Promise<object>} A frozen, validated rule evaluation result.
 */
export async function evaluateRule(rule, context, options = {}) {
  const summary = ruleSummary(rule);
  const durationMs = typeof options.durationMs === "function" ? options.durationMs : () => 0;

  // Defense in depth: a descriptor can be corrupted after registration, and a rule
  // that cannot be evaluated is a framework observation about that rule, not a crash.
  try {
    validateRule(rule);
  } catch (error) {
    return failedResult(summary, {
      kind: RULE_FAILURE_KINDS.INVALID_RULE,
      error,
      ruleId: rule?.id ?? null,
      durationMs: durationMs(),
    });
  }

  let applicability;
  try {
    applicability = evaluateRuleApplicability(rule, context);
  } catch (error) {
    return failedResult(summary, {
      kind: error?.kind ?? RULE_FAILURE_KINDS.INVALID_APPLICABILITY,
      error,
      ruleId: rule.id,
      durationMs: durationMs(),
    });
  }

  if (applicability.applicable !== true) {
    const status =
      applicability.coverage === APPLICABILITY_COVERAGE.UNKNOWN
        ? RULE_OUTCOME_STATUSES.UNKNOWN
        : RULE_OUTCOME_STATUSES.NOT_APPLICABLE;
    return buildResult({
      rule: summary,
      status,
      applicability,
      findings: [],
      evidence: [],
      metrics: {},
      metadata: {},
      errors: [],
      durationMs: durationMs(),
    });
  }

  let raw;
  try {
    raw = await rule.detect(context);
  } catch (error) {
    return failedResult(summary, {
      kind: RULE_FAILURE_KINDS.RULE_FAILURE,
      error,
      ruleId: rule.id,
      durationMs: durationMs(),
    });
  }

  const modelEvidenceIds = new Set(Object.keys(context.repository.indexes?.evidenceById ?? {}));
  const runEvidenceIds = options.runEvidenceIds ?? new Set(modelEvidenceIds);
  const ownEvidence = new Set();

  let evidence;
  let findings;
  try {
    const detected = interpretDetection(raw, rule);
    evidence = resolveRuleEvidence(detected.evidence, rule, ownEvidence, runEvidenceIds);
    const allowedEvidenceIds = new Set([...modelEvidenceIds, ...ownEvidence]);
    findings = normalizeRuleFindings(detected.findings, rule, allowedEvidenceIds);
  } catch (error) {
    return failedResult(summary, {
      kind: error?.kind ?? RULE_FAILURE_KINDS.INVALID_RULE_RESULT,
      error,
      ruleId: rule.id,
      durationMs: durationMs(),
    });
  }

  // The result carries the observations the rule relied on — its own new records
  // plus the model records its findings cite, resolved to whole records.
  const cited = new Set(evidence.map((record) => record.id));
  for (const finding of findings) for (const id of finding.evidence) cited.add(id);
  const evidenceById = new Map(context.repository.evidence.map((record) => [record.id, record]));
  for (const record of evidence) evidenceById.set(record.id, record);
  const resolvedEvidence = [...cited]
    .sort()
    .map((id) => evidenceById.get(id))
    .filter((record) => record !== undefined);

  return buildResult({
    rule: summary,
    status:
      findings.length > 0 ? RULE_OUTCOME_STATUSES.VIOLATION : RULE_OUTCOME_STATUSES.PASS,
    applicability,
    findings,
    evidence: resolvedEvidence,
    metrics: sanitizeDeclarativeValue(raw?.metrics) ?? {},
    metadata: sanitizeDeclarativeValue(raw?.metadata) ?? {},
    errors: [],
    durationMs: durationMs(),
  });
}
