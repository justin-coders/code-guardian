/**
 * Code Guardian Core — Contract Validation
 *
 * Lightweight, dependency-free validation for the Core contracts.
 *
 * Every validator collects *all* issues and then throws a single
 * `ValidationError` whose `details.issues` lists them, so callers get a useful
 * report instead of a single opaque failure. Validators return the validated
 * value on success so they compose (`const f = validateFinding(input)`).
 *
 * This module validates shapes only. It performs no scanning, no execution,
 * and imports no transports.
 */

import { ValidationError } from "../errors/core-error.js";
import {
  REPOSITORY_MODEL_AREAS,
  SCAN_REQUIRED_FIELDS,
} from "../contracts/repository-model.js";
import { EVIDENCE_TYPES } from "../contracts/evidence.js";
import {
  FINDING_SEVERITIES,
  FINDING_STATUSES,
  CONFIDENCE_MIN,
  CONFIDENCE_MAX,
  isValidConfidence,
} from "../contracts/finding.js";
import { VERSION_PATTERN } from "../contracts/rule.js";
import { ANALYSIS_RESULT_FIELDS } from "../contracts/analyzer.js";
import { ANALYSIS_CONTEXT_FIELDS } from "../contracts/analysis-context.js";
import {
  EXECUTION_REQUEST_FIELDS,
  EXECUTION_RESULT_FIELDS,
} from "../contracts/execution.js";

// ─── Primitive checks ────────────────────────────────────────────────────────

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isNonEmptyString(value) {
  return typeof value === "string" && value.trim().length > 0;
}

function isNonNegativeInteger(value) {
  return Number.isInteger(value) && value >= 0;
}

function isNonNegativeNumber(value) {
  return typeof value === "number" && Number.isFinite(value) && value >= 0;
}

function isPositiveInteger(value) {
  return Number.isInteger(value) && value > 0;
}

function isVersionString(value) {
  return typeof value === "string" && VERSION_PATTERN.test(value);
}

function isStringArray(value) {
  return (
    Array.isArray(value) && value.every((entry) => typeof entry === "string")
  );
}

// ─── Issue collector ─────────────────────────────────────────────────────────

function createIssueCollector() {
  const issues = [];
  return {
    issues,
    fail(path, message) {
      issues.push(`${path}: ${message}`);
    },
    throwIfInvalid(contract) {
      if (issues.length === 0) return;
      throw new ValidationError(`Invalid ${contract}`, {
        details: { contract, issues: [...issues] },
      });
    },
  };
}

function requireObject(value, ctx, path) {
  if (isPlainObject(value)) return true;
  ctx.fail(path, "must be a plain object");
  return false;
}

function requireField(object, field, ctx, path) {
  if (Object.prototype.hasOwnProperty.call(object, field)) return true;
  ctx.fail(`${path}.${field}`, "is required");
  return false;
}

function checkRequiredString(object, field, ctx, path) {
  if (!requireField(object, field, ctx, path)) return;
  if (!isNonEmptyString(object[field])) {
    ctx.fail(`${path}.${field}`, "must be a non-empty string");
  }
}

function checkOptionalObject(object, field, ctx, path) {
  if (!(field in object)) return;
  if (!isPlainObject(object[field])) {
    ctx.fail(`${path}.${field}`, "must be a plain object");
  }
}

function checkOptionalStringArray(object, field, ctx, path) {
  if (!(field in object)) return;
  if (!isStringArray(object[field])) {
    ctx.fail(`${path}.${field}`, "must be an array of strings");
  }
}

// ─── RepositoryModel ─────────────────────────────────────────────────────────

function collectScanIssues(scan, ctx, path) {
  if (!requireObject(scan, ctx, path)) return;

  for (const field of SCAN_REQUIRED_FIELDS) {
    requireField(scan, field, ctx, path);
  }
  if ("complete" in scan && typeof scan.complete !== "boolean") {
    ctx.fail(`${path}.complete`, "must be a boolean");
  }
  if ("truncated" in scan && typeof scan.truncated !== "boolean") {
    ctx.fail(`${path}.truncated`, "must be a boolean");
  }
  if ("limits" in scan && !isPlainObject(scan.limits)) {
    ctx.fail(`${path}.limits`, "must be a plain object");
  }
  if ("errors" in scan) {
    if (!Array.isArray(scan.errors)) {
      ctx.fail(`${path}.errors`, "must be an array");
    } else {
      scan.errors.forEach((entry, index) => {
        if (!isPlainObject(entry)) {
          ctx.fail(`${path}.errors[${index}]`, "must be a plain object");
        }
      });
    }
  }
  if (scan.truncated === true && scan.complete === true) {
    ctx.fail(
      path,
      "cannot be complete and truncated at once; a truncated scan must report complete: false",
    );
  }
}

function collectRepositoryModelIssues(value, ctx, path = "repositoryModel") {
  if (!requireObject(value, ctx, path)) return;

  checkRequiredString(value, "version", ctx, path);

  for (const area of REPOSITORY_MODEL_AREAS) {
    if (!(area in value)) {
      ctx.fail(`${path}.${area}`, "is required");
    }
  }

  if ("identity" in value && !isPlainObject(value.identity)) {
    ctx.fail(`${path}.identity`, "must be a plain object");
  }

  if ("files" in value) {
    if (!isPlainObject(value.files)) {
      ctx.fail(`${path}.files`, "must be a plain object");
    } else {
      if (!("entries" in value.files)) {
        ctx.fail(`${path}.files.entries`, "is required");
      } else if (!Array.isArray(value.files.entries)) {
        ctx.fail(`${path}.files.entries`, "must be an array");
      }
      if ("count" in value.files && !isNonNegativeInteger(value.files.count)) {
        ctx.fail(`${path}.files.count`, "must be a non-negative integer");
      }
      if (
        "truncated" in value.files &&
        typeof value.files.truncated !== "boolean"
      ) {
        ctx.fail(`${path}.files.truncated`, "must be a boolean");
      }
    }
  }

  for (const field of ["languages", "frameworks"]) {
    if (field in value && !Array.isArray(value[field])) {
      ctx.fail(`${path}.${field}`, "must be an array");
    }
  }

  for (const field of [
    "manifests",
    "dependencies",
    "scripts",
    "configuration",
    "git",
    "tests",
    "ci",
    "architecture",
    "metadata",
  ]) {
    if (field in value && !isPlainObject(value[field])) {
      ctx.fail(`${path}.${field}`, "must be a plain object");
    }
  }

  if ("scan" in value) {
    collectScanIssues(value.scan, ctx, `${path}.scan`);
  }
}

// ─── Evidence ────────────────────────────────────────────────────────────────

function collectLocationIssues(location, ctx, path) {
  if (!requireObject(location, ctx, path)) return;
  if ("path" in location && !isNonEmptyString(location.path)) {
    ctx.fail(`${path}.path`, "must be a non-empty string");
  }
  if ("line" in location && !isPositiveInteger(location.line)) {
    ctx.fail(`${path}.line`, "must be a positive integer");
  }
  if ("column" in location && !isPositiveInteger(location.column)) {
    ctx.fail(`${path}.column`, "must be a positive integer");
  }
}

function collectProvenanceIssues(provenance, ctx, path) {
  if (!requireObject(provenance, ctx, path)) return;
  if (!("deterministic" in provenance)) {
    ctx.fail(`${path}.deterministic`, "is required");
  } else if (typeof provenance.deterministic !== "boolean") {
    ctx.fail(`${path}.deterministic`, "must be a boolean");
  }
  if ("collector" in provenance && !isNonEmptyString(provenance.collector)) {
    ctx.fail(`${path}.collector`, "must be a non-empty string");
  }
  if ("timestamp" in provenance && typeof provenance.timestamp !== "string") {
    ctx.fail(`${path}.timestamp`, "must be a string");
  }
}

function collectEvidenceIssues(value, ctx, path = "evidence") {
  if (!requireObject(value, ctx, path)) return;

  checkRequiredString(value, "id", ctx, path);

  if (!requireField(value, "type", ctx, path)) {
    // missing type reported above
  } else if (!EVIDENCE_TYPES.includes(value.type)) {
    ctx.fail(`${path}.type`, `must be one of: ${EVIDENCE_TYPES.join(", ")}`);
  }

  if (!requireField(value, "location", ctx, path)) {
    // missing location reported above
  } else {
    collectLocationIssues(value.location, ctx, `${path}.location`);
  }

  if (!requireField(value, "source", ctx, path)) {
    // missing source reported above
  } else if (!isPlainObject(value.source)) {
    ctx.fail(`${path}.source`, "must be a plain object");
  }

  if (!requireField(value, "data", ctx, path)) {
    // missing data reported above
  } else if (!isPlainObject(value.data)) {
    ctx.fail(`${path}.data`, "must be a plain object");
  }

  if (!requireField(value, "provenance", ctx, path)) {
    // missing provenance reported above
  } else {
    collectProvenanceIssues(value.provenance, ctx, `${path}.provenance`);
  }
}

// ─── Finding ─────────────────────────────────────────────────────────────────

function collectFindingIssues(value, ctx, path = "finding") {
  if (!requireObject(value, ctx, path)) return;

  for (const field of ["id", "ruleId", "category", "title", "fingerprint"]) {
    checkRequiredString(value, field, ctx, path);
  }

  if (!requireField(value, "description", ctx, path)) {
    // missing description reported above
  } else if (typeof value.description !== "string") {
    ctx.fail(`${path}.description`, "must be a string");
  }

  if (!requireField(value, "severity", ctx, path)) {
    // missing severity reported above
  } else if (!FINDING_SEVERITIES.includes(value.severity)) {
    ctx.fail(
      `${path}.severity`,
      `must be one of: ${FINDING_SEVERITIES.join(", ")}`,
    );
  }

  if (!requireField(value, "confidence", ctx, path)) {
    // missing confidence reported above
  } else if (!isValidConfidence(value.confidence)) {
    ctx.fail(
      `${path}.confidence`,
      `must be a number between ${CONFIDENCE_MIN} and ${CONFIDENCE_MAX}`,
    );
  }

  if (!requireField(value, "evidence", ctx, path)) {
    // missing evidence reported above
  } else if (!Array.isArray(value.evidence)) {
    ctx.fail(
      `${path}.evidence`,
      "must be an array of evidence reference IDs (strings)",
    );
  } else {
    value.evidence.forEach((reference, index) => {
      if (!isNonEmptyString(reference)) {
        ctx.fail(
          `${path}.evidence[${index}]`,
          "must be an evidence reference ID (non-empty string), not an embedded object",
        );
      }
    });
  }

  if (!requireField(value, "status", ctx, path)) {
    // missing status reported above
  } else if (!FINDING_STATUSES.includes(value.status)) {
    ctx.fail(
      `${path}.status`,
      `must be one of: ${FINDING_STATUSES.join(", ")}`,
    );
  }

  if (!requireField(value, "metadata", ctx, path)) {
    // missing metadata reported above
  } else if (!isPlainObject(value.metadata)) {
    ctx.fail(`${path}.metadata`, "must be a plain object");
  }

  checkOptionalObject(value, "impact", ctx, path);
  checkOptionalObject(value, "remediation", ctx, path);
}

// ─── Rule ────────────────────────────────────────────────────────────────────

function collectRuleIssues(value, ctx, path = "rule") {
  if (!requireObject(value, ctx, path)) return;

  checkRequiredString(value, "id", ctx, path);
  checkRequiredString(value, "category", ctx, path);
  checkRequiredString(value, "title", ctx, path);

  if (!requireField(value, "version", ctx, path)) {
    // missing version reported above
  } else if (!isVersionString(value.version)) {
    ctx.fail(`${path}.version`, 'must be a version string such as "1.0.0"');
  }

  if (!requireField(value, "description", ctx, path)) {
    // missing description reported above
  } else if (typeof value.description !== "string") {
    ctx.fail(`${path}.description`, "must be a string");
  }

  if (!requireField(value, "severity", ctx, path)) {
    // missing severity reported above
  } else if (!FINDING_SEVERITIES.includes(value.severity)) {
    ctx.fail(
      `${path}.severity`,
      `must be one of: ${FINDING_SEVERITIES.join(", ")}`,
    );
  }

  if (!requireField(value, "applicability", ctx, path)) {
    // missing applicability reported above
  } else if (!isPlainObject(value.applicability)) {
    ctx.fail(`${path}.applicability`, "must be a plain object");
  }

  if (!requireField(value, "detect", ctx, path)) {
    // missing detect reported above
  } else if (typeof value.detect !== "function") {
    ctx.fail(`${path}.detect`, "must be a function (detection behavior)");
  }

  if (!requireField(value, "remediation", ctx, path)) {
    // missing remediation reported above
  } else if (!isPlainObject(value.remediation)) {
    ctx.fail(`${path}.remediation`, "must be a plain object");
  }

  if (!requireField(value, "metadata", ctx, path)) {
    // missing metadata reported above
  } else if (!isPlainObject(value.metadata)) {
    ctx.fail(`${path}.metadata`, "must be a plain object");
  }
}

// ─── Analyzer ────────────────────────────────────────────────────────────────

function collectAnalyzerIssues(value, ctx, path = "analyzer") {
  if (!requireObject(value, ctx, path)) return;

  checkRequiredString(value, "id", ctx, path);

  if (!requireField(value, "version", ctx, path)) {
    // missing version reported above
  } else if (!isVersionString(value.version)) {
    ctx.fail(`${path}.version`, 'must be a version string such as "1.0.0"');
  }

  for (const method of ["canAnalyze", "analyze"]) {
    if (!requireField(value, method, ctx, path)) {
      // missing method reported above
    } else if (typeof value[method] !== "function") {
      ctx.fail(`${path}.${method}`, "must be a function");
    }
  }
}

function collectApplicabilityIssues(value, ctx, path = "applicability") {
  if (!requireObject(value, ctx, path)) return;
  if (!requireField(value, "applicable", ctx, path)) {
    // missing applicable reported above
  } else if (typeof value.applicable !== "boolean") {
    ctx.fail(`${path}.applicable`, "must be a boolean");
  }
  if ("reason" in value && typeof value.reason !== "string") {
    ctx.fail(`${path}.reason`, "must be a string");
  }
}

function collectAnalyzerResultIssues(value, ctx, path = "analyzerResult") {
  if (!isPlainObject(value)) {
    ctx.fail(
      path,
      "must be a plain object; an analyzer must not return null or undefined",
    );
    return;
  }

  for (const field of ANALYSIS_RESULT_FIELDS) {
    requireField(value, field, ctx, path);
  }

  if ("findings" in value) {
    if (!Array.isArray(value.findings)) {
      ctx.fail(`${path}.findings`, "must be an array");
    } else {
      value.findings.forEach((finding, index) => {
        collectFindingIssues(finding, ctx, `${path}.findings[${index}]`);
      });
    }
  }

  if ("evidence" in value) {
    if (!Array.isArray(value.evidence)) {
      ctx.fail(`${path}.evidence`, "must be an array");
    } else {
      value.evidence.forEach((evidence, index) => {
        collectEvidenceIssues(evidence, ctx, `${path}.evidence[${index}]`);
      });
    }
  }

  if ("metrics" in value && !isPlainObject(value.metrics)) {
    ctx.fail(`${path}.metrics`, "must be a plain object");
  }
  if ("metadata" in value && !isPlainObject(value.metadata)) {
    ctx.fail(`${path}.metadata`, "must be a plain object");
  }
}

// ─── AnalysisContext ─────────────────────────────────────────────────────────

function collectAnalysisContextIssues(value, ctx, path = "analysisContext") {
  if (!requireObject(value, ctx, path)) return;

  for (const field of ANALYSIS_CONTEXT_FIELDS) {
    requireField(value, field, ctx, path);
  }

  if ("repository" in value && !isPlainObject(value.repository)) {
    ctx.fail(`${path}.repository`, "must be a plain object (RepositoryModel)");
  }
  checkOptionalObject(value, "configuration", ctx, path);
  checkOptionalObject(value, "execution", ctx, path);
  checkOptionalObject(value, "options", ctx, path);

  if ("rules" in value && !Array.isArray(value.rules)) {
    ctx.fail(`${path}.rules`, "must be an array");
  }
  if ("evidence" in value && !Array.isArray(value.evidence)) {
    ctx.fail(`${path}.evidence`, "must be an array");
  }
}

// ─── Execution ───────────────────────────────────────────────────────────────

function collectExecutionLimitsIssues(value, ctx, path) {
  if (!requireObject(value, ctx, path)) return;
  if ("maxOutputBytes" in value && !isPositiveInteger(value.maxOutputBytes)) {
    ctx.fail(`${path}.maxOutputBytes`, "must be a positive integer");
  }
  if ("maxProcesses" in value && !isPositiveInteger(value.maxProcesses)) {
    ctx.fail(`${path}.maxProcesses`, "must be a positive integer");
  }
}

function collectExecutionPolicyIssues(value, ctx, path) {
  if (!requireObject(value, ctx, path)) return;
  for (const field of ["allowCommands", "denyCommands", "allowedRoots"]) {
    checkOptionalStringArray(value, field, ctx, path);
  }
  if ("network" in value && !isNonEmptyString(value.network)) {
    ctx.fail(`${path}.network`, "must be a non-empty string");
  }
  for (const field of ["maxDurationMs", "maxOutputBytes", "maxProcesses"]) {
    if (field in value && !isPositiveInteger(value[field])) {
      ctx.fail(`${path}.${field}`, "must be a positive integer");
    }
  }
}

function collectExecutionRequestIssues(value, ctx, path = "executionRequest") {
  if (!requireObject(value, ctx, path)) return;

  for (const field of EXECUTION_REQUEST_FIELDS) {
    requireField(value, field, ctx, path);
  }

  checkRequiredString(value, "command", ctx, path);
  checkRequiredString(value, "cwd", ctx, path);

  if ("args" in value && !isStringArray(value.args)) {
    ctx.fail(`${path}.args`, "must be an array of strings");
  }
  checkOptionalObject(value, "environment", ctx, path);

  if ("timeout" in value && !isPositiveInteger(value.timeout)) {
    ctx.fail(`${path}.timeout`, "must be a positive integer (milliseconds)");
  }
  if ("limits" in value) {
    collectExecutionLimitsIssues(value.limits, ctx, `${path}.limits`);
  }
  if ("policy" in value) {
    collectExecutionPolicyIssues(value.policy, ctx, `${path}.policy`);
  }
}

function collectExecutionResultIssues(value, ctx, path = "executionResult") {
  if (!requireObject(value, ctx, path)) return;

  for (const field of EXECUTION_RESULT_FIELDS) {
    requireField(value, field, ctx, path);
  }

  if ("exitCode" in value) {
    const code = value.exitCode;
    if (code !== null && !Number.isInteger(code)) {
      ctx.fail(`${path}.exitCode`, "must be an integer or null");
    }
  }
  for (const field of ["stdout", "stderr"]) {
    if (field in value && typeof value[field] !== "string") {
      ctx.fail(`${path}.${field}`, "must be a string");
    }
  }
  if ("duration" in value && !isNonNegativeNumber(value.duration)) {
    ctx.fail(
      `${path}.duration`,
      "must be a non-negative number (milliseconds)",
    );
  }
  for (const field of ["timedOut", "killed", "truncated"]) {
    if (field in value && typeof value[field] !== "boolean") {
      ctx.fail(`${path}.${field}`, "must be a boolean");
    }
  }
}

// ─── Public validators ───────────────────────────────────────────────────────
// Each validates its contract, throws a single ValidationError if invalid, and
// returns the validated value on success.

/** @returns {object} The validated RepositoryModel. */
export function validateRepositoryModel(value) {
  const ctx = createIssueCollector();
  collectRepositoryModelIssues(value, ctx);
  ctx.throwIfInvalid("RepositoryModel");
  return value;
}

/** @returns {object} The validated Evidence object. */
export function validateEvidence(value) {
  const ctx = createIssueCollector();
  collectEvidenceIssues(value, ctx);
  ctx.throwIfInvalid("Evidence");
  return value;
}

/** @returns {object} The validated Finding. */
export function validateFinding(value) {
  const ctx = createIssueCollector();
  collectFindingIssues(value, ctx);
  ctx.throwIfInvalid("Finding");
  return value;
}

/** @returns {object} The validated Rule. */
export function validateRule(value) {
  const ctx = createIssueCollector();
  collectRuleIssues(value, ctx);
  ctx.throwIfInvalid("Rule");
  return value;
}

/** @returns {object} The validated Analyzer. */
export function validateAnalyzer(value) {
  const ctx = createIssueCollector();
  collectAnalyzerIssues(value, ctx);
  ctx.throwIfInvalid("Analyzer");
  return value;
}

/** @returns {object} The validated `canAnalyze()` result. */
export function validateAnalyzerApplicability(value) {
  const ctx = createIssueCollector();
  collectApplicabilityIssues(value, ctx);
  ctx.throwIfInvalid("AnalyzerApplicability");
  return value;
}

/** @returns {object} The validated analyzer AnalysisResult. */
export function validateAnalyzerResult(value) {
  const ctx = createIssueCollector();
  collectAnalyzerResultIssues(value, ctx);
  ctx.throwIfInvalid("AnalysisResult");
  return value;
}

/** @returns {object} The validated AnalysisContext. */
export function validateAnalysisContext(value) {
  const ctx = createIssueCollector();
  collectAnalysisContextIssues(value, ctx);
  ctx.throwIfInvalid("AnalysisContext");
  return value;
}

/** @returns {object} The validated ExecutionRequest. */
export function validateExecutionRequest(value) {
  const ctx = createIssueCollector();
  collectExecutionRequestIssues(value, ctx);
  ctx.throwIfInvalid("ExecutionRequest");
  return value;
}

/** @returns {object} The validated ExecutionResult. */
export function validateExecutionResult(value) {
  const ctx = createIssueCollector();
  collectExecutionResultIssues(value, ctx);
  ctx.throwIfInvalid("ExecutionResult");
  return value;
}

/** @returns {object} The validated execution policy. */
export function validateExecutionPolicy(value) {
  const ctx = createIssueCollector();
  collectExecutionPolicyIssues(value, ctx, "executionPolicy");
  ctx.throwIfInvalid("ExecutionPolicy");
  return value;
}

/** @returns {object} The validated execution limits. */
export function validateExecutionLimits(value) {
  const ctx = createIssueCollector();
  collectExecutionLimitsIssues(value, ctx, "executionLimits");
  ctx.throwIfInvalid("ExecutionLimits");
  return value;
}

const VALIDATORS = Object.freeze({
  repositoryModel: validateRepositoryModel,
  evidence: validateEvidence,
  finding: validateFinding,
  rule: validateRule,
  analyzer: validateAnalyzer,
  analyzerApplicability: validateAnalyzerApplicability,
  analyzerResult: validateAnalyzerResult,
  analysisContext: validateAnalysisContext,
  executionRequest: validateExecutionRequest,
  executionResult: validateExecutionResult,
  executionPolicy: validateExecutionPolicy,
  executionLimits: validateExecutionLimits,
});

/**
 * Validate a value against a named contract.
 * @param {string} contract One of the keys of the validator registry.
 * @param {unknown} value
 * @returns {unknown} The validated value.
 * @throws {ValidationError} If the contract name is unknown or the value is invalid.
 */
export function validateContract(contract, value) {
  const validator = VALIDATORS[contract];
  if (typeof validator !== "function") {
    throw new ValidationError(`Unknown contract: ${String(contract)}`, {
      details: {
        contract: String(contract),
        issues: [`unknown contract "${String(contract)}"`],
        knownContracts: Object.keys(VALIDATORS),
      },
    });
  }
  return validator(value);
}

/** Names of the contracts the validation layer understands. */
export const KNOWN_CONTRACTS = Object.freeze(Object.keys(VALIDATORS));
