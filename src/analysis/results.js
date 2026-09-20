/**
 * Code Guardian — Analysis Results (Phase 9)
 *
 * Two result contracts, both shape/draft factories validated by a matching
 * validator — the same Core convention used everywhere else in this codebase:
 *
 *   analyzer run result   what one analyzer did: its status, applicability, the
 *                         findings it produced, the evidence those findings
 *                         cite, its metrics and any failures.
 *   analysis run result   the aggregate: which repository was analysed, every
 *                         analyzer result, the deduplicated findings, duplicate
 *                         groups and the run metadata.
 *
 * The per-analyzer result is deliberately *the Core `AnalysisResult` plus run
 * facts*: it keeps `findings`, `evidence`, `metrics` and `metadata` with their
 * Core meanings and adds `analyzer`, `status`, `applicability`, `errors` and
 * `durationMs`. It is a superset of the Core contract, not a competing version of
 * it.
 *
 * Neither result can express a judgment. There is no score, grade, verdict or
 * readiness field anywhere, and `validateAnalysisRunResult` rejects them: an
 * aggregate that can say "72% secure" will eventually say it.
 *
 * `durationMs` is the only non-deterministic field. It is metadata: it never
 * participates in a fingerprint, an id or an ordering, and `stableAnalysisView`
 * removes it so two runs of the same model and analyzers can be compared byte for
 * byte.
 */

import {
  ValidationError,
  validateEvidence,
  validateFinding,
} from "../core/index.js";

import {
  ABNORMAL_ANALYZER_STATUSES,
  ANALYZER_ENGINE_VERSION,
  ANALYZER_FAILURE_KINDS,
  ANALYZER_RUN_STATUSES,
  ANALYSIS_JUDGMENT_KEYS,
  VERSION_PATTERN,
} from "./contracts.js";

const FAILURE_KINDS = Object.freeze(Object.values(ANALYZER_FAILURE_KINDS));
const STATUSES = Object.freeze(Object.values(ANALYZER_RUN_STATUSES));

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isNonEmptyString(value) {
  return typeof value === "string" && value.trim() !== "";
}

function isNonNegativeNumber(value) {
  return typeof value === "number" && Number.isFinite(value) && value >= 0;
}

/** Fields every analyzer run result declares. */
export const ANALYZER_RUN_RESULT_FIELDS = Object.freeze([
  "analyzer",
  "status",
  "applicability",
  "findings",
  "evidence",
  "metrics",
  "metadata",
  "errors",
  "durationMs",
]);

/** Fields the aggregate analysis run result declares. */
export const ANALYSIS_RUN_RESULT_FIELDS = Object.freeze([
  "version",
  "repository",
  "analyzers",
  "findings",
  "duplicates",
  "errors",
  "metadata",
  "durationMs",
  "complete",
]);

/**
 * Build an analyzer run result draft.
 *
 * Defaults are semantically neutral: a draft describes an analyzer that ran and
 * produced nothing, and never claims success for a status the caller did not set.
 *
 * @param {object} [input]
 * @returns {object} An AnalyzerRunResult-shaped draft; run the validator first.
 */
export function createAnalyzerRunResult(input = {}) {
  return {
    analyzer: input.analyzer ?? {},
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
 * Build an aggregate analysis run result draft.
 *
 * @param {object} [input]
 * @returns {object} An AnalysisRunResult-shaped draft; run the validator first.
 */
export function createAnalysisRunResult(input = {}) {
  return {
    version: input.version ?? ANALYZER_ENGINE_VERSION,
    repository: input.repository ?? {},
    analyzers: input.analyzers ?? [],
    findings: input.findings ?? [],
    duplicates: input.duplicates ?? [],
    errors: input.errors ?? [],
    metadata: input.metadata ?? {},
    durationMs: input.durationMs ?? 0,
    complete: input.complete ?? false,
  };
}

/**
 * Collect the problems with an analyzer's *return value*, before normalization.
 *
 * An analyzer returns a **draft**: the Finding Engine fills what the analyzer
 * omitted (a finding id from its fingerprint, a status, a description from the
 * matched rule) and then the completed result is validated against the Core
 * `AnalysisResult` contract. What cannot wait is the container shape — a findings
 * list that is not a list, a finding that is not an object, a metrics field that
 * is not an object — because normalization could not meaningfully interpret it.
 *
 * Absent collections are treated as empty: an analyzer that found nothing is a
 * valid analyzer.
 *
 * @param {unknown} value
 * @returns {string[]} Empty when the draft is interpretable.
 */
export function analyzerResultDraftIssues(value) {
  if (!isPlainObject(value)) {
    return [
      "analyzerResult: must be a plain object; an analyzer must not return null, undefined or an array",
    ];
  }

  const issues = [];
  for (const field of ["findings", "evidence"]) {
    if (field in value && !Array.isArray(value[field])) {
      issues.push(`analyzerResult.${field}: must be an array`);
    }
  }
  if (Array.isArray(value.findings)) {
    value.findings.forEach((finding, index) => {
      if (!isPlainObject(finding)) {
        issues.push(`analyzerResult.findings[${index}]: must be a plain object`);
      }
    });
  }
  for (const field of ["metrics", "metadata"]) {
    if (field in value && !isPlainObject(value[field])) {
      issues.push(`analyzerResult.${field}: must be a plain object`);
    }
  }
  return issues;
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
  if (entry.analyzerId !== null && !isNonEmptyString(entry.analyzerId)) {
    fail(`${path}.analyzerId`, "must be a non-empty string or null");
  }
  if ("details" in entry && !isPlainObject(entry.details)) {
    fail(`${path}.details`, "must be a plain object");
  }
}

function collectFindingIssues(finding, fail, path) {
  try {
    validateFinding(finding);
  } catch (error) {
    const issues = error?.details?.issues;
    if (Array.isArray(issues) && issues.length > 0) {
      for (const issue of issues) fail(path, issue);
    } else {
      fail(path, "must be a canonical Finding");
    }
  }
}

/**
 * Validate an analyzer run result.
 *
 * @param {unknown} value
 * @returns {object} The same value when valid.
 * @throws {ValidationError} Listing every violation.
 */
export function validateAnalyzerRunResult(value) {
  const issues = [];
  const fail = (path, message) => issues.push(`${path}: ${message}`);

  if (!isPlainObject(value)) {
    throw new ValidationError("Invalid analyzer run result", {
      details: { contract: "AnalyzerRunResult", issues: ["result: must be a plain object"] },
    });
  }

  for (const field of ANALYZER_RUN_RESULT_FIELDS) {
    if (!(field in value)) fail(`analyzerRunResult.${field}`, "is required");
  }

  const analyzer = value.analyzer;
  if (!isPlainObject(analyzer)) {
    fail("analyzerRunResult.analyzer", "must be a plain object");
  } else {
    for (const field of ["id", "name", "version", "scope"]) {
      if (!isNonEmptyString(analyzer[field])) {
        fail(`analyzerRunResult.analyzer.${field}`, "must be a non-empty string");
      }
    }
  }

  if (!STATUSES.includes(value.status)) {
    fail("analyzerRunResult.status", `must be one of: ${STATUSES.join(", ")}`);
  }

  if (value.applicability !== null) {
    if (!isPlainObject(value.applicability) || typeof value.applicability.applicable !== "boolean") {
      fail("analyzerRunResult.applicability", "must be null or { applicable: boolean, reason?: string }");
    } else if (
      "reason" in value.applicability &&
      typeof value.applicability.reason !== "string"
    ) {
      fail("analyzerRunResult.applicability.reason", "must be a string");
    }
  }

  if (!Array.isArray(value.findings)) {
    fail("analyzerRunResult.findings", "must be an array of canonical findings");
  } else {
    const fingerprints = new Set();
    value.findings.forEach((finding, index) => {
      collectFindingIssues(finding, fail, `analyzerRunResult.findings[${index}]`);
      if (isPlainObject(finding) && isNonEmptyString(finding.fingerprint)) {
        if (fingerprints.has(finding.fingerprint)) {
          fail(
            `analyzerRunResult.findings[${index}]`,
            "duplicate fingerprint within one analyzer result",
          );
        }
        fingerprints.add(finding.fingerprint);
      }
    });
  }

  if (!Array.isArray(value.evidence)) {
    fail("analyzerRunResult.evidence", "must be an array of Evidence records");
  } else {
    value.evidence.forEach((record, index) => {
      try {
        validateEvidence(record);
      } catch (error) {
        const reported = error?.details?.issues ?? ["must be a valid Evidence record"];
        for (const issue of reported) {
          fail(`analyzerRunResult.evidence[${index}]`, issue);
        }
      }
    });
  }

  for (const field of ["metrics", "metadata"]) {
    if (!isPlainObject(value[field])) fail(`analyzerRunResult.${field}`, "must be a plain object");
  }

  if (!Array.isArray(value.errors)) {
    fail("analyzerRunResult.errors", "must be an array");
  } else {
    value.errors.forEach((entry, index) =>
      collectFailureEntryIssues(entry, fail, `analyzerRunResult.errors[${index}]`),
    );
  }

  if (!isNonNegativeNumber(value.durationMs)) {
    fail("analyzerRunResult.durationMs", "must be a non-negative number (metadata only)");
  }

  // Status/result coherence: a status must not overstate what happened.
  if (value.status === ANALYZER_RUN_STATUSES.NOT_APPLICABLE) {
    if (!isPlainObject(value.applicability) || value.applicability.applicable !== false) {
      fail(
        "analyzerRunResult.applicability",
        "a not-applicable result must record applicability.applicable === false",
      );
    }
    if (Array.isArray(value.findings) && value.findings.length > 0) {
      fail("analyzerRunResult.findings", "a not-applicable analyzer cannot produce findings");
    }
  }
  if (value.status === ANALYZER_RUN_STATUSES.COMPLETED) {
    if (isPlainObject(value.applicability) && value.applicability.applicable === false) {
      fail(
        "analyzerRunResult.applicability",
        "a completed result cannot be marked not-applicable",
      );
    }
  }
  if (value.status === ANALYZER_RUN_STATUSES.SKIPPED) {
    if (value.applicability !== null) {
      fail("analyzerRunResult.applicability", "a skipped analyzer was never evaluated");
    }
    if (Array.isArray(value.findings) && value.findings.length > 0) {
      fail("analyzerRunResult.findings", "a skipped analyzer cannot produce findings");
    }
    if (Array.isArray(value.errors) && value.errors.length === 0) {
      fail("analyzerRunResult.errors", "a skipped analyzer must record why it was skipped");
    }
  }
  if (
    value.status === ANALYZER_RUN_STATUSES.FAILED &&
    Array.isArray(value.errors) &&
    value.errors.length === 0
  ) {
    fail("analyzerRunResult.errors", "a failed analyzer must record at least one failure");
  }

  if (issues.length > 0) {
    throw new ValidationError("Invalid analyzer run result", {
      details: { contract: "AnalyzerRunResult", issues },
    });
  }

  return value;
}

/**
 * Validate the aggregate analysis run result.
 *
 * Enforced here rather than documented, because each of these invariants has been
 * the source of a real class of mistake elsewhere in this codebase:
 *
 *   - analyzer results are sorted by id and unique;
 *   - findings are canonical, sorted, and unique by fingerprint;
 *   - every duplicate group points at a surviving finding;
 *   - `complete` is true only when no analyzer failed or was skipped;
 *   - no judgment key appears anywhere at the top level.
 *
 * @param {unknown} value
 * @returns {object} The same value when valid.
 * @throws {ValidationError} Listing every violation.
 */
export function validateAnalysisRunResult(value) {
  const issues = [];
  const fail = (path, message) => issues.push(`${path}: ${message}`);

  if (!isPlainObject(value)) {
    throw new ValidationError("Invalid analysis run result", {
      details: { contract: "AnalysisRunResult", issues: ["result: must be a plain object"] },
    });
  }

  for (const field of ANALYSIS_RUN_RESULT_FIELDS) {
    if (!(field in value)) fail(`analysisRunResult.${field}`, "is required");
  }

  if (!isNonEmptyString(value.version) || !VERSION_PATTERN.test(String(value.version))) {
    fail("analysisRunResult.version", 'must be a version string such as "1"');
  }

  const repository = value.repository;
  if (!isPlainObject(repository)) {
    fail("analysisRunResult.repository", "must be a plain object");
  } else {
    if (!isNonEmptyString(repository.repositoryId)) {
      fail("analysisRunResult.repository.repositoryId", "must be a non-empty string");
    }
    if (!isNonEmptyString(repository.root)) {
      fail("analysisRunResult.repository.root", "must be a non-empty string");
    }
    if (!isPlainObject(repository.coverage)) {
      fail("analysisRunResult.repository.coverage", "must be a plain object");
    }
  }

  if (!Array.isArray(value.analyzers)) {
    fail("analysisRunResult.analyzers", "must be an array");
  } else {
    const analyzerIds = [];
    value.analyzers.forEach((result, index) => {
      const path = `analysisRunResult.analyzers[${index}]`;
      if (!isPlainObject(result)) {
        fail(path, "must be an analyzer run result");
        return;
      }
      try {
        validateAnalyzerRunResult(result);
      } catch (error) {
        const reported = error?.details?.issues ?? ["invalid analyzer run result"];
        for (const issue of reported) fail(path, issue);
      }
      if (isNonEmptyString(result.analyzer?.id)) analyzerIds.push(result.analyzer.id);
    });
    const sorted = [...analyzerIds].sort();
    if (analyzerIds.join("\u0000") !== sorted.join("\u0000")) {
      fail("analysisRunResult.analyzers", "must be sorted by analyzer id");
    }
    if (new Set(analyzerIds).size !== analyzerIds.length) {
      fail("analysisRunResult.analyzers", "must not contain an analyzer twice");
    }
  }

  if (!Array.isArray(value.findings)) {
    fail("analysisRunResult.findings", "must be an array of canonical findings");
  } else {
    const fingerprints = new Set();
    value.findings.forEach((finding, index) => {
      const path = `analysisRunResult.findings[${index}]`;
      collectFindingIssues(finding, fail, path);
      if (isPlainObject(finding) && isNonEmptyString(finding.fingerprint)) {
        if (fingerprints.has(finding.fingerprint)) {
          fail(path, "duplicate fingerprint: the aggregate must be deduplicated");
        }
        fingerprints.add(finding.fingerprint);
      }
    });
  }

  if (!Array.isArray(value.duplicates)) {
    fail("analysisRunResult.duplicates", "must be an array");
  } else {
    const known = new Set(
      Array.isArray(value.findings)
        ? value.findings.map((finding) => finding?.fingerprint).filter(isNonEmptyString)
        : [],
    );
    value.duplicates.forEach((group, index) => {
      const path = `analysisRunResult.duplicates[${index}]`;
      if (!isPlainObject(group) || !isNonEmptyString(group.fingerprint)) {
        fail(path, "must be a plain object with a fingerprint");
        return;
      }
      if (!known.has(group.fingerprint)) {
        fail(path, "must point at a surviving finding");
      }
      if (!Array.isArray(group.duplicates) || group.duplicates.length === 0) {
        fail(`${path}.duplicates`, "must record at least one duplicate");
      }
    });
  }

  if (!Array.isArray(value.errors)) {
    fail("analysisRunResult.errors", "must be an array");
  } else {
    value.errors.forEach((entry, index) =>
      collectFailureEntryIssues(entry, fail, `analysisRunResult.errors[${index}]`),
    );
    const keys = value.errors.map(
      (entry) => `${entry?.analyzerId ?? ""}\u0000${entry?.kind ?? ""}\u0000${entry?.code ?? ""}`,
    );
    const sorted = [...keys].sort();
    if (keys.join("\u0002") !== sorted.join("\u0002")) {
      fail("analysisRunResult.errors", "must be sorted deterministically");
    }
  }

  if (typeof value.complete !== "boolean") {
    fail("analysisRunResult.complete", "must be a boolean");
  }
  if (Array.isArray(value.analyzers) && typeof value.complete === "boolean") {
    const abnormal = value.analyzers.filter((result) =>
      ABNORMAL_ANALYZER_STATUSES.includes(result?.status),
    );
    if (value.complete === true && abnormal.length > 0) {
      fail(
        "analysisRunResult.complete",
        "cannot be true while an analyzer failed or was skipped",
      );
    }
    if (value.complete === false && abnormal.length === 0) {
      fail(
        "analysisRunResult.complete",
        "must be false when an analyzer failed or was skipped",
      );
    }
  }

  if (!isPlainObject(value.metadata)) {
    fail("analysisRunResult.metadata", "must be a plain object");
  }
  if (!isNonNegativeNumber(value.durationMs)) {
    fail("analysisRunResult.durationMs", "must be a non-negative number (metadata only)");
  }

  for (const key of ANALYSIS_JUDGMENT_KEYS) {
    if (key in value) {
      fail(`analysisRunResult.${key}`, "the framework reports facts and failures, never judgments");
    }
  }

  if (issues.length > 0) {
    throw new ValidationError("Invalid analysis run result", {
      details: { contract: "AnalysisRunResult", issues },
    });
  }

  return value;
}

/**
 * A structural copy of a run result with timing metadata removed.
 *
 * Use this to compare two runs, to baseline a result, or to hash one: the
 * remaining structure is fully deterministic for a given model, analyzer set and
 * configuration.
 *
 * @param {object} result An analysis run result.
 * @returns {object} A JSON-safe copy without `durationMs`.
 */
export function stableAnalysisView(result) {
  if (result === null || typeof result !== "object") return result;
  if (Array.isArray(result)) return result.map(stableAnalysisView);
  const out = {};
  for (const key of Object.keys(result)) {
    if (key === "durationMs") continue;
    out[key] = stableAnalysisView(result[key]);
  }
  return out;
}
