/**
 * Code Guardian — Canonical Result (Official Roadmap Phase 19)
 *
 * Pipeline stage 9 is "generate canonical result". This module defines that
 * contract: a shape/draft factory plus the validator that is the authority on
 * validity, the same Core convention used everywhere else in this codebase.
 *
 * ### Why not reuse `AnalysisRunResult`
 *
 * `AnalysisRunResult` is the *analyzer framework's* result and deliberately rejects
 * judgment fields (`score`, `grade`, `verdict`, `productionReady`, `risk`,
 * `quality`). The Guardian Core is the first layer permitted a documented risk
 * profile, so it needs a *higher-level* contract rather than a corrupted lower one.
 * The canonical result therefore embeds the analyzer facts, the canonical findings
 * and the evidence the analyzer framework produced, and adds exactly two things the
 * framework must never own: a `risk` profile and run-level `analysis`/`metrics`.
 *
 * ### The shape follows the architecture specification (§43)
 *
 *   schemaVersion, repository, analysis, analyzers, findings, evidence,
 *   metrics, risk, scan
 *
 * It is versioned (`schemaVersion`), validated, deeply frozen, serializable, and
 * independent of MCP/CLI/HTTP rendering: no transport type appears anywhere in it.
 *
 * ### Distinctions it must preserve
 *
 *   facts              `repository`, `scan`, `analysis`, `metrics`
 *   findings           `findings` (canonical, fingerprinted) and `analyzers`
 *   risk               the `risk` profile
 *   coverage/unknowns  `risk.coverage` and `risk.limitations`
 *   failures           `analyzers[].errors` and `risk.limitations`
 *
 * `durationMs` is the only non-deterministic field, and it is metadata: it never
 * takes part in a fingerprint, an id or an ordering, and `stableGuardianView`
 * removes it so two runs of the same model, analyzers and configuration can be
 * compared byte for byte. The result carries no wall-clock timestamps at all,
 * matching the accepted analysis results.
 */

import { VERSION_PATTERN, validateEvidence, validateFinding } from "../core/index.js";
import {
  ANALYZER_RUN_STATUSES,
  deepFreeze,
  stableAnalysisView,
} from "../analysis/index.js";

import {
  FORBIDDEN_GUARDIAN_RESULT_KEYS,
  GUARDIAN_ANALYZER_SUMMARY_FIELDS,
  GUARDIAN_ENGINE_NAME,
  GUARDIAN_ENGINE_VERSION,
  GUARDIAN_RESULT_FIELDS,
  GUARDIAN_RESULT_SCHEMA_VERSION,
} from "./contracts.js";
import { GuardianValidationError } from "./errors.js";

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

/**
 * Build a canonical Guardian result draft.
 *
 * Defaults are semantically neutral: a draft describes an audit that has not yet
 * been assembled and never claims completeness the caller did not set.
 *
 * @param {object} [input]
 * @returns {object} A GuardianResult-shaped draft; run the validator first.
 */
export function createGuardianResult(input = {}) {
  return {
    schemaVersion: input.schemaVersion ?? GUARDIAN_RESULT_SCHEMA_VERSION,
    engine: input.engine ?? {},
    repository: input.repository ?? {},
    analysis: input.analysis ?? {},
    analyzers: input.analyzers ?? [],
    findings: input.findings ?? [],
    evidence: input.evidence ?? [],
    metrics: input.metrics ?? {},
    risk: input.risk ?? {},
    scan: input.scan ?? {},
  };
}

/** Validate the `engine` identity block. */
function collectEngineIssues(engine, fail) {
  if (!isPlainObject(engine)) {
    fail("guardianResult.engine", "must be a plain object");
    return;
  }
  for (const field of ["name", "version", "fingerprintAlgorithm"]) {
    if (!isNonEmptyString(engine[field])) {
      fail(`guardianResult.engine.${field}`, "must be a non-empty string");
    }
  }
  if (isNonEmptyString(engine.version) && !VERSION_PATTERN.test(engine.version)) {
    fail("guardianResult.engine.version", 'must be a version string such as "1.0.0"');
  }
}

/** Validate the `repository` facts block. */
function collectRepositoryIssues(repository, fail) {
  if (!isPlainObject(repository)) {
    fail("guardianResult.repository", "must be a plain object");
    return;
  }
  for (const field of ["repositoryId", "root", "modelVersion"]) {
    if (!isNonEmptyString(repository[field])) {
      fail(`guardianResult.repository.${field}`, "must be a non-empty string");
    }
  }
  if (!isPlainObject(repository.coverage)) {
    fail("guardianResult.repository.coverage", "must be a plain object");
  }
  if (repository.fileCount !== undefined && !isNonNegativeNumber(repository.fileCount)) {
    fail("guardianResult.repository.fileCount", "must be a non-negative number");
  }
  if (repository.evidenceCount !== undefined && !isNonNegativeNumber(repository.evidenceCount)) {
    fail("guardianResult.repository.evidenceCount", "must be a non-negative number");
  }
}

/** Validate the `scan` coverage block. */
function collectScanIssues(scan, fail) {
  if (!isPlainObject(scan)) {
    fail("guardianResult.scan", "must be a plain object");
    return;
  }
  if (typeof scan.complete !== "boolean") {
    fail("guardianResult.scan.complete", "must be a boolean");
  }
  if (typeof scan.truncated !== "boolean") {
    fail("guardianResult.scan.truncated", "must be a boolean");
  }
  if (!isNonEmptyString(scan.guarantee)) {
    fail("guardianResult.scan.guarantee", "must be a non-empty string");
  }
}

/** Validate the `analysis` run block and its coherence with the analyzer summaries. */
function collectAnalysisIssues(analysis, analyzerIds, statuses, fail) {
  if (!isPlainObject(analysis)) {
    fail("guardianResult.analysis", "must be a plain object");
    return;
  }
  if (typeof analysis.complete !== "boolean") {
    fail("guardianResult.analysis.complete", "must be a boolean");
  }
  if (typeof analysis.failFast !== "boolean") {
    fail("guardianResult.analysis.failFast", "must be a boolean");
  }
  if (!isNonNegativeNumber(analysis.durationMs)) {
    fail("guardianResult.analysis.durationMs", "must be a non-negative number (metadata only)");
  }
  if (!Array.isArray(analysis.selectedAnalyzers)) {
    fail("guardianResult.analysis.selectedAnalyzers", "must be an array of analyzer ids");
  } else if (
    analysis.selectedAnalyzers.join("\u0000") !== analyzerIds.join("\u0000")
  ) {
    fail(
      "guardianResult.analysis.selectedAnalyzers",
      "must list the analyzer summaries' ids in the same order",
    );
  }

  const counts = analysis.analyzers;
  if (!isPlainObject(counts)) {
    fail("guardianResult.analysis.analyzers", "must be an object of status counts");
    return;
  }
  for (const field of ["selected", "completed", "notApplicable", "failed", "skipped"]) {
    if (!isNonNegativeNumber(counts[field])) {
      fail(`guardianResult.analysis.analyzers.${field}`, "must be a non-negative number");
    }
  }

  const expected = {
    selected: statuses.length,
    completed: statuses.filter((status) => status === ANALYZER_RUN_STATUSES.COMPLETED).length,
    notApplicable: statuses.filter((status) => status === ANALYZER_RUN_STATUSES.NOT_APPLICABLE)
      .length,
    failed: statuses.filter((status) => status === ANALYZER_RUN_STATUSES.FAILED).length,
    skipped: statuses.filter((status) => status === ANALYZER_RUN_STATUSES.SKIPPED).length,
  };
  for (const field of Object.keys(expected)) {
    if (isNonNegativeNumber(counts[field]) && counts[field] !== expected[field]) {
      fail(
        `guardianResult.analysis.analyzers.${field}`,
        `must equal the analyzer summaries' ${field} count (${expected[field]})`,
      );
    }
  }

  const abnormal = expected.failed + expected.skipped;
  if (typeof analysis.complete === "boolean") {
    if (analysis.complete === true && abnormal > 0) {
      fail(
        "guardianResult.analysis.complete",
        "cannot be true while an analyzer failed or was skipped",
      );
    }
    if (analysis.complete === false && abnormal === 0) {
      fail(
        "guardianResult.analysis.complete",
        "must be false when an analyzer failed or was skipped",
      );
    }
  }
}

/** Validate one per-analyzer attribution summary. */
function collectAnalyzerSummaryIssues(entry, fail, path) {
  if (!isPlainObject(entry)) {
    fail(path, "must be a plain object");
    return null;
  }
  for (const field of GUARDIAN_ANALYZER_SUMMARY_FIELDS) {
    if (!(field in entry)) fail(`${path}.${field}`, "is required");
  }
  for (const field of ["id", "name", "version", "scope"]) {
    if (!isNonEmptyString(entry[field])) fail(`${path}.${field}`, "must be a non-empty string");
  }
  if (!STATUSES.includes(entry.status)) {
    fail(`${path}.status`, `must be one of: ${STATUSES.join(", ")}`);
  }
  if (entry.applicability !== null) {
    if (!isPlainObject(entry.applicability) || typeof entry.applicability.applicable !== "boolean") {
      fail(`${path}.applicability`, "must be null or { applicable: boolean, reason?: string }");
    }
  }
  for (const field of ["findings", "evidence"]) {
    if (!Array.isArray(entry[field])) {
      fail(`${path}.${field}`, "must be an array of id strings");
    } else {
      entry[field].forEach((value, index) => {
        if (!isNonEmptyString(value)) {
          fail(`${path}.${field}[${index}]`, "must be a non-empty string");
        }
      });
    }
  }
  if (!isPlainObject(entry.metrics)) fail(`${path}.metrics`, "must be a plain object");
  if (!Array.isArray(entry.errors)) fail(`${path}.errors`, "must be an array");
  return isNonEmptyString(entry.id) ? entry.id : null;
}

/**
 * Validate a canonical Guardian result.
 *
 * The checks are the ones this codebase has learned to enforce, not decoration:
 *
 *   - every declared field is present and the judgment keys are absent;
 *   - analyzer summaries are sorted by id and unique;
 *   - findings are canonical, sorted by fingerprint and unique by fingerprint;
 *   - evidence ids are unique and sorted, and every finding's references resolve;
 *   - the analysis status counts, the `complete` flag and the selection agree with
 *     the analyzer summaries;
 *   - the risk profile agrees with the findings and the coverage facts.
 *
 * @param {unknown} value
 * @returns {object} The same value when valid.
 * @throws {GuardianValidationError} Listing every violation.
 */
export function validateGuardianResult(value) {
  const issues = [];
  const fail = (path, message) => issues.push(`${path}: ${message}`);

  if (!isPlainObject(value)) {
    throw new GuardianValidationError("Invalid canonical Guardian result", {
      issues: ["result: must be a plain object"],
    });
  }

  for (const field of GUARDIAN_RESULT_FIELDS) {
    if (!(field in value)) fail(`guardianResult.${field}`, "is required");
  }
  for (const key of FORBIDDEN_GUARDIAN_RESULT_KEYS) {
    if (key in value) {
      fail(`guardianResult.${key}`, "the Core reports facts, findings and a risk profile, never a collapsed score");
    }
  }

  if (!isNonEmptyString(value.schemaVersion) || !VERSION_PATTERN.test(String(value.schemaVersion))) {
    fail("guardianResult.schemaVersion", 'must be a version string such as "1"');
  }

  collectEngineIssues(value.engine, fail);
  collectRepositoryIssues(value.repository, fail);
  collectScanIssues(value.scan, fail);

  const analyzerIds = [];
  const statuses = [];
  if (!Array.isArray(value.analyzers)) {
    fail("guardianResult.analyzers", "must be an array");
  } else {
    value.analyzers.forEach((entry, index) => {
      const id = collectAnalyzerSummaryIssues(entry, fail, `guardianResult.analyzers[${index}]`);
      if (id !== null) analyzerIds.push(id);
      if (isPlainObject(entry) && STATUSES.includes(entry.status)) statuses.push(entry.status);
    });
    const sorted = [...analyzerIds].sort();
    if (analyzerIds.join("\u0000") !== sorted.join("\u0000")) {
      fail("guardianResult.analyzers", "must be sorted by analyzer id");
    }
    if (new Set(analyzerIds).size !== analyzerIds.length) {
      fail("guardianResult.analyzers", "must not contain an analyzer twice");
    }
  }

  const findingFingerprints = new Set();
  if (!Array.isArray(value.findings)) {
    fail("guardianResult.findings", "must be an array of canonical findings");
  } else {
    let previous = null;
    value.findings.forEach((finding, index) => {
      const path = `guardianResult.findings[${index}]`;
      try {
        validateFinding(finding);
      } catch (error) {
        const reported = error?.details?.issues ?? ["must be a canonical Finding"];
        for (const issue of reported) fail(path, issue);
      }
      if (isPlainObject(finding) && isNonEmptyString(finding.fingerprint)) {
        if (findingFingerprints.has(finding.fingerprint)) {
          fail(path, "duplicate fingerprint: the aggregate must be deduplicated");
        }
        findingFingerprints.add(finding.fingerprint);
        if (previous !== null && finding.fingerprint < previous) {
          fail("guardianResult.findings", "must be sorted by fingerprint");
        }
        previous = finding.fingerprint;
      }
    });
  }

  const evidenceIds = new Set();
  if (!Array.isArray(value.evidence)) {
    fail("guardianResult.evidence", "must be an array of Evidence records");
  } else {
    let previous = null;
    value.evidence.forEach((record, index) => {
      const path = `guardianResult.evidence[${index}]`;
      try {
        validateEvidence(record);
      } catch (error) {
        const reported = error?.details?.issues ?? ["must be a valid Evidence record"];
        for (const issue of reported) fail(path, issue);
      }
      if (isPlainObject(record) && isNonEmptyString(record.id)) {
        if (evidenceIds.has(record.id)) fail(path, "duplicate evidence id");
        evidenceIds.add(record.id);
        if (previous !== null && record.id < previous) {
          fail("guardianResult.evidence", "must be sorted by evidence id");
        }
        previous = record.id;
      }
    });
  }

  // Provenance: every finding must trace to evidence the result carries.
  if (Array.isArray(value.findings)) {
    value.findings.forEach((finding, index) => {
      if (!isPlainObject(finding) || !Array.isArray(finding.evidence)) return;
      for (const reference of finding.evidence) {
        if (!evidenceIds.has(reference)) {
          fail(
            `guardianResult.findings[${index}].evidence`,
            `references "${reference}", which the result does not carry`,
          );
        }
      }
    });
  }

  collectAnalysisIssues(value.analysis, analyzerIds, statuses, fail);

  if (!isPlainObject(value.metrics)) {
    fail("guardianResult.metrics", "must be a plain object");
  }

  collectRiskIssues(value.risk, value.findings, fail);

  if (issues.length > 0) {
    throw new GuardianValidationError("Invalid canonical Guardian result", { issues });
  }

  return value;
}

/** Validate the `risk` profile and its coherence with the findings. */
function collectRiskIssues(risk, findings, fail) {
  if (!isPlainObject(risk)) {
    fail("guardianResult.risk", "must be a plain object");
    return;
  }
  if (!isNonEmptyString(risk.version) || !VERSION_PATTERN.test(String(risk.version))) {
    fail("guardianResult.risk.version", 'must be a version string such as "1"');
  }
  if (typeof risk.complete !== "boolean") {
    fail("guardianResult.risk.complete", "must be a boolean");
  }

  const counts = risk.counts;
  if (!isPlainObject(counts)) {
    fail("guardianResult.risk.counts", "must be an object of severity counts");
  } else {
    for (const field of ["total", "info", "low", "medium", "high", "critical"]) {
      if (!isNonNegativeNumber(counts[field])) {
        fail(`guardianResult.risk.counts.${field}`, "must be a non-negative number");
      }
    }
    if (Array.isArray(findings) && isNonNegativeNumber(counts.total)) {
      if (counts.total !== findings.length) {
        fail(
          "guardianResult.risk.counts.total",
          `must equal the number of canonical findings (${findings.length})`,
        );
      }
      for (const severity of ["info", "low", "medium", "high", "critical"]) {
        const expected = findings.filter((finding) => finding?.severity === severity).length;
        if (isNonNegativeNumber(counts[severity]) && counts[severity] !== expected) {
          fail(
            `guardianResult.risk.counts.${severity}`,
            `must equal the number of ${severity} findings (${expected})`,
          );
        }
      }
    }
  }

  if (risk.highestSeverity !== null && !["info", "low", "medium", "high", "critical"].includes(risk.highestSeverity)) {
    fail("guardianResult.risk.highestSeverity", "must be null or a Core severity");
  }

  if (!isPlainObject(risk.coverage)) {
    fail("guardianResult.risk.coverage", "must be a plain object");
  } else {
    if (!isPlainObject(risk.coverage.repository)) {
      fail("guardianResult.risk.coverage.repository", "must be a plain object");
    }
    if (!isPlainObject(risk.coverage.analysis)) {
      fail("guardianResult.risk.coverage.analysis", "must be a plain object");
    }
  }

  if (!Array.isArray(risk.limitations)) {
    fail("guardianResult.risk.limitations", "must be an array of reason strings");
  } else {
    const sorted = [...risk.limitations].sort();
    if (risk.limitations.join("\u0000") !== sorted.join("\u0000")) {
      fail("guardianResult.risk.limitations", "must be sorted deterministically");
    }
    if (risk.complete === true && risk.limitations.length > 0) {
      fail("guardianResult.risk.limitations", "must be empty when the run is complete");
    }
    if (risk.complete === false && risk.limitations.length === 0) {
      fail("guardianResult.risk.limitations", "must record why the run is not complete");
    }
  }
}

/**
 * A structural copy of a canonical result with timing metadata removed.
 *
 * Use this to compare two runs, to baseline a result or to hash one: the remaining
 * structure is fully deterministic for a given model, analyzer set and
 * configuration.
 *
 * @param {object} result A canonical Guardian result.
 * @returns {object} A JSON-safe copy without `durationMs`.
 */
export function stableGuardianView(result) {
  return stableAnalysisView(result);
}

/** Deep-freeze a validated result and return it. */
export function freezeGuardianResult(result) {
  return deepFreeze(result);
}

/** The engine identity recorded on every result. */
export function guardianEngineIdentity(fingerprintAlgorithm) {
  return Object.freeze({
    name: GUARDIAN_ENGINE_NAME,
    version: GUARDIAN_ENGINE_VERSION,
    fingerprintAlgorithm,
  });
}
