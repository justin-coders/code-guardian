/**
 * Code Guardian — Audit Configuration Resolution (Official Roadmap Phase 19)
 *
 * Phase 19's first pipeline stage is "load configuration". This module is that
 * stage: it takes the caller's raw `options` and turns them into one validated,
 * frozen, deterministic configuration object — or fails loudly.
 *
 * ### It is data, and only data
 *
 * The resolved configuration carries declarative values and Core contract objects
 * (`rules`, `evidence`). It is never code: there is no expression language, no
 * `eval`, no dynamic module load and no configuration fetched from a network. The
 * only non-data key is the injected millisecond `clock`, which is a *runtime
 * dependency* (it is never serialized into the result) rather than configuration —
 * and it exists so tests can make a run fully deterministic.
 *
 * ### Unknown keys fail
 *
 * An option key that is not in `AUDIT_OPTION_KEYS` is an error, never a silently
 * ignored option. An ignored option is a capability the caller believed they had.
 *
 * ### The resolved shape is the contract
 *
 * Every audit reports the *same* configuration shape regardless of what the
 * caller supplied, with defaults filled only for semantically neutral values
 * ("run every analyzer", "no extra rules", "no extra evidence"). Nothing that
 * could be misread as a detection, a selection of last resort or a certainty is
 * defaulted.
 */

import { deepFreeze } from "../analysis/index.js";
import { SCAN_OPTION_KEYS } from "../repository/scanner/index.js";
import { declarativeDataIssues } from "../rules/index.js";

import {
  AUDIT_OPTION_KEYS,
  DECLARATIVE_AUDIT_KEYS,
  GUARDIAN_SELECTION_ALL,
  MAX_AUDIT_ANALYZERS,
} from "./contracts.js";
import { GUARDIAN_FAILURE_CODES, GuardianConfigurationError } from "./errors.js";

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isBoundedString(value) {
  return typeof value === "string" && value.trim() !== "";
}

function invalid(message, details) {
  return new GuardianConfigurationError(message, {
    code: GUARDIAN_FAILURE_CODES.invalidConfiguration,
    details,
  });
}

/**
 * Resolve the analyzer selection from the raw option.
 *
 * @param {unknown} value `"all"`, an array of ids, or undefined.
 * @returns {string[]|"all"} A validated, de-duplicated, sorted id list or `"all"`.
 */
function resolveAnalyzers(value) {
  if (value === undefined || value === null) return GUARDIAN_SELECTION_ALL;
  if (value === GUARDIAN_SELECTION_ALL) return GUARDIAN_SELECTION_ALL;
  if (!Array.isArray(value)) {
    throw invalid('options.analyzers: must be an array of analyzer ids or the string "all"', {
      field: "options.analyzers",
    });
  }
  if (value.length > MAX_AUDIT_ANALYZERS) {
    throw invalid(`options.analyzers: must select at most ${MAX_AUDIT_ANALYZERS} analyzers`, {
      field: "options.analyzers",
    });
  }
  const ids = [];
  for (const entry of value) {
    if (!isBoundedString(entry)) {
      throw invalid("options.analyzers: every entry must be a non-empty analyzer id", {
        field: "options.analyzers",
      });
    }
    if (!ids.includes(entry)) ids.push(entry);
  }
  // Sorted here as well as in the registry, so the resolved configuration itself is
  // order-independent and two callers that listed the same ids differently get the
  // same configuration.
  return ids.sort();
}

/**
 * Validate one declarative option slot and return a frozen copy.
 *
 * @param {unknown} value
 * @param {string} field
 * @returns {object|Array}
 */
function resolveDeclarative(value, field) {
  if (value === undefined || value === null) return {};
  const issues = declarativeDataIssues(value, field);
  if (issues.length > 0) {
    throw invalid(`${field}: must be declarative data`, { field, issues });
  }
  return value;
}

/** Validate the scanner options used only when the repository is a path. */
function resolveScan(value) {
  const resolved = resolveDeclarative(value, "options.scan");
  for (const key of Object.keys(resolved)) {
    if (!SCAN_OPTION_KEYS.includes(key)) {
      throw invalid(
        `options.scan.${key}: unknown scanner option (expected one of: ${SCAN_OPTION_KEYS.join(", ")})`,
        { field: `options.scan.${key}` },
      );
    }
  }
  return resolved;
}

/** Validate the runtime clock dependency. */
function resolveClock(value) {
  if (value === undefined || value === null) return null;
  if (typeof value !== "function") {
    throw invalid("options.clock: must be a function returning milliseconds", {
      field: "options.clock",
    });
  }
  return value;
}

/** Validate a Core contract object list passed through to the context. */
function resolveContracts(value, field) {
  if (value === undefined || value === null) return [];
  if (!Array.isArray(value)) {
    throw invalid(`${field}: must be an array of contract objects`, { field });
  }
  return value;
}

/**
 * Resolve the audit options into the canonical configuration.
 *
 * @param {object} [options] The caller's raw options.
 * @returns {object} A deeply frozen configuration:
 *   `{ analyzers, rules, evidence, configuration, execution, analysis, failFast, scan, clock }`.
 * @throws {GuardianConfigurationError} When an option key or value is invalid.
 */
export function resolveAuditOptions(options = {}) {
  if (!isPlainObject(options)) {
    throw invalid("audit options must be a plain object", { field: "options" });
  }

  const issues = [];
  for (const key of Object.keys(options)) {
    if (!AUDIT_OPTION_KEYS.includes(key)) {
      issues.push(
        `options.${key}: unknown option (expected one of: ${AUDIT_OPTION_KEYS.join(", ")})`,
      );
    }
  }
  if (issues.length > 0) {
    throw invalid("Invalid audit options", { issues });
  }

  // Left as `undefined` when unspecified so an engine-level fail-fast default is
  // preserved rather than silently overridden by a per-audit default.
  const failFast = options.failFast;
  if (failFast !== undefined && typeof failFast !== "boolean") {
    throw invalid("options.failFast: must be a boolean", { field: "options.failFast" });
  }

  const resolved = {
    analyzers: resolveAnalyzers(options.analyzers),
    rules: resolveContracts(options.rules, "options.rules"),
    evidence: resolveContracts(options.evidence, "options.evidence"),
    configuration: resolveDeclarative(options.configuration, "options.configuration"),
    execution: resolveDeclarative(options.execution, "options.execution"),
    analysis: resolveDeclarative(options.analysis, "options.analysis"),
    failFast,
    scan: resolveScan(options.scan),
    clock: resolveClock(options.clock),
  };

  // `DECLARATIVE_AUDIT_KEYS` documents which slots were validated as declarative
  // data; asserted here so the two lists cannot drift silently.
  for (const key of DECLARATIVE_AUDIT_KEYS) {
    if (!(key in resolved)) {
      throw invalid(`internal: declarative option "${key}" is not resolved`, { field: key });
    }
  }

  return deepFreeze(resolved);
}
