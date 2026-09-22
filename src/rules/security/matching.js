/**
 * Code Guardian — Security Filename Matching (Phase 12)
 *
 * A tiny, declarative matcher over the *names* the RepositoryModel already recorded.
 * It exists so the eight security rules share one matching implementation — and one
 * set of tests — instead of each inventing its own `endsWith` chain, and so the
 * matching policy is inspectable data rather than behaviour hidden in a predicate.
 *
 * ### Data, not a language
 *
 * A spec is a frozen object of array criteria:
 *
 *   basenames      exact basename
 *   extensions     exact extension, including the dot
 *   namePrefixes   basename starts with
 *   nameSuffixes   basename ends with
 *   pathSegments   a directory segment anywhere in the path
 *
 * Positive criteria are **OR**-ed — a file matches when *any* listed criterion
 * matches. `exclude` holds the same five criteria and is checked first, so an
 * exclusion always wins (`.env.example` is a template, `id_rsa.pub` is a public
 * key). There are no regular expressions, no globs, no negation syntax, no
 * expression evaluation and no way for a spec to consume unbounded work: every
 * comparison is a bounded string test, which keeps a hostile filename from being a
 * denial-of-service vector.
 *
 * ### Normalization
 *
 * Names, extensions and paths are lower-cased before comparison and the criteria
 * are lower-cased when the spec is defined, so `ID_RSA` matches. Paths are split on
 * `/` directly — the model's paths are already normalized POSIX-relative strings,
 * and importing `node:path` here would give the rules layer filesystem-path
 * authority it must not have.
 *
 * ### Validation is not optional
 *
 * `defineFileSpec` validates shape and freezes the result. A spec with no positive
 * criterion is rejected rather than accepted as "matches everything": an
 * everything-matcher in a security pack produces one finding per file, which is
 * indistinguishable from a broken rule.
 */

import { ValidationError } from "../../core/index.js";

/** The only criteria keys a spec (or its `exclude`) may declare. */
export const FILE_SPEC_CRITERIA = Object.freeze([
  "basenames",
  "extensions",
  "namePrefixes",
  "nameSuffixes",
  "pathSegments",
]);

const CRITERIA = FILE_SPEC_CRITERIA;

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function collectCriteriaIssues(value, path, issues) {
  if (!isPlainObject(value)) {
    issues.push(`${path}: must be a plain object of criteria arrays`);
    return false;
  }
  for (const key of Object.keys(value)) {
    if (!CRITERIA.includes(key)) {
      issues.push(
        `${path}.${key}: unknown criterion (expected one of: ${CRITERIA.join(", ")})`,
      );
    }
  }
  let declared = 0;
  for (const key of CRITERIA) {
    if (!(key in value)) continue;
    const entries = value[key];
    if (!Array.isArray(entries)) {
      issues.push(`${path}.${key}: must be an array`);
      continue;
    }
    entries.forEach((entry, index) => {
      if (typeof entry !== "string" || entry.trim() === "") {
        issues.push(`${path}.${key}[${index}]: must be a non-empty string`);
        return;
      }
      declared += 1;
    });
  }
  return declared > 0;
}

function normalizeCriteria(value) {
  const normalized = {};
  for (const key of CRITERIA) {
    const entries = value?.[key];
    if (!Array.isArray(entries) || entries.length === 0) continue;
    normalized[key] = Object.freeze(entries.map((entry) => entry.toLowerCase()));
  }
  return Object.freeze(normalized);
}

/**
 * Validate, normalize and freeze a filename spec.
 *
 * @param {object} spec Criteria object, optionally with an `exclude`.
 * @param {object} [options]
 * @param {string} [options.name] Contract name used in the error message.
 * @returns {object} A frozen, lower-cased spec.
 * @throws {ValidationError} When the spec has an unknown criterion, a malformed
 *   entry, or no positive criterion at all.
 */
export function defineFileSpec(spec, { name = "SensitiveFileSpec" } = {}) {
  const issues = [];
  const positive = isPlainObject(spec)
    ? Object.fromEntries(Object.entries(spec).filter(([key]) => key !== "exclude"))
    : spec;
  const hasPositive = collectCriteriaIssues(positive, name, issues);
  if (isPlainObject(spec) && "exclude" in spec) {
    collectCriteriaIssues(spec.exclude, `${name}.exclude`, issues);
  }
  if (isPlainObject(spec) && !hasPositive && issues.length === 0) {
    issues.push(`${name}: must declare at least one positive criterion`);
  }
  if (issues.length > 0) {
    throw new ValidationError(`Invalid ${name}`, {
      details: { contract: name, issues },
    });
  }
  return Object.freeze({
    ...normalizeCriteria(spec),
    exclude: normalizeCriteria(spec.exclude),
  });
}

/** The directory segments of a repository-relative path, lower-cased. */
function directorySegments(path) {
  const segments = String(path ?? "")
    .toLowerCase()
    .split("/");
  segments.pop();
  return segments;
}

function matchesCriteria(criteria, name, extension, segments) {
  if (criteria.basenames !== undefined && criteria.basenames.includes(name)) return true;
  if (criteria.extensions !== undefined && criteria.extensions.includes(extension)) return true;
  if (
    criteria.namePrefixes !== undefined &&
    criteria.namePrefixes.some((prefix) => name.startsWith(prefix))
  ) {
    return true;
  }
  if (
    criteria.nameSuffixes !== undefined &&
    criteria.nameSuffixes.some((suffix) => name.endsWith(suffix))
  ) {
    return true;
  }
  if (
    criteria.pathSegments !== undefined &&
    criteria.pathSegments.some((segment) => segments.includes(segment))
  ) {
    return true;
  }
  return false;
}

/**
 * Whether an observed file entity matches a spec. Pure and deterministic: the same
 * entity and spec always produce the same answer, and nothing outside the entity is
 * consulted.
 *
 * @param {object} spec A spec from `defineFileSpec` (or a frozen literal of the same
 *   shape).
 * @param {object} file A `file` entity from the RepositoryModel.
 * @returns {boolean}
 */
export function matchesFileSpec(spec, file) {
  if (!isPlainObject(spec) || !isPlainObject(file)) return false;
  const name = String(file.name ?? "").toLowerCase();
  const extension = String(file.extension ?? "").toLowerCase();
  if (spec.exclude !== undefined && matchesCriteria(spec.exclude, name, extension, directorySegments(file.path))) {
    return false;
  }
  return matchesCriteria(spec, name, extension, directorySegments(file.path));
}
