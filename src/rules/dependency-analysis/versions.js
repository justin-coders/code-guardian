/**
 * Code Guardian — Dependency Version Semantics (Official Roadmap Phase 15)
 *
 * Version comparison is ecosystem-aware on purpose. The roadmap's warning is real: `"10.0.0" <
 * "9.0.0"` lexically is wrong, and not every ecosystem means SemVer. This module therefore
 * compares only ecosystems whose semantics it can establish — today `node` (npm SemVer) — and
 * returns `null` (an honest *cannot compare*) for every other ecosystem or any input it cannot
 * parse. `null` is what makes the outdated and vulnerability rules answer `unknown` rather than
 * an incorrect comparison.
 *
 * It is pure, bounded and deterministic: no clock, no environment, no external call, and a
 * bounded input length so a hostile range string cannot become a parsing cost.
 */

import { SEMVER_ECOSYSTEMS } from "./contracts.js";

const MAX_VERSION_LENGTH = 128;
const MAX_RANGE_LENGTH = 256;

/** Whether this build can compare versions in an ecosystem at all. */
export function isComparableEcosystem(ecosystem) {
  return SEMVER_ECOSYSTEMS.includes(ecosystem);
}

/** Whether a string is a plausible version token for the bounded parse below. */
function isBoundedText(text, max) {
  return typeof text === "string" && text.length > 0 && text.length <= max;
}

/**
 * Parse a SemVer-ish version into numeric parts.
 *
 * Accepts an optional leading `v`, `major[.minor[.patch]]` with missing parts treated as zero,
 * and ignores build metadata / a prerelease suffix for comparison purposes. Returns `null` when
 * the text is not numeric-dotted or is out of bounds — never a guessed value.
 *
 * @param {string} text
 * @returns {{major: number, minor: number, patch: number}|null}
 */
export function parseVersion(text) {
  if (!isBoundedText(text, MAX_VERSION_LENGTH)) return null;
  const trimmed = text.trim().replace(/^v/, "");
  const core = trimmed.split("+")[0].split("-")[0];
  const parts = core.split(".");
  if (parts.length === 0 || parts.length > 3) return null;
  const numbers = [];
  for (const part of parts) {
    if (!/^\d+$/.test(part)) return null;
    const value = Number(part);
    if (!Number.isSafeInteger(value)) return null;
    numbers.push(value);
  }
  while (numbers.length < 3) numbers.push(0);
  return { major: numbers[0], minor: numbers[1], patch: numbers[2] };
}

function compareParsed(a, b) {
  if (a.major !== b.major) return a.major < b.major ? -1 : 1;
  if (a.minor !== b.minor) return a.minor < b.minor ? -1 : 1;
  if (a.patch !== b.patch) return a.patch < b.patch ? -1 : 1;
  return 0;
}

/**
 * Compare two versions in an ecosystem.
 *
 * @param {string} ecosystem
 * @param {string} a
 * @param {string} b
 * @returns {-1|0|1|null} `null` when the ecosystem or either version cannot be compared.
 */
export function compareVersions(ecosystem, a, b) {
  if (!isComparableEcosystem(ecosystem)) return null;
  const left = parseVersion(a);
  const right = parseVersion(b);
  if (left === null || right === null) return null;
  return compareParsed(left, right);
}

function bump(parsed, level) {
  if (level === "major") return { major: parsed.major + 1, minor: 0, patch: 0 };
  if (level === "minor") return { major: parsed.major, minor: parsed.minor + 1, patch: 0 };
  return { major: parsed.major, minor: parsed.minor, patch: parsed.patch + 1 };
}

/**
 * The inclusive/exclusive bounds a single comparator establishes, or `null`.
 *
 * Supports the npm range forms this build documents: `*`/`x`, an exact version, `=`, `>`, `>=`,
 * `<`, `<=`, `^`, `~`, and partial `1` / `1.2` / `1.x` / `1.2.x` forms. Anything else is `null`,
 * so an unparsed range never produces a comparison.
 */
function comparatorBounds(term) {
  const text = term.trim();
  if (text === "" || text === "*" || text === "x" || text === "X") return { min: null, max: null };

  const match = /^(\^|~|>=|<=|>|<|=)?\s*(.+)$/.exec(text);
  if (match === null) return null;
  const operator = match[1] ?? "=";
  const raw = match[2].trim();

  const partial = /^(\d+)(?:\.(\d+|[xX*]))?(?:\.(\d+|[xX*]))?$/.exec(raw);
  if (partial !== null) {
    const wildMinor = partial[2] === undefined || /^[xX*]$/.test(partial[2]);
    const wildPatch = partial[3] === undefined || /^[xX*]$/.test(partial[3]);
    const major = Number(partial[1]);
    if (wildMinor) return { min: { major, minor: 0, patch: 0 }, max: bump({ major, minor: 0, patch: 0 }, "major"), maxExclusive: true };
    const minor = Number(partial[2]);
    if (wildPatch) return { min: { major, minor, patch: 0 }, max: bump({ major, minor, patch: 0 }, "minor"), maxExclusive: true };
  }

  const parsed = parseVersion(raw);
  if (parsed === null) return null;

  if (operator === "=") return { min: parsed, max: parsed, maxExclusive: false };
  if (operator === ">") return { min: bump(parsed, "patch"), max: null, minExclusive: false };
  if (operator === ">=") return { min: parsed, max: null };
  if (operator === "<") return { min: null, max: parsed, maxExclusive: true };
  if (operator === "<=") return { min: null, max: parsed, maxExclusive: false };
  if (operator === "~") return { min: parsed, max: bump(parsed, "minor"), maxExclusive: true };
  if (operator === "^") {
    // npm caret: the leftmost non-zero component is held; `^0.0.3` allows only 0.0.3.
    let upper;
    if (parsed.major !== 0) upper = { major: parsed.major + 1, minor: 0, patch: 0 };
    else if (parsed.minor !== 0) upper = { major: 0, minor: parsed.minor + 1, patch: 0 };
    else upper = { major: 0, minor: 0, patch: parsed.patch + 1 };
    return { min: parsed, max: upper, maxExclusive: true };
  }
  return null;
}

/** A version against one comparator term. `null` when the term cannot be parsed. */
function satisfiesTerm(parsed, term) {
  const bounds = comparatorBounds(term);
  if (bounds === null) return null;
  if (bounds.min !== null) {
    const comparison = compareParsed(parsed, bounds.min);
    if (bounds.minExclusive === false && comparison < 0) return false;
    if (bounds.minExclusive !== false && comparison < 0) return false;
  }
  if (bounds.max !== null) {
    const comparison = compareParsed(parsed, bounds.max);
    if (bounds.maxExclusive === true && comparison >= 0) return false;
    if (bounds.maxExclusive !== true && comparison > 0) return false;
  }
  return true;
}

/**
 * Whether a version satisfies a range in an ecosystem.
 *
 * Multiple space-separated comparators are AND-ed; `||` separates OR alternatives. Returns
 * `null` when the ecosystem is not comparable, the version cannot be parsed, or any alternative
 * contains an unparsed term — a partial answer is never promoted to a whole one.
 *
 * @param {string} ecosystem
 * @param {string} version
 * @param {string} range
 * @returns {boolean|null}
 */
export function satisfiesRange(ecosystem, version, range) {
  if (!isComparableEcosystem(ecosystem)) return null;
  const parsed = parseVersion(version);
  if (parsed === null) return null;
  if (!isBoundedText(range, MAX_RANGE_LENGTH)) return null;

  const alternatives = range.split("||");
  if (alternatives.length > 32) return null;

  let sawParsed = false;
  for (const alternative of alternatives) {
    const terms = alternative.trim().split(/\s+/).filter((term) => term !== "");
    if (terms.length > 16) return null;
    let allTrue = true;
    for (const term of terms) {
      const result = satisfiesTerm(parsed, term);
      if (result === null) return null;
      sawParsed = true;
      if (result === false) {
        allTrue = false;
        break;
      }
    }
    if (allTrue) return true;
  }
  return sawParsed ? false : null;
}

/**
 * Whether a declared specifier pins an exact version (no range operators, no wildcards).
 *
 * Used so a repository with no lockfile can still have its *pinned* declaration compared, while
 * a range declaration is never mistaken for an installed version.
 *
 * @param {string} spec
 * @returns {string|null} The exact version, or `null`.
 */
export function exactDeclaredVersion(spec) {
  if (typeof spec !== "string") return null;
  const trimmed = spec.trim();
  if (trimmed === "" || /[\^~<>=*xX|,\s]/.test(trimmed)) return null;
  const parsed = parseVersion(trimmed);
  return parsed === null ? null : trimmed.replace(/^v/, "");
}
