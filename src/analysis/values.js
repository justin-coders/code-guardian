/**
 * Code Guardian — Analyzer Framework Value Handling (Phase 9)
 *
 * Analyzers are code, and their output crosses a trust boundary into a result
 * that gets serialized, baselined and reported. This module makes that crossing
 * boring: every analyzer-supplied object is copied into **plain, bounded,
 * JSON-safe data** before it reaches a finding or a result.
 *
 * Why not trust the analyzer's objects directly?
 *
 *   - Functions, symbols, class instances and accessors do not survive
 *     serialization, and an accessor could run arbitrary code during a later
 *     `JSON.stringify`.
 *   - Cycles make results unserializable.
 *   - `__proto__` / `constructor` / `prototype` keys can smuggle prototype
 *     pollution into consumers.
 *   - Unbounded metadata makes a "deterministic" result payload unbounded.
 *
 * Sanitizing is deterministic: the same input always produces the same output,
 * which is what keeps fingerprints and canonical comparisons stable.
 *
 * This module performs no I/O, no clock reads and no randomness.
 */

/** Default limits applied to analyzer-supplied data. */
export const SANITIZE_LIMITS = Object.freeze({
  /** Maximum object/array nesting copied. */
  maxDepth: 4,
  /** Maximum keys copied from one object. */
  maxKeys: 200,
  /** Maximum elements copied from one array. */
  maxArrayLength: 200,
  /** Maximum length of a copied string. */
  maxStringLength: 500,
});

/** Keys that must never be copied, whatever the analyzer sends. */
export const UNSAFE_KEYS = Object.freeze(["__proto__", "constructor", "prototype"]);

/** Marker used when a value is dropped for being too deep. */
export const TRUNCATION_MARKER = "[truncated]";

function isPlainObject(value) {
  if (value === null || typeof value !== "object") return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

/**
 * Copy a value into bounded, plain, JSON-safe data.
 *
 * Dropped: functions, symbols, undefined, class instances, accessors, cyclic
 * references, unsafe keys, values past the depth/key/length limits. Kept:
 * strings, finitely-numbered numbers, booleans, null, plain arrays and plain
 * objects.
 *
 * @param {unknown} value
 * @param {object} [limits] Overrides for `SANITIZE_LIMITS`.
 * @param {WeakSet} [seen] Cycle tracking (internal).
 * @param {number} [depth] Current depth (internal).
 * @returns {unknown} A plain copy safe to serialize, or `TRUNCATION_MARKER`.
 */
export function sanitizeDeclarativeValue(value, limits = SANITIZE_LIMITS, seen = new WeakSet(), depth = 0) {
  if (value === null) return null;

  const type = typeof value;
  if (type === "string") {
    return value.length > limits.maxStringLength
      ? value.slice(0, limits.maxStringLength)
      : value;
  }
  if (type === "number") return Number.isFinite(value) ? value : null;
  if (type === "boolean") return value;
  if (type !== "object") return undefined;

  if (depth >= limits.maxDepth) return TRUNCATION_MARKER;
  if (seen.has(value)) return TRUNCATION_MARKER;
  seen.add(value);

  if (Array.isArray(value)) {
    const out = [];
    const length = Math.min(value.length, limits.maxArrayLength);
    for (let index = 0; index < length; index += 1) {
      const copied = sanitizeDeclarativeValue(value[index], limits, seen, depth + 1);
      out.push(copied === undefined ? null : copied);
    }
    return out;
  }

  if (!isPlainObject(value)) return undefined;

  const out = {};
  let copied = 0;
  for (const key of Object.keys(value).sort()) {
    if (copied >= limits.maxKeys) break;
    if (UNSAFE_KEYS.includes(key)) continue;
    const nested = sanitizeDeclarativeValue(value[key], limits, seen, depth + 1);
    if (nested === undefined) continue;
    // `Object.defineProperty` avoids the setter path entirely, so a hostile key
    // can never re-enter the prototype chain.
    Object.defineProperty(out, key, {
      value: nested,
      enumerable: true,
      writable: true,
      configurable: true,
    });
    copied += 1;
  }
  return out;
}

/**
 * Objects this module has already frozen *throughout* — i.e. every object
 * reachable from them was visited. Membership, not `Object.isFrozen`, is what
 * licenses skipping a subtree.
 */
const DEEPLY_FROZEN = new WeakSet();

/**
 * Deeply freeze a value in place.
 *
 * Analyzer results are shared between the aggregate result and per-analyzer
 * results, so freezing guarantees one analyzer (or one consumer) cannot corrupt
 * another's view.
 *
 * Note what this function deliberately does **not** trust: `Object.isFrozen` as
 * proof that a subtree is *deeply* frozen. Objects here are frozen shallowly in
 * legitimate places — `normalizeFinding` freezes each canonical Finding so its
 * identity cannot change, and Core's draft factories freeze what they return — so
 * treating a frozen node as a finished one would stop the walk at, for example,
 * `finding.evidence` and leave that array mutable (a real defect this function
 * used to have). A node is therefore skipped only when this module has itself
 * completed a walk of it, which both keeps the shared Phase 8D RepositoryModel
 * from being re-walked on every context build and makes "already frozen" mean
 * "verified frozen" rather than "assumed frozen".
 *
 * @param {unknown} value
 * @param {WeakSet<object>} [seen] Per-call cycle guard.
 * @returns {unknown} The same value, frozen as far as it is traversable.
 */
export function deepFreeze(value, seen = new WeakSet()) {
  if (
    value === null ||
    typeof value !== "object" ||
    seen.has(value) ||
    DEEPLY_FROZEN.has(value)
  ) {
    return value;
  }
  seen.add(value);
  if (!Object.isFrozen(value)) Object.freeze(value);
  for (const key of Object.keys(value)) deepFreeze(value[key], seen);
  // Added only after the whole subtree has been visited, so the entry cannot
  // hide a mutable descendant.
  DEEPLY_FROZEN.add(value);
  return value;
}
