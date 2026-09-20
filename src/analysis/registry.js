/**
 * Code Guardian — Analyzer Registry (Phase 9)
 *
 * The registry is a catalog, not a scheduler: it stores analyzers, guarantees
 * their ids are unique, and hands them out in a documented order. The engine
 * decides what runs and in what order.
 *
 * Two guarantees matter for determinism and attribution:
 *
 *   1. **Ids are unique and stable.** Registering a duplicate id fails
 *      deterministically rather than silently replacing an analyzer — a silent
 *      replacement would change what a run means without changing the caller's
 *      code.
 *   2. **Ordering is explicit.** `list()` sorts by id and never exposes Map or
 *      insertion order. Object key order is an implementation detail of
 *      JavaScript, not an execution contract.
 *
 * Registration validates against the Core Analyzer contract *and* the framework's
 * attribution requirements (`name`, `scope`), because a registry entry has to be
 * identifiable in a report. The registry stores analyzers by reference and never
 * calls them.
 */

import { validateAnalyzer } from "../core/index.js";

import {
  ANALYZER_FAILURE_KINDS,
  ANALYZER_ID_PATTERN,
  ANALYZER_SCOPE_PATTERN,
  MAX_IDENTIFIER_LENGTH,
  VERSION_PATTERN,
} from "./contracts.js";
import { AnalyzerConfigurationError, AnalyzerRegistrationError } from "./errors.js";

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function boundedString(value, maxLength = MAX_IDENTIFIER_LENGTH) {
  return typeof value === "string" && value.trim() !== "" && value.length <= maxLength;
}

/**
 * Collect everything wrong with an analyzer descriptor.
 *
 * Runs the Core contract first (identity, version, and the two functions), then
 * the framework's attribution requirements. Returning issues rather than throwing
 * lets the registry report every problem at once.
 *
 * @param {unknown} analyzer
 * @returns {string[]} Empty when the analyzer may be registered.
 */
export function analyzerDescriptorIssues(analyzer) {
  const issues = [];

  if (!isPlainObject(analyzer)) {
    return ["analyzer: must be a plain object"];
  }

  try {
    validateAnalyzer(analyzer);
  } catch (error) {
    const reported = error?.details?.issues;
    if (Array.isArray(reported)) issues.push(...reported);
    else issues.push("analyzer: does not satisfy the Core Analyzer contract");
  }

  if (typeof analyzer.id === "string") {
    if (analyzer.id.length > MAX_IDENTIFIER_LENGTH) {
      issues.push(`analyzer.id: must be at most ${MAX_IDENTIFIER_LENGTH} characters`);
    } else if (!ANALYZER_ID_PATTERN.test(analyzer.id)) {
      issues.push(
        'analyzer.id: must be a lower-case dotted namespace such as "security.node"',
      );
    }
  }

  if (!boundedString(analyzer.name)) {
    issues.push("analyzer.name: must be a non-empty bounded string");
  }

  if (!boundedString(analyzer.scope, 40) || !ANALYZER_SCOPE_PATTERN.test(String(analyzer.scope))) {
    issues.push('analyzer.scope: must be a lower-case domain such as "security"');
  }

  if (analyzer.description !== undefined && typeof analyzer.description !== "string") {
    issues.push("analyzer.description: must be a string");
  }

  if (analyzer.metadata !== undefined && !isPlainObject(analyzer.metadata)) {
    issues.push("analyzer.metadata: must be a plain object");
  }

  if (typeof analyzer.version === "string" && !VERSION_PATTERN.test(analyzer.version)) {
    // The Core validator already reports this; kept for a clearer message when
    // the descriptor is used without Core validation.
    if (!issues.some((issue) => issue.includes("version"))) {
      issues.push('analyzer.version: must be a version string such as "1.0.0"');
    }
  }

  return issues;
}

/**
 * Create an empty analyzer registry.
 *
 * @param {object[]} [analyzers] Analyzers to register immediately.
 * @returns {object} A frozen registry handle.
 */
export function createAnalyzerRegistry(analyzers = []) {
  const byId = new Map();

  const registry = {
    /**
     * Register one analyzer.
     * @throws {AnalyzerRegistrationError} When the descriptor is invalid.
     * @throws {AnalyzerConfigurationError} When the id is already registered.
     */
    register(analyzer) {
      const issues = analyzerDescriptorIssues(analyzer);
      if (issues.length > 0) {
        throw new AnalyzerRegistrationError(issues);
      }
      if (byId.has(analyzer.id)) {
        throw new AnalyzerConfigurationError(
          ANALYZER_FAILURE_KINDS.DUPLICATE_ANALYZER,
          `Analyzer "${analyzer.id}" is already registered`,
          { analyzerId: analyzer.id },
        );
      }
      byId.set(analyzer.id, analyzer);
      return registry;
    },

    /** Register many analyzers in the given order. */
    registerAll(list) {
      for (const analyzer of list) registry.register(analyzer);
      return registry;
    },

    /** The analyzer with this id, or `null`. */
    get(id) {
      return typeof id === "string" ? byId.get(id) ?? null : null;
    },

    /** Whether an id is registered. */
    has(id) {
      return typeof id === "string" && byId.has(id);
    },

    /** Registered ids, sorted ascending. */
    ids() {
      return [...byId.keys()].sort();
    },

    /** Registered analyzers, sorted by id (never insertion order). */
    list() {
      return registry.ids().map((id) => byId.get(id));
    },

    /**
     * Resolve ids to analyzers, sorted by id and de-duplicated.
     *
     * An id that is not registered is a *framework* failure, never a silent
     * no-op: a run that quietly analyses nothing is worse than a run that fails.
     *
     * @throws {AnalyzerConfigurationError} When any id is unknown.
     */
    select(ids) {
      const requested = [...new Set(ids)].sort();
      const unknown = requested.filter((id) => !byId.has(id)).sort();
      if (unknown.length > 0) {
        throw new AnalyzerConfigurationError(
          ANALYZER_FAILURE_KINDS.UNKNOWN_ANALYZER,
          `Unknown analyzer${unknown.length === 1 ? "" : "s"}: ${unknown.join(", ")}`,
          { unknown },
        );
      }
      return requested.map((id) => byId.get(id));
    },

    /** Number of registered analyzers. */
    get size() {
      return byId.size;
    },
  };

  registry.registerAll(analyzers);
  return Object.freeze(registry);
}
