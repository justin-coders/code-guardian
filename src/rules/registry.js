/**
 * Code Guardian — Rule Registry (Phase 10)
 *
 * The registry is a catalog, not an evaluator: it stores rules, guarantees their
 * ids are unique, validates their declarative shape, and hands them out in a
 * documented order. The engine decides what runs and in what order.
 *
 * Two guarantees matter for determinism and safety:
 *
 *   1. **Ids are unique and stable.** Registering a duplicate id fails
 *      deterministically rather than silently replacing a rule — a silent
 *      replacement would change what a run means without changing the caller's
 *      code.
 *   2. **Ordering is explicit.** `list()` sorts by rule id and never exposes Map
 *      or insertion order. Object key order is an implementation detail of
 *      JavaScript, not an execution contract.
 *
 * Registration validates the Core Rule contract *and* the framework's additional
 * requirements: the id must be a bounded lower-case namespace, and `applicability`
 * must be a selector object drawn from the Core vocabulary (`languages`,
 * `frameworks`, `files`, `capabilities`) with array-of-string values. Validating
 * selectors here means a typo'd selector is a registration error rather than a
 * rule that silently never applies.
 *
 * The registry stores a frozen structural copy of each rule, so a caller that
 * keeps a reference cannot mutate what the registry will run — and the caller's
 * own object is not frozen as a side effect.
 */

import { VERSION_PATTERN, validateRule } from "../core/index.js";
import { isRepositoryRelativePath } from "../repository/model/index.js";

import { deepFreeze } from "../analysis/index.js";

import {
  MAX_IDENTIFIER_LENGTH,
  RULE_FAILURE_KINDS,
  RULE_ID_PATTERN,
  RULE_SELECTOR_KEYS,
} from "./contracts.js";
import { RuleConfigurationError, RuleRegistrationError } from "./errors.js";

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function boundedString(value, maxLength = MAX_IDENTIFIER_LENGTH) {
  return typeof value === "string" && value.trim() !== "" && value.length <= maxLength;
}

/** Identifier-shaped selector value (languages, frameworks, capabilities). */
const SELECTOR_ID_PATTERN = /^[a-z0-9][a-z0-9._-]*$/;

/** Which selector keys accept repository-relative paths rather than identifiers. */
const PATH_SELECTOR_KEYS = Object.freeze(["files"]);

/**
 * Collect everything wrong with a rule's `applicability` selector object.
 *
 * @param {unknown} applicability
 * @param {string} path
 * @returns {string[]}
 */
export function applicabilitySelectorIssues(applicability, path = "rule.applicability") {
  if (!isPlainObject(applicability)) {
    return [`${path}: must be a plain object of selector arrays`];
  }

  const issues = [];
  for (const key of Object.keys(applicability)) {
    if (!RULE_SELECTOR_KEYS.includes(key)) {
      issues.push(
        `${path}.${key}: unknown selector (expected one of: ${RULE_SELECTOR_KEYS.join(", ")})`,
      );
      continue;
    }
    const value = applicability[key];
    if (!Array.isArray(value)) {
      issues.push(`${path}.${key}: must be an array`);
      continue;
    }
    const acceptsPaths = PATH_SELECTOR_KEYS.includes(key);
    value.forEach((entry, index) => {
      if (!boundedString(entry)) {
        issues.push(`${path}.${key}[${index}]: must be a non-empty bounded string`);
        return;
      }
      if (acceptsPaths) {
        if (!isRepositoryRelativePath(entry)) {
          issues.push(
            `${path}.${key}[${index}]: must be a repository-relative path`,
          );
        }
        return;
      }
      if (!SELECTOR_ID_PATTERN.test(entry)) {
        issues.push(
          `${path}.${key}[${index}]: must be a lower-case identifier such as "typescript"`,
        );
      }
    });
  }
  return issues;
}

/**
 * Collect everything wrong with a rule descriptor.
 *
 * Runs the Core contract first (identity, version, metadata and the `detect`
 * function), then the framework's id-shape and selector requirements. Returning
 * issues rather than throwing lets the registry report every problem at once.
 *
 * @param {unknown} rule
 * @returns {string[]} Empty when the rule may be registered.
 */
export function ruleDescriptorIssues(rule) {
  const issues = [];

  if (!isPlainObject(rule)) {
    return ["rule: must be a plain object"];
  }

  try {
    validateRule(rule);
  } catch (error) {
    const reported = error?.details?.issues;
    if (Array.isArray(reported)) issues.push(...reported);
    else issues.push("rule: does not satisfy the Core Rule contract");
  }

  if (typeof rule.id === "string") {
    if (rule.id.length > MAX_IDENTIFIER_LENGTH) {
      issues.push(`rule.id: must be at most ${MAX_IDENTIFIER_LENGTH} characters`);
    } else if (!RULE_ID_PATTERN.test(rule.id)) {
      issues.push('rule.id: must be a lower-case dotted namespace such as "security.hardcoded-secret"');
    }
  }

  if (rule.applicability !== undefined) {
    issues.push(...applicabilitySelectorIssues(rule.applicability));
  }

  if (typeof rule.version === "string" && !VERSION_PATTERN.test(rule.version)) {
    if (!issues.some((issue) => issue.includes("version"))) {
      issues.push('rule.version: must be a version string such as "1.0.0"');
    }
  }

  return issues;
}

/** A frozen structural copy: the registry owns its entry, the caller keeps theirs. */
function freezeEntry(rule) {
  return deepFreeze({
    ...rule,
    applicability: { ...(isPlainObject(rule.applicability) ? rule.applicability : {}) },
    remediation: { ...(isPlainObject(rule.remediation) ? rule.remediation : {}) },
    metadata: { ...(isPlainObject(rule.metadata) ? rule.metadata : {}) },
  });
}

/**
 * Create an empty rule registry.
 *
 * @param {object[]} [rules] Rules to register immediately.
 * @returns {object} A frozen registry handle.
 */
export function createRuleRegistry(rules = []) {
  const byId = new Map();

  const registry = {
    /**
     * Register one rule.
     * @throws {RuleRegistrationError} When the descriptor is invalid.
     * @throws {RuleConfigurationError} When the id is already registered.
     */
    register(rule) {
      const issues = ruleDescriptorIssues(rule);
      if (issues.length > 0) {
        throw new RuleRegistrationError(issues);
      }
      if (byId.has(rule.id)) {
        throw new RuleConfigurationError(
          RULE_FAILURE_KINDS.DUPLICATE_RULE,
          `Rule "${rule.id}" is already registered`,
          { ruleId: rule.id },
        );
      }
      byId.set(rule.id, freezeEntry(rule));
      return registry;
    },

    /** Register many rules in the given order. */
    registerAll(list) {
      for (const rule of list) registry.register(rule);
      return registry;
    },

    /** The rule with this id, or `null`. */
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

    /** Registered rules, sorted by id (never insertion order). */
    list() {
      return registry.ids().map((id) => byId.get(id));
    },

    /**
     * Resolve ids to rules, sorted by id and de-duplicated.
     *
     * An id that is not registered is a *framework* failure, never a silent no-op:
     * a run that quietly evaluates nothing is worse than a run that fails.
     *
     * @throws {RuleConfigurationError} When any id is unknown.
     */
    select(ids) {
      const requested = [...new Set(ids)].sort();
      const unknown = requested.filter((id) => !byId.has(id)).sort();
      if (unknown.length > 0) {
        throw new RuleConfigurationError(
          RULE_FAILURE_KINDS.UNKNOWN_RULE,
          `Unknown rule${unknown.length === 1 ? "" : "s"}: ${unknown.join(", ")}`,
          { unknown },
        );
      }
      return requested.map((id) => byId.get(id));
    },

    /** Number of registered rules. */
    get size() {
      return byId.size;
    },
  };

  registry.registerAll(rules);
  return Object.freeze(registry);
}
