/**
 * Code Guardian — Rule Registry (Phase 10, formalized in Phase 18)
 *
 * The registry is a catalog, not an evaluator: it stores rules, guarantees their
 * ids are unique, validates their declarative shape, and hands them out in a
 * documented order. The engine decides what runs and in what order; applicability
 * is answered by `evaluateRuleApplicability`; detection is never executed here.
 *
 * Two guarantees matter for determinism and safety:
 *
 *   1. **Ids are unique and stable.** Registering a duplicate id fails
 *      deterministically rather than silently replacing a rule — a silent
 *      replacement would change what a run means without changing the caller's
 *      code.
 *   2. **Ordering is explicit.** Every list answer sorts by rule id and never
 *      exposes Map or insertion order. Object key order is an implementation
 *      detail of JavaScript, not an execution contract.
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
 *
 * ### Phase 18 formalization
 *
 * Phase 18 turns this catalog into the roadmap's rule-management surface without
 * collapsing layers. The catalog now exposes, all deterministic and all derived
 * from the canonical registered entries:
 *
 *   register / registerAll   registration (unchanged)
 *   lookup / get / has       identity lookup
 *   version                  declared-version discovery
 *   list / ids               the whole catalog, id-sorted
 *   filter                   catalog entries matching metadata selectors
 *   select / selectCategories execution candidates after configuration
 *   enable / disable / isEnabled   explicit activation configuration
 *   configure / configuration      the closed, data-only configuration channel
 *   describe / describeAll   safe metadata discovery (no `detect`)
 *   evaluateApplicability    a convenience delegate to the existing evaluator
 *
 * Enablement is **configuration**, not a conclusion: a disabled rule remains
 * registered, discoverable, filterable and versioned. Filtering over the catalog
 * returns disabled rules; execution selection does not. Applicability is decided
 * solely by `evaluateRuleApplicability`, so `unknown` is never turned into
 * `not-applicable`. Configuration is plain, bounded, serializable data — never a
 * function, never `eval`, never a module load — and it overrides registry state
 * rather than mutating the immutable Rule descriptor.
 */

import { VERSION_PATTERN, validateRule } from "../core/index.js";
import { isRepositoryRelativePath } from "../repository/model/index.js";

import {
  SANITIZE_LIMITS,
  UNSAFE_KEYS,
  deepFreeze,
  sanitizeDeclarativeValue,
} from "../analysis/index.js";

import {
  MAX_CONFIGURATION_VALUES,
  MAX_IDENTIFIER_LENGTH,
  RULE_CONFIGURATION_KEYS,
  RULE_FAILURE_KINDS,
  RULE_FILTER_KEYS,
  RULE_ID_PATTERN,
  RULE_SELECTOR_KEYS,
} from "./contracts.js";
import { RuleConfigurationError, RuleRegistrationError } from "./errors.js";

import { evaluateRuleApplicability } from "./applicability.js";

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
 * Collect everything wrong with a value that must be plain, bounded, serializable
 * configuration data.
 *
 * Configuration crosses a trust boundary into registry state, so it is validated
 * rather than sanitized-silently: a function, a class instance, a cyclic graph, an
 * unsafe key (`__proto__`/`constructor`/`prototype`) or an over-large structure is
 * an explicit error, never a value quietly dropped.
 *
 * @param {unknown} value
 * @param {string} path
 * @param {object} [state]
 * @returns {string[]}
 */
export function declarativeDataIssues(value, path, state = { path: new WeakSet(), depth: 0 }) {
  const issues = [];
  if (value === null) return issues;

  const type = typeof value;
  if (type === "string") {
    if (value.length > SANITIZE_LIMITS.maxStringLength) {
      issues.push(`${path}: string exceeds ${SANITIZE_LIMITS.maxStringLength} characters`);
    }
    return issues;
  }
  if (type === "number") {
    if (!Number.isFinite(value)) issues.push(`${path}: must be a finite number`);
    return issues;
  }
  if (type === "boolean") return issues;
  if (type !== "object") {
    issues.push(`${path}: must be plain data (string, number, boolean, null, array or object)`);
    return issues;
  }

  if (state.depth >= SANITIZE_LIMITS.maxDepth) {
    issues.push(`${path}: exceeds the maximum nesting depth of ${SANITIZE_LIMITS.maxDepth}`);
    return issues;
  }
  // Path-based cycle detection: a node only on the *current* descent is a cycle; the
  // same object reached twice as siblings is not.
  if (state.path.has(value)) {
    issues.push(`${path}: must not contain a cyclic reference`);
    return issues;
  }
  state.path.add(value);

  if (Array.isArray(value)) {
    if (value.length > SANITIZE_LIMITS.maxArrayLength) {
      issues.push(`${path}: array exceeds ${SANITIZE_LIMITS.maxArrayLength} elements`);
    }
    const length = Math.min(value.length, SANITIZE_LIMITS.maxArrayLength);
    for (let index = 0; index < length; index += 1) {
      issues.push(
        ...declarativeDataIssues(value[index], `${path}[${index}]`, {
          path: state.path,
          depth: state.depth + 1,
        }),
      );
    }
    state.path.delete(value);
    return issues;
  }

  if (!isPlainObject(value)) {
    issues.push(`${path}: must be a plain object`);
    state.path.delete(value);
    return issues;
  }

  const keys = Object.keys(value);
  if (keys.length > SANITIZE_LIMITS.maxKeys) {
    issues.push(`${path}: object exceeds ${SANITIZE_LIMITS.maxKeys} keys`);
  }
  for (const key of keys.slice(0, SANITIZE_LIMITS.maxKeys)) {
    if (UNSAFE_KEYS.includes(key)) {
      issues.push(`${path}.${key}: unsafe key`);
      continue;
    }
    if (typeof key !== "string" || key.length > SANITIZE_LIMITS.maxStringLength) {
      issues.push(`${path}: key exceeds ${SANITIZE_LIMITS.maxStringLength} characters`);
      continue;
    }
    issues.push(
      ...declarativeDataIssues(value[key], `${path}.${key}`, {
        path: state.path,
        depth: state.depth + 1,
      }),
    );
  }
  state.path.delete(value);
  return issues;
}

/**
 * Copy already-validated declarative data faithfully.
 *
 * Unlike `sanitizeDeclarativeValue` (which bounds *untrusted* analyzer output and
 * marks a second visit to one object `[truncated]`), configuration has already
 * passed `declarativeDataIssues`, so this copy preserves shared references, array
 * order and every validated leaf — a legitimate value is never silently altered.
 * A `memo` keeps shared sub-objects shared rather than duplicated.
 */
function copyDeclarativeData(value, memo = new Map()) {
  if (value === null || typeof value !== "object") return value;
  if (memo.has(value)) return memo.get(value);
  if (Array.isArray(value)) {
    const out = [];
    memo.set(value, out);
    for (const entry of value) out.push(copyDeclarativeData(entry, memo));
    return out;
  }
  const out = {};
  memo.set(value, out);
  for (const key of Object.keys(value)) {
    // `Object.defineProperty` avoids the setter path, so an unsafe key can never
    // re-enter the prototype chain (unsafe keys are already rejected upstream).
    Object.defineProperty(out, key, {
      value: copyDeclarativeData(value[key], memo),
      enumerable: true,
      writable: true,
      configurable: true,
    });
  }
  return out;
}

/** Normalize one selector value into a bounded, deduplicated, non-empty list. */
function normalizeSelectorList(value, path, { allowBoolean = false } = {}) {
  const values = Array.isArray(value) ? value : [value];
  if (values.length === 0 || values.length > MAX_CONFIGURATION_VALUES) {
    throw new RuleConfigurationError(
      RULE_FAILURE_KINDS.INVALID_CONFIGURATION,
      `${path}: must carry between 1 and ${MAX_CONFIGURATION_VALUES} values`,
      { path },
    );
  }
  const normalized = [];
  for (const entry of values) {
    if (allowBoolean) {
      if (typeof entry !== "boolean") {
        throw new RuleConfigurationError(
          RULE_FAILURE_KINDS.INVALID_CONFIGURATION,
          `${path}: must be a boolean`,
          { path },
        );
      }
      normalized.push(entry);
      continue;
    }
    if (!boundedString(entry)) {
      throw new RuleConfigurationError(
        RULE_FAILURE_KINDS.INVALID_CONFIGURATION,
        `${path}: values must be non-empty strings of at most ${MAX_IDENTIFIER_LENGTH} characters`,
        { path },
      );
    }
    normalized.push(entry);
  }
  return [...new Set(normalized)].sort();
}

/**
 * Create an empty rule registry.
 *
 * @param {object[]} [rules] Rules to register immediately.
 * @param {object} [configuration] Optional initial Phase 18 configuration (see `configure`).
 * @returns {object} A frozen registry handle.
 */
export function createRuleRegistry(rules = [], configuration = null) {
  const byId = new Map();

  // Phase 18 configuration state. This is *configuration*, accumulated through the
  // frozen handle exactly as `register` accumulates rules; it never mutates a Rule
  // descriptor and never executes anything.
  const disabledIds = new Set();
  const enabledIds = new Set();
  let categoryAllowlist = null;
  let includeRules = null;
  const excludeRules = new Set();
  const ruleOptions = new Map();

  /** Whether a registered entry is enabled under the current configuration. */
  const isEntryEnabled = (rule) => {
    if (disabledIds.has(rule.id)) return false;
    if (excludeRules.has(rule.id)) return false;
    if (enabledIds.has(rule.id)) return true;
    if (categoryAllowlist !== null && !categoryAllowlist.has(rule.category)) return false;
    if (includeRules !== null && !includeRules.has(rule.id)) return false;
    return true;
  };

  /** Every category a registered rule declares, derived from the rules themselves. */
  const knownCategories = () => {
    const categories = new Set();
    for (const rule of byId.values()) {
      if (typeof rule.category === "string") categories.add(rule.category);
    }
    return categories;
  };

  const requireRegistered = (id, path) => {
    if (typeof id !== "string" || !byId.has(id)) {
      throw new RuleConfigurationError(
        RULE_FAILURE_KINDS.UNKNOWN_RULE,
        `${path}: "${id}" is not a registered rule`,
        { unknown: [typeof id === "string" ? id : null].filter((value) => value !== null) },
      );
    }
  };

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

    /** The rule with this id, or `null`. Canonical Phase 18 lookup name. */
    lookup(id) {
      return registry.get(id);
    },

    /** Whether an id is registered (independent of enablement). */
    has(id) {
      return typeof id === "string" && byId.has(id);
    },

    /** Registered ids, sorted ascending — includes disabled rules. */
    ids() {
      return [...byId.keys()].sort();
    },

    /** Registered rules, sorted by id (never insertion order) — includes disabled rules. */
    list() {
      return registry.ids().map((id) => byId.get(id));
    },

    /**
     * The declared version of a registered rule, or `null` when the id is
     * unregistered. The version is the rule's own — the registry never substitutes
     * or maintains a second version.
     */
    version(id) {
      const rule = registry.get(id);
      return rule === null ? null : rule.version;
    },

    /**
     * Catalog entries matching declarative selectors.
     *
     * Selector keys combine with **AND**; values inside one key combine with **OR**:
     * `{ category: ["security", "reliability"], tags: ["network"] }` means
     * `(category is security OR reliability) AND (tags include network)`.
     *
     * Recognized keys: `id`, `namespace`, `category`, `version`, `tags`,
     * `deprecated`, `enabled`. An unknown key is a configuration error rather than a
     * silently ignored criterion. Filtering never executes a rule and never mutates
     * registry state. Disabled rules are catalog entries, so `filter` returns them
     * unless `enabled: false/true` narrows the result.
     *
     * @param {object} [criteria]
     * @returns {object[]} Matching rules, id-sorted and deeply frozen.
     */
    filter(criteria = {}) {
      if (!isPlainObject(criteria)) {
        throw new RuleConfigurationError(
          RULE_FAILURE_KINDS.INVALID_CONFIGURATION,
          "filter criteria must be a plain object",
          { field: "criteria" },
        );
      }
      for (const key of Object.keys(criteria)) {
        if (!RULE_FILTER_KEYS.includes(key)) {
          throw new RuleConfigurationError(
            RULE_FAILURE_KINDS.INVALID_CONFIGURATION,
            `filter criteria.${key}: unknown selector (expected one of: ${RULE_FILTER_KEYS.join(", ")})`,
            { field: `criteria.${key}` },
          );
        }
      }

      const idValues = "id" in criteria ? normalizeSelectorList(criteria.id, "criteria.id") : null;
      const namespaceValues =
        "namespace" in criteria ? normalizeSelectorList(criteria.namespace, "criteria.namespace") : null;
      const categoryValues =
        "category" in criteria ? normalizeSelectorList(criteria.category, "criteria.category") : null;
      const versionValues =
        "version" in criteria ? normalizeSelectorList(criteria.version, "criteria.version") : null;
      const tagValues = "tags" in criteria ? normalizeSelectorList(criteria.tags, "criteria.tags") : null;
      const deprecatedValues =
        "deprecated" in criteria
          ? normalizeSelectorList(criteria.deprecated, "criteria.deprecated", { allowBoolean: true })
          : null;
      const enabledValues =
        "enabled" in criteria
          ? normalizeSelectorList(criteria.enabled, "criteria.enabled", { allowBoolean: true })
          : null;

      const matches = registry.list().filter((rule) => {
        if (idValues !== null && !idValues.includes(rule.id)) return false;
        if (
          namespaceValues !== null &&
          !namespaceValues.some((ns) => rule.id === ns || rule.id.startsWith(`${ns}.`))
        ) {
          return false;
        }
        if (categoryValues !== null && !categoryValues.includes(rule.category)) return false;
        if (versionValues !== null && !versionValues.includes(rule.version)) return false;
        if (tagValues !== null) {
          const tags = Array.isArray(rule.metadata?.tags) ? rule.metadata.tags : [];
          if (!tagValues.some((tag) => tags.includes(tag))) return false;
        }
        if (deprecatedValues !== null && !deprecatedValues.includes(rule.metadata?.deprecated === true)) {
          return false;
        }
        if (enabledValues !== null && !enabledValues.includes(isEntryEnabled(rule))) return false;
        return true;
      });

      return deepFreeze(matches);
    },

    /**
     * Resolve ids to rules, sorted by id and de-duplicated.
     *
     * An id that is not registered, or that configuration does not enable, is a
     * *framework* failure — never a silent no-op: a run that quietly evaluates
     * nothing (or quietly drops a requested rule) is worse than a run that fails.
     *
     * @throws {RuleConfigurationError} When any id is unknown or disabled.
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
      const disabled = requested.filter((id) => !isEntryEnabled(byId.get(id))).sort();
      if (disabled.length > 0) {
        throw new RuleConfigurationError(
          RULE_FAILURE_KINDS.DISABLED_RULE,
          `Disabled rule${disabled.length === 1 ? "" : "s"}: ${disabled.join(", ")}`,
          { disabled },
        );
      }
      return requested.map((id) => byId.get(id));
    },

    /**
     * Execution candidates in the given categories.
     *
     * Only registered **and enabled** rules are returned, id-sorted and
     * de-duplicated. A category no registered rule declares is a configuration
     * error rather than an empty result that reads like "no such rules exist".
     *
     * @param {string[]} categories
     * @throws {RuleConfigurationError} When any category is unknown.
     */
    selectCategories(categories) {
      const values = normalizeSelectorList(categories, "categories");
      const known = knownCategories();
      const unknown = values.filter((category) => !known.has(category));
      if (unknown.length > 0) {
        throw new RuleConfigurationError(
          RULE_FAILURE_KINDS.UNKNOWN_CATEGORY,
          `Unknown categor${unknown.length === 1 ? "y" : "ies"}: ${unknown.join(", ")}`,
          { unknown },
        );
      }
      const requested = new Set(values);
      return registry.list().filter((rule) => requested.has(rule.category) && isEntryEnabled(rule));
    },

    /** Registered, enabled rule ids, sorted ascending. */
    enabledIds() {
      return registry.ids().filter((id) => isEntryEnabled(byId.get(id)));
    },

    /** Registered, enabled rules, sorted by id. */
    activeRules() {
      return registry.enabledIds().map((id) => byId.get(id));
    },

    /** Whether a registered rule is enabled. Unknown ids are a configuration error. */
    isEnabled(id) {
      requireRegistered(id, "isEnabled");
      return isEntryEnabled(byId.get(id));
    },

    /**
     * Enable a registered rule, clearing any prior disable/exclusion so activation
     * is a last-write-wins configuration. Returns the registry for chaining.
     */
    enable(id) {
      requireRegistered(id, "enable");
      disabledIds.delete(id);
      excludeRules.delete(id);
      enabledIds.add(id);
      return registry;
    },

    /** Disable a registered rule. Disabled wins over enabled/exclusions. */
    disable(id) {
      requireRegistered(id, "disable");
      disabledIds.add(id);
      return registry;
    },

    /**
     * Apply a closed, data-only configuration object.
     *
     * Recognized keys: `enabled`, `disabled`, `includeRules`, `excludeRules`,
     * `categories`, `ruleOptions`. An unknown key, an unknown rule id, an unknown
     * category or a non-declarative value is an explicit error. Configuration is
     * accumulated onto registry state; the immutable Rule descriptors are never
     * touched. Returns the registry for chaining.
     *
     * @param {object} config
     * @throws {RuleConfigurationError}
     */
    configure(config = {}) {
      if (!isPlainObject(config)) {
        throw new RuleConfigurationError(
          RULE_FAILURE_KINDS.INVALID_CONFIGURATION,
          "configuration must be a plain object",
          { field: "configuration" },
        );
      }
      for (const key of Object.keys(config)) {
        if (!RULE_CONFIGURATION_KEYS.includes(key)) {
          throw new RuleConfigurationError(
            RULE_FAILURE_KINDS.INVALID_CONFIGURATION,
            `configuration.${key}: unknown key (expected one of: ${RULE_CONFIGURATION_KEYS.join(", ")})`,
            { field: `configuration.${key}` },
          );
        }
      }

      if ("enabled" in config) {
        for (const id of normalizeSelectorList(config.enabled, "configuration.enabled")) {
          requireRegistered(id, "configuration.enabled");
          disabledIds.delete(id);
          excludeRules.delete(id);
          enabledIds.add(id);
        }
      }
      if ("disabled" in config) {
        for (const id of normalizeSelectorList(config.disabled, "configuration.disabled")) {
          requireRegistered(id, "configuration.disabled");
          disabledIds.add(id);
        }
      }
      if ("includeRules" in config) {
        const ids = normalizeSelectorList(config.includeRules, "configuration.includeRules");
        for (const id of ids) requireRegistered(id, "configuration.includeRules");
        includeRules = new Set(ids);
      }
      if ("excludeRules" in config) {
        const ids = normalizeSelectorList(config.excludeRules, "configuration.excludeRules");
        for (const id of ids) requireRegistered(id, "configuration.excludeRules");
        for (const id of ids) excludeRules.add(id);
      }
      if ("categories" in config) {
        const values = normalizeSelectorList(config.categories, "configuration.categories");
        const known = knownCategories();
        const unknown = values.filter((category) => !known.has(category));
        if (unknown.length > 0) {
          throw new RuleConfigurationError(
            RULE_FAILURE_KINDS.UNKNOWN_CATEGORY,
            `Unknown categor${unknown.length === 1 ? "y" : "ies"}: ${unknown.join(", ")}`,
            { unknown },
          );
        }
        categoryAllowlist = new Set(values);
      }
      if ("ruleOptions" in config) {
        const options = config.ruleOptions;
        if (!isPlainObject(options)) {
          throw new RuleConfigurationError(
            RULE_FAILURE_KINDS.INVALID_CONFIGURATION,
            "configuration.ruleOptions: must be a plain object keyed by rule id",
            { field: "configuration.ruleOptions" },
          );
        }
        const keys = Object.keys(options);
        if (keys.length > MAX_CONFIGURATION_VALUES) {
          throw new RuleConfigurationError(
            RULE_FAILURE_KINDS.INVALID_CONFIGURATION,
            `configuration.ruleOptions: must carry at most ${MAX_CONFIGURATION_VALUES} entries`,
            { field: "configuration.ruleOptions" },
          );
        }
        for (const id of [...keys].sort()) {
          requireRegistered(id, "configuration.ruleOptions");
          const issues = declarativeDataIssues(options[id], `configuration.ruleOptions.${id}`);
          if (issues.length > 0) {
            throw new RuleConfigurationError(
              RULE_FAILURE_KINDS.INVALID_CONFIGURATION,
              `configuration.ruleOptions.${id}: must be declarative data`,
              { issues },
            );
          }
          ruleOptions.set(id, deepFreeze(copyDeclarativeData(options[id])));
        }
      }

      return registry;
    },

    /** The effective configuration as a deterministic, frozen, serializable snapshot. */
    configuration() {
      const options = {};
      for (const id of [...ruleOptions.keys()].sort()) {
        options[id] = ruleOptions.get(id);
      }
      return deepFreeze({
        enabled: [...enabledIds].sort(),
        disabled: [...disabledIds].sort(),
        includeRules: includeRules === null ? [] : [...includeRules].sort(),
        excludeRules: [...excludeRules].sort(),
        categories: categoryAllowlist === null ? [] : [...categoryAllowlist].sort(),
        ruleOptions: options,
      });
    },

    /**
     * A safe, declarative description of a registered rule, or `null` when the id
     * is unregistered.
     *
     * The record exposes identity, version, category, title, description, severity,
     * the declarative applicability selectors, the rule's declarative metadata, the
     * `deprecated` flag and the current enabled state. It never exposes `detect`,
     * host paths, runtime handles or mutable internals: the record is a deep copy,
     * sanitized to bounded plain data and deeply frozen.
     */
    describe(id) {
      const rule = registry.get(id);
      if (rule === null) return null;
      return deepFreeze({
        id: rule.id,
        version: rule.version,
        category: rule.category,
        title: rule.title,
        description: rule.description,
        severity: rule.severity,
        applicability: sanitizeDeclarativeValue(rule.applicability ?? {}),
        metadata: sanitizeDeclarativeValue(rule.metadata ?? {}),
        deprecated: rule.metadata?.deprecated === true,
        enabled: isEntryEnabled(rule),
      });
    },

    /** Every registered rule's description, id-sorted and deeply frozen. */
    describeAll() {
      return deepFreeze(registry.ids().map((id) => registry.describe(id)));
    },

    /**
     * A convenience delegate to the single applicability authority,
     * `evaluateRuleApplicability`. The registry does not evaluate selectors itself;
     * it only pairs the rule with the model and returns the evaluator's frozen
     * `{ applicable, reason, coverage }` under the rule id, preserving `unknown`.
     *
     * @throws {RuleConfigurationError} When the id is not registered.
     */
    evaluateApplicability(id, context) {
      requireRegistered(id, "evaluateApplicability");
      const result = evaluateRuleApplicability(byId.get(id), context);
      return deepFreeze({ id, ...result });
    },

    /** Number of registered rules (includes disabled rules). */
    get size() {
      return byId.size;
    },
  };

  registry.registerAll(rules);
  if (configuration !== null) registry.configure(configuration);
  return Object.freeze(registry);
}
