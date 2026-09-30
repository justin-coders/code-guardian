/**
 * Code Guardian — Policy Preset Contracts (Phase 23)
 *
 * The closed vocabulary of the preset registry. This module is a **leaf**: it imports nothing at
 * all — no Core contract, no scanner, no model, no filesystem, no network, no clock. That is the
 * point of the phase. A preset is a frozen in-memory object; resolving one is a pure function of
 * two in-memory values, so the whole subsystem can be read, verified and reasoned about without a
 * repository, a process or a request.
 *
 * ### The vocabulary is re-declared, not imported
 *
 * The scanner owns the JSON schema and the reasons it refuses a document; the model owns the shape
 * of what it publishes; this layer owns the presets those documents may name. Each layer therefore
 * *restates* the domains and the key order rather than importing them, exactly as the model
 * restates the scanner's, and the three lists are pinned together by tests, so a rename on any side
 * fails the suite instead of silently retiring a preset key.
 *
 * ### What a preset is, and what it is not
 *
 * A preset is a **complete** policy document: all six domains, every key each domain declares. It
 * states requirements, never judgments, and it carries no condition, no expression, no reference to
 * another preset and no interpolation — there is nothing to evaluate, so there is nothing that
 * could be evaluated differently on two runs. `minimal` is the only complete document that states
 * *no* requirement, which is why it can be a preset at all.
 *
 * ### Provenance is a closed two-token vocabulary
 *
 * Every resolved value comes from exactly one of two places: the repository's own document
 * (`user`) or the built-in preset it named (`preset:<name>`). The token is a *string* rather than a
 * boolean because the name it carries is the only thing that makes a compliance item's provenance
 * answerable months later, when `web-production` and `strict` may both be in use.
 */

/** The one policy document version this build resolves. */
export const POLICY_PRESET_VERSION = "1";

/** The six policy domains, in the order every layer declares them. */
export const POLICY_PRESET_DOMAINS = Object.freeze([
  "environment",
  "container",
  "ci",
  "api",
  "dependencies",
  "architecture",
]);

/**
 * The closed schema, restated from the acquisition layer.
 *
 * Every preset must state every key, and a document that names a preset continues to be validated
 * against this table — so a preset can never introduce a setting the compliance engine has no
 * measurement for.
 */
export const POLICY_PRESET_SCHEMA = Object.freeze({
  environment: Object.freeze({
    requireTemplate: "boolean",
    allowMultipleTemplates: "boolean",
  }),
  container: Object.freeze({
    requireHealthcheck: "boolean",
  }),
  ci: Object.freeze({
    requireTestsForRelease: "boolean",
    requireLintForRelease: "boolean",
    maxReleaseWorkflows: "integer",
  }),
  api: Object.freeze({
    requireResolvedMiddleware: "boolean",
  }),
  dependencies: Object.freeze({
    requireLockfile: "boolean",
    allowMultipleManagers: "boolean",
  }),
  architecture: Object.freeze({
    requireConnectedEntrypoints: "boolean",
  }),
});

/** Every key each domain declares, in schema order. */
export const POLICY_PRESET_KEYS = Object.freeze(
  POLICY_PRESET_DOMAINS.reduce((accumulator, domain) => {
    accumulator[domain] = Object.freeze(Object.keys(POLICY_PRESET_SCHEMA[domain]));
    return accumulator;
  }, {}),
);

/** Every `domain.key` a preset states, in declared order. */
export const POLICY_PRESET_KEY_IDS = Object.freeze(
  POLICY_PRESET_DOMAINS.flatMap((domain) =>
    POLICY_PRESET_KEYS[domain].map((key) => `${domain}.${key}`),
  ),
);

/** The largest accepted `maxReleaseWorkflows`, restated with the schema. */
export const MAX_PRESET_RELEASE_WORKFLOWS = 1000;

/**
 * Where a resolved value came from. Two tokens, and the second one is a *prefix*.
 *
 * `user` means the repository's own document stated the value; `preset:<name>` means the named
 * built-in preset stated it. Nothing else may appear, so "preserve provenance" is a closed
 * vocabulary rather than a promise.
 */
export const POLICY_PRESET_SOURCES = Object.freeze({
  USER: "user",
  PRESET: "preset",
});

/** The prefix every inherited value's provenance token carries. */
export const PRESET_SOURCE_PREFIX = "preset:";

/** The only origin a built-in preset may claim. */
export const POLICY_PRESET_ORIGIN = "built-in";

/** Bounds on what the preset layer will build and publish. */
export const POLICY_PRESET_LIMITS = Object.freeze({
  /** Presets one registry carries. */
  maxPresets: 64,
  /** Characters a preset name may occupy. */
  maxPresetNameLength: 32,
  /** Characters a preset's purpose statement may occupy. */
  maxPurposeLength: 120,
  /** `domain.key` pairs a resolved provenance may carry (the schema's own total). */
  maxSources: POLICY_PRESET_KEY_IDS.length,
});

/** A preset name is a lowercase identifier: the closed shape every built-in name satisfies. */
export const POLICY_PRESET_NAME_PATTERN = /^[a-z][a-z0-9-]*$/;

/**
 * Why a declared policy document could not be resolved into an effective one.
 *
 * Closed, and none of the three says anything about the repository's engineering: each states that
 * this build could not turn what the repository wrote into a policy it can measure. An unknown
 * preset refuses the **whole** document — never the preset alone — because a policy that was
 * silently half-honoured would make every compliance answer wrong in a way no consumer could see.
 */
export const POLICY_RESOLUTION_FAILURES = Object.freeze({
  PRESET_NOT_ESTABLISHED: "preset-not-established",
  VERSION_NOT_SUPPORTED: "version-not-supported",
  DOCUMENT_NOT_INTERPRETED: "document-not-interpreted",
});

/** The resolution-failure vocabulary as a list, for validation and tests. */
export const POLICY_RESOLUTION_FAILURE_VALUES = Object.freeze(
  Object.values(POLICY_RESOLUTION_FAILURES),
);

/** The provenance token for a value inherited from a named preset. */
export function presetSource(name) {
  return `${PRESET_SOURCE_PREFIX}${name}`;
}

/** Whether a provenance token names a preset. */
export function isPresetSource(source) {
  return typeof source === "string" && source.startsWith(PRESET_SOURCE_PREFIX);
}

/** Whether a provenance token names the repository's own document. */
export function isUserSource(source) {
  return source === POLICY_PRESET_SOURCES.USER;
}

/** The preset name a provenance token names, or `null`. */
export function presetSourceName(source) {
  if (!isPresetSource(source)) return null;
  const name = source.slice(PRESET_SOURCE_PREFIX.length);
  return name === "" ? null : name;
}

/** Whether a preset name is a well-formed identifier. */
export function isPresetName(value) {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= POLICY_PRESET_LIMITS.maxPresetNameLength &&
    POLICY_PRESET_NAME_PATTERN.test(value)
  );
}

/** Whether a value is a plain object (and not an array). */
export function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
