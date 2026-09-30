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
  // Phase 24 — the four ways a *pack reference* fails to name a policy definition. They are
  // separate from `preset-not-established` on purpose: "this build holds no preset called that"
  // and "this pack does not exist, or does not hold that preset, or holds two versions of it" are
  // different facts about the declaration, and a repository author can act on each one. Every one
  // of them refuses the whole document, exactly as an unknown preset does.
  PACK_REFERENCE_NOT_ESTABLISHED: "pack-reference-not-established",
  PACK_NOT_ESTABLISHED: "pack-not-established",
  PACK_VERSION_NOT_ESTABLISHED: "pack-version-not-established",
  PACK_PRESET_NOT_ESTABLISHED: "pack-preset-not-established",
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

// ── Policy packs (Phase 24) ─────────────────────────────────────────────────
//
// A pack is the *distribution* unit a preset arrives in. Phase 23 resolved a preset by name; a
// name is unique only inside the registry that holds it, so two builds, two vendors or two
// internal teams could each ship a preset called `web-production` and a document naming that name
// would identify neither of them. A pack gives a preset a qualified identity — `name@version` —
// and the preset is then addressed as `<pack>:<preset>` or `<pack>@<version>:<preset>`.
//
// The vocabulary below is the closed grammar of that identity. It is deliberately made of
// characters that cannot appear in another part: a pack name cannot contain `@` or `:`, a version
// cannot either, so a reference splits unambiguously and no two spellings identify one policy
// definition.

/**
 * The pack contract version this build interprets.
 *
 * Pinned, like the policy document version: a pack that states another one is refused rather than
 * read on a best-effort basis, because a pack this build only partly understands would supply
 * policy values it cannot fully account for.
 */
export const POLICY_PACK_VERSION = "1";

/**
 * The pack this build ships, and the pack a bare preset name resolves against.
 *
 * Every Phase 23 document named a preset without naming a pack, because there was only one place a
 * preset could come from. That stays true: an unqualified name means *this* pack, pinned to the
 * version this build ships. It is a constant, never "the latest one", so a Phase 23 document keeps
 * resolving to exactly what it resolved to then.
 */
export const BUILT_IN_PACK_NAME = "code-guardian-core";
export const BUILT_IN_PACK_VERSION = "1";

/** The separator between a pack name and its pinned version. */
export const POLICY_PACK_REFERENCE_SEPARATOR = "@";

/** The separator between a pack reference and the preset it selects. */
export const POLICY_PACK_PRESET_SEPARATOR = ":";

/** The canonical reference of the built-in pack: `code-guardian-core@1`. */
export const BUILT_IN_PACK_REFERENCE = `${BUILT_IN_PACK_NAME}${POLICY_PACK_REFERENCE_SEPARATOR}${BUILT_IN_PACK_VERSION}`;

/** The origin vocabulary a pack may claim. One value: this build's own registry. */
export const POLICY_PACK_ORIGINS = Object.freeze({
  BUILT_IN: "built-in",
});

/** The origin vocabulary as a list, for validation and tests. */
export const POLICY_PACK_ORIGIN_VALUES = Object.freeze(Object.values(POLICY_PACK_ORIGINS));

/**
 * The exact fields a pack definition states, in declared order.
 *
 * A closed schema, like every other contract in this codebase: a pack stating a field this table
 * does not declare is refused as a whole rather than carried with an extra key nobody validated —
 * which is what makes "a pack is data" a checkable property rather than a promise.
 */
export const POLICY_PACK_FIELDS = Object.freeze([
  "name",
  "version",
  "origin",
  "title",
  "purpose",
  "presets",
]);

/** The pack's identity fields, in declared order — everything but the presets it carries. */
export const POLICY_PACK_IDENTITY_FIELDS = Object.freeze(["name", "version", "origin"]);

/**
 * The exact fields a preset *definition* states inside a pack.
 *
 * A pack's presets are the policy definitions it distributes, so the same closed-schema rule applies
 * one level down: a preset stating a field this table does not declare is refused with the pack that
 * carries it. A preset is `{name, purpose, document}` and nothing else — there is no place in it for
 * a condition, a reference to another preset or a note to a future phase.
 */
export const POLICY_PRESET_DEFINITION_FIELDS = Object.freeze(["name", "purpose", "document"]);

/**
 * Fields a *frozen* pack carries on top of the declared ones.
 *
 * `reference` is derived from `name` and `version` rather than stated, so it is not part of the
 * declaration a caller writes — but a frozen pack has it, and validation covers both shapes. It is
 * allowed to be absent and required to be correct when present, so `name@version` can never be
 * spelled two ways.
 */
export const POLICY_PACK_DERIVED_FIELDS = Object.freeze(["reference"]);

/** Bounds on what the pack layer will build and publish. */
export const POLICY_PACK_LIMITS = Object.freeze({
  /** Packs one registry carries. */
  maxPacks: 32,
  /** Versions one pack name may be registered under. */
  maxVersionsPerPack: 16,
  /** Presets one pack may carry. */
  maxPresetsPerPack: POLICY_PRESET_LIMITS.maxPresets,
  /** Characters a pack name may occupy. */
  maxPackNameLength: 32,
  /** Characters a pack version may occupy. */
  maxPackVersionLength: 16,
  /** Characters a pack's title may occupy. */
  maxTitleLength: 80,
  /** Characters a pack's purpose statement may occupy. */
  maxPurposeLength: POLICY_PRESET_LIMITS.maxPurposeLength,
  /** Characters of a reference retained in a resolution failure `detail`. */
  maxDetailLength: 48,
});

/** A pack name is a lowercase identifier, with its own namespace and its own bounds. */
export const POLICY_PACK_NAME_PATTERN = /^[a-z][a-z0-9-]*$/;

/**
 * A pack version is dot-separated whole numbers: `1`, `2`, `1.0`.
 *
 * Pinned rather than floating — no range, no `*`, no `latest`, no comparison. A document that
 * names a version this registry does not hold is refused; this build never picks the nearest one.
 */
export const POLICY_PACK_VERSION_PATTERN = /^[0-9]+(\.[0-9]+)*$/;

/** Whether a pack name is a well-formed identifier. */
export function isPackName(value) {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= POLICY_PACK_LIMITS.maxPackNameLength &&
    POLICY_PACK_NAME_PATTERN.test(value)
  );
}

/** Whether a pack version is a well-formed pinned version. */
export function isPackVersion(value) {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= POLICY_PACK_LIMITS.maxPackVersionLength &&
    POLICY_PACK_VERSION_PATTERN.test(value)
  );
}

/** Whether an origin is one a pack may claim. */
export function isPackOrigin(value) {
  return POLICY_PACK_ORIGIN_VALUES.includes(value);
}

/** The canonical `name@version` reference of a pack. */
export function packReference(name, version) {
  return `${name}${POLICY_PACK_REFERENCE_SEPARATOR}${version}`;
}

/**
 * Whether a value is a well-formed `name@version` reference.
 *
 * A predicate only, and it is total: the per-part bounds make the whole reference bounded too — a
 * name of at most 32 characters, a version of at most 16 and one separator cannot exceed any other
 * limit — so there is no extra total-length check here that a well-formed reference could fail.
 * Deciding *which* pack it names is the registry's question, and splitting a reference into its
 * parts is `parsePresetReference`'s — this layer owns the vocabulary, not the lookup.
 */
export function isPackReference(value) {
  if (typeof value !== "string") return false;
  const parts = value.split(POLICY_PACK_REFERENCE_SEPARATOR);
  if (parts.length !== 2) return false;
  return isPackName(parts[0]) && isPackVersion(parts[1]);
}

/**
 * The canonical reference of a preset selected out of a pack: `pack@version:preset`.
 *
 * This is the *fully qualified* form of what a document may write. A document may also write the
 * pack alone, or nothing at all, and the registry pins what is missing — but this is the form every
 * resolved answer is reported in, so two spellings of one selection cannot produce two strings.
 */
export function packPresetReference(name, version, presetName) {
  return `${packReference(name, version)}${POLICY_PACK_PRESET_SEPARATOR}${presetName}`;
}

/**
 * Bound a repository-authored policy reference before it travels as a failure detail.
 *
 * The reference is the one repository-authored string this layer carries, and it travels as a
 * bounded identifier rather than free text — the same discipline every other acquisition detail
 * follows. `@`, `:` and `.` are kept because they are part of the grammar, so a detail can still
 * show *which* reference failed to resolve.
 */
export function boundedPolicyReference(value) {
  if (typeof value !== "string") return null;
  const sanitized = value.replace(/[^A-Za-z0-9_.@:-]/g, "");
  if (sanitized === "") return null;
  return sanitized.slice(0, POLICY_PACK_LIMITS.maxDetailLength);
}
