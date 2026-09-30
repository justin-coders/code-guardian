/**
 * Code Guardian — Policy Pack Validation (Phase 24)
 *
 * Two checks live here, and they are the two halves of "a policy selection is deterministic":
 *
 *   `parsePresetReference`  reads what a repository *wrote* — the one place a repository-authored
 *                           reference is interpreted — and refuses anything outside the closed
 *                           grammar instead of guessing at it;
 *   `packDefinitionIssues`  validates a pack a *caller* built, completely and before registration,
 *                           so a malformed pack is refused as a whole rather than half-registered.
 *
 * ### The grammar, in full
 *
 *     reference := presetName                          → this build's pack, pinned to its version
 *                | packName ":" presetName              → the pack this build ships, at its version
 *                | packName "@" version ":" presetName  → exactly that pack, at exactly that version
 *
 * It is unambiguous by construction: a pack name cannot contain `:` or `@`, and a pack version
 * cannot contain either, so a reference splits into its parts one way only and no two spellings
 * identify one policy definition.
 *
 * ### The two rules that matter most
 *
 *   - **A bare preset name never reaches another pack.** It resolves against
 *     `code-guardian-core@1` and nothing else. Falling back to "whichever pack happens to hold a
 *     preset with this name" is exactly the silent substitution this phase exists to prevent, and it
 *     is why the parse result carries `explicit` rather than the resolver testing a name.
 *   - **A missing version is refused when it is ambiguous, not chosen.** Naming a pack without a
 *     version resolves only if that pack holds exactly one version; otherwise the reference
 *     establishes nothing. A version is never inferred from what is available.
 *
 * Nothing here reads a file, a directory, a package, a URL or a clock: a reference is a string and a
 * pack is an object this process built.
 */

import {
  POLICY_PACK_DERIVED_FIELDS,
  POLICY_PACK_FIELDS,
  POLICY_PACK_LIMITS,
  POLICY_PACK_REFERENCE_SEPARATOR,
  POLICY_PACK_PRESET_SEPARATOR,
  POLICY_PACK_VERSION_PATTERN,
  POLICY_PRESET_DEFINITION_FIELDS,
  POLICY_RESOLUTION_FAILURES,
  boundedPolicyReference,
  isPackName,
  isPackOrigin,
  isPackVersion,
  isPlainObject,
  isPresetName,
  packReference,
} from "./contracts.js";
import { presetDefinitionIssues } from "./registry.js";

/**
 * A resolution failure whose `detail` is the reference that failed, bounded and sanitized.
 *
 * Exported so the pack resolver reports a reference failure exactly as the parser found it: two
 * descriptions of one refusal would be two things to keep in step.
 */
export function referenceFailure(reason, reference) {
  return Object.freeze({
    ok: false,
    reason,
    detail: boundedPolicyReference(reference),
  });
}

/**
 * Parse a policy selection as a repository wrote it.
 *
 * @param {unknown} value The `preset` field of a declared policy document.
 * @returns {{ok: true, presetName: string, packName: string|null, packVersion: string|null,
 *   explicit: boolean} | {ok: false, reason: string, detail: string|null}}
 *   `explicit` says whether the *repository* named the pack. A bare preset name is not an error and
 *   not an explicit pack: it is the Phase 23 spelling, and the registry pins the pack it means.
 */
export function parsePresetReference(value) {
  if (typeof value !== "string" || value === "") {
    // The same verdict Phase 23 reached for a preset that is not a name: nothing was selected.
    return referenceFailure(POLICY_RESOLUTION_FAILURES.PRESET_NOT_ESTABLISHED, value);
  }
  const parts = value.split(POLICY_PACK_PRESET_SEPARATOR);

  if (parts.length === 1) {
    // Phase 23's spelling. It is *always* the built-in pack, so a name that happens to exist in
    // some other pack can never be reached from it.
    if (value.includes(POLICY_PACK_REFERENCE_SEPARATOR)) {
      return referenceFailure(POLICY_RESOLUTION_FAILURES.PACK_REFERENCE_NOT_ESTABLISHED, value);
    }
    if (!isPresetName(value)) {
      // Names the shape of a preset, not a pack: an unknown preset, exactly as Phase 23 read it. The
      // check is the preset layer's own `isPresetName`, so "what a preset may be called" has one
      // definition and a name this layer accepts is one the registry could hold.
      return referenceFailure(POLICY_RESOLUTION_FAILURES.PRESET_NOT_ESTABLISHED, value);
    }
    return Object.freeze({
      ok: true,
      presetName: value,
      packName: null,
      packVersion: null,
      explicit: false,
    });
  }

  if (parts.length !== 2 || parts[0] === "" || parts[1] === "") {
    return referenceFailure(POLICY_RESOLUTION_FAILURES.PACK_REFERENCE_NOT_ESTABLISHED, value);
  }

  const [head, presetName] = parts;
  if (!isPresetName(presetName)) {
    return referenceFailure(POLICY_RESOLUTION_FAILURES.PACK_REFERENCE_NOT_ESTABLISHED, value);
  }

  const identity = head.split(POLICY_PACK_REFERENCE_SEPARATOR);
  if (identity.length === 0 || identity.length > 2) {
    return referenceFailure(POLICY_RESOLUTION_FAILURES.PACK_REFERENCE_NOT_ESTABLISHED, value);
  }
  const [packName, packVersion = null] = identity;
  if (!isPackName(packName)) {
    return referenceFailure(POLICY_RESOLUTION_FAILURES.PACK_REFERENCE_NOT_ESTABLISHED, value);
  }
  if (packVersion !== null && !isPackVersion(packVersion)) {
    return referenceFailure(POLICY_RESOLUTION_FAILURES.PACK_REFERENCE_NOT_ESTABLISHED, value);
  }

  return Object.freeze({ ok: true, presetName, packName, packVersion, explicit: true });
}

/**
 * Every reason a pack definition is not registrable.
 *
 * A pack is refused **as a whole**: an unknown field, a name outside the vocabulary, a floating
 * version, a reference that disagrees with the pack's own identity, a preset that is not a complete
 * policy document, two presets under one name — each of them means this build cannot account for
 * what the pack would supply, so none of it is registered.
 * Partial registration would leave a registry that answers *some* questions, which is worse than one
 * that answers none.
 *
 * @param {unknown} definition
 * @returns {string[]} Empty when the definition satisfies the pack contract.
 */
export function packDefinitionIssues(definition) {
  if (!isPlainObject(definition)) return ["pack: must be a plain object"];

  const issues = [];
  const label = `pack(${typeof definition.name === "string" ? definition.name : "?"})`;

  const declaredFields = [...POLICY_PACK_FIELDS, ...POLICY_PACK_DERIVED_FIELDS];
  for (const field of POLICY_PACK_FIELDS) {
    if (!Object.hasOwn(definition, field)) issues.push(`${label}.${field}: is required`);
  }
  for (const field of Object.keys(definition)) {
    if (!declaredFields.includes(field)) {
      issues.push(`${label}.${field}: is not a declared pack field`);
    }
  }
  // Derived, so it may be absent; if a frozen pack carries it, it must be the one its own name and
  // version spell. A pack whose reference disagreed with its identity would be two packs.
  if (Object.hasOwn(definition, "reference") && definition.reference !== packReference(definition.name, definition.version)) {
    issues.push(`${label}.reference: must be the pack's own name and version`);
  }

  if (!isPackName(definition.name)) {
    issues.push(
      `${label}.name: must be a lowercase identifier of at most ${POLICY_PACK_LIMITS.maxPackNameLength} characters`,
    );
  }
  if (!isPackVersion(definition.version)) {
    issues.push(
      `${label}.version: must be a pinned version of the form ${POLICY_PACK_VERSION_PATTERN.source}`,
    );
  }
  if (!isPackOrigin(definition.origin)) {
    issues.push(`${label}.origin: must be a declared pack origin`);
  }
  if (typeof definition.title !== "string" || definition.title === "") {
    issues.push(`${label}.title: must be a non-empty sentence`);
  } else if (definition.title.length > POLICY_PACK_LIMITS.maxTitleLength) {
    issues.push(`${label}.title: must stay within the declared bound`);
  }
  if (typeof definition.purpose !== "string" || definition.purpose === "") {
    issues.push(`${label}.purpose: must be a non-empty sentence`);
  } else if (definition.purpose.length > POLICY_PACK_LIMITS.maxPurposeLength) {
    issues.push(`${label}.purpose: must stay within the declared bound`);
  }

  if (!Array.isArray(definition.presets)) {
    issues.push(`${label}.presets: must be an array of preset definitions`);
    return issues;
  }
  if (definition.presets.length === 0) {
    issues.push(`${label}.presets: must carry at least one preset`);
  }
  if (definition.presets.length > POLICY_PACK_LIMITS.maxPresetsPerPack) {
    issues.push(`${label}.presets: must stay within the declared preset bound`);
  }

  const seen = new Set();
  definition.presets.forEach((preset, index) => {
    // The preset schema is closed one level down too: a preset inside a pack states its name, its
    // purpose and its document, and a field beyond those is refused with the pack that carries it.
    if (isPlainObject(preset)) {
      for (const field of Object.keys(preset)) {
        if (!POLICY_PRESET_DEFINITION_FIELDS.includes(field)) {
          issues.push(`${label}.presets[${index}].${field}: is not a declared preset field`);
        }
      }
    }
    for (const issue of presetDefinitionIssues(preset)) {
      issues.push(`${label}.presets[${index}] ${issue}`);
    }
    if (isPlainObject(preset) && typeof preset.name === "string") {
      if (seen.has(preset.name)) {
        issues.push(`${label}.presets[${index}].name: "${preset.name}" is declared twice`);
      }
      seen.add(preset.name);
    }
  });

  return issues;
}

/** Copy the settings of one domain, so a resolved value never reads the caller's object again. */
function copySettings(settings) {
  const copy = {};
  for (const key of Object.keys(settings)) copy[key] = settings[key];
  return copy;
}

/** Copy a preset document into plain, freshly built objects of exactly the schema's shape. */
function copyDocument(document) {
  if (!isPlainObject(document)) return document;
  const copy = {};
  for (const domain of Object.keys(document)) {
    const settings = document[domain];
    copy[domain] = isPlainObject(settings) ? copySettings(settings) : settings;
  }
  return copy;
}

/** Copy a preset definition, keeping any undeclared field so validation can still refuse it. */
function copyPresetDefinition(preset) {
  if (!isPlainObject(preset)) return preset;
  const copy = {};
  for (const key of Object.keys(preset)) copy[key] = preset[key];
  if (Object.hasOwn(preset, "document")) copy.document = copyDocument(preset.document);
  return copy;
}

/**
 * Copy a pack definition into plain objects this layer owns.
 *
 * The registry validates and registers the copy, never the caller's object. That is what makes a pack
 * a *value*: a getter on a pack field is consulted exactly once, a mutation of the caller's
 * definition afterwards cannot change an answer, and registering never freezes an object the caller
 * still holds. Undeclared fields are carried into the copy rather than dropped, so the schema check
 * still refuses them instead of silently ignoring them.
 *
 * @param {unknown} definition
 * @returns {unknown} A plain copy, or the value itself when it is not a plain object.
 */
export function snapshotPackDefinition(definition) {
  if (!isPlainObject(definition)) return definition;
  const snapshot = {};
  for (const key of Object.keys(definition)) snapshot[key] = definition[key];
  if (Array.isArray(definition.presets)) {
    snapshot.presets = definition.presets.map(copyPresetDefinition);
  }
  return snapshot;
}
