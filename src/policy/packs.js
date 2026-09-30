/**
 * Code Guardian — Built-in Policy Pack (Phase 24)
 *
 * The pack this build ships: one identity, one pinned version, one origin, and the five presets
 * Phase 23 already declared.
 *
 * ### Why a pack, when a preset registry already existed
 *
 * Phase 23 resolved a preset by *name*, and a name is unique only inside the registry that holds
 * it. Two builds, two vendors or two internal teams could each ship a preset called
 * `web-production`, and a document naming that name would identify neither of them. A pack gives
 * the preset a qualified identity — `code-guardian-core@1:web-production` — so a policy selection
 * names a policy definition and not merely a word. The pack adds *no* policy value: it wraps the
 * same frozen documents, so every Phase 23 answer is unchanged.
 *
 * ### A pack is data, and this module is where that is decided
 *
 * The definition below is a plain object: strings, one bounded sentence, and an array of preset
 * definitions. There is no function, no getter, no callback, no expression, no path, no URL and
 * nothing to evaluate — the pack layer reads no file, imports no module, contacts nothing and
 * consults no clock, because a pack that could *do* something would be a policy that could execute
 * code. `presets` is an array of exactly the Phase 23 preset-definition shape, so the pack needs no
 * second preset schema and `createPresetRegistry` validates the presets verbatim.
 *
 * ### The five presets are wrapped, never restated
 *
 * `BUILT_IN_PRESETS` is reused as it stands. Rewriting the documents here would create a second
 * copy of every requirement, and the two would drift — which is precisely what proves the semantic
 * values unchanged: there is only one copy to change.
 *
 * `title` and `purpose` are bounded, developer-facing sentences about the *pack*. They are never
 * shown to a repository author as advice, and nothing here ranks a preset, scores a preset or
 * recommends one.
 */

import {
  BUILT_IN_PACK_NAME,
  BUILT_IN_PACK_VERSION,
  POLICY_PACK_LIMITS,
  POLICY_PACK_ORIGINS,
  POLICY_PACK_VERSION,
  isPackName,
  isPackVersion,
  packReference,
} from "./contracts.js";
import { BUILT_IN_PRESETS, freezePreset } from "./presets.js";

/** The pack this build ships. The name is part of the closed vocabulary, not a default to change. */
export const BUILT_IN_PACK_TITLE = "Code Guardian core policies";

/** One bounded sentence describing what the pack holds. Never advice, never a ranking. */
export const BUILT_IN_PACK_PURPOSE =
  "The built-in policy presets this build ships, with the pack's identity and version pinned.";

function deepFreeze(value) {
  if (value === null || typeof value !== "object" || Object.isFrozen(value)) return value;
  Object.freeze(value);
  for (const key of Object.keys(value)) deepFreeze(value[key]);
  return value;
}

/**
 * Freeze a pack definition.
 *
 * The presets are frozen through the Phase 23 `freezePreset`, so a pack can never hold a preset the
 * preset layer would refuse to hold, and the `reference` is *derived* from the name and version
 * rather than stated — two spellings of one identity cannot exist.
 *
 * @param {object} definition
 * @returns {object} A deeply frozen `{name, version, origin, title, purpose, presets, reference}`.
 */
export function freezePack(definition) {
  const presets = Array.isArray(definition.presets) ? definition.presets : [];
  return deepFreeze({
    name: definition.name,
    version: definition.version,
    origin: definition.origin,
    title: definition.title,
    purpose: definition.purpose,
    reference: packReference(definition.name, definition.version),
    presets: presets.map(freezePreset),
  });
}

/**
 * The built-in pack, deeply frozen.
 *
 * Declared with its presets in the order Phase 23 declares them; the *registry* sorts the names it
 * reports, so the two orders are deliberately independent and a store that reorders its input
 * cannot change any answer.
 */
export const BUILT_IN_PACK = freezePack({
  name: BUILT_IN_PACK_NAME,
  version: BUILT_IN_PACK_VERSION,
  origin: POLICY_PACK_ORIGINS.BUILT_IN,
  title: BUILT_IN_PACK_TITLE,
  purpose: BUILT_IN_PACK_PURPOSE,
  presets: BUILT_IN_PRESETS,
});

/** Every pack this build declares, in declared order. One, and it is the built-in pack. */
export const BUILT_IN_PACKS = Object.freeze([BUILT_IN_PACK]);

/** The pack contract version this build's packs speak, restated for consumers. */
export const BUILT_IN_PACK_CONTRACT_VERSION = POLICY_PACK_VERSION;

/**
 * Assert the built-in pack is well-formed.
 *
 * Deliberately *not* run at module load, for the same reason `builtInPresetIssues` is not: a thrown
 * error at import time would take down every consumer of the package, including one that never
 * touches policy. The test suite calls it, and the registry validates whatever it is handed anyway.
 *
 * @returns {string[]} Empty when the built-in pack satisfies the contract.
 */
export function builtInPackIssues() {
  const issues = [];
  const pack = BUILT_IN_PACK;
  if (!isPackName(pack.name)) issues.push("BUILT_IN_PACK: name must be a well-formed pack name");
  if (!isPackVersion(pack.version)) {
    issues.push("BUILT_IN_PACK: version must be a pinned pack version");
  }
  if (pack.reference !== packReference(pack.name, pack.version)) {
    issues.push("BUILT_IN_PACK: reference must be derived from its own name and version");
  }
  if (typeof pack.title !== "string" || pack.title === "") {
    issues.push("BUILT_IN_PACK: title must be a non-empty sentence");
  } else if (pack.title.length > POLICY_PACK_LIMITS.maxTitleLength) {
    issues.push("BUILT_IN_PACK: title must stay within the declared bound");
  }
  if (typeof pack.purpose !== "string" || pack.purpose === "") {
    issues.push("BUILT_IN_PACK: purpose must be a non-empty sentence");
  } else if (pack.purpose.length > POLICY_PACK_LIMITS.maxPurposeLength) {
    issues.push("BUILT_IN_PACK: purpose must stay within the declared bound");
  }
  if (!Array.isArray(pack.presets) || pack.presets.length === 0) {
    issues.push("BUILT_IN_PACK: must carry at least one preset");
  } else if (pack.presets.length > POLICY_PACK_LIMITS.maxPresetsPerPack) {
    issues.push("BUILT_IN_PACK: must stay within the declared preset bound");
  }
  if (BUILT_IN_PACKS.length === 0) issues.push("BUILT_IN_PACKS: must declare at least one pack");
  if (BUILT_IN_PACKS.length > POLICY_PACK_LIMITS.maxPacks) {
    issues.push("BUILT_IN_PACKS: must stay within the declared pack bound");
  }
  return issues;
}
