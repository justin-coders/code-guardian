/**
 * Code Guardian — Policy Preset Layer Boundary (Phase 23)
 *
 * The stable import surface for the preset subsystem. The model imports from here and nothing
 * deeper, so a future interface layer can consume the same registry without reaching into the
 * individual modules.
 *
 * ### It is a leaf, and that is enforced
 *
 * Every module in this directory imports either nothing at all or a sibling here — no Core contract,
 * no scanner, no model, no `node:fs`, `node:path`, `child_process`, network, clock, randomness or
 * environment. A test in `tests/policy-presets.test.js` enforces it, because this layer exists to
 * make policy resolution a *pure* function of in-memory values, and an import is how that property
 * would be lost.
 *
 * ### What the layer promises
 *
 *   - the built-in presets are five complete, deeply frozen documents and nothing can add to them
 *     through this boundary;
 *   - resolution is deterministic: preset first, the repository's own values on top, and no result
 *     depends on iteration order, a clock, the environment or the surrounding process;
 *   - every resolved key carries a source, and an unknown preset refuses the whole document rather
 *     than applying part of it;
 *   - nothing here scores, recommends, ranks or compares one preset against another.
 *
 * ### Phase 24 — the pack layer sits under the preset layer, not over it
 *
 * A preset name is unique only inside the registry that holds it, so Phase 24 addresses a policy
 * definition by pack: `code-guardian-core@1:web-production`. The pack modules added here
 * (`packs.js`, `pack-validation.js`, `pack-registry.js`, `pack-resolution.js`) answer *identity* —
 * which pack, which version, which preset — and then call the Phase 23 resolver to answer *policy*.
 * The preset layer above them is unchanged, which is what keeps the compliance engine, which reads
 * only the effective document, exactly as it was accepted.
 */

export {
  BUILT_IN_PACK_NAME,
  BUILT_IN_PACK_REFERENCE,
  BUILT_IN_PACK_VERSION,
  MAX_PRESET_RELEASE_WORKFLOWS,
  POLICY_PACK_FIELDS,
  POLICY_PACK_IDENTITY_FIELDS,
  POLICY_PACK_LIMITS,
  POLICY_PACK_NAME_PATTERN,
  POLICY_PACK_ORIGINS,
  POLICY_PACK_ORIGIN_VALUES,
  POLICY_PACK_REFERENCE_SEPARATOR,
  POLICY_PACK_PRESET_SEPARATOR,
  POLICY_PACK_VERSION,
  POLICY_PACK_VERSION_PATTERN,
  POLICY_PRESET_DEFINITION_FIELDS,
  POLICY_PRESET_DOMAINS,
  POLICY_PRESET_KEY_IDS,
  POLICY_PRESET_KEYS,
  POLICY_PRESET_LIMITS,
  POLICY_PRESET_NAME_PATTERN,
  POLICY_PRESET_ORIGIN,
  POLICY_PRESET_SCHEMA,
  POLICY_PRESET_SOURCES,
  POLICY_PRESET_VERSION,
  POLICY_RESOLUTION_FAILURES,
  POLICY_RESOLUTION_FAILURE_VALUES,
  PRESET_SOURCE_PREFIX,
  boundedPolicyReference,
  isPackName,
  isPackOrigin,
  isPackReference,
  isPackVersion,
  isPlainObject,
  isPresetName,
  isPresetSource,
  isUserSource,
  packPresetReference,
  packReference,
  presetSource,
  presetSourceName,
} from "./contracts.js";

export {
  POLICY_PACK_ERROR_CODE,
  POLICY_PACK_ERROR_KINDS,
  POLICY_PRESET_ERROR_CODE,
  POLICY_PRESET_ERROR_KINDS,
  POLICY_PRESET_ERROR_KIND_VALUES,
  PolicyPackError,
  PolicyPresetError,
} from "./errors.js";

export {
  BUILT_IN_PRESETS,
  MAX_BUILT_IN_PURPOSE_LENGTH,
  PRESET_NAMES,
  builtInPresetIssues,
  freezePreset,
  isBuiltInPresetName,
} from "./presets.js";

export { DEFAULT_PRESET_REGISTRY, createPresetRegistry, presetDefinitionIssues } from "./registry.js";

export {
  boundedPresetName,
  effectivePolicyIssues,
  resolvePolicyDocument,
} from "./resolver.js";

// ── Policy packs (Phase 24) ──────────────────────────────────────────────────
export {
  BUILT_IN_PACK,
  BUILT_IN_PACKS,
  BUILT_IN_PACK_CONTRACT_VERSION,
  BUILT_IN_PACK_PURPOSE,
  BUILT_IN_PACK_TITLE,
  builtInPackIssues,
  freezePack,
} from "./packs.js";

export {
  packDefinitionIssues,
  parsePresetReference,
  referenceFailure,
  snapshotPackDefinition,
} from "./pack-validation.js";

export { DEFAULT_PACK_REGISTRY, createPolicyPackRegistry } from "./pack-registry.js";

export {
  packPolicyIssues,
  resolvePackPolicyDocument,
  resolvePackPreset,
} from "./pack-resolution.js";
