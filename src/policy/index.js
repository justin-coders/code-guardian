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
 */

export {
  MAX_PRESET_RELEASE_WORKFLOWS,
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
  isPlainObject,
  isPresetName,
  isPresetSource,
  isUserSource,
  presetSource,
  presetSourceName,
} from "./contracts.js";

export {
  POLICY_PRESET_ERROR_CODE,
  POLICY_PRESET_ERROR_KINDS,
  POLICY_PRESET_ERROR_KIND_VALUES,
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
