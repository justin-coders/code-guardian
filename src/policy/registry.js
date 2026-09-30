/**
 * Code Guardian — Policy Preset Registry (Phase 23)
 *
 * A deterministic, immutable, in-memory store of presets. There is no loader here: nothing reads a
 * file, imports a module, resolves a path, contacts a network or evaluates a string. The registry
 * holds objects the process itself constructed.
 *
 * ### Determinism is a property of the store, not of its input
 *
 * `names` is **sorted**, so a registry built from a differently-ordered list of the same presets
 * reports the same names in the same order. That matters more than it looks: a preset name travels
 * into a provenance token, a compliance item's source and a finding's metadata, and an order that
 * depended on how a store was assembled would make those values depend on assembly too.
 *
 * ### Immutability is enforced by construction, not by convention
 *
 * The handle returned here, its `names` array and every preset it holds are deeply frozen. A caller
 * cannot replace a preset, add one or reorder `names` — a mutation attempt throws in strict mode
 * (every module in this codebase is a module, so every consumer is in strict mode) rather than
 * silently changing what a later resolution returns.
 *
 * ### Duplicate names are refused, not merged
 *
 * Two presets under one name would make `get` order-dependent — the exact non-determinism this phase
 * exists to remove — so a duplicate is a `PolicyPresetError` and not a silent last-one-wins.
 */

import { PolicyPresetError, POLICY_PRESET_ERROR_KINDS } from "./errors.js";
import { BUILT_IN_PRESETS, freezePreset } from "./presets.js";
import {
  MAX_PRESET_RELEASE_WORKFLOWS,
  POLICY_PRESET_DOMAINS,
  POLICY_PRESET_KEYS,
  POLICY_PRESET_LIMITS,
  POLICY_PRESET_SCHEMA,
  isPresetName,
  isPlainObject,
} from "./contracts.js";

/**
 * Every reason a preset definition is not usable.
 *
 * A preset is a *complete* policy document, so the check is complete too: every domain present,
 * every key of every domain present and in schema order, and every value the type the schema
 * declares. A preset that stated eight of ten keys would resolve to a policy whose ninth key has no
 * source at all, which is precisely what "never lose provenance" forbids.
 *
 * @param {unknown} definition
 * @returns {string[]} Empty when the definition satisfies the contract.
 */
export function presetDefinitionIssues(definition) {
  if (!isPlainObject(definition)) return ["preset: must be a plain object"];
  const issues = [];
  if (!isPresetName(definition.name)) {
    issues.push(`preset.name: "${String(definition.name)}" is not a well-formed preset name`);
  }
  if (typeof definition.purpose !== "string" || definition.purpose === "") {
    issues.push(`preset(${String(definition.name)}).purpose: must be a non-empty sentence`);
  } else if (definition.purpose.length > POLICY_PRESET_LIMITS.maxPurposeLength) {
    issues.push(`preset(${String(definition.name)}).purpose: must stay within the declared bound`);
  }

  const document = definition.document;
  if (!isPlainObject(document)) {
    issues.push(`preset(${String(definition.name)}).document: must be a plain object`);
    return issues;
  }

  for (const domain of Object.keys(document)) {
    if (!POLICY_PRESET_DOMAINS.includes(domain)) {
      issues.push(`preset(${String(definition.name)}).document.${domain}: is not a declared domain`);
    }
  }
  for (const domain of POLICY_PRESET_DOMAINS) {
    if (!Object.hasOwn(document, domain)) {
      issues.push(
        `preset(${String(definition.name)}).document.${domain}: every built-in preset must state this domain`,
      );
      continue;
    }
    const settings = document[domain];
    if (!isPlainObject(settings)) {
      issues.push(
        `preset(${String(definition.name)}).document.${domain}: must be a plain object of settings`,
      );
      continue;
    }
    // A preset states *every* key its domains declare, in schema order. Filtering the schema by the
    // keys present — rather than comparing against the whole list — would let a preset that stated
    // one of three keys pass, and every resolution of it would then leave two values without a
    // source at all.
    const keys = Object.keys(settings);
    if (keys.join("\u0000") !== POLICY_PRESET_KEYS[domain].join("\u0000")) {
      issues.push(
        `preset(${String(definition.name)}).document.${domain}: must state every declared setting in schema order`,
      );
      continue;
    }
    for (const key of keys) {
      const value = settings[key];
      if (POLICY_PRESET_SCHEMA[domain][key] === "boolean") {
        if (typeof value !== "boolean") {
          issues.push(
            `preset(${String(definition.name)}).document.${domain}.${key}: must be a boolean`,
          );
        }
        continue;
      }
      if (
        !Number.isInteger(value) ||
        value < 0 ||
        value > MAX_PRESET_RELEASE_WORKFLOWS
      ) {
        issues.push(
          `preset(${String(definition.name)}).document.${domain}.${key}: must be a whole number within the declared bound`,
        );
      }
    }
  }

  return issues;
}

/**
 * Build a preset registry.
 *
 * @param {object} [input]
 * @param {object[]} [input.presets] The presets to hold (defaults to the built-in set).
 * @returns {object} A frozen registry handle: `{names, size, has, get, describe}`.
 * @throws {PolicyPresetError} kind `invalid-preset` for a malformed definition, `duplicate-preset`
 *   for a repeated name.
 */
export function createPresetRegistry({ presets = BUILT_IN_PRESETS } = {}) {
  if (!Array.isArray(presets)) {
    throw new PolicyPresetError(POLICY_PRESET_ERROR_KINDS.INVALID_PRESET, {
      detail: null,
      message: "createPresetRegistry: presets must be an array of preset definitions",
    });
  }
  if (presets.length > POLICY_PRESET_LIMITS.maxPresets) {
    throw new PolicyPresetError(POLICY_PRESET_ERROR_KINDS.INVALID_PRESET, {
      detail: null,
      message: "createPresetRegistry: too many presets",
    });
  }

  const byName = new Map();
  presets.forEach((definition, index) => {
    const issues = presetDefinitionIssues(definition);
    if (issues.length > 0) {
      throw new PolicyPresetError(POLICY_PRESET_ERROR_KINDS.INVALID_PRESET, {
        detail: isPlainObject(definition) && typeof definition.name === "string" ? definition.name : null,
        message: `createPresetRegistry: presets[${index}] ${issues.join("; ")}`,
      });
    }
    if (byName.has(definition.name)) {
      throw new PolicyPresetError(POLICY_PRESET_ERROR_KINDS.DUPLICATE_PRESET, {
        detail: definition.name,
        message: `createPresetRegistry: "${definition.name}" is declared twice`,
      });
    }
    byName.set(definition.name, freezePreset(definition));
  });

  const names = Object.freeze([...byName.keys()].sort());

  const registry = {
    /** Every preset name this registry holds, sorted. */
    names,
    /** How many presets it holds. */
    size: names.length,
    /** Whether a name is held. */
    has(name) {
      return typeof name === "string" && byName.has(name);
    },
    /**
     * The frozen preset a name refers to, or `null`.
     *
     * `null` is the honest answer for a name this registry does not hold — an unknown preset is a
     * fact about a repository document, not a programmer error, so it is returned rather than
     * thrown.
     */
    get(name) {
      if (typeof name !== "string") return null;
      return byName.get(name) ?? null;
    },
    /** A compact description of a held preset, or `null`. */
    describe(name) {
      const preset = registry.get(name);
      if (preset === null) return null;
      return Object.freeze({
        name: preset.name,
        purpose: preset.purpose,
        domains: Object.freeze([...POLICY_PRESET_DOMAINS]),
      });
    },
  };

  return Object.freeze(registry);
}

/** The registry every resolution uses unless a caller supplies another. */
export const DEFAULT_PRESET_REGISTRY = createPresetRegistry();
