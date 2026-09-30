/**
 * Code Guardian — Policy Pack Registry (Phase 24)
 *
 * A deterministic, immutable, in-memory store of packs. Like the Phase 23 preset registry it loads
 * nothing: no file, no directory, no package, no module resolution, no network, no clock, no
 * randomness and no environment. The registry holds objects this process built.
 *
 * ### Identity is `name@version`, and that is the whole address
 *
 * A version is never inferred, never compared and never ranged over: `get` answers for exactly the
 * reference it was given, and a version this build does not hold is a miss rather than a request to
 * choose the nearest one. The one place a version is *resolved* is `resolveVersion`, for a reference
 * that names a pack without pinning it — and there it refuses when the answer is ambiguous instead
 * of picking a version.
 *
 * ### Each pack gets its own preset registry, built once
 *
 * The Phase 23 merge engine resolves a preset against a *preset* registry, and `resolvePolicyDocument`
 * stays exactly that. So each pack's presets become one of those registries, validated by the same
 * `presetDefinitionIssues` every other registry uses, and built once at construction rather than per
 * resolution — a resolution is then a lookup, not a rebuild. The registries are held privately: a
 * caller reads pack identity through `get`, and reaches preset *values* only through
 * `presetRegistry`, which is what keeps "which preset documents does this pack hold" a deliberate
 * question rather than an incidental property of the handle.
 *
 * ### Determinism is a property of the store, not of its input
 *
 * `names`, `references`, `versions(name)` and `list()` are all sorted. A pack identity travels into a
 * provenance record, a query answer and a finding's metadata, so an order that depended on how a
 * registry was assembled would make those values depend on assembly too.
 *
 * ### Immutability is enforced by construction, not by convention
 *
 * Every value a caller can reach — the handle, its arrays, the pack records and each pack's own
 * preset registry — is deeply frozen. Nothing can be added, replaced or reordered after
 * construction. A duplicate `name@version` is refused rather than overwritten: two packs under one
 * reference would make `get` order-dependent, which is the failure this layer exists to remove.
 */

import { POLICY_PACK_ERROR_KINDS, PolicyPackError } from "./errors.js";
import { BUILT_IN_PACKS } from "./packs.js";
import { packDefinitionIssues, snapshotPackDefinition } from "./pack-validation.js";
import { createPresetRegistry } from "./registry.js";
import {
  POLICY_PACK_LIMITS,
  POLICY_RESOLUTION_FAILURES,
  isPackReference,
  isPlainObject,
  packReference,
} from "./contracts.js";

/** A compact description of a pack: identity, metadata and the preset names it holds. */
function describePack(pack) {
  return Object.freeze({
    name: pack.name,
    version: pack.version,
    origin: pack.origin,
    title: pack.title,
    purpose: pack.purpose,
    reference: pack.reference,
    presets: Object.freeze([...pack.presets]),
  });
}

/** Sort strings the one way this layer ever compares them. */
function sortedUnique(values) {
  return Object.freeze([...new Set(values)].sort());
}

/**
 * Build a policy pack registry.
 *
 * @param {object} [input]
 * @param {object[]} [input.packs] The packs to hold (defaults to the built-in pack).
 * @returns {object} A frozen registry handle.
 * @throws {PolicyPackError} kind `invalid-pack` for a malformed or oversized pack, `duplicate-pack`
 *   for a repeated `name@version`.
 */
export function createPolicyPackRegistry({ packs = BUILT_IN_PACKS } = {}) {
  if (!Array.isArray(packs)) {
    throw new PolicyPackError(POLICY_PACK_ERROR_KINDS.INVALID_PACK, {
      detail: null,
      message: "createPolicyPackRegistry: packs must be an array of pack definitions",
    });
  }
  if (packs.length > POLICY_PACK_LIMITS.maxPacks) {
    throw new PolicyPackError(POLICY_PACK_ERROR_KINDS.INVALID_PACK, {
      detail: null,
      message: "createPolicyPackRegistry: too many packs",
    });
  }

  const byReference = new Map();
  const descriptors = new Map();
  const registries = new Map();
  const versionsByName = new Map();

  packs.forEach((raw, index) => {
    // The pack is **copied once**, then validated and registered from the copy. Nothing downstream
    // reads the caller's object again: a getter on a pack field is consulted exactly once, a later
    // mutation of the caller's definition cannot change an answer, and registering never freezes an
    // object the caller still holds. A pack is a value, so this layer treats it as one.
    const definition = snapshotPackDefinition(raw);
    const issues = packDefinitionIssues(definition);
    if (issues.length > 0) {
      throw new PolicyPackError(POLICY_PACK_ERROR_KINDS.INVALID_PACK, {
        detail:
          isPlainObject(definition) && typeof definition.name === "string"
            ? definition.name
            : null,
        message: `createPolicyPackRegistry: packs[${index}] ${issues.join("; ")}`,
      });
    }

    const reference = packReference(definition.name, definition.version);
    if (byReference.has(reference)) {
      throw new PolicyPackError(POLICY_PACK_ERROR_KINDS.DUPLICATE_PACK, {
        detail: reference,
        message: `createPolicyPackRegistry: "${reference}" is declared twice`,
      });
    }

    // One preset registry per pack, built here so a resolution is a lookup. It validates the
    // presets through the Phase 23 contract, so a pack cannot hold a preset the preset layer
    // itself would refuse — a second, weaker preset check would be a hole.
    registries.set(reference, createPresetRegistry({ presets: definition.presets }));

    byReference.set(
      reference,
      Object.freeze({
        name: definition.name,
        version: definition.version,
        origin: definition.origin,
        title: definition.title,
        purpose: definition.purpose,
        reference,
        // The preset *names* the pack holds, sorted. The documents stay behind `presetRegistry`.
        presets: sortedUnique(definition.presets.map((preset) => preset.name)),
      }),
    );

    versionsByName.set(definition.name, [
      ...(versionsByName.get(definition.name) ?? []),
      definition.version,
    ]);
    descriptors.set(
      reference,
      describePack({
        name: definition.name,
        version: definition.version,
        origin: definition.origin,
        title: definition.title,
        purpose: definition.purpose,
        reference,
        presets: sortedUnique(definition.presets.map((preset) => preset.name)),
      }),
    );
  });

  for (const [name, versions] of versionsByName) {
    if (versions.length > POLICY_PACK_LIMITS.maxVersionsPerPack) {
      throw new PolicyPackError(POLICY_PACK_ERROR_KINDS.INVALID_PACK, {
        detail: name,
        message: `createPolicyPackRegistry: "${name}" declares more versions than this build holds`,
      });
    }
  }

  const references = sortedUnique([...byReference.keys()]);
  const names = sortedUnique([...versionsByName.keys()]);

  const registry = {
    /** How many pack versions the registry holds. */
    size: references.length,
    /** Every pack reference it holds, `name@version`, sorted. */
    references,
    /** Every pack name it holds, sorted and each once. */
    names,
    /** Whether it holds exactly this reference. */
    has(name, version) {
      return (
        typeof name === "string" &&
        typeof version === "string" &&
        byReference.has(packReference(name, version))
      );
    },
    /** The frozen pack record for exactly this reference, or `null`. */
    get(name, version) {
      if (typeof name !== "string" || typeof version !== "string") return null;
      return byReference.get(packReference(name, version)) ?? null;
    },
    /** Every version held for a name, sorted, or an empty array. */
    versions(name) {
      if (typeof name !== "string") return Object.freeze([]);
      return sortedUnique(versionsByName.get(name) ?? []);
    },
    /**
     * Resolve the version a reference should be read as.
     *
     * A pinned version answers for itself or not at all. A *missing* version answers only when the
     * pack holds exactly one: two versions under one name is an ambiguity this method refuses rather
     * than guesses at, because guessing would make the policy a repository is measured against
     * depend on what happened to be registered.
     *
     * @returns {{ok: true, version: string} | {ok: false, reason: string}}
     */
    resolveVersion(name, version = null) {
      const held = versionsByName.get(name) ?? [];
      // A name this registry does not hold is a missing *pack*, whatever version was asked for — the
      // two refusals are different facts, and a repository author can act on each one.
      if (held.length === 0) {
        return { ok: false, reason: POLICY_RESOLUTION_FAILURES.PACK_NOT_ESTABLISHED };
      }
      if (version !== null) {
        return held.includes(version)
          ? { ok: true, version }
          : { ok: false, reason: POLICY_RESOLUTION_FAILURES.PACK_VERSION_NOT_ESTABLISHED };
      }
      if (held.length > 1) {
        return { ok: false, reason: POLICY_RESOLUTION_FAILURES.PACK_VERSION_NOT_ESTABLISHED };
      }
      return { ok: true, version: held[0] };
    },
    /**
     * The Phase 23 preset registry of one pack, or `null`.
     *
     * This is how the resolver reaches preset *documents*: the pack layer answers which pack holds a
     * preset, and the preset layer answers what that preset states. Neither duplicates the other.
     */
    presetRegistry(name, version) {
      if (typeof name !== "string" || typeof version !== "string") return null;
      return registries.get(packReference(name, version)) ?? null;
    },
    /** Whether a string is a well-formed pack reference — a predicate, with no lookup. */
    isReference(value) {
      return isPackReference(value);
    },
    /** A compact description of a held pack, or `null`. Carries no preset document. */
    describe(name, version) {
      if (typeof name !== "string" || typeof version !== "string") return null;
      return descriptors.get(packReference(name, version)) ?? null;
    },
    /** Every held pack, as a compact description, sorted by reference. */
    list() {
      return Object.freeze(references.map((reference) => descriptors.get(reference)));
    },
  };

  return Object.freeze(registry);
}

/** The registry every resolution uses unless a caller supplies another. */
export const DEFAULT_PACK_REGISTRY = createPolicyPackRegistry();
