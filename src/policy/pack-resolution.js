/**
 * Code Guardian — Policy Pack Resolution (Phase 24)
 *
 * The layer that answers *which pack holds this preset*, and then hands the merge to the Phase 23
 * resolver unchanged:
 *
 *     declared PolicyDocument
 *              │  preset: "code-guardian-core@1:web-production"
 *              ▼
 *      parsePresetReference          (closed grammar, one way to read it)
 *              ▼
 *      pack registry                 (which pack@version holds this preset?)
 *              ▼
 *      that pack's preset registry
 *              ▼
 *      resolvePolicyDocument         (Phase 23: preset + overrides → effective + provenance)
 *              ▼
 *      effective policy, declared policy, preset, pack, provenance
 *
 * ### The separation is the point
 *
 * The pack layer answers identity: which pack, which version, which preset. The preset layer answers
 * policy: what does that preset state, and what did the repository override. Neither duplicates the
 * other, so the compliance engine — which reads only the effective document — keeps working against
 * exactly the code it was accepted with, and the pack layer cannot accidentally change compliance
 * semantics.
 *
 * ### A bare preset name still means the built-in pack, and only that pack
 *
 * A Phase 23 document writes `{"preset": "web-production"}`, and Phase 24 must not require it to
 * change. It resolves against `code-guardian-core@1` — pinned by constant, never "whichever
 * registered pack happens to hold a preset with that name". If a registry does not hold the built-in
 * pack, a bare name establishes nothing, rather than silently reaching a different pack's preset.
 *
 * ### The declared document keeps what the repository actually wrote
 *
 * The merge runs against the *parsed* preset name, but `declared.preset` is published as the
 * reference the repository wrote — `code-guardian-core@1:web-production` — because "what was
 * declared" must remain the declaration, not this build's normalization of it. The canonically
 * re-ordered domains still come from the preset layer, so two spellings of one policy serialize
 * identically apart from the reference itself.
 */

import {
  BUILT_IN_PACK_NAME,
  BUILT_IN_PACK_VERSION,
  POLICY_PRESET_VERSION,
  POLICY_RESOLUTION_FAILURES,
  isPlainObject,
  packPresetReference,
} from "./contracts.js";
import { DEFAULT_PACK_REGISTRY } from "./pack-registry.js";
import { parsePresetReference, referenceFailure } from "./pack-validation.js";
import { boundedPresetName, resolvePolicyDocument } from "./resolver.js";

function deepFreeze(value) {
  if (value === null || typeof value !== "object" || Object.isFrozen(value)) return value;
  Object.freeze(value);
  for (const key of Object.keys(value)) deepFreeze(value[key]);
  return value;
}

/**
 * The pack identity a resolution published.
 *
 * Six fields, and each one answers a question a consumer would otherwise have to reconstruct:
 * which pack, which version, whose registry it came from, the canonical reference, whether the
 * *repository* named the pack or this build pinned it, and which preset it supplied. Deliberately no
 * title, purpose or preset documents: those describe the pack to a developer, not the repository.
 */
function packRecord({ pack, presetName, explicit }) {
  return {
    name: pack.name,
    version: pack.version,
    origin: pack.origin,
    reference: pack.reference,
    explicit,
    preset: presetName,
  };
}

/**
 * Select the policy definition a reference names.
 *
 * @param {object} input
 * @param {unknown} input.reference The `preset` field as the repository wrote it.
 * @param {object} [input.packs] The pack registry to resolve against.
 * @returns {{ok: true, pack: object, registry: object, presetName: string, packName: string,
 *   packVersion: string, explicit: boolean, reference: string}
 *   | {ok: false, reason: string, detail: string|null}} A frozen result either way.
 */
export function resolvePackPreset({ reference, packs = DEFAULT_PACK_REGISTRY } = {}) {
  const parsed = parsePresetReference(reference);
  if (!parsed.ok) return parsed;

  /**
   * Report a miss in the vocabulary the repository's own spelling earned.
   *
   * A **bare** preset name is the Phase 23 spelling: the repository named no pack, so whatever went
   * wrong, the honest fact is still "this build does not hold that preset" — which is exactly the
   * reading Phase 23 published, and the one a repository author can act on. A reference the
   * repository *qualified* is a claim about a named pack, so the miss is reported as a fact about
   * that pack: which pack, which version, which preset inside it.
   */
  const missing = (reason) =>
    parsed.explicit
      ? referenceFailure(reason, reference)
      : referenceFailure(POLICY_RESOLUTION_FAILURES.PRESET_NOT_ESTABLISHED, parsed.presetName);

  const registry = isPlainObject(packs) && typeof packs.resolveVersion === "function" ? packs : null;
  if (registry === null) {
    return missing(POLICY_RESOLUTION_FAILURES.PACK_NOT_ESTABLISHED);
  }

  // A bare preset name is *always* the built-in pack, at the version this build ships: the pin is a
  // constant, so it cannot depend on what a registry happens to hold. An explicitly named pack may
  // leave its version to the registry, which refuses rather than chooses when it is ambiguous.
  const packName = parsed.packName ?? BUILT_IN_PACK_NAME;
  const pinned = parsed.explicit ? parsed.packVersion : BUILT_IN_PACK_VERSION;

  const resolved = registry.resolveVersion(packName, pinned);
  if (!resolved.ok) return missing(resolved.reason);

  const presets = registry.presetRegistry(packName, resolved.version);
  const pack = registry.get(packName, resolved.version);
  if (presets === null || pack === null) {
    return missing(POLICY_RESOLUTION_FAILURES.PACK_NOT_ESTABLISHED);
  }
  if (!presets.has(parsed.presetName)) {
    return missing(POLICY_RESOLUTION_FAILURES.PACK_PRESET_NOT_ESTABLISHED);
  }

  return Object.freeze({
    ok: true,
    pack,
    registry: presets,
    presetName: parsed.presetName,
    packName,
    packVersion: resolved.version,
    explicit: parsed.explicit,
    reference: packPresetReference(packName, resolved.version, parsed.presetName),
  });
}

/**
 * Resolve a declared policy document through its pack.
 *
 * @param {object} input
 * @param {unknown} input.document The declared document: `{version?, preset?, ...domains}`.
 * @param {object} [input.packs] The pack registry to resolve against.
 * @returns {{ok: true, effective: object, declared: object, preset: object|null, pack: object|null,
 *   provenance: object} | {ok: false, reason: string, detail: string|null}} A deeply frozen result.
 *   `pack` is `null` exactly when the document named no preset — which is an answer, not a failure.
 */
export function resolvePackPolicyDocument({ document, packs = DEFAULT_PACK_REGISTRY } = {}) {
  if (!isPlainObject(document)) {
    return Object.freeze({
      ok: false,
      reason: POLICY_RESOLUTION_FAILURES.DOCUMENT_NOT_INTERPRETED,
      detail: null,
    });
  }

  // The version is pinned, and it is checked before anything else is read, so a document this build
  // does not interpret is refused as a whole rather than partly resolved.
  if (document.version !== undefined && document.version !== POLICY_PRESET_VERSION) {
    return Object.freeze({
      ok: false,
      reason: POLICY_RESOLUTION_FAILURES.VERSION_NOT_SUPPORTED,
      detail: boundedPresetName(document.version),
    });
  }

  let selected = null;
  let resolution;
  if (document.preset === undefined) {
    // No preset at all: the Phase 23 path, bit for bit. Nothing is inherited, so no pack supplied
    // anything.
    resolution = resolvePolicyDocument({ document });
  } else {
    selected = resolvePackPreset({ reference: document.preset, packs });
    if (!selected.ok) return selected;
    // The merge runs against the preset *name*; only an explicitly qualified reference has to be
    // re-keyed, so a bare name reaches the Phase 23 resolver as the very object the repository wrote.
    const merged = selected.explicit ? { ...document, preset: selected.presetName } : document;
    resolution = resolvePolicyDocument({ document: merged, registry: selected.registry });
  }
  if (!resolution.ok) return resolution;

  // The declaration is published as the repository wrote it, not as this build normalized it, so an
  // explicitly qualified reference keeps its own spelling.
  const declared =
    selected !== null && selected.explicit
      ? deepFreeze({ ...resolution.declared, preset: document.preset })
      : resolution.declared;

  return deepFreeze({
    ok: true,
    effective: resolution.effective,
    declared,
    preset: resolution.preset,
    pack: selected === null ? null : packRecord(selected),
    provenance: {
      version: resolution.provenance.version,
      preset: resolution.provenance.preset,
      // The pack that supplied the inherited values, or `null` when nothing was inherited. One
      // document names one preset, hence one pack, so the pack is a property of the whole provenance
      // record: every inherited token is read against it, and no per-key token has to repeat an
      // identity that cannot differ per key. The field is always present, so "no pack supplied
      // anything" is a stated fact rather than a missing key.
      pack: selected === null ? null : selected.pack.reference,
      sources: resolution.provenance.sources,
      inherited: resolution.provenance.inherited,
      overridden: resolution.provenance.overridden,
      limits: resolution.provenance.limits,
    },
  });
}

/**
 * Re-resolve a declared document and check it reproduces a published effective policy, provenance and
 * pack.
 *
 * The Phase 23 counterpart of this function proved an effective document was *derived*; this one
 * proves the same about the pack answer, so a hand-edited `pack` or `pack.explicit` is a validation
 * failure rather than an answer.
 *
 * @param {object} input
 * @param {unknown} input.declared The published declared document.
 * @param {unknown} input.effective The published effective document.
 * @param {unknown} input.provenance The published provenance.
 * @param {unknown} input.pack The published pack identity, or `null`.
 * @param {object} [input.packs]
 * @returns {string[]} Empty when the published values are the resolved ones.
 */
export function packPolicyIssues({ declared, effective, provenance, pack, packs }) {
  const resolution = resolvePackPolicyDocument({ document: declared, packs });
  if (!resolution.ok) {
    return [`declared: could not be resolved (${resolution.reason})`];
  }
  const issues = [];
  if (JSON.stringify(resolution.effective) !== JSON.stringify(effective)) {
    issues.push("effective: must be the document the declared policy resolves to");
  }
  if (JSON.stringify(resolution.provenance) !== JSON.stringify(provenance)) {
    issues.push("provenance: must be the provenance the declared policy resolves to");
  }
  if (JSON.stringify(resolution.pack) !== JSON.stringify(pack ?? null)) {
    issues.push("pack: must be the pack identity the declared policy resolves to");
  }
  return issues;
}
