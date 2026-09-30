/**
 * Code Guardian — Policy Preset Errors (Phase 23)
 *
 * Two errors share one type, and the split between them is the phase's whole safety story.
 *
 *   `duplicate-preset`  a registry was asked to hold two presets with one name. This is a
 *                       *programmer* error: the built-in registry cannot produce it, so it can only
 *                       come from a caller building a custom registry. It throws.
 *   `invalid-preset`    a preset definition does not satisfy the closed schema. Also a programmer
 *                       error, and also throws.
 *
 * An *unknown preset name written by a repository* is deliberately **not** an error: it is a fact
 * about the repository, and it is reported as a policy reading that established nothing. Throwing
 * there would turn a repository's typo into a crashed analysis, and — worse — it would tempt a
 * caller to catch the throw and carry on with a partly-applied policy. So `resolvePolicyDocument`
 * returns a failure object for it, and `PolicyPresetError` is never constructed for it.
 *
 * Phase 24 adds two kinds on the same principle. `invalid-pack` and `duplicate-pack` are
 * *programmer* errors: they can only come from a caller building a pack or a registry, never from a
 * repository document, because a repository can only ever *name* a pack. A repository naming a pack
 * this build does not hold is a reading that established nothing — a failure object, never a throw.
 */

/** The closed kinds a `PolicyPresetError` may carry. */
export const POLICY_PRESET_ERROR_KINDS = Object.freeze({
  DUPLICATE_PRESET: "duplicate-preset",
  INVALID_PRESET: "invalid-preset",
  // Phase 24 — the pack layer's two ways of being built wrongly.
  DUPLICATE_PACK: "duplicate-pack",
  INVALID_PACK: "invalid-pack",
});

/** The kind vocabulary as a list, for validation and tests. */
export const POLICY_PRESET_ERROR_KIND_VALUES = Object.freeze(
  Object.values(POLICY_PRESET_ERROR_KINDS),
);

/** The stable code every error of this type carries. */
export const POLICY_PRESET_ERROR_CODE = "POLICY_PRESET_ERROR";

/** The stable code a policy *pack* error carries. */
export const POLICY_PACK_ERROR_CODE = "POLICY_PACK_ERROR";

/**
 * A programmer error in the preset layer.
 *
 * `detail` is a bounded identifier naming the preset involved, never a value from a repository
 * document: the layer's own inputs are trusted programmatic contracts, so the message is written
 * for the developer who built the registry, not for the repository author.
 */
export class PolicyPresetError extends Error {
  /**
   * @param {string} kind A `POLICY_PRESET_ERROR_KINDS` value.
   * @param {object} [details]
   * @param {string|null} [details.detail] A bounded identifier, or `null`.
   * @param {string} [details.message] A developer-facing explanation.
   */
  constructor(kind, { detail = null, message } = {}) {
    const text =
      typeof message === "string" && message !== ""
        ? message
        : `policy preset error: ${kind}${detail === null ? "" : ` (${detail})`}`;
    super(text);
    this.name = "PolicyPresetError";
    this.code = POLICY_PRESET_ERROR_CODE;
    this.kind = kind;
    this.detail = detail;
  }
}

/** The pack kinds a `PolicyPackError` may carry: the two Phase 24 values above. */
export const POLICY_PACK_ERROR_KINDS = Object.freeze({
  DUPLICATE_PACK: POLICY_PRESET_ERROR_KINDS.DUPLICATE_PACK,
  INVALID_PACK: POLICY_PRESET_ERROR_KINDS.INVALID_PACK,
});

/**
 * A programmer error in the policy pack layer.
 *
 * `detail` is the bounded `name@version` reference of the pack involved — pack identity is a
 * developer-facing contract, so unlike a preset name it is safe to carry in full — or `null` when
 * the failure is about the registry as a whole. The message is written for the developer who built
 * the pack, never for a repository author: no repository document can reach this constructor.
 */
export class PolicyPackError extends Error {
  /**
   * @param {string} kind A `POLICY_PACK_ERROR_KINDS` value.
   * @param {object} [details]
   * @param {string|null} [details.detail] A bounded pack reference, or `null`.
   * @param {string} [details.message] A developer-facing explanation.
   */
  constructor(kind, { detail = null, message } = {}) {
    const text =
      typeof message === "string" && message !== ""
        ? message
        : `policy pack error: ${kind}${detail === null ? "" : ` (${detail})`}`;
    super(text);
    this.name = "PolicyPackError";
    this.code = POLICY_PACK_ERROR_CODE;
    this.kind = kind;
    this.detail = detail;
  }
}
