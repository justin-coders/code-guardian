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
 */

/** The closed kinds a `PolicyPresetError` may carry. */
export const POLICY_PRESET_ERROR_KINDS = Object.freeze({
  DUPLICATE_PRESET: "duplicate-preset",
  INVALID_PRESET: "invalid-preset",
});

/** The kind vocabulary as a list, for validation and tests. */
export const POLICY_PRESET_ERROR_KIND_VALUES = Object.freeze(
  Object.values(POLICY_PRESET_ERROR_KINDS),
);

/** The stable code every error of this type carries. */
export const POLICY_PRESET_ERROR_CODE = "POLICY_PRESET_ERROR";

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
