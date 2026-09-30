/**
 * Code Guardian — Policy Preset Audit Pack Contracts (Phase 23)
 *
 * The vocabulary of the one rule this pack ships: `policy.preset.audit`.
 *
 * ### One rule, and it is *informational*
 *
 * The pack exists to prove one thing: the preset answer Phase 23 projects is consumable through the
 * accepted Rule Engine — a rule can name the built-in preset that governs a repository's policy,
 * list the keys the preset supplied and the keys the repository replaced, and cite the policy
 * document that made the preset active, without reading a file, a preset registry, a clock or the
 * environment. It decides nothing. There is no violation, no score, no grade, no percentage and no
 * recommendation anywhere in the pack, and `severity` is the word `info` — the only severity a
 * statement about a *configuration choice* may carry.
 *
 * ### Why the rule abstains rather than reporting "no preset"
 *
 * "This repository started from `minimal`" and "this repository named no preset" are different
 * facts, and the second is not an audit result: there is no preset to report. The same is true of a
 * policy that was never established. Both cases abstain, with a closed reason, rather than emitting
 * a finding that reads like a defect. `unknown` is never a pass and never a violation.
 *
 * ### The wording maps are closed over the model's own vocabularies
 *
 * Each phrase table below is pinned to the list it describes by the pack's test, so a rename on
 * either side fails the suite instead of silently retiring a value.
 */

/** Version of the pack as a whole (analyzer version, rule set revision). */
export const POLICY_RULE_PACK_VERSION = "1.0.0";

/** Initial version of the rule in the pack. */
export const POLICY_RULE_VERSION = "1.0.0";

/** Analyzer identity. `policy` is the domain namespace, not a rule. */
export const POLICY_ANALYZER_ID = "policy";
export const POLICY_ANALYZER_NAME = "Policy Preset Audit";
export const POLICY_ANALYZER_SCOPE = "policy";

/** Category recorded on the finding (Core Finding contract). */
export const POLICY_CATEGORY = "architecture";

/** Every policy rule id must live in this namespace. */
export const POLICY_RULE_ID_PREFIX = "policy.";

/** The rules this pack ships. Exactly one, and it is informational. */
export const POLICY_RULE_IDS = Object.freeze({
  PRESET_AUDIT: "policy.preset.audit",
});

/**
 * The severity the rule declares, and the whole vocabulary it may use.
 *
 * `info` is not a placeholder: the rule reports which configuration a repository chose, and a
 * configuration choice is not a defect. The list is exhaustive so the pack's test can assert that
 * no severity above `info` can appear in it at all.
 */
export const POLICY_RULE_SEVERITY = "info";
export const POLICY_SEVERITY_VALUES = Object.freeze(["info"]);

/**
 * Confidence policy.
 *
 * One honest level: `RESOLVED_PRESET` means this build resolved the repository's declared policy
 * against a built-in preset and recorded, for every value, whether the preset or the repository
 * stated it. It says nothing about whether the preset *suits* the repository, and this pack has no
 * opinion that could.
 */
export const POLICY_CONFIDENCE = Object.freeze({
  RESOLVED_PRESET: 0.9,
});

/** `metadata.basis` recorded on the finding. */
export const POLICY_BASIS = "declared-policy-preset-audit";

/** Findings one rule run will report. One preset governs a policy, so one finding reports it. */
export const MAX_POLICY_FINDINGS = 1;

/**
 * Why the rule abstains. Closed vocabulary of the *pack's* own reasons.
 *
 * They are deliberately not the model's reading reasons: an abstention here is about what the audit
 * could report, not about what the repository declared.
 */
export const POLICY_ABSTENTION_REASONS = Object.freeze({
  NO_POLICY_AREA: "no-policy-area",
  POLICY_NOT_ESTABLISHED: "policy-not-established",
  PRESET_NOT_ACTIVE: "preset-not-active",
  POLICY_EVIDENCE_NOT_CARRIED: "policy-evidence-not-carried",
});

/** The abstention vocabulary as a list, for validation and tests. */
export const POLICY_ABSTENTION_REASON_VALUES = Object.freeze(
  Object.values(POLICY_ABSTENTION_REASONS),
);

/** How each abstention reason reads in an applicability statement. */
export const POLICY_ABSTENTION_WORDING = Object.freeze({
  "no-policy-area":
    "this model carries no repository policy area, so there is no policy preset to audit",
  "policy-not-established":
    "the repository's policy reading established nothing, so no preset could have been applied",
  "preset-not-active":
    "the repository's policy names no preset, so no built-in preset governs it",
  "policy-evidence-not-carried":
    "the policy document's own observation is not carried by this model, so the audit would cite nothing",
});

/** How the policy reading state reads in the finding's metadata. */
export const POLICY_STATE_WORDING = Object.freeze({
  established: "a policy document was resolved against its preset",
  absent: "the repository declares no policy, and the scan covered the repository",
  unsupported: "a policy document exists in a format this build does not read",
  unknown: "a policy document exists but could not be interpreted, or the scan could not look",
  truncated: "the scan stopped early, so the absence of a policy cannot be established",
});

/** The policy-state vocabulary this pack can describe, for tests. */
export const POLICY_DESCRIBED_STATES = Object.freeze(Object.keys(POLICY_STATE_WORDING));
