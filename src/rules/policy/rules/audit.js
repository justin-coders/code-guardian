/**
 * Code Guardian — Policy Preset Audit Rule (Phase 23)
 *
 * The integration proof for Phase 23's preset layer, and deliberately **one informational rule**:
 * it reports which built-in preset governs a repository's policy, which requirements that preset
 * supplied and which the repository replaced.
 *
 * ### What the rule proves about the preset substrate
 *
 *   - it reads the answer **only** through the Phase 11 query API (`policyPreset`,
 *     `effectivePolicy`, `policyProvenance`, `policy`) — never the raw model area, never a preset
 *     registry, never a file;
 *   - the finding cites the policy document's own observation, because the declaration is what made
 *     the preset active: a preset audit with no declaration behind it would be a claim about a
 *     configuration nobody stated;
 *   - `inherited` and `overridden` come from the resolver's provenance, never from diffing two
 *     documents in this rule, so the audit cannot disagree with the model about where a value came
 *     from;
 *   - **a repository whose policy names no preset abstains.** It does not report "no preset" as a
 *     finding, it does not score one configuration against another, and it never recommends a
 *     preset. "No preset was named" and "the `strict` preset was applied" are different facts and
 *     are reported differently.
 *
 * ### What is deliberately absent
 *
 * No violation, no severity above `info`, no score, grade, percentage or traffic light, no
 * comparison against any other preset, and no remediation. A finding here states a configuration
 * choice and the declaration that made it.
 */

import { createRule } from "../../../core/index.js";
import { stabilityHash } from "../../../repository/model/index.js";

import { APPLICABILITY_COVERAGE } from "../../contracts.js";
import { createRuleDetection } from "../../evaluation.js";

import {
  MAX_POLICY_FINDINGS,
  POLICY_ABSTENTION_REASONS,
  POLICY_ABSTENTION_WORDING,
  POLICY_BASIS,
  POLICY_CATEGORY,
  POLICY_CONFIDENCE,
  POLICY_RULE_IDS,
  POLICY_RULE_SEVERITY,
  POLICY_RULE_VERSION,
  POLICY_STATE_WORDING,
} from "../contracts.js";
import {
  activePreset,
  effectivePolicy,
  policyArea,
  policyProvenance,
  queryFor,
} from "../signals.js";

/** An abstention carrying the pack's own metadata, so a caller still sees what was read. */
function abstain(reason, metadata) {
  return {
    ...createRuleDetection({
      findings: [],
      coverage: APPLICABILITY_COVERAGE.UNKNOWN,
      reason: POLICY_ABSTENTION_WORDING[reason] ?? "no policy preset could be audited",
    }),
    metadata,
  };
}

/**
 * Report the preset that governs this repository's policy.
 *
 * @param {object} context A validated AnalysisContext.
 * @returns {object} A detection object.
 */
function detectPreset(context) {
  const query = queryFor(context);
  const policy = policyArea(query);
  const preset = activePreset(query);
  const effective = effectivePolicy(query);
  const provenance = policyProvenance(query);

  const metadata = {
    basis: POLICY_BASIS,
    policyState: policy?.state ?? null,
    policyStateWording: policy === null ? null : POLICY_STATE_WORDING[policy.state] ?? null,
    policyEstablished: policy?.established === true,
    presetActive: preset?.active === true,
    preset: preset?.name ?? null,
    presetVersion: preset?.version ?? null,
    presetOrigin: preset?.origin ?? null,
    effectiveVersion: effective?.version ?? null,
    effectiveDomains: [...(effective?.domains ?? [])],
    effectiveSettings: effective?.settings ?? 0,
    inheritedKeys: [...(provenance?.inherited ?? [])],
    overriddenKeys: [...(provenance?.overridden ?? [])],
    sources: { ...(provenance?.sources ?? {}) },
    findings: 0,
    reported: 0,
    capped: false,
  };

  if (policy === null) return abstain(POLICY_ABSTENTION_REASONS.NO_POLICY_AREA, metadata);

  if (preset === null || preset.active !== true) {
    // Two different facts, reported differently: a reading that established nothing, and an
    // established policy that names no preset. Neither is an audit result, and neither is a defect.
    const reason =
      policy.established === true
        ? POLICY_ABSTENTION_REASONS.PRESET_NOT_ACTIVE
        : POLICY_ABSTENTION_REASONS.POLICY_NOT_ESTABLISHED;
    return abstain(reason, metadata);
  }

  if (provenance === null || effective === null) {
    // A preset answer with no resolved policy behind it is a model this rule will not describe.
    return abstain(POLICY_ABSTENTION_REASONS.POLICY_EVIDENCE_NOT_CARRIED, metadata);
  }

  const evidence = [...(policy.coverage?.evidenceIds ?? [])].sort();
  if (evidence.length === 0) {
    return abstain(POLICY_ABSTENTION_REASONS.POLICY_EVIDENCE_NOT_CARRIED, metadata);
  }

  const inherited = [...provenance.inherited];
  const overridden = [...provenance.overridden];
  const resolved = Object.keys(provenance.sources).length;
  const reported = Math.min(1, MAX_POLICY_FINDINGS);

  const finding = {
    severity: POLICY_RULE_SEVERITY,
    title: `Active policy preset: ${preset.name}`,
    description:
      `The repository's policy starts from the built-in "${preset.name}" preset. ${inherited.length} of the ${resolved} requirements it resolves to came from the preset and ${overridden.length} were stated by the repository itself. This is an informational statement about the configuration the repository declared — it is not a violation, it is not scored or compared against any other preset, and no preset is recommended.`,
    confidence: POLICY_CONFIDENCE.RESOLVED_PRESET,
    // The declaration that made the preset active. A preset audit with no declaration behind it
    // would be a claim about a configuration nobody stated.
    evidence,
    metadata: {
      ...metadata,
      findings: 1,
      reported,
      // One preset governs one policy, so the run produces a single finding; the key exists so the
      // canonical fingerprint is derived from the preset's own identity rather than from position.
      fingerprintKey: `policy:preset:${stabilityHash(`${preset.name}@${preset.version}`)}`,
    },
  };

  return {
    findings: [finding],
    evidence: [],
    metadata: { ...metadata, findings: 1, reported, capped: reported < 1 },
  };
}

const NO_RECOMMENDATION =
  "No preset is recommended, ranked, scored or compared: a finding names the preset the repository chose, the keys it supplied and the keys the repository replaced, and stops there.";

const NOT_READ =
  "Nothing here reads a file, ignores a path, loads a preset from disk, evaluates an expression, contacts a registry or a network, or reads a clock or the environment: every statement comes from the repository model's already-resolved policy, preset and provenance, and the finding cites the declaration behind them.";

export const policyRules = Object.freeze([
  createRule({
    id: POLICY_RULE_IDS.PRESET_AUDIT,
    version: POLICY_RULE_VERSION,
    category: POLICY_CATEGORY,
    title: "Policy preset resolved for this repository",
    description:
      `Reports the built-in policy preset a repository's own \`.codeguardian/policy.json\` named, the requirements that preset supplied and the requirements the repository's document replaced, all read from the model's resolved effective policy and its per-key provenance. A policy that names no preset — and a policy whose reading established nothing — makes this rule abstain rather than report, because "no preset was named" is not an audit result. ${NO_RECOMMENDATION} ${NOT_READ}`,
    severity: POLICY_RULE_SEVERITY,
    // Every repository that was scanned is in scope; a rule with no selectors is universally
    // applicable (Core Rule contract).
    applicability: {},
    detect: detectPreset,
    remediation: {},
    metadata: {
      basis: POLICY_BASIS,
      tags: ["policy", "preset", "configuration", "audit"],
      falsePositives: [
        "the active preset is reported from the repository's own declaration, so a repository that starts from `strict` and overrides nothing is reported as satisfying a policy it declared — this rule makes no claim about whether the repository actually satisfies it (the compliance pack does)",
        "a value the repository restates with the same value the preset already states is still reported as `overridden`, because provenance records who stated it, not whether it changed anything",
        "a policy that names a preset this build does not hold resolves to nothing, so this rule abstains rather than reporting a preset that was never applied",
      ],
    },
  }),
]);
