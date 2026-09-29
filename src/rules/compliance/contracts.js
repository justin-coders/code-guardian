/**
 * Code Guardian — Compliance Rule Pack Contracts (Phase 22)
 *
 * The vocabulary of the `compliance.*` rules. This pack exists to prove one thing: the
 * ComplianceReport Phase 22 projects is *consumable through the accepted Rule Engine* — a rule can
 * read one policy domain's items, report a violation as a finding that cites both the repository
 * observation and the policy declaration behind it, and **abstain** when the domain has no policy
 * or nothing could be measured, without any rule reading a file, parsing source, running a
 * container, resolving a dependency, contacting a network or scoring anything.
 *
 * ### Six rules, one per policy domain, and none of them passes by default
 *
 * `compliance.environment`, `compliance.container`, `compliance.ci`, `compliance.api`,
 * `compliance.dependencies` and `compliance.architecture` each report one section. There is no
 * aggregate rule, no compliance percentage, no grade and no traffic light anywhere in the pack —
 * and the one property the phase turns on is that a domain **without** a declared policy makes its
 * rule abstain. "No policy" is never a pass. Neither is a requirement the repository declares no
 * subject for: a policy that requires a healthcheck of a repository with no container definition
 * is unmeasured, not satisfied.
 *
 * ### A violation is two-sided, and the pack carries both sides
 *
 * Every violation finding cites the repository observation that proves the condition *and* the
 * policy document that makes the condition wrong. The report already refuses to emit a violation
 * with one side missing; the pack repeats the rule at its own boundary, so a hand-built detection
 * cannot smuggle in an accusation either.
 *
 * ### Prose is a closed map over the report's own vocabularies
 *
 * A domain, a status, an item status or an abstention reason the report can produce but this pack
 * cannot describe is a contract mismatch. Each map below is a closed phrase table over one of
 * those vocabularies, and the pack's test pins each one to its source, so a rename on either side
 * fails the suite instead of silently retiring a value.
 *
 * ### Rule identity is a long-term contract
 *
 * Rule ids appear in every fingerprint the rule produces, so a rename retires every existing
 * fingerprint. `COMPLIANCE_RULE_IDS` declares the shipped ids in one place and the registry fails
 * if a declared rule is missing or an id leaves the `compliance.` namespace.
 */

/** Version of the pack as a whole (analyzer version, rule set revision). */
export const COMPLIANCE_RULE_PACK_VERSION = "1.0.0";

/** Initial version of every rule in the pack. */
export const COMPLIANCE_RULE_VERSION = "1.0.0";

/** Analyzer identity. `compliance` is the domain namespace, not a rule. */
export const COMPLIANCE_ANALYZER_ID = "compliance";
export const COMPLIANCE_ANALYZER_NAME = "Project Policy Compliance";
export const COMPLIANCE_ANALYZER_SCOPE = "compliance";

/** Category recorded on every compliance finding (Core Finding contract). */
export const COMPLIANCE_CATEGORY = "architecture";

/** Every compliance rule id must live in this namespace. */
export const COMPLIANCE_RULE_ID_PREFIX = "compliance.";

/** The rules this pack ships: exactly one per policy domain, in the report's own order. */
export const COMPLIANCE_RULE_IDS = Object.freeze({
  ENVIRONMENT: "compliance.environment",
  CONTAINER: "compliance.container",
  CI: "compliance.ci",
  API: "compliance.api",
  DEPENDENCIES: "compliance.dependencies",
  ARCHITECTURE: "compliance.architecture",
});

/**
 * The severity each rule declares.
 *
 * A rule's declared severity is the strongest severity its own detection table can produce. Here
 * that is one word for all six, and it is the strongest statement this pack may make: a
 * `violation` is a defect the repository's own declaration establishes, so it is `medium` — the
 * same ceiling the production packs hold — and nothing above it exists in this pack. An item that
 * could not be measured is never a finding at all: it is an abstention.
 */
export const COMPLIANCE_RULE_SEVERITIES = Object.freeze({
  environment: "medium",
  container: "medium",
  ci: "medium",
  api: "medium",
  dependencies: "medium",
  architecture: "medium",
});

/** The severity vocabulary this pack uses, for validation and tests. */
export const COMPLIANCE_SEVERITY_VALUES = Object.freeze(["info", "low", "medium"]);

/**
 * Confidence policy.
 *
 * One honest level, and it is *not* certainty: `DECLARED_POLICY_VIOLATION` means the repository's
 * own evidence establishes the condition and the repository's own declaration requires the
 * opposite — the two-sided statement the whole phase is built on. It says nothing about
 * consequence, and this pack has no aggregate that could.
 */
export const COMPLIANCE_CONFIDENCE = Object.freeze({
  DECLARED_POLICY_VIOLATION: 0.9,
});

/** `metadata.basis` recorded on every compliance finding. */
export const COMPLIANCE_BASIS = "declared-policy-compliance-report";

/** Findings one rule run will report before it stops and says so. */
export const MAX_COMPLIANCE_FINDINGS = 200;

/** How each policy domain reads in a finding. */
export const COMPLIANCE_SECTION_WORDING = Object.freeze({
  environment: "environment policy",
  container: "container policy",
  ci: "CI policy",
  api: "API policy",
  dependencies: "dependency policy",
  architecture: "architecture policy",
});

/** How each section state reads in a finding's metadata. */
export const COMPLIANCE_STATE_WORDING = Object.freeze({
  pass: "every requirement this domain declares was measured and satisfied",
  violation: "at least one requirement this domain declares is contradicted by the repository",
  partial:
    "some requirements were measured and satisfied, and something else could not be measured",
  unknown: "no requirement in this domain could be measured",
});

/** How each item status reads. */
export const COMPLIANCE_STATUS_WORDING = Object.freeze({
  pass: "the observation satisfies the requirement",
  violation: "the observation contradicts the requirement",
  unknown: "the requirement could not be measured",
});

/** How each policy reading state reads. */
export const COMPLIANCE_POLICY_STATE_WORDING = Object.freeze({
  established: "a validated policy document was read",
  absent: "the repository declares no policy, and the scan covered the repository",
  unsupported: "a policy document exists in a format this build does not read",
  unknown: "a policy document exists but could not be interpreted, or the scan could not look",
  truncated: "the scan stopped early, so the absence of a policy cannot be established",
});

/**
 * How each abstention reason reads.
 *
 * Closed over the report's `COMPLIANCE_UNKNOWN_REASONS`: every reason the report can record is
 * described here, and the pack's test pins the two lists together.
 */
export const COMPLIANCE_ABSTENTION_WORDING = Object.freeze({
  "policy-not-established":
    "this model carries no repository policy area, so no requirement can be measured",
  "policy-document-not-established":
    "no policy document was established, so no requirement can be measured",
  "policy-domain-not-declared":
    "the repository's policy states nothing for this domain, so it declares no requirement here",
  "policy-requirement-not-declared":
    "the policy declares this domain but none of the requirements this build measures",
  "compliance-domain-not-established":
    "the accepted production report did not establish this domain, so nothing can be measured",
  "compliance-no-subject-to-measure":
    "the repository declares no subject this requirement ranges over, so nothing was measured against it",
  "compliance-reading-not-complete":
    "the domain was read, but not completely enough for the claim this item makes",
  "workflow-purpose-not-established":
    "a workflow file name states no purpose, so the workflow set is not established",
  "compliance-evidence-not-established":
    "the evidence behind a measurement is not carried by this model",
  "compliance-items-truncated":
    "a declared bound stopped this section, so its item list is not the complete list",
  "repository-scan-not-complete":
    "the scan behind the report did not cover the repository",
});
