/**
 * Code Guardian — Compliance Report (Phase 22)
 *
 * Phase 20 answered *what the repository contains*. Phase 21 answered *which conditions its own
 * evidence proves*. This module answers the question neither could: **which declared project
 * policies are satisfied, and which are violated.**
 *
 * ### The one rule
 *
 * An item here is a `violation` only when **both** halves hold:
 *
 *   1. repository evidence establishes the observed condition, and
 *   2. a policy the repository itself declares requires the opposite.
 *
 * The policy is never inferred. It comes from `.codeguardian/policy.json`, read at one path,
 * validated against a closed schema, and published as first-class evidence — so a violation
 * always cites two things: the observation that proves the condition, and the declaration that
 * makes that condition wrong. `pass` and `unknown` complete the vocabulary, and `unknown` is
 * what every unmeasured combination becomes — a domain with no declared policy, a reading that
 * was not established, an item whose evidence the model does not carry. An unknown is never a
 * pass.
 *
 * ### A requirement is measured against subjects, never against nothing
 *
 * Every check ranges over *subjects* the accepted ProductionReport established — the container
 * definitions, routes, release workflows, manifests and entrypoint-shaped files the repository
 * actually declares. When a declared requirement's domain declares none, nothing was compared,
 * so the key is `unknown` with `compliance-no-subject-to-measure` rather than `pass`. A vacuous
 * `pass` would be the one hole this phase cannot leave open: a repository with no Dockerfile, no
 * route, no workflow and no manifest would report back that its whole declared policy is
 * satisfied, which is exactly the "a requirement nobody measured reads as satisfied" failure
 * the report exists to prevent. `pass` therefore always rests on at least one subject the
 * repository declared, and on the observation that proves it.
 *
 * ### It reads accepted projections, and nothing else
 *
 * The subjects it measures are read from the **ProductionReport** — the six-section projection
 * the accepted graphs already produced — plus the policy area and the evidence list. So there is
 * no second notion of "which routes exist" or "which Dockerfile declares a healthcheck": the
 * compliance layer compares one declaration against facts another phase already established.
 * Nothing here reads a file, parses source, resolves a dependency, starts a container, contacts
 * a network or a registry, or consults a clock.
 *
 * ### No score, no percentage, no grade
 *
 * There is no compliance percentage, no grade, no traffic light and no severity anywhere in this
 * report. `COMPLIANCE_STATES` says what was *established*, and the item lists say what follows
 * from it. Counting is deliberately not scoring: `coverage.violations` is how many items a
 * consumer must read, not how bad the repository is.
 *
 * ### Determinism and bounds
 *
 * Sections appear in the declared domain order, items are sorted by `(domain, key, subject)`,
 * evidence ids are sorted and unique, abstentions are merged and sorted, and every collection is
 * bounded by `COMPLIANCE_LIMITS` with a bound that bit recorded rather than silently applied.
 * The `rationale` of every item is *rendered* from its own closed fields by
 * `renderComplianceRationale`, and the model validator recomputes it, so no prose can drift from
 * the tuple it describes.
 */

import {
  POLICY_DOCUMENT_KEYS,
  POLICY_DOCUMENT_SCHEMA,
  POLICY_DOMAINS,
  POLICY_READ_STATUSES,
  isEstablishedPolicyState,
} from "./policy.js";

/** Version of the compliance report contract. */
export const COMPLIANCE_VERSION = "1";

/** Producer recorded in the model's metadata for this projection. */
export const COMPLIANCE_BUILDER = "phase-22-compliance-report";

/** The six policy domains, in the order the report declares them. */
export const COMPLIANCE_SECTIONS = POLICY_DOMAINS;

/** Human-readable section labels. */
export const COMPLIANCE_SECTION_TITLES = Object.freeze({
  environment: "Environment policy",
  container: "Container policy",
  ci: "CI policy",
  api: "API policy",
  dependencies: "Dependency policy",
  architecture: "Architecture policy",
});

/**
 * The three statuses one compliance item can have.
 *
 * `pass` and `violation` are *measurements*: both rest on repository evidence, and the policy
 * requirement decides which one they are. `unknown` is the absence of a measurement, for one of
 * the named reasons — and it is deliberately not a pass.
 */
export const COMPLIANCE_STATUSES = Object.freeze({
  PASS: "pass",
  VIOLATION: "violation",
  UNKNOWN: "unknown",
});

/** The status vocabulary as a list, for validation. */
export const COMPLIANCE_STATUS_VALUES = Object.freeze(Object.values(COMPLIANCE_STATUSES));

/**
 * The state of one section.
 *
 * `pass` and `violation` are outcomes; `partial` means some items were measured and something
 * else could not be; `unknown` means nothing in the domain could be measured. A section with no
 * items at all is `unknown` — which is exactly what "this policy declares no requirement in this
 * domain" produces, and the reason that case can never read as a pass.
 */
export const COMPLIANCE_SECTION_STATES = Object.freeze({
  PASS: "pass",
  VIOLATION: "violation",
  PARTIAL: "partial",
  UNKNOWN: "unknown",
});

/** The section-state vocabulary as a list, for validation. */
export const COMPLIANCE_SECTION_STATE_VALUES = Object.freeze(
  Object.values(COMPLIANCE_SECTION_STATES),
);

/**
 * The state of the report as a whole.
 *
 * The precedence is `violation` → `truncated` → `pass` → `partial` → `unknown`: a proven
 * violation is the headline fact, a bound that bit is the next most important caveat, `pass`
 * requires *every* domain to have been measured and satisfied, `partial` means at least one was
 * measured, and `unknown` means none was.
 */
export const COMPLIANCE_STATES = Object.freeze({
  VIOLATION: "violation",
  TRUNCATED: "truncated",
  PASS: "pass",
  PARTIAL: "partial",
  UNKNOWN: "unknown",
});

/** The report-state vocabulary as a list, for validation. */
export const COMPLIANCE_STATE_VALUES = Object.freeze(Object.values(COMPLIANCE_STATES));

/**
 * Why a section or an item has no measurement. Closed vocabulary.
 *
 * Every reason is about *knowledge*: there is no reason in this list that says a requirement was
 * broken, because a broken requirement is a `violation`, and a violation can only come from
 * evidence.
 */
export const COMPLIANCE_UNKNOWN_REASONS = Object.freeze({
  /** This model carries no policy area at all. */
  POLICY_NOT_ESTABLISHED: "policy-not-established",
  /** A policy exists, but not in a form this build established. */
  POLICY_DOCUMENT_NOT_ESTABLISHED: "policy-document-not-established",
  /** The policy states nothing for this domain. */
  POLICY_DOMAIN_NOT_DECLARED: "policy-domain-not-declared",
  /** The policy declares the domain but none of the requirements a check could measure. */
  POLICY_REQUIREMENT_NOT_DECLARED: "policy-requirement-not-declared",
  /** The accepted production report carries no section for this domain. */
  DOMAIN_NOT_ESTABLISHED: "compliance-domain-not-established",
  /**
   * The requirement ranges over subjects the repository declares, and it declares none: there was
   * nothing to compare the declared requirement against, so it is not satisfied — it is
   * unmeasured.
   */
  NO_SUBJECT_TO_MEASURE: "compliance-no-subject-to-measure",
  /** The domain was read, but not completely enough for the claim this item makes. */
  READING_NOT_COMPLETE: "compliance-reading-not-complete",
  /** A workflow's name states no purpose, so the workflow set is not established. */
  WORKFLOW_PURPOSE_NOT_ESTABLISHED: "workflow-purpose-not-established",
  /** The evidence behind a measurement is not carried by this model. */
  EVIDENCE_NOT_ESTABLISHED: "compliance-evidence-not-established",
  /** A declared bound stopped this section. */
  ITEMS_TRUNCATED: "compliance-items-truncated",
  /** The scan behind the report did not cover the repository. */
  REPOSITORY_SCAN_NOT_COMPLETE: "repository-scan-not-complete",
});

/** The unknown-reason vocabulary as a list, for validation. */
export const COMPLIANCE_UNKNOWN_REASON_VALUES = Object.freeze(
  Object.values(COMPLIANCE_UNKNOWN_REASONS),
);

/**
 * Which policy keys bind, and at which value.
 *
 * A compliance item measures a *requirement*. A key that states no requirement produces no item,
 * so this table is what decides whether a key exists as a measurement at all:
 *
 *   - `true`  the key requires the condition when it is `true` (`requireTemplate: true` requires
 *             a template; `requireTemplate: false` requires nothing)
 *   - `false` the key *forbids* the condition when it is `false` (`allowMultipleTemplates: false`
 *             allows at most one; `allowMultipleTemplates: true` allows any number)
 *   - `value` the key always binds, whatever it is set to (`maxReleaseWorkflows: 0` means no
 *             release workflow may exist, which is a requirement like any other)
 */
export const POLICY_REQUIREMENT_BINDING = Object.freeze({
  environment: Object.freeze({
    requireTemplate: true,
    allowMultipleTemplates: false,
  }),
  container: Object.freeze({
    requireHealthcheck: true,
  }),
  ci: Object.freeze({
    requireTestsForRelease: true,
    requireLintForRelease: true,
    maxReleaseWorkflows: "value",
  }),
  api: Object.freeze({
    requireResolvedMiddleware: true,
  }),
  dependencies: Object.freeze({
    requireLockfile: true,
    allowMultipleManagers: false,
  }),
  architecture: Object.freeze({
    requireConnectedEntrypoints: true,
  }),
});

/**
 * The closed `observed` vocabulary, per policy key.
 *
 * `not-established` appears on every key: it is the state of a key whose reading was not complete
 * enough for the claim it makes. It is a measurement of the *reading*, never of the repository,
 * and the rationale it renders says so. A key whose value makes no requirement has no token at
 * all, because it produces no item — there is no requirement to measure, and the section records
 * `policy-requirement-not-declared` instead.
 *
 * Every other token is an observation of a subject the repository declared. A key with no subject
 * to measure has no token either: the item is never produced, and the section records
 * `compliance-no-subject-to-measure`.
 *
 * One token is not a token: `ci.maxReleaseWorkflows` observes a **count**, so its `observed`
 * field is either a non-negative integer or one of its two fallback words.
 */
export const COMPLIANCE_OBSERVED_VALUES = Object.freeze({
  "environment.requireTemplate": Object.freeze([
    "template-observed",
    "template-not-observed",
    "not-established",
  ]),
  "environment.allowMultipleTemplates": Object.freeze([
    "templates-single",
    "templates-multiple",
    "not-established",
  ]),
  "container.requireHealthcheck": Object.freeze([
    "healthcheck-declared",
    "healthcheck-absent",
    "healthcheck-disabled",
    "structure-not-established",
    "not-established",
  ]),
  "ci.requireTestsForRelease": Object.freeze([
    "test-workflow-observed",
    "test-workflow-not-observed",
    "workflow-purpose-not-established",
    "not-established",
  ]),
  "ci.requireLintForRelease": Object.freeze([
    "lint-workflow-observed",
    "lint-workflow-not-observed",
    "workflow-purpose-not-established",
    "not-established",
  ]),
  "ci.maxReleaseWorkflows": Object.freeze(["count-not-established", "not-established"]),
  "api.requireResolvedMiddleware": Object.freeze([
    "middleware-resolved",
    "middleware-none-observed",
    "middleware-unresolved",
    "route-protection-not-established",
    "not-established",
  ]),
  "dependencies.requireLockfile": Object.freeze([
    "lockfile-observed",
    "lockfile-not-observed",
    "source-not-established",
    "not-established",
  ]),
  "dependencies.allowMultipleManagers": Object.freeze([
    "ecosystems-single",
    "ecosystems-multiple",
    "not-established",
  ]),
  "architecture.requireConnectedEntrypoints": Object.freeze([
    "entrypoint-connected",
    "entrypoint-disconnected",
    "not-established",
  ]),
});

/**
 * Every `domain.key` a check exists for, in declared order.
 *
 * It is the table above read as a list, and a test pins it to the schema's own keys, so a policy
 * key this report has no measurement for is a failing test rather than a silently ignored
 * declaration.
 */
export const COMPLIANCE_CHECK_IDS = Object.freeze(Object.keys(COMPLIANCE_OBSERVED_VALUES));

/** Bounds on what the report retains. */
export const COMPLIANCE_LIMITS = Object.freeze({
  /** Items one section carries. */
  maxItemsPerSection: 200,
  /** Evidence ids cited by one item. */
  maxEvidencePerItem: 16,
  /** Abstentions one section carries. */
  maxUnknownReasonsPerSection: 32,
  /** Characters a rendered rationale may occupy. */
  maxRationaleLength: 240,
});

function deepFreeze(value) {
  if (value === null || typeof value !== "object" || Object.isFrozen(value)) return value;
  Object.freeze(value);
  for (const key of Object.keys(value)) deepFreeze(value[key]);
  return value;
}

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

/** Sort by a list of keys, treating a missing token as the empty string. */
function compareByKeys(keys) {
  return (a, b) => {
    for (const key of keys) {
      const left = a?.[key];
      const right = b?.[key];
      if (left === right) continue;
      const leftKey = left === null || left === undefined ? "" : String(left);
      const rightKey = right === null || right === undefined ? "" : String(right);
      if (leftKey === rightKey) continue;
      return leftKey < rightKey ? -1 : 1;
    }
    return 0;
  };
}

/** Build one abstention record. */
function abstention(reason, detail, count) {
  return { reason, detail: detail ?? null, count };
}

/** Merge abstention records that share a `(reason, detail)` pair. */
function mergeAbstentions(records) {
  const merged = new Map();
  for (const record of records) {
    const key = `${record.reason}\u0000${record.detail ?? ""}`;
    const existing = merged.get(key);
    if (existing === undefined) merged.set(key, { ...record });
    else existing.count += record.count;
  }
  return [...merged.values()].sort(compareByKeys(["reason", "detail"]));
}

/**
 * The compliance reporting policy: an item cites only ids the model actually carries.
 *
 * An id that is not present is dropped, never invented — and a *violation* that cannot cite both
 * halves is withheld and recorded as an abstention instead, because a violation is an accusation
 * and this phase makes every accusation two-sided.
 */
function createCitation(existing) {
  return function cite(...ids) {
    const unique = [...new Set(ids.filter((id) => typeof id === "string" && existing.has(id)))];
    return unique.sort().slice(0, COMPLIANCE_LIMITS.maxEvidencePerItem);
  };
}

/**
 * Render one item's rationale from its own closed fields.
 *
 * The function is pure and total over the closed vocabulary: it takes a `(domain, key, expected,
 * observed)` tuple and returns the one sentence that describes it. Nothing else may vary the
 * text — the model validator recomputes it for every item and refuses a mismatch — so prose can
 * never disagree with the tuple it claims to describe, and no rationale can smuggle in a
 * judgment the vocabulary cannot express.
 *
 * @param {object} item
 * @returns {string}
 */
export function renderComplianceRationale(item) {
  const id = `${item.domain}.${item.key}`;
  const phrases = COMPLIANCE_RATIONALE_PHRASES[id];
  if (phrases === undefined) return NOT_ESTABLISHED_PHRASE;
  // The one key whose observation is a number rather than a token renders through its own
  // function, because the count is part of the sentence and must come from the item itself.
  if (typeof item.observed === "number") {
    return typeof phrases.within === "function"
      ? phrases.within(item).slice(0, COMPLIANCE_LIMITS.maxRationaleLength)
      : NOT_ESTABLISHED_PHRASE;
  }
  const phrase = phrases[item.observed];
  if (typeof phrase === "function") {
    return phrase(item).slice(0, COMPLIANCE_LIMITS.maxRationaleLength);
  }
  if (typeof phrase === "string") return phrase.slice(0, COMPLIANCE_LIMITS.maxRationaleLength);
  // Every other unmeasured shape — `not-established`, and any future token a check adds — reads
  // as the same statement, so a token can never acquire a rationale this table did not write.
  return NOT_ESTABLISHED_PHRASE;
}

/**
 * The closed phrase table behind `renderComplianceRationale`.
 *
 * One phrase per `(domain, key, observed)` triple, in the order the tokens are declared. Every
 * phrase states what was measured and what the policy requires — never how serious the
 * difference is, and never a recommendation, because a compliance report states the difference
 * between a declaration and the repository, not what to do about it.
 */
const COMPLIANCE_RATIONALE_PHRASES = Object.freeze({
  "environment.requireTemplate": Object.freeze({
    "template-observed":
      "the policy requires an environment template and the environment reading observed one",
    "template-not-observed":
      "the policy requires an environment template and the environment reading observed none",
  }),
  "environment.allowMultipleTemplates": Object.freeze({
    "templates-single":
      "the policy allows at most one environment template and no more than one was observed",
    "templates-multiple":
      "the policy allows at most one environment template and more than one was observed",
  }),
  "container.requireHealthcheck": Object.freeze({
    "healthcheck-declared":
      "the policy requires a healthcheck and this container definition declares one",
    "healthcheck-absent":
      "the policy requires a healthcheck and this container definition declares none",
    "healthcheck-disabled":
      "the policy requires a healthcheck and this container definition disables it",
    "structure-not-established":
      "this container definition's instructions were not established, so its healthcheck cannot be measured",
  }),
  "ci.requireTestsForRelease": Object.freeze({
    "test-workflow-observed":
      "the policy requires a test workflow beside the release workflows and the CI reading observed one",
    "test-workflow-not-observed":
      "the policy requires a test workflow beside this release workflow and none was observed",
    "workflow-purpose-not-established":
      "a workflow file name states no purpose, so whether a test workflow exists is not established",
  }),
  "ci.requireLintForRelease": Object.freeze({
    "lint-workflow-observed":
      "the policy requires a lint workflow beside the release workflows and the CI reading observed one",
    "lint-workflow-not-observed":
      "the policy requires a lint workflow beside this release workflow and none was observed",
    "workflow-purpose-not-established":
      "a workflow file name states no purpose, so whether a lint workflow exists is not established",
  }),
  "ci.maxReleaseWorkflows": Object.freeze({
    within: (item) =>
      `the policy allows at most ${String(item.expected)} release workflows and the repository declares ${String(
        item.observed,
      )}`,
    "count-not-established":
      "the policy limits release workflows and a workflow file name states no purpose, so the count is not established",
  }),
  "api.requireResolvedMiddleware": Object.freeze({
    "middleware-resolved":
      "the policy requires every route's middleware to be established and this route's middleware is established",
    "middleware-none-observed":
      "the policy requires every route's middleware to be established and this route's middleware state is established as none",
    "middleware-unresolved":
      "the policy requires every route's middleware to be established and this route's middleware could not be resolved",
    "route-protection-not-established":
      "this route's protection state was not established, so its middleware cannot be measured",
  }),
  "dependencies.requireLockfile": Object.freeze({
    "lockfile-observed":
      "the policy requires a lockfile in this manifest's ecosystem and the dependency reading observed one",
    "lockfile-not-observed":
      "the policy requires a lockfile in this manifest's ecosystem and none was observed",
    "source-not-established":
      "this dependency source was not interpreted, so its ecosystem's lockfile cannot be measured",
  }),
  "dependencies.allowMultipleManagers": Object.freeze({
    "ecosystems-single":
      "the policy allows one dependency ecosystem and the repository declares one",
    "ecosystems-multiple":
      "the policy allows one dependency ecosystem and the repository declares more than one",
  }),
  "architecture.requireConnectedEntrypoints": Object.freeze({
    "entrypoint-connected":
      "the policy requires entrypoints to be related by the import graph and this entrypoint is",
    "entrypoint-disconnected":
      "the policy requires entrypoints to be related by the import graph and no import edge relates this entrypoint",
  }),
});

/** The shared phrase for every key whose reading was not established. */
const NOT_ESTABLISHED_PHRASE = "the policy states this requirement and the reading behind it was not established";

/**
 * Measure one check that rests on a set of subjects.
 *
 * The shape every domain builder shares, so no check can forget a rule:
 *
 *   - the domain must have been established at all, or every item is `unknown`;
 *   - a requirement with **no subject** is `unknown` and never a pass: nothing was compared, so
 *     there is no measurement to report;
 *   - a check whose *violation* rests on an absence additionally needs a **complete** reading —
 *     "no template was observed" is only a fact about a repository whose environment
 *     configuration was read in full;
 *   - a violation must cite repository evidence *and* the policy document; if either half is
 *     missing the item is withheld and the section records why, because an accusation with one
 *     side is exactly what this phase forbids;
 *   - an item is dropped when the evidence behind it is absent, so nothing in the report claims
 *     something the model cannot prove.
 *
 * @param {object} input
 * @returns {{items: object[], unknown: object[]}}
 */
function measure({
  domain,
  key,
  expected,
  subjects,
  cite,
  policyEvidenceIds,
  domainEstablished,
  domainComplete,
  requiresCompleteReading,
}) {
  const items = [];
  const unknown = [];
  const id = `${domain}.${key}`;
  const binding = POLICY_REQUIREMENT_BINDING[domain]?.[key];
  const binds = binding === "value" || expected === binding;

  if (!domainEstablished) {
    unknown.push(abstention(COMPLIANCE_UNKNOWN_REASONS.DOMAIN_NOT_ESTABLISHED, id, 1));
    return { items, unknown };
  }

  if (!binds) return { items, unknown };

  // A requirement is a statement about the subjects the repository declares. With none, nothing
  // was compared, so the key is `unknown` — never a pass, because passing a requirement nothing
  // was measured against would let a repository that declares nothing measurable report its whole
  // policy satisfied.
  if (subjects.length === 0) {
    unknown.push(abstention(COMPLIANCE_UNKNOWN_REASONS.NO_SUBJECT_TO_MEASURE, id, 1));
    return { items, unknown };
  }

  const notComplete = requiresCompleteReading === true && domainComplete !== true;

  for (const subject of subjects) {
    const observed = notComplete ? "not-established" : subject.observed;
    let status = COMPLIANCE_STATUSES.UNKNOWN;
    if (observed === "not-established") {
      status = COMPLIANCE_STATUSES.UNKNOWN;
      unknown.push(
        abstention(
          notComplete
            ? COMPLIANCE_UNKNOWN_REASONS.READING_NOT_COMPLETE
            : COMPLIANCE_UNKNOWN_REASONS.DOMAIN_NOT_ESTABLISHED,
          id,
          1,
        ),
      );
    } else if (subject.status === COMPLIANCE_STATUSES.UNKNOWN) {
      status = COMPLIANCE_STATUSES.UNKNOWN;
      unknown.push(
        abstention(
          subject.reason ?? COMPLIANCE_UNKNOWN_REASONS.DOMAIN_NOT_ESTABLISHED,
          subject.detail ?? id,
          1,
        ),
      );
    } else {
      status = subject.status;
    }

    const policyIds = cite(...policyEvidenceIds);
    const evidenceIds = cite(...(subject.evidenceIds ?? []));
    const item = {
      // A subject-less item's id is its key: it measures the repository as a whole, so there is
      // nothing to disambiguate it from and no trailing separator to carry.
      id: subject.subject === null || subject.subject === undefined ? id : `${id}:${subject.subject}`,
      domain,
      key,
      policyKey: id,
      expected,
      observed,
      status,
      subject: subject.subject ?? null,
      basis: subject.basis ?? null,
      rationale: renderComplianceRationale({ domain, key, expected, observed, subject: subject.subject ?? null }),
      policyEvidenceIds: policyIds,
      evidenceIds,
    };

    if (status === COMPLIANCE_STATUSES.VIOLATION) {
      // A violation is an accusation: it needs the repository fact and the declaration. When
      // either is missing the item is withheld rather than softened into a pass.
      if (evidenceIds.length === 0 || policyIds.length === 0) {
        unknown.push(abstention(COMPLIANCE_UNKNOWN_REASONS.EVIDENCE_NOT_ESTABLISHED, item.id, 1));
        continue;
      }
    }
    if (status !== COMPLIANCE_STATUSES.VIOLATION && evidenceIds.length === 0 && policyIds.length === 0) {
      unknown.push(abstention(COMPLIANCE_UNKNOWN_REASONS.EVIDENCE_NOT_ESTABLISHED, item.id, 1));
      continue;
    }

    items.push(item);
  }

  return { items, unknown };
}

/** Assemble one section, applying the bounds in one place. */
function assembleSection({ name, items, unknown, policyKeys, policyDeclared, policyEvidenceIds }) {
  const sorted = [...items].sort(compareByKeys(["key", "subject", "id"]));
  const capped = sorted.length > COMPLIANCE_LIMITS.maxItemsPerSection;
  const retained = capped ? sorted.slice(0, COMPLIANCE_LIMITS.maxItemsPerSection) : sorted;

  const unbounded = mergeAbstentions(unknown);
  const reasonsCapped = unbounded.length > COMPLIANCE_LIMITS.maxUnknownReasonsPerSection;
  const records = reasonsCapped
    ? unbounded.slice(0, COMPLIANCE_LIMITS.maxUnknownReasonsPerSection)
    : unbounded;

  const violations = retained.filter((item) => item.status === COMPLIANCE_STATUSES.VIOLATION);
  const passed = retained.filter((item) => item.status === COMPLIANCE_STATUSES.PASS);
  const unknowns = retained.filter((item) => item.status === COMPLIANCE_STATUSES.UNKNOWN);

  // Four outcomes, and every one of them is derived from the items rather than assumed:
  // nothing measured is `unknown` — never a pass — a proven violation is the headline even when
  // other items were unmeasured (their own statuses keep that visible), a section whose items
  // all passed is `pass`, and anything measured *and* partly unmeasured is `partial`.
  let state;
  if (retained.length === 0) state = COMPLIANCE_SECTION_STATES.UNKNOWN;
  else if (violations.length > 0) state = COMPLIANCE_SECTION_STATES.VIOLATION;
  else if (passed.length > 0 && unknowns.length === 0) state = COMPLIANCE_SECTION_STATES.PASS;
  else if (passed.length > 0) state = COMPLIANCE_SECTION_STATES.PARTIAL;
  else state = COMPLIANCE_SECTION_STATES.UNKNOWN;

  const ifCapped = capped
    ? mergeAbstentions([...records, abstention(COMPLIANCE_UNKNOWN_REASONS.ITEMS_TRUNCATED, null, sorted.length - retained.length)])
    : records;

  const evidenceIds = [...new Set(retained.flatMap((item) => [...item.evidenceIds, ...item.policyEvidenceIds]))].sort();
  const established = state !== COMPLIANCE_SECTION_STATES.UNKNOWN;

  return {
    name,
    title: COMPLIANCE_SECTION_TITLES[name],
    state,
    established,
    policyDeclared: policyDeclared === true,
    policyKeys: [...policyKeys],
    items: retained,
    counts: {
      items: retained.length,
      violations: violations.length,
      passed: passed.length,
      unknown: unknowns.length,
    },
    evidenceIds,
    policyEvidenceIds: [...policyEvidenceIds],
    unknown: ifCapped,
    coverage: {
      state,
      established,
      policyDeclared: policyDeclared === true,
      complete: !capped && !reasonsCapped,
      items: retained.length,
      violations: violations.length,
      passed: passed.length,
      unknown: unknowns.length,
      evidence: evidenceIds.length,
      truncated: capped || reasonsCapped,
      unknownReasons: records.length,
    },
  };
}

/**
 * Build the ComplianceReport.
 *
 * @param {object} input
 * @param {object|null} input.policy The model's policy area.
 * @param {object|null} input.report The accepted ProductionReport, or `null`.
 * @param {object[]} input.evidence Every observation the model carries.
 * @returns {object} A deeply frozen `ComplianceReport`.
 */
export function buildComplianceReport({ policy, report, evidence }) {
  const existing = new Set((evidence ?? []).map((record) => record.id));
  const cite = createCitation(existing);

  const policyEstablished = isEstablishedPolicyState(policy?.state);
  const document = isPlainObject(policy?.document) ? policy.document : null;
  const policyEvidenceIds = (policy?.coverage?.evidenceIds ?? []).filter((id) =>
    existing.has(id),
  );

  const sectionsOf = (name) => {
    const section = Array.isArray(report?.sections)
      ? report.sections.find((entry) => entry.name === name) ?? null
      : null;
    return section;
  };
  const observationsOf = (name, kind) => {
    const section = sectionsOf(name);
    if (section === null || !Array.isArray(section.observations)) return [];
    return section.observations.filter((entry) => entry.kind === kind);
  };

  const built = [];

  for (const domain of COMPLIANCE_SECTIONS) {
    const section = sectionsOf(domain);
    const domainEstablished = section?.established === true && section?.state !== "unsupported";
    // `complete` is the production section's own statement that every input it reads was read in
    // full — for the architecture chapter, that its graph *and* the import graph were both
    // complete — so an absence-shaped claim is measured only against a complete reading and is
    // withheld as `not-established` otherwise.
    const domainComplete = section?.state === "complete";
    const declared = document !== null && isPlainObject(document[domain]);
    const settings = declared ? document[domain] : {};
    const keys = declared ? Object.keys(settings) : [];

    const items = [];
    const unknown = [];

    // Two gates stand in front of every domain, and both produce `unknown` rather than a
    // measurement: the model must carry an *answered* policy, and the domain must have been
    // established by the accepted report. Neither is ever a pass.
    const gateReason =
      policy === null || policy === undefined
        ? COMPLIANCE_UNKNOWN_REASONS.POLICY_NOT_ESTABLISHED
        : !policyEstablished
          ? COMPLIANCE_UNKNOWN_REASONS.POLICY_DOCUMENT_NOT_ESTABLISHED
          : !declared
            ? COMPLIANCE_UNKNOWN_REASONS.POLICY_DOMAIN_NOT_DECLARED
            : !domainEstablished
              ? COMPLIANCE_UNKNOWN_REASONS.DOMAIN_NOT_ESTABLISHED
              : null;

    if (gateReason !== null) {
      unknown.push(abstention(gateReason, domain, 1));
      built.push(
        assembleSection({
          name: domain,
          items: [],
          unknown,
          policyKeys: keys,
          policyDeclared: declared,
          policyEvidenceIds,
        }),
      );
      continue;
    }

    for (const key of POLICY_DOCUMENT_KEYS[domain]) {
      if (!Object.hasOwn(settings, key)) continue;
      const expected = settings[key];
      const check = DOMAIN_CHECKS[domain]?.[key];
      if (check === undefined) continue;
      const measured = measure({
        domain,
        key,
        expected,
        subjects: check.build({
          settings,
          expected,
          observationsOf,
          domain,
          section,
        }),
        cite,
        policyEvidenceIds,
        domainEstablished,
        domainComplete,
        requiresCompleteReading: check.requiresCompleteReading === true,
      });
      items.push(...measured.items);
      unknown.push(...measured.unknown);
    }

    if (items.length === 0 && unknown.length === 0) {
      unknown.push(abstention(COMPLIANCE_UNKNOWN_REASONS.POLICY_REQUIREMENT_NOT_DECLARED, domain, 1));
    }

    built.push(
      assembleSection({
        name: domain,
        items,
        unknown,
        policyKeys: keys,
        policyDeclared: declared,
        policyEvidenceIds,
      }),
    );
  }

  const sections = built;
  const allItems = sections.flatMap((section) => section.items);
  const violations = allItems.filter((item) => item.status === COMPLIANCE_STATUSES.VIOLATION);
  const passed = allItems.filter((item) => item.status === COMPLIANCE_STATUSES.PASS);
  const unknowns = allItems.filter((item) => item.status === COMPLIANCE_STATUSES.UNKNOWN);
  const anyTruncated = sections.some((section) => section.coverage.truncated === true);
  const everySectionPass = sections.every(
    (section) => section.state === COMPLIANCE_SECTION_STATES.PASS,
  );
  const anyEstablished = sections.some((section) => section.established === true);

  const state =
    violations.length > 0
      ? COMPLIANCE_STATES.VIOLATION
      : anyTruncated
        ? COMPLIANCE_STATES.TRUNCATED
        : everySectionPass
          ? COMPLIANCE_STATES.PASS
          : anyEstablished
            ? COMPLIANCE_STATES.PARTIAL
            : COMPLIANCE_STATES.UNKNOWN;

  const reasons = {};
  for (const section of sections) {
    for (const record of section.unknown) {
      reasons[record.reason] = (reasons[record.reason] ?? 0) + record.count;
    }
  }

  const report_ = {
    version: COMPLIANCE_VERSION,
    state,
    established: anyEstablished,
    sections: sections.map((section) => ({ ...section })),
    violations: violations.map((item) => ({ ...item })),
    passed: passed.map((item) => ({ ...item })),
    unknown: unknowns.map((item) => ({ ...item })),
    coverage: {
      state,
      established: anyEstablished,
      complete: state === COMPLIANCE_STATES.PASS,
      truncated: anyTruncated,
      sections: sections.length,
      sectionsEstablished: sections.filter((section) => section.established === true).length,
      items: allItems.length,
      violations: violations.length,
      passed: passed.length,
      unknown: unknowns.length,
      // What the policy itself established, so a consumer can tell "nothing to comply with"
      // apart when the report says nothing could be measured, without re-reading the policy area.
      policyState: policy?.state ?? null,
      policyEstablished: policyEstablished,
      policyDomains: declaredDomains(document),
      policySettings: declaredSettingCount(document),
      evidence: [...new Set(allItems.flatMap((item) => [...item.evidenceIds, ...item.policyEvidenceIds]))].sort(),
      limits: { ...COMPLIANCE_LIMITS },
      unknownReasons: Object.keys(reasons)
        .sort()
        .reduce((accumulator, reason) => {
          accumulator[reason] = reasons[reason];
          return accumulator;
        }, {}),
    },
  };

  return deepFreeze(report_);
}

/** The declared domains of a document, in declared order. */
function declaredDomains(document) {
  if (!isPlainObject(document)) return [];
  return COMPLIANCE_SECTIONS.filter((domain) => isPlainObject(document[domain]));
}

/** How many settings a document states. */
function declaredSettingCount(document) {
  let total = 0;
  for (const domain of declaredDomains(document)) {
    total += Object.keys(document[domain]).length;
  }
  return total;
}

/**
 * How each domain's subjects are read.
 *
 * One entry per policy key, and each returns the subjects to measure. Every subject carries the
 * closed `observed` token it established, the `status` that follows from it, the `basis` the
 * observation rests on, and the evidence ids behind it — so the measurement itself is a lookup
 * rather than a judgment, and the evidence is the report's own.
 *
 * The subjects come from the accepted ProductionReport: `api-route` for a route's protection
 * state, `dependency-manifest` for a source and its role, `architecture-entrypoint` for an
 * entrypoint-shaped file, and so on. Reading them from there is what keeps this phase from
 * introducing a second opinion about what the repository contains.
 */
const DOMAIN_CHECKS = Object.freeze({
  environment: Object.freeze({
    requireTemplate: Object.freeze({
      requiresCompleteReading: true,
      build: ({ observationsOf }) => {
        const templates = [
          ...observationsOf("environment", "environment-example"),
          ...observationsOf("environment", "environment-template"),
        ];
        if (templates.length > 0) {
          return [
            {
              subject: null,
              observed: "template-observed",
              status: COMPLIANCE_STATUSES.PASS,
              basis: "file-name",
              evidenceIds: [...new Set(templates.flatMap((entry) => entry.evidenceIds))],
            },
          ];
        }
        const files = observationsOf("environment", "environment-file");
        // No environment artifact at all: the requirement ranges over nothing, and claiming it
        // satisfied (or broken) would be a statement about a reading that never happened.
        if (files.length === 0) return [];
        return [
          {
            subject: null,
            observed: "template-not-observed",
            status: COMPLIANCE_STATUSES.VIOLATION,
            basis: "file-name",
            evidenceIds: [...new Set(files.flatMap((entry) => entry.evidenceIds))],
          },
        ];
      },
    }),
    allowMultipleTemplates: Object.freeze({
      build: ({ observationsOf }) => {
        const templates = [
          ...observationsOf("environment", "environment-example"),
          ...observationsOf("environment", "environment-template"),
        ];
        // "At most one template" is a constraint on the templates that exist; with none there is
        // no subject to measure.
        if (templates.length === 0) return [];
        return [
          {
            subject: null,
            observed: templates.length > 1 ? "templates-multiple" : "templates-single",
            status:
              templates.length > 1 ? COMPLIANCE_STATUSES.VIOLATION : COMPLIANCE_STATUSES.PASS,
            basis: "file-name",
            evidenceIds: [...new Set(templates.flatMap((entry) => entry.evidenceIds))],
          },
        ];
      },
    }),
  }),
  container: Object.freeze({
    requireHealthcheck: Object.freeze({
      // One subject per container *definition*, not per structure: a Dockerfile whose
      // instructions were not established has no structure observation, and measuring only the
      // definitions that were read would silently skip it. The skipped one becomes `unknown`.
      build: ({ observationsOf }) => {
        // One subject per container definition. A repository that declares none has nothing for
        // `requireHealthcheck` to be about, so the check reports no subject and the section
        // abstains rather than passing a requirement nothing was measured against.
        const definitions = observationsOf("container", "container-definition");
        if (definitions.length === 0) return [];
        const structureByPath = new Map(
          observationsOf("container", "container-structure").map((entry) => [entry.path, entry]),
        );
        return definitions.map((definition) => {
          const structure = structureByPath.get(definition.path);
          if (structure === undefined) {
            return {
              subject: definition.path,
              observed: "structure-not-established",
              status: COMPLIANCE_STATUSES.UNKNOWN,
              reason: COMPLIANCE_UNKNOWN_REASONS.READING_NOT_COMPLETE,
              detail: definition.path,
              basis: "dockerfile-instructions",
              evidenceIds: [...definition.evidenceIds],
            };
          }
          const observed =
            structure.healthcheck === true
              ? "healthcheck-declared"
              : structure.healthcheckDisabled === true
                ? "healthcheck-disabled"
                : "healthcheck-absent";
          return {
            subject: definition.path,
            observed,
            status:
              observed === "healthcheck-declared"
                ? COMPLIANCE_STATUSES.PASS
                : COMPLIANCE_STATUSES.VIOLATION,
            basis: "dockerfile-instructions",
            evidenceIds: [...definition.evidenceIds, ...structure.evidenceIds],
          };
        });
      },
    }),
  }),
  ci: Object.freeze({
    requireTestsForRelease: Object.freeze({
      requiresCompleteReading: true,
      build: ({ observationsOf }) => workflowSubjects(observationsOf, "test"),
    }),
    requireLintForRelease: Object.freeze({
      requiresCompleteReading: true,
      build: ({ observationsOf }) => workflowSubjects(observationsOf, "lint"),
    }),
    maxReleaseWorkflows: Object.freeze({
      build: ({ observationsOf, expected }) => {
        const workflows = observationsOf("ci", "ci-workflow");
        // A repository with no CI configuration at all declares no workflow for a release limit
        // to range over, so there is no subject to measure.
        if (workflows.length === 0) return [];
        const releases = workflows.filter((entry) => entry.purpose === "release");
        const unclassified = workflows.filter((entry) => entry.purpose === "unclassified");
        if (unclassified.length > 0) {
          // A lower bound cannot prove a limit is respected, so the count is withheld. It *can*
          // prove a limit is exceeded, which is why the comparison below still runs when the
          // release set already exceeds the limit.
          const exceeds = Number.isInteger(expected) && releases.length > expected;
          if (!exceeds) {
            return [
              {
                subject: null,
                observed: "count-not-established",
                status: COMPLIANCE_STATUSES.UNKNOWN,
                reason: COMPLIANCE_UNKNOWN_REASONS.WORKFLOW_PURPOSE_NOT_ESTABLISHED,
                detail: null,
                basis: "workflow-name",
                evidenceIds: [...new Set(unclassified.flatMap((entry) => entry.evidenceIds))],
              },
            ];
          }
        }
        return [
          {
            subject: null,
            observed: releases.length,
            status:
              Number.isInteger(expected) && releases.length > expected
                ? COMPLIANCE_STATUSES.VIOLATION
                : COMPLIANCE_STATUSES.PASS,
            basis: "workflow-name",
            // The count rests on the whole workflow inventory, not only on the release-shaped
            // names: "the repository declares no release workflow" is a statement the *classified*
            // names establish, so the item cites the observation that proves it either way.
            evidenceIds: [...new Set(workflows.flatMap((entry) => entry.evidenceIds))],
          },
        ];
      },
    }),
  }),
  api: Object.freeze({
    requireResolvedMiddleware: Object.freeze({
      build: ({ observationsOf }) => {
        // One subject per route. A repository that declares no route has nothing for the
        // requirement to be about, so it is not measured — and it is certainly not passed.
        const routes = observationsOf("api", "api-route");
        if (routes.length === 0) return [];
        return routes.map((entry) => {
          const protection = entry.protection;
          const observed =
            protection === "protected"
              ? "middleware-resolved"
              : protection === "none-observed"
                ? "middleware-none-observed"
                : protection === "unresolved"
                  ? "middleware-unresolved"
                  : "route-protection-not-established";
          // Three answers, and the middle one is the only violation: a *resolved* middleware
          // state (including "nothing applies to this route") satisfies a requirement that the
          // middleware be established, an unresolved registration contradicts it, and a state
          // the graph never established is not measured at all.
          const status =
            protection === "protected" || protection === "none-observed"
              ? COMPLIANCE_STATUSES.PASS
              : protection === "unresolved"
                ? COMPLIANCE_STATUSES.VIOLATION
                : COMPLIANCE_STATUSES.UNKNOWN;
          return {
            subject: entry.route,
            observed,
            status,
            reason:
              status === COMPLIANCE_STATUSES.UNKNOWN
                ? COMPLIANCE_UNKNOWN_REASONS.DOMAIN_NOT_ESTABLISHED
                : null,
            detail: observed,
            basis: "middleware-graph-protection",
            evidenceIds: [...entry.evidenceIds],
          };
        });
      },
    }),
  }),
  dependencies: Object.freeze({
    requireLockfile: Object.freeze({
      requiresCompleteReading: true,
      build: ({ observationsOf }) => {
        const manifests = observationsOf("dependencies", "dependency-manifest");
        const lockfiles = observationsOf("dependencies", "dependency-lockfile");
        const lockedEcosystems = new Set(lockfiles.map((entry) => entry.ecosystem));
        return manifests
          .filter((entry) => entry.role === "manifest")
          .map((entry) => {
            const established = entry.status === "parsed";
            const locked = lockedEcosystems.has(entry.ecosystem);
            return {
              subject: entry.path,
              observed: !established
                ? "source-not-established"
                : locked
                  ? "lockfile-observed"
                  : "lockfile-not-observed",
              status: !established
                ? COMPLIANCE_STATUSES.UNKNOWN
                : locked
                  ? COMPLIANCE_STATUSES.PASS
                  : COMPLIANCE_STATUSES.VIOLATION,
              reason: established ? null : COMPLIANCE_UNKNOWN_REASONS.DOMAIN_NOT_ESTABLISHED,
              detail: entry.path,
              basis: "dependency-source-role",
              evidenceIds: [...entry.evidenceIds],
            };
          });
      },
    }),
    allowMultipleManagers: Object.freeze({
      build: ({ observationsOf }) => {
        const ecosystems = observationsOf("dependencies", "dependency-ecosystem");
        // "At most one ecosystem" constrains the ecosystems that exist. A repository that
        // declares none declares no dependency manager at all, so there is nothing to measure —
        // and reporting it as a single ecosystem would be a statement the repository contradicts.
        if (ecosystems.length === 0) return [];
        const multiple = ecosystems.length > 1;
        return [
          {
            subject: null,
            observed: multiple ? "ecosystems-multiple" : "ecosystems-single",
            status: multiple ? COMPLIANCE_STATUSES.VIOLATION : COMPLIANCE_STATUSES.PASS,
            basis: "dependency-ecosystem-census",
            evidenceIds: [...new Set(ecosystems.flatMap((entry) => entry.evidenceIds))],
          },
        ];
      },
    }),
  }),
  architecture: Object.freeze({
    requireConnectedEntrypoints: Object.freeze({
      requiresCompleteReading: true,
      build: ({ observationsOf }) => {
        // One subject per entrypoint-shaped file. A repository that declares none has nothing
        // for the requirement to range over, so it abstains instead of passing.
        const entrypoints = observationsOf("architecture", "architecture-entrypoint");
        if (entrypoints.length === 0) return [];
        const isolated = new Set(
          observationsOf("architecture", "architecture-isolated-file").map((entry) => entry.path),
        );
        return entrypoints.map((entry) => {
          const disconnected = isolated.has(entry.path);
          return {
            subject: entry.path,
            observed: disconnected ? "entrypoint-disconnected" : "entrypoint-connected",
            status: disconnected ? COMPLIANCE_STATUSES.VIOLATION : COMPLIANCE_STATUSES.PASS,
            basis: "import-graph-connectivity",
            evidenceIds: [...entry.evidenceIds],
          };
        });
      },
    }),
  }),
});

/**
 * The subjects of a release-workflow requirement.
 *
 * One subject per release-shaped workflow, because the requirement is about *each* release path:
 * "a release workflow with no test workflow beside it". A repository that declares no release
 * workflow declares no release path, so there is no subject and the key is unmeasured — reported
 * by `measure` as `compliance-no-subject-to-measure`, never as a satisfied requirement.
 *
 * The `workflow-purpose-not-established` case is the one place where an unclassified name changes
 * an answer: `ci.yml` may be the release path *and* the test pipeline, so neither "there is no
 * release workflow" nor "this release workflow has no test workflow" is established, and the key
 * is `unknown` rather than a pass or a violation.
 *
 * @param {Function} observationsOf
 * @param {string} purpose `test` or `lint`.
 * @returns {object[]}
 */
function workflowSubjects(observationsOf, purpose) {
  const workflows = observationsOf("ci", "ci-workflow");
  const releases = workflows.filter((entry) => entry.purpose === "release");
  const matched = workflows.filter((entry) => entry.purpose === purpose);
  const unclassified = workflows.filter((entry) => entry.purpose === "unclassified");

  if (releases.length === 0) {
    // "This repository declares no release workflow" is only a fact about the names that state
    // a purpose, so an unclassified name withholds it: `ci.yml` may be the release path — and a
    // release workflow that does not exist cannot be required to have a test workflow beside it.
    if (unclassified.length > 0) {
      return [
        {
          subject: null,
          observed: "workflow-purpose-not-established",
          status: COMPLIANCE_STATUSES.UNKNOWN,
          reason: COMPLIANCE_UNKNOWN_REASONS.WORKFLOW_PURPOSE_NOT_ESTABLISHED,
          detail: null,
          basis: "workflow-name",
          evidenceIds: [...new Set(unclassified.flatMap((entry) => entry.evidenceIds))],
        },
      ];
    }
    return [];
  }

  return releases.map((entry) => {
    if (matched.length > 0) {
      return {
        subject: entry.path,
        observed: `${purpose}-workflow-observed`,
        status: COMPLIANCE_STATUSES.PASS,
        basis: "workflow-name",
        evidenceIds: [...new Set(matched.flatMap((workflow) => workflow.evidenceIds))],
      };
    }
    if (unclassified.length > 0) {
      return {
        subject: entry.path,
        observed: "workflow-purpose-not-established",
        status: COMPLIANCE_STATUSES.UNKNOWN,
        reason: COMPLIANCE_UNKNOWN_REASONS.WORKFLOW_PURPOSE_NOT_ESTABLISHED,
        detail: entry.path,
        basis: "workflow-name",
        evidenceIds: [...new Set(unclassified.flatMap((workflow) => workflow.evidenceIds))],
      };
    }
    return {
      subject: entry.path,
      observed: `${purpose}-workflow-not-observed`,
      status: COMPLIANCE_STATUSES.VIOLATION,
      basis: "workflow-name",
      evidenceIds: [...entry.evidenceIds],
    };
  });
}

/** The read statuses the report may encounter, re-exported for tests and validation. */
export const COMPLIANCE_POLICY_READ_STATUSES = POLICY_READ_STATUSES;

/** The document schema, re-exported so a consumer reads one source for the policy's shape. */
export const COMPLIANCE_POLICY_SCHEMA = POLICY_DOCUMENT_SCHEMA;
