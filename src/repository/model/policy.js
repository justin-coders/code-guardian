/**
 * Code Guardian — Repository Policy (Phase 22)
 *
 * The model's first *declared* input. Every phase before this one answered "what does the
 * repository contain?"; this module answers "what does the repository **require of itself**?"
 *
 * The answer is one document, `.codeguardian/policy.json`, and it is translated into the model
 * as facts about the reading — where it was looked for, whether it was read, which domains it
 * declares, and which observation proves it — never as a verdict. `model.policy` carries no
 * judgment at all: whether a requirement is *satisfied* is the compliance report's question, and
 * that question needs the repository facts, the graphs and this document together.
 *
 * ### The vocabulary is re-declared, not imported
 *
 * The acquisition layer owns the JSON schema and the reasons it refuses a document; the model
 * owns the shape of what it publishes. This module therefore *restates* the domains, the schema,
 * the read statuses and the refusal reasons rather than importing them, exactly as the Dockerfile
 * structure vocabulary is restated, so the model depends on no scanner module. The two lists are
 * pinned together by a test, so a rename on either side fails the suite instead of silently
 * retiring a value.
 *
 * ### Malformed policy never enters the model
 *
 * A document that could not be parsed, or that the schema refuses, produces **no** document in
 * the model: `state` is `unknown`, one bounded reason says why, and `document` is `null`. The
 * alternative — publishing the parsed-but-invalid value and leaving each consumer to notice —
 * would make every compliance answer depend on a validation each consumer has to remember to
 * redo. A refusal is also never a *finding*: a malformed policy is a failure of this model, not
 * a defect in the repository's engineering.
 *
 * ### Five states, and only two of them are an answer
 *
 *   established  a document was read, parsed and satisfied the schema
 *   absent       the repository declares no policy, and the scan covered the repository
 *   unsupported  a policy document exists in a format this build does not read
 *   unknown      a document exists but could not be interpreted, or the scan could not look
 *   truncated    the scan itself stopped early, so absence cannot be established
 *
 * `established` and `absent` are the two states that answer "what does this repository
 * declare?" — including "nothing". `unsupported`, `unknown` and `truncated` are three different
 * ways of having no answer, and none of them may be read as "no policy": that is the distinction
 * the whole phase rests on, because a compliance rule must abstain over every one of them.
 */

import {
  DEFAULT_PRESET_REGISTRY,
  POLICY_PRESET_VERSION,
  POLICY_RESOLUTION_FAILURES,
  resolvePolicyDocument,
} from "../../policy/index.js";

import { EVIDENCE_SUBJECTS } from "./evidence.js";
import { evidenceId } from "./identity.js";

/** Version of the policy area's contract. */
export const POLICY_VERSION = "1";

/**
 * The one policy document version this model resolves, restated from the acquisition layer.
 *
 * Phase 23 pins it here as well because the model now *derives* an effective policy from the
 * declared one: a document whose version this build does not resolve produces no effective policy
 * at all, so the constant is part of the model's own contract and not only the reader's.
 */
export const POLICY_DOCUMENT_VERSION = POLICY_PRESET_VERSION;

/**
 * The document-level fields a policy may state beside its domains, in canonical order.
 *
 * They are metadata about the *document* — which version of the contract it speaks and which preset
 * it starts from — never settings, so nothing here becomes a compliance requirement. They sit
 * before the domains in the canonical order the acquisition layer rebuilds.
 */
export const POLICY_DOCUMENT_METADATA_KEYS = Object.freeze(["version", "preset"]);

/** The one metadata key that names a preset. */
export const POLICY_DOCUMENT_PRESET_KEY = "preset";

/** Producer recorded in the model's metadata for this area. */
export const POLICY_BUILDER = "phase-22-repository-policy";

/** The one path this build reads a policy from. */
export const POLICY_DOCUMENT_PATH = ".codeguardian/policy.json";

/** The six policy domains, in the order the model declares them. */
export const POLICY_DOMAINS = Object.freeze([
  "environment",
  "container",
  "ci",
  "api",
  "dependencies",
  "architecture",
]);

/**
 * The closed schema, restated from the acquisition layer.
 *
 * Six domains; within each, exactly the keys listed, each `boolean` except one `integer`. The
 * model needs the schema in two places — to validate a document it is handed and to decide
 * whether a domain *declares* a requirement at all — and in both it must refuse anything the
 * acquisition could not have produced.
 */
export const POLICY_DOCUMENT_SCHEMA = Object.freeze({
  environment: Object.freeze({
    requireTemplate: "boolean",
    allowMultipleTemplates: "boolean",
  }),
  container: Object.freeze({
    requireHealthcheck: "boolean",
  }),
  ci: Object.freeze({
    requireTestsForRelease: "boolean",
    requireLintForRelease: "boolean",
    maxReleaseWorkflows: "integer",
  }),
  api: Object.freeze({
    requireResolvedMiddleware: "boolean",
  }),
  dependencies: Object.freeze({
    requireLockfile: "boolean",
    allowMultipleManagers: "boolean",
  }),
  architecture: Object.freeze({
    requireConnectedEntrypoints: "boolean",
  }),
});

/** The keys each domain declares, in schema order. */
export const POLICY_DOCUMENT_KEYS = Object.freeze(
  POLICY_DOMAINS.reduce((accumulator, domain) => {
    accumulator[domain] = Object.freeze(Object.keys(POLICY_DOCUMENT_SCHEMA[domain]));
    return accumulator;
  }, {}),
);

/** The largest accepted `maxReleaseWorkflows`, restated with the schema. */
export const MAX_RELEASE_WORKFLOWS = 1000;

/** What the acquisition established about the document. */
export const POLICY_READ_STATUSES = Object.freeze({
  ABSENT: "absent",
  PARSED: "parsed",
  FAILED: "failed",
  UNSUPPORTED: "unsupported",
});

/** The read status vocabulary as a list, for validation. */
export const POLICY_READ_STATUS_VALUES = Object.freeze(Object.values(POLICY_READ_STATUSES));

/** Why a document was observed and not interpreted, restated from the acquisition layer. */
export const POLICY_READ_FAILURE_REASONS = Object.freeze([
  "read-failed",
  "too-large",
  "not-text",
  "invalid-json",
  "not-an-object",
  "unknown-domain",
  "unknown-key",
  "wrong-type",
  "out-of-range",
  // Phase 23 — the document states a version this build does not resolve. Restated from the
  // acquisition layer like every other refusal, and pinned to it by a test.
  "unsupported-version",
]);

/** Why a document this build does not read was recorded as unsupported. */
export const POLICY_READ_UNSUPPORTED_REASONS = Object.freeze(["policy-format-not-interpreted"]);

/**
 * The area's own state vocabulary.
 *
 * Five values, and the naming is deliberately not the report vocabulary's: a *report* is
 * complete or partial, whereas a policy *area* is an answer or not. Two of these are answers.
 */
export const POLICY_STATES = Object.freeze({
  ESTABLISHED: "established",
  ABSENT: "absent",
  UNSUPPORTED: "unsupported",
  UNKNOWN: "unknown",
  TRUNCATED: "truncated",
});

/** The state vocabulary as a list, for validation. */
export const POLICY_STATE_VALUES = Object.freeze(Object.values(POLICY_STATES));

/** The states that answer "what does this repository declare?". */
export const POLICY_ANSWERED_STATES = Object.freeze([
  POLICY_STATES.ESTABLISHED,
  POLICY_STATES.ABSENT,
]);

/**
 * Whether a state is an answer.
 *
 * @param {string} state
 * @returns {boolean}
 */
export function isEstablishedPolicyState(state) {
  return POLICY_ANSWERED_STATES.includes(state);
}

/**
 * Why the policy area has no answer. Closed vocabulary.
 *
 * Each reason is about the *reading*: nothing here says a policy is wrong, only that this build
 * could not establish what it says.
 */
export const POLICY_UNKNOWN_REASONS = Object.freeze({
  DOCUMENT_NOT_INTERPRETED: "policy-document-not-interpreted",
  FORMAT_NOT_INTERPRETED: "policy-document-format-not-interpreted",
  PRESET_NOT_ESTABLISHED: "policy-preset-not-established",
  VERSION_NOT_SUPPORTED: "policy-version-not-supported",
  PATH_IGNORED: "policy-path-ignored",
  PATH_UNREADABLE: "policy-path-unreadable",
  COVERAGE_NOT_COMPLETE: "policy-coverage-not-complete",
  SCAN_TRUNCATED: "repository-scan-truncated",
});

/** The unknown-reason vocabulary as a list, for validation. */
export const POLICY_UNKNOWN_REASON_VALUES = Object.freeze(
  Object.values(POLICY_UNKNOWN_REASONS),
);

/** Bounds on what the area retains. */
export const POLICY_LIMITS = Object.freeze({
  maxDomains: POLICY_DOMAINS.length,
  maxKeysPerDomain: Math.max(
    ...POLICY_DOMAINS.map((domain) => POLICY_DOCUMENT_KEYS[domain].length),
  ),
  maxDetailLength: 48,
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

/** The evidence id of the policy document's own observation. */
export function policyDocumentEvidenceId(path) {
  return evidenceId(EVIDENCE_SUBJECTS.POLICY, `policy-document:${path}`);
}

/** The domains a document declares, in the declared order. */
export function policyDocumentDomains(document) {
  if (!isPlainObject(document)) return [];
  return POLICY_DOMAINS.filter((domain) => isPlainObject(document[domain]));
}

/** How many settings a document states. */
export function policyDocumentSettingCount(document) {
  let total = 0;
  for (const domain of policyDocumentDomains(document)) {
    total += Object.keys(document[domain]).length;
  }
  return total;
}

/**
 * The reason a failed read is published under.
 *
 * The acquisition's own failure reason is *carried* in `detail` rather than widened into this
 * vocabulary: which of the nine refusals happened is a fact about the document, and flattening
 * nine causes into one word would lose the only thing a repository author needs in order to fix
 * it. Both fields are closed, bounded tokens, so nothing free-text travels here.
 *
 * @param {string|null} reason
 * @returns {string}
 */
function unknownReasonForFailure(reason) {
  if (reason === "read-failed") return POLICY_UNKNOWN_REASONS.PATH_UNREADABLE;
  return POLICY_UNKNOWN_REASONS.DOCUMENT_NOT_INTERPRETED;
}

/** The preset a declared document names, or `null` when it names none. */
export function policyDocumentPresetName(document) {
  if (!isPlainObject(document)) return null;
  const preset = document[POLICY_DOCUMENT_PRESET_KEY];
  return typeof preset === "string" && preset !== "" ? preset : null;
}

/**
 * The reading reason a resolution failure is published under.
 *
 * A declared document that names a preset this build does not hold establishes **nothing**: the
 * whole document is refused, not merely the preset. The alternative — applying the domains the
 * document happened to state and quietly dropping the preset — would measure the repository
 * against a policy it never declared, which is the one thing a policy reading must never do. The
 * refusal is carried as a reading reason, so no consumer has to remember to check for it.
 */
const RESOLUTION_UNKNOWN_REASONS = Object.freeze({
  [POLICY_RESOLUTION_FAILURES.PRESET_NOT_ESTABLISHED]:
    POLICY_UNKNOWN_REASONS.PRESET_NOT_ESTABLISHED,
  [POLICY_RESOLUTION_FAILURES.VERSION_NOT_SUPPORTED]: POLICY_UNKNOWN_REASONS.VERSION_NOT_SUPPORTED,
  [POLICY_RESOLUTION_FAILURES.DOCUMENT_NOT_INTERPRETED]:
    POLICY_UNKNOWN_REASONS.DOCUMENT_NOT_INTERPRETED,
});

/**
 * Build the model's policy area.
 *
 * The reading is resolved in one place, in a fixed order, so no combination of scan state and
 * document state can produce two answers:
 *
 *   1. a validated document            → `established`, whatever the scan's own completeness
 *      was: the document was read in full, and a truncated *inventory* says nothing about it
 *   2. a document in an unread format  → `unsupported`
 *   3. a document that refused to parse→ `unknown`, with the acquisition's reason as `detail`
 *   4. the policy path ignored         → `unknown`: the file may exist and this scan did not look
 *   5. the policy path unreadable      → `unknown`
 *   6. the scan was truncated          → `truncated`: absence cannot be established
 *   7. the scan did not complete       → `unknown`: an ignored or unreadable path elsewhere
 *      could have been the policy document
 *   8. otherwise                       → `absent`: the repository declares no policy
 *
 * Steps 4–7 are why this is a *reading* state rather than a boolean: "no policy" is only a fact
 * when the scan could have seen one, and every case where it could not is named.
 *
 * ### Phase 23 — the declared document is resolved before it is published
 *
 * A parsed document is no longer published as-is. It is handed to the preset resolver, which merges
 * the preset it names (if any) with the values the repository stated and returns an *effective*
 * policy plus a per-key provenance. `document` is that effective document — so the compliance engine
 * below receives exactly what it always did, and is not aware that presets exist — while `declared`
 * keeps the repository-authored document, `preset` names the built-in preset that was applied and
 * `provenance` says, for every key, whether the repository or the preset stated it. A document that
 * names a preset this build does not hold establishes nothing at all: the effective document is
 * `null` and the reason is `policy-preset-not-established`.
 *
 * @param {object} input
 * @param {object|null} input.policy The projected policy record from the entity layer.
 * @param {object} input.scan The model-shaped scan state (`complete`, `truncated`, `coverage`).
 * @param {object} [input.registry] The preset registry to resolve against.
 * @returns {object} A deeply frozen policy area.
 */
export function buildPolicyArea({ policy, scan, registry = DEFAULT_PRESET_REGISTRY }) {
  const observed = isPlainObject(policy) ? policy : {};
  const path = typeof observed.path === "string" ? observed.path : POLICY_DOCUMENT_PATH;
  const status = POLICY_READ_STATUS_VALUES.includes(observed.status)
    ? observed.status
    : POLICY_READ_STATUSES.ABSENT;
  const reason = typeof observed.reason === "string" ? observed.reason : null;
  const detail = typeof observed.detail === "string" ? observed.detail : null;
  const parsed =
    status === POLICY_READ_STATUSES.PARSED && isPlainObject(observed.document)
      ? observed.document
      : null;

  const ignoredPaths = (scan?.coverage?.ignored?.paths ?? [])
    .map((entry) => entry.path)
    .filter((value) => typeof value === "string");
  const unreadablePaths = (scan?.coverage?.unreadable?.paths ?? [])
    .map((entry) => entry.path)
    .filter((value) => typeof value === "string");
  const scanTruncated = scan?.truncated === true;
  const scanComplete = scan?.complete === true && scanTruncated !== true;

  const evidenceIds = Array.isArray(observed.evidenceIds)
    ? [...observed.evidenceIds].sort()
    : [];

  // Phase 23 — resolve the declared document into the effective policy this model measures. The
  // resolution is a pure function of the two in-memory values, so it has no failure mode the
  // reading does not already name.
  let declared = null;
  let document = null;
  let provenance = null;
  let preset = null;
  let resolutionReason = null;
  let resolutionDetail = null;
  if (parsed !== null) {
    const resolution = resolvePolicyDocument({ document: parsed, registry });
    if (resolution.ok) {
      declared = resolution.declared;
      document = resolution.effective;
      provenance = resolution.provenance;
      preset = resolution.preset;
    } else {
      resolutionReason =
        RESOLUTION_UNKNOWN_REASONS[resolution.reason] ??
        POLICY_UNKNOWN_REASONS.PRESET_NOT_ESTABLISHED;
      resolutionDetail = resolution.detail;
    }
  }

  let state;
  let unknownReason = null;
  let unknownDetail = null;

  if (document !== null) {
    state = POLICY_STATES.ESTABLISHED;
  } else if (resolutionReason !== null) {
    // A document was read, but this build could not turn it into a policy it can measure — most
    // often because it names a preset the registry does not hold. It establishes nothing, and says
    // exactly that, rather than publishing a partly-applied policy.
    state = POLICY_STATES.UNKNOWN;
    unknownReason = resolutionReason;
    unknownDetail = resolutionDetail;
  } else if (status === POLICY_READ_STATUSES.UNSUPPORTED) {
    state = POLICY_STATES.UNSUPPORTED;
    unknownReason = POLICY_UNKNOWN_REASONS.FORMAT_NOT_INTERPRETED;
    unknownDetail = detail;
  } else if (status === POLICY_READ_STATUSES.FAILED) {
    state = POLICY_STATES.UNKNOWN;
    unknownReason = unknownReasonForFailure(reason);
    unknownDetail = reason;
  } else if (ignoredPaths.includes(path)) {
    state = POLICY_STATES.UNKNOWN;
    unknownReason = POLICY_UNKNOWN_REASONS.PATH_IGNORED;
  } else if (unreadablePaths.includes(path)) {
    state = POLICY_STATES.UNKNOWN;
    unknownReason = POLICY_UNKNOWN_REASONS.PATH_UNREADABLE;
  } else if (scanTruncated) {
    state = POLICY_STATES.TRUNCATED;
    unknownReason = POLICY_UNKNOWN_REASONS.SCAN_TRUNCATED;
  } else if (!scanComplete) {
    state = POLICY_STATES.UNKNOWN;
    unknownReason = POLICY_UNKNOWN_REASONS.COVERAGE_NOT_COMPLETE;
  } else {
    state = POLICY_STATES.ABSENT;
  }

  const domains = policyDocumentDomains(document);
  const settings = policyDocumentSettingCount(document);
  const answered = isEstablishedPolicyState(state);

  const area = {
    // Whether the contracted path was observed at all — not whether it was understood.
    detected: observed.detected === true,
    // Whether this model established what the repository declares, *including* that it declares
    // nothing. A consumer that needs "there is a document" reads `state === established`.
    established: answered,
    state,
    // The effective policy the compliance engine measures against: the preset's values with the
    // repository's own values applied on top.
    document,
    // The repository-authored document — version, preset and the domains it stated — or `null` when
    // nothing was resolved. Carried so "what was declared" and "what is required" stay distinct.
    declared,
    // The built-in preset that was applied, or `null` when the document named none.
    preset,
    // Where every effective value came from. Null exactly when there is no effective document.
    provenance,
    coverage: {
      state,
      established: answered,
      // The reading's own completeness, which is not the scan's: a document read in full is a
      // complete answer even when the inventory that found it stopped early.
      complete: state === POLICY_STATES.ESTABLISHED || state === POLICY_STATES.ABSENT,
      inspected: observed.inspected === true,
      truncated: state === POLICY_STATES.TRUNCATED,
      path,
      reason: unknownReason,
      detail: unknownDetail,
      domains,
      settings,
      evidenceIds,
      limits: { ...POLICY_LIMITS },
    },
  };

  return deepFreeze(area);
}

/**
 * The empty area a contracted model skeleton carries.
 *
 * It is the same shape and the same `unknown` state as a reading that established nothing, which
 * is what the query layer's `null` distinguishes: no area at all means this model says nothing
 * about repository policy.
 */
export function emptyPolicyArea() {
  return buildPolicyArea({ policy: null, scan: { complete: false, truncated: false } });
}
