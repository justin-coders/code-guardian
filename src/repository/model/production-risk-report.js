/**
 * Code Guardian — Production Risk Report (Phase 21)
 *
 * The first evidence-backed production **risk** auditor. Phase 20's ProductionReport
 * inventories what a repository states across six domains; this projection states the
 * **production conditions** those same facts prove — and, where the repository's own
 * declaration proves one, a defect — and it states them the only way this architecture
 * allows:
 *
 * > What repository evidence proves this?
 *
 * Never "this is probably insecure". A finding is not an assessment; it is a small record
 * whose every sentence is a restatement of an observation the model already carries, whose
 * provenance is a list of evidence ids the model already validated, and whose severity comes
 * from a closed table rather than from a heuristic or a comparison against anything.
 *
 * ### A defect is claimed only where the repository's own declaration proves one
 *
 * The load-bearing distinction of this projection: a structural condition is not a defect
 * until something the architecture already states makes it one. Every kind therefore carries a
 * **classification** from a closed table, because the two halves of that test are separate
 * questions:
 *
 *   risk         the repository's own declaration cannot hold inside the repository it
 *                describes — a service naming a Dockerfile the repository does not contain
 *                while the container reading was complete, or a build declaration the
 *                supported declaration contract cannot resolve at all. The declaration
 *                contradicts the repository's own contents, so no policy is needed to call it
 *                a defect.
 *   observation  the repository's evidence establishes the condition and **no** policy
 *                contract in the model makes it required: a Dockerfile whose own instructions
 *                declare no `HEALTHCHECK`, a release-shaped workflow name with no test-shaped
 *                name beside it, a manifest with no lockfile, `main.js` with no import
 *                relationship. These are facts about what the repository states; this build
 *                does not invent the missing policy that would make them violations.
 *
 * A finding is a *risk* only when both halves hold, so an absence this build can prove is
 * still an observation, and a recommendation follows only from a proven defect: a
 * policy-dependent condition states its fact and recommends nothing. Presence in the
 * repository is never evidence of a policy — a condition that resembles common practice is
 * still only an observation until the model states otherwise.
 *
 * ### It derives from the inventory report, and never re-reads
 *
 * The six domains, the observations behind each finding and the coverage states all come
 * from the ProductionReport the builder already produced — the same sections a consumer can
 * read through `productionSection`. Three graph projections are read directly, for facts the
 * inventory report deliberately does not carry: the middleware graph (which middleware a
 * route's declaration could not establish), the api graph (which file declares a route) and
 * the architecture and import graphs (how a module's files relate to the rest). Nothing here
 * opens a file, parses source, resolves a module, runs a container, starts a process,
 * contacts a network or a registry, consults a vulnerability database, reads a clock or
 * consults the environment.
 *
 * ### Absence is never inferred from an incomplete reading
 *
 * The load-bearing rule of this phase, and the reason this file is longer than it looks:
 * a finding that states a *gap by absence* — no environment template exists, no workflow
 * name states a test purpose, no lockfile was observed, a service names a Dockerfile the
 * inventory does not contain, nothing in the import graph relates
 * this file — is only emitted while the reading behind it was complete. When the inventory
 * section was partial (an ignored path, an unparsed source, an unclassified workflow, an
 * incomplete graph, a bound that bit) the corresponding detection is **withheld** and the
 * section records why, naming the detection it could not make. A finding that states a
 * *present* fact — this Dockerfile declares no `HEALTHCHECK`, this declaration resolved to a
 * path the classifier could not resolve, this route's middleware was not established —
 * needs only the record that proves it, because it claims nothing about what the repository
 * does not have.
 *
 * ### No score, no grade, no percentage, no traffic light, no verdict
 *
 * There is no aggregate anywhere in this module: findings are not summed into a number, no
 * finding is compared with another, there is no readiness percentage and no pass/fail state.
 * `severity` describes the certainty of the *defect* and nothing else, and it is a closed word
 * assigned per finding *kind* by a documented table — `info` for an observation that claims no
 * defect, `medium` for a defect the repository's own declaration proves, `low` reserved for a
 * defect whose proof would be weaker than the declaration itself — and it is never computed.
 * `confidence` is likewise a closed word (`declared`, `absent`, `name-derived`,
 * `graph-derived`) naming *how* the fact was established, not how strongly anyone believes
 * it. `coverage.severities` is a census of the records the report contains, which is a count
 * of findings and not a score.
 *
 * ### Every sentence is a pure function of the record
 *
 * `renderRiskStatement(kind, finding)` and `renderRiskRemediation(kind, finding)` produce the
 * finding's prose from its own structured fields, and the model contract recomputes both and
 * rejects a report whose prose disagrees with its data. A remediation is stated only when the
 * evidence implies one — the mirror of the gap: a missing named counterpart, a duplicated
 * declaration, a declaration naming a file that does not exist, a declaration that cannot
 * resolve inside the repository. Where the gap is about *what this build could establish*
 * rather than about a declaration the repository should change, the remediation is `null` and
 * nothing is recommended.
 */

import { IMPORT_GRAPH_EDGE_TYPES, IMPORT_GRAPH_STATES } from "./import-graph.js";
import { ARCHITECTURE_EDGE_TYPES } from "./architecture-graph.js";
import { MIDDLEWARE_PROTECTION_STATES } from "./middleware-graph.js";
import {
  CI_PURPOSES,
  ENVIRONMENT_CLASSES,
  PRODUCTION_REPORT_STATES,
  PRODUCTION_SECTIONS,
  PRODUCTION_SECTION_TITLES,
  isEstablishedProductionState,
} from "./production-report.js";

/** Version of the risk report contract. */
export const PRODUCTION_RISK_REPORT_VERSION = "1";

/** Producer recorded in the model's metadata for this projection. */
export const PRODUCTION_RISK_REPORT_BUILDER = "phase-21-production-risk-report";

/** The six audit domains, in the order the report declares them. */
export const PRODUCTION_RISK_SECTIONS = PRODUCTION_SECTIONS;

/** Human-readable section labels. One word longer than the inventory report's on purpose. */
export const PRODUCTION_RISK_SECTION_TITLES = Object.freeze({
  environment: "Environment configuration gaps",
  container: "Container configuration gaps",
  ci: "CI configuration gaps",
  api: "API protection gaps",
  dependencies: "Dependency hygiene gaps",
  architecture: "Architecture integrity gaps",
});

/** The coverage states. The same five-way vocabulary every accepted graph uses. */
export const PRODUCTION_RISK_STATES = PRODUCTION_REPORT_STATES;

/** The coverage-state vocabulary as a list, for validation. */
export const PRODUCTION_RISK_STATE_VALUES = Object.freeze(Object.values(PRODUCTION_RISK_STATES));

/**
 * The severity vocabulary. Three closed words, never `high`, never `critical`.
 *
 * `severity` describes one thing only: how certain this build is that the condition it states
 * is a **defect**. It is assigned per finding *kind* by `PRODUCTION_RISK_SEVERITY_BY_KIND` and
 * is never derived from a count, a ratio, a comparison, an estimate, or a resemblance to common
 * practice. The three words mean three strengths of statement, documented once, here:
 *
 *   info    no defect is claimed. The repository's evidence establishes the condition — an
 *           instruction its own Dockerfile does not declare, a workflow name with no
 *           counterpart name beside it, a manifest with no lockfile, a file no import edge
 *           relates — and nothing in the architecture makes it required, so it is a
 *           *structural observation* rather than a violation
 *   low     deliberately unassigned in this phase: a defect whose proof would be weaker than
 *           the repository's own declaration, resting for instance on a reading-level
 *           assumption rather than on the declaration itself. No kind sits here, the word is
 *           kept in the closed vocabulary on purpose, and a rule can neither raise nor lower a
 *           severity
 *   medium  a defect the repository's own declaration proves. The declaration cannot hold
 *           inside the repository it describes, so the contradiction is in the repository's own
 *           terms and needs no policy, no threat model and no runtime observation
 *
 * Only `PRODUCTION_RISK_CLASSIFICATION_BY_KIND` decides whether a kind may claim a defect at
 * all; this table decides only how certain that claim is, and the validator requires the two to
 * agree.
 */
export const PRODUCTION_RISK_SEVERITIES = Object.freeze({
  INFO: "info",
  LOW: "low",
  MEDIUM: "medium",
});

/** The severity vocabulary as a list, for validation. */
export const PRODUCTION_RISK_SEVERITY_VALUES = Object.freeze(
  Object.values(PRODUCTION_RISK_SEVERITIES),
);

/**
 * The classification vocabulary: whether a finding claims a defect at all.
 *
 * Two closed words, and the distinction is the correction this phase carries:
 *
 *   risk         the repository's own declaration cannot hold inside the repository it
 *                describes, so repository facts alone prove the defect
 *   observation  the repository's evidence establishes the condition, and no policy contract
 *                in the model makes it required, so no defect is claimed
 *
 * A finding may claim a defect only when *both* halves of the test hold: the evidence
 * establishes the condition, **and** something the architecture already states makes the
 * condition wrong. The second half is never supplied by this build. Where a policy would be
 * needed — a healthcheck must be declared, a release path must have a test path, a manifest
 * must be locked, an entrypoint must be imported — the finding is an observation, and the
 * missing policy is not invented to promote it.
 */
export const PRODUCTION_RISK_CLASSIFICATIONS = Object.freeze({
  RISK: "risk",
  OBSERVATION: "observation",
});

/** The classification vocabulary as a list, for validation. */
export const PRODUCTION_RISK_CLASSIFICATION_VALUES = Object.freeze(
  Object.values(PRODUCTION_RISK_CLASSIFICATIONS),
);

/**
 * Classification per kind: the table that decides whether a defect may be claimed.
 *
 * Two of the twenty-two kinds are `risk`, and both are Compose *declarations* that contradict
 * the repository's own contents under the supported declaration contract: a build naming a
 * Dockerfile the repository does not contain while the container reading was complete, and a
 * build declaration the classifier could not resolve inside the repository at all. Each is a
 * statement the repository makes about itself that its own contents do not satisfy, so no
 * external policy is required to call it wrong.
 *
 * Every other kind is an `observation`. Each states a condition the repository's evidence
 * establishes — an instruction a Dockerfile does not declare, a workflow name with no
 * counterpart name beside it, a manifest with no lockfile, a route whose middleware this build
 * could not establish, a file no import edge relates — and no contract in this architecture
 * makes any of them required. Calling them defects would mean inventing a policy, which this
 * report refuses to do; calling them facts is exactly what it does.
 *
 * The list is a decision, written out rather than computed from severity, and the validator
 * rejects a finding whose classification disagrees with its kind or whose severity claims a
 * defect its classification does not.
 */
export const PRODUCTION_RISK_CLASSIFICATION_BY_KIND = Object.freeze({
  "environment-file-without-template": PRODUCTION_RISK_CLASSIFICATIONS.OBSERVATION,
  "environment-template-class-duplicated": PRODUCTION_RISK_CLASSIFICATIONS.OBSERVATION,
  "environment-template-classes-conflict": PRODUCTION_RISK_CLASSIFICATIONS.OBSERVATION,
  "environment-configuration-without-sample": PRODUCTION_RISK_CLASSIFICATIONS.OBSERVATION,
  "container-healthcheck-missing": PRODUCTION_RISK_CLASSIFICATIONS.OBSERVATION,
  "container-compose-dockerfile-not-observed": PRODUCTION_RISK_CLASSIFICATIONS.RISK,
  "container-compose-build-context-unresolved": PRODUCTION_RISK_CLASSIFICATIONS.RISK,
  "container-service-image-without-build": PRODUCTION_RISK_CLASSIFICATIONS.OBSERVATION,
  "ci-release-without-test": PRODUCTION_RISK_CLASSIFICATIONS.OBSERVATION,
  "ci-release-without-lint": PRODUCTION_RISK_CLASSIFICATIONS.OBSERVATION,
  "ci-workflows-unclassified": PRODUCTION_RISK_CLASSIFICATIONS.OBSERVATION,
  "ci-release-workflows-multiple": PRODUCTION_RISK_CLASSIFICATIONS.OBSERVATION,
  "api-route-protection-unresolved": PRODUCTION_RISK_CLASSIFICATIONS.OBSERVATION,
  "api-protected-route-partially-unresolved": PRODUCTION_RISK_CLASSIFICATIONS.OBSERVATION,
  "api-router-inheritance-incomplete": PRODUCTION_RISK_CLASSIFICATIONS.OBSERVATION,
  "dependency-manifest-without-lockfile": PRODUCTION_RISK_CLASSIFICATIONS.OBSERVATION,
  "dependency-lockfile-without-manifest": PRODUCTION_RISK_CLASSIFICATIONS.OBSERVATION,
  "dependency-ecosystems-multiple": PRODUCTION_RISK_CLASSIFICATIONS.OBSERVATION,
  "dependency-source-unresolved": PRODUCTION_RISK_CLASSIFICATIONS.OBSERVATION,
  "architecture-entrypoint-disconnected": PRODUCTION_RISK_CLASSIFICATIONS.OBSERVATION,
  "architecture-isolated-cluster": PRODUCTION_RISK_CLASSIFICATIONS.OBSERVATION,
  "architecture-module-unconnected": PRODUCTION_RISK_CLASSIFICATIONS.OBSERVATION,
});

/**
 * The confidence vocabulary: how the fact behind a finding was established.
 *
 * Four closed words, and none of them is a number. They describe the *shape* of the evidence,
 * which is the only thing this build can honestly say about it:
 *
 *   declared      the repository's own declaration states the gap, and the declaration was
 *                 read (a Dockerfile's instructions, a Compose build declaration, a service's
 *                 `image:` key, a dependency source's own status)
 *   absent        the gap *is* an absence, and it is reported only over a reading that
 *                 finished (no template for a live environment file, no lockfile beside a
 *                 manifest, no workflow name stating a purpose)
 *   name-derived  the fact rests on the artifact's own file name and on nothing else (a
 *                 template class, a workflow's purpose)
 *   graph-derived the fact is read from an accepted graph's own record (a route's protection
 *                 state, an unresolved middleware registration, an import relationship)
 */
export const PRODUCTION_RISK_CONFIDENCES = Object.freeze({
  DECLARED: "declared",
  ABSENT: "absent",
  NAME_DERIVED: "name-derived",
  GRAPH_DERIVED: "graph-derived",
});

/** The confidence vocabulary as a list, for validation. */
export const PRODUCTION_RISK_CONFIDENCE_VALUES = Object.freeze(
  Object.values(PRODUCTION_RISK_CONFIDENCES),
);

/**
 * The finding kinds each section may produce.
 *
 * Closed per section, exactly as the inventory report's observation kinds are: a kind a
 * section did not declare is a contract mismatch, and the validator rejects it. The list is
 * the phase's own detection list, one kind per detection, and nothing else is detected.
 */
export const PRODUCTION_RISK_FINDING_KINDS = Object.freeze({
  environment: Object.freeze([
    "environment-file-without-template",
    "environment-template-class-duplicated",
    "environment-template-classes-conflict",
    "environment-configuration-without-sample",
  ]),
  container: Object.freeze([
    "container-healthcheck-missing",
    "container-compose-dockerfile-not-observed",
    "container-compose-build-context-unresolved",
    "container-service-image-without-build",
  ]),
  ci: Object.freeze([
    "ci-release-without-test",
    "ci-release-without-lint",
    "ci-workflows-unclassified",
    "ci-release-workflows-multiple",
  ]),
  api: Object.freeze([
    "api-route-protection-unresolved",
    "api-protected-route-partially-unresolved",
    "api-router-inheritance-incomplete",
  ]),
  dependencies: Object.freeze([
    "dependency-manifest-without-lockfile",
    "dependency-lockfile-without-manifest",
    "dependency-ecosystems-multiple",
    "dependency-source-unresolved",
  ]),
  architecture: Object.freeze([
    "architecture-entrypoint-disconnected",
    "architecture-isolated-cluster",
    "architecture-module-unconnected",
  ]),
});

/**
 * Severity per kind: the table the phase requires, declared once and never computed.
 *
 * Every value is one of `PRODUCTION_RISK_SEVERITIES`, every kind has exactly one, and the
 * validator rejects a finding whose severity disagrees with its kind, whose severity claims a
 * defect its classification does not, or whose classification cannot support its severity. A
 * rule cannot raise or lower a severity, and no severity is `high` or `critical` in this
 * phase: two kinds are `medium` — the two Compose declarations that cannot hold — and every
 * other kind is `info`, because a condition the repository's own evidence establishes and no
 * policy contract makes wrong is an observation, not a defect.
 */
export const PRODUCTION_RISK_SEVERITY_BY_KIND = Object.freeze({
  "environment-file-without-template": PRODUCTION_RISK_SEVERITIES.INFO,
  "environment-template-class-duplicated": PRODUCTION_RISK_SEVERITIES.INFO,
  "environment-template-classes-conflict": PRODUCTION_RISK_SEVERITIES.INFO,
  "environment-configuration-without-sample": PRODUCTION_RISK_SEVERITIES.INFO,
  "container-healthcheck-missing": PRODUCTION_RISK_SEVERITIES.INFO,
  "container-compose-dockerfile-not-observed": PRODUCTION_RISK_SEVERITIES.MEDIUM,
  "container-compose-build-context-unresolved": PRODUCTION_RISK_SEVERITIES.MEDIUM,
  "container-service-image-without-build": PRODUCTION_RISK_SEVERITIES.INFO,
  "ci-release-without-test": PRODUCTION_RISK_SEVERITIES.INFO,
  "ci-release-without-lint": PRODUCTION_RISK_SEVERITIES.INFO,
  "ci-workflows-unclassified": PRODUCTION_RISK_SEVERITIES.INFO,
  "ci-release-workflows-multiple": PRODUCTION_RISK_SEVERITIES.INFO,
  "api-route-protection-unresolved": PRODUCTION_RISK_SEVERITIES.INFO,
  "api-protected-route-partially-unresolved": PRODUCTION_RISK_SEVERITIES.INFO,
  "api-router-inheritance-incomplete": PRODUCTION_RISK_SEVERITIES.INFO,
  "dependency-manifest-without-lockfile": PRODUCTION_RISK_SEVERITIES.INFO,
  "dependency-lockfile-without-manifest": PRODUCTION_RISK_SEVERITIES.INFO,
  "dependency-ecosystems-multiple": PRODUCTION_RISK_SEVERITIES.INFO,
  "dependency-source-unresolved": PRODUCTION_RISK_SEVERITIES.INFO,
  "architecture-entrypoint-disconnected": PRODUCTION_RISK_SEVERITIES.INFO,
  "architecture-isolated-cluster": PRODUCTION_RISK_SEVERITIES.INFO,
  "architecture-module-unconnected": PRODUCTION_RISK_SEVERITIES.INFO,
});

/**
 * Confidence per kind: the second closed table, assigned for the same reason severity is.
 */
export const PRODUCTION_RISK_CONFIDENCE_BY_KIND = Object.freeze({
  "environment-file-without-template": PRODUCTION_RISK_CONFIDENCES.ABSENT,
  "environment-template-class-duplicated": PRODUCTION_RISK_CONFIDENCES.NAME_DERIVED,
  "environment-template-classes-conflict": PRODUCTION_RISK_CONFIDENCES.NAME_DERIVED,
  "environment-configuration-without-sample": PRODUCTION_RISK_CONFIDENCES.ABSENT,
  "container-healthcheck-missing": PRODUCTION_RISK_CONFIDENCES.DECLARED,
  "container-compose-dockerfile-not-observed": PRODUCTION_RISK_CONFIDENCES.DECLARED,
  "container-compose-build-context-unresolved": PRODUCTION_RISK_CONFIDENCES.DECLARED,
  "container-service-image-without-build": PRODUCTION_RISK_CONFIDENCES.DECLARED,
  "ci-release-without-test": PRODUCTION_RISK_CONFIDENCES.NAME_DERIVED,
  "ci-release-without-lint": PRODUCTION_RISK_CONFIDENCES.NAME_DERIVED,
  "ci-workflows-unclassified": PRODUCTION_RISK_CONFIDENCES.NAME_DERIVED,
  "ci-release-workflows-multiple": PRODUCTION_RISK_CONFIDENCES.NAME_DERIVED,
  "api-route-protection-unresolved": PRODUCTION_RISK_CONFIDENCES.GRAPH_DERIVED,
  "api-protected-route-partially-unresolved": PRODUCTION_RISK_CONFIDENCES.GRAPH_DERIVED,
  "api-router-inheritance-incomplete": PRODUCTION_RISK_CONFIDENCES.GRAPH_DERIVED,
  "dependency-manifest-without-lockfile": PRODUCTION_RISK_CONFIDENCES.ABSENT,
  "dependency-lockfile-without-manifest": PRODUCTION_RISK_CONFIDENCES.ABSENT,
  "dependency-ecosystems-multiple": PRODUCTION_RISK_CONFIDENCES.DECLARED,
  "dependency-source-unresolved": PRODUCTION_RISK_CONFIDENCES.DECLARED,
  "architecture-entrypoint-disconnected": PRODUCTION_RISK_CONFIDENCES.GRAPH_DERIVED,
  "architecture-isolated-cluster": PRODUCTION_RISK_CONFIDENCES.GRAPH_DERIVED,
  "architecture-module-unconnected": PRODUCTION_RISK_CONFIDENCES.GRAPH_DERIVED,
});

/**
 * The deterministic basis per kind: a bounded token naming what was read.
 *
 * It is the answer to "what proves this?" in one word — `dockerfile-instructions`,
 * `compose-build-declaration`, `workflow-name-table` — and the validator rejects a finding
 * whose basis disagrees with its kind, so the field can never drift into free text.
 */
export const PRODUCTION_RISK_BASIS_BY_KIND = Object.freeze({
  "environment-file-without-template": "environment-name-table",
  "environment-template-class-duplicated": "duplicate-name-class",
  "environment-template-classes-conflict": "conflicting-name-class",
  "environment-configuration-without-sample": "environment-name-table",
  "container-healthcheck-missing": "dockerfile-instructions",
  "container-compose-dockerfile-not-observed": "compose-build-declaration",
  "container-compose-build-context-unresolved": "compose-declaration-classification",
  "container-service-image-without-build": "compose-service-key",
  "ci-release-without-test": "workflow-name-table",
  "ci-release-without-lint": "workflow-name-table",
  "ci-workflows-unclassified": "workflow-name-table",
  "ci-release-workflows-multiple": "workflow-name-table",
  "api-route-protection-unresolved": "middleware-graph-protection",
  "api-protected-route-partially-unresolved": "middleware-graph-protection",
  "api-router-inheritance-incomplete": "middleware-graph-unresolved-scope",
  "dependency-manifest-without-lockfile": "dependency-source-role",
  "dependency-lockfile-without-manifest": "dependency-source-role",
  "dependency-ecosystems-multiple": "dependency-ecosystem-census",
  "dependency-source-unresolved": "dependency-source-status",
  "architecture-entrypoint-disconnected": "import-graph-isolation",
  "architecture-isolated-cluster": "import-graph-isolation",
  "architecture-module-unconnected": "import-graph-module-connectivity",
});

/**
 * The reasons each section may abstain with, beyond the inventory report's own.
 *
 * A risk section carries the inventory section's abstentions verbatim — the knowledge gaps
 * are the same gaps — and may add exactly these: that a detection was withheld because the
 * reading behind it was not complete, that the model carries no report to derive from, that a
 * finding had to be dropped because its provenance was not in the model, or that a bound bit.
 * Every phrase is about knowledge, never about quality.
 */
export const PRODUCTION_RISK_UNKNOWN_REASONS = Object.freeze({
  environment: Object.freeze([
    "production-report-not-established",
    "environment-coverage-not-complete",
    "risk-finding-without-evidence",
    "risk-findings-truncated",
  ]),
  container: Object.freeze([
    "production-report-not-established",
    "container-coverage-not-complete",
    "risk-finding-without-evidence",
    "risk-findings-truncated",
  ]),
  ci: Object.freeze([
    "production-report-not-established",
    "ci-coverage-not-complete",
    "workflow-purpose-not-established",
    "risk-finding-without-evidence",
    "risk-findings-truncated",
  ]),
  api: Object.freeze([
    "production-report-not-established",
    "middleware-graph-not-established",
    "risk-finding-without-evidence",
    "risk-findings-truncated",
  ]),
  dependencies: Object.freeze([
    "production-report-not-established",
    "dependency-coverage-not-complete",
    "risk-finding-without-evidence",
    "risk-findings-truncated",
  ]),
  architecture: Object.freeze([
    "production-report-not-established",
    "architecture-coverage-not-complete",
    "risk-finding-without-evidence",
    "risk-findings-truncated",
  ]),
});

/** The risk-specific reasons the section genuinely has no interpretation basis for. */
export const PRODUCTION_RISK_UNSUPPORTED_REASONS = Object.freeze({
  environment: Object.freeze([]),
  container: Object.freeze([]),
  ci: Object.freeze([]),
  api: Object.freeze(["api-framework-not-interpreted", "api-source-not-interpreted"]),
  dependencies: Object.freeze(["dependency-format-not-interpreted"]),
  architecture: Object.freeze([]),
});

/**
 * The receiver scope a route's *inherited* middleware is registered under.
 *
 * Exported so the pack's test pins it against the middleware graph's own scope vocabulary — a
 * rename on either side must fail the suite rather than quietly retiring the third API
 * detection below.
 */
export const PRODUCTION_RISK_ROUTER_SCOPE = "router";

/** Hard bounds on one risk report. */
export const PRODUCTION_RISK_REPORT_LIMITS = Object.freeze({
  /** Findings retained per section. */
  maxFindingsPerSection: 200,
  /** Abstention records retained per section. */
  maxUnknownReasonsPerSection: 32,
  /** Evidence ids cited by one finding. */
  maxEvidencePerFinding: 16,
  /** Paths listed inside one finding. */
  maxPathsPerFinding: 16,
  /** Characters in one rendered remediation. */
  maxRemediationLength: 240,
});

/** A parenthesised list of backticked values, bounded by the caller. */
function list(values) {
  return values.length === 0 ? "" : ` (${values.map((value) => `\`${value}\``).join(", ")})`;
}

/** A count with a singular/plural noun. */
function count(value, noun) {
  return `${value} ${noun}${value === 1 ? "" : "s"}`;
}

/** Sort a list of strings, unique. */
function sortedUnique(values) {
  return [...new Set(values)].sort();
}

/** Sort by a list of keys, so no two records compare equal. */
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

/** Freeze a value and everything reachable from it. */
function deepFreeze(value) {
  if (value === null || typeof value !== "object" || Object.isFrozen(value)) return value;
  Object.freeze(value);
  for (const key of Object.keys(value)) deepFreeze(value[key]);
  return value;
}

/** Build one abstention record. */
function abstention(reason, detail, countValue) {
  return { reason, detail: detail ?? null, count: countValue };
}

/** Merge abstention records that share a `(reason, detail)` pair, and sort them. */
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

/** Whether a value is a plain object. */
function isPlainObject(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Cap a list of paths, reporting whether the cap bit. */
function boundedPaths(paths) {
  const sorted = sortedUnique(paths);
  return {
    paths: sorted.slice(0, PRODUCTION_RISK_REPORT_LIMITS.maxPathsPerFinding),
    pathsTruncated: sorted.length > PRODUCTION_RISK_REPORT_LIMITS.maxPathsPerFinding,
  };
}

/**
 * The clause every statement ends with, and the reason the clause is a constant.
 *
 * Whether a finding claims a defect is a property of its *kind*, not of its fields, so the
 * sentence that says so is one of exactly two sentences rather than per-kind prose: a reader
 * who never looks at the record still cannot read a structural observation as a violation, and
 * the validator recomputes the whole sentence either way. Neither clause names a consequence, a
 * likelihood, a severity word or a runtime state, because none of those is established.
 */
const RISK_CLAUSE =
  "This is a defect, not a policy preference: the repository's own declaration cannot hold inside the repository it describes.";

const OBSERVATION_CLAUSE =
  "This is a structural observation, not a defect: no policy contract in this model states that this condition is required.";

/**
 * The prose of a finding, rendered from its own record. Pure, total, and validated.
 *
 * The fact is rendered from the finding's own fields and the clause that says whether it is a
 * defect is appended from its kind's own table, so a finding cannot be worded as a defect while
 * its kind is an observation, or the other way round.
 */
export function renderRiskStatement(kind, finding) {
  const clause =
    PRODUCTION_RISK_CLASSIFICATION_BY_KIND[kind] === PRODUCTION_RISK_CLASSIFICATIONS.RISK
      ? RISK_CLAUSE
      : OBSERVATION_CLAUSE;
  return `${renderRiskObservation(kind, finding)} ${clause}`;
}

/** The fact one finding states, without the clause that says whether it is a defect. */
function renderRiskObservation(kind, finding) {
  const paths = Array.isArray(finding.paths) ? finding.paths : [];
  const more = finding.pathsTruncated === true ? " and more" : "";
  const path = typeof finding.path === "string" ? finding.path : null;

  switch (kind) {
    case "environment-file-without-template":
      return `The scan observed ${count(finding.count, "live environment file")}${list(paths)}${more} and no example or template file. No environment file is opened, so which keys it holds is not established, and the repository states no template for it.`;

    case "environment-template-class-duplicated":
      return `${count(finding.count, "file")} state the same \`${finding.class}\` template class${list(paths)}${more}. Which of them is authoritative is not established; no environment file is opened.`;

    case "environment-template-classes-conflict":
      return `The environment template is stated in more than one naming class${list(finding.classes ?? [])}, naming ${count(finding.count, "file")}${list(paths)}${more}. Neither class is established as canonical; no environment file is opened.`;

    case "environment-configuration-without-sample":
      return `The scan observed ${count(finding.count, "environment artifact")}${list(paths)}${more} and no sample configuration file. Which class the repository uses to state the configuration's shape is not established.`;

    case "container-healthcheck-missing":
      return `\`${path}\` declares no \`HEALTHCHECK\` instruction and does not disable one, read from its own instructions: ${count(finding.instructions, "instruction")} examined. Whether the image it builds is healthy at runtime is not established.`;

    case "container-compose-dockerfile-not-observed":
      return `\`${finding.source}\` declares that service \`${finding.service}\` builds \`${path}\`, and the inventory contains no such file, so the build names a Dockerfile this repository does not contain.`;

    case "container-compose-build-context-unresolved":
      return `\`${path}\` states ${count(finding.count, "build declaration")} this build could not resolve inside the repository (\`${finding.detail}\`), so the build they describe does not hold as written. The declaration's text is not carried.`;

    case "container-service-image-without-build":
      return `\`${finding.source}\` declares service \`${finding.service}\` with an \`image:\` reference and no build context, so which Dockerfile produced the image it runs is not established. The reference itself is not carried into the model.`;

    case "ci-release-without-test":
      return `${count(finding.count, "workflow file name")}${list(paths)}${more} states a release purpose, and no workflow file name states a test purpose, so the repository states a release path with no test-shaped pipeline named beside it. Only file names are read.`;

    case "ci-release-without-lint":
      return `${count(finding.count, "workflow file name")}${list(paths)}${more} states a release purpose, and no workflow file name states a lint purpose. Only file names are read, so whether anything lints inside another workflow is not established.`;

    case "ci-workflows-unclassified":
      return `The repository declares ${count(finding.count, "workflow file")}${list(paths)}${more} and none of their names states a release, lint or test purpose, so what each pipeline runs is not established by its name.`;

    case "ci-release-workflows-multiple":
      return `${count(finding.count, "workflow file name")}${list(paths)}${more} states a release purpose, so the repository names more than one release path. Which of them gates a release is not established.`;

    case "api-route-protection-unresolved":
      return `The route \`${finding.method} ${finding.path}\` is declared in ${list(paths)}${more}, and the middleware graph established no middleware for it while recording ${count(finding.unresolved, "middleware-shaped occurrence")} it could not establish, so its structural protection is \`unresolved\`. Whether anything protects it at runtime is not established.`;

    case "api-protected-route-partially-unresolved":
      return `The route \`${finding.method} ${finding.path}\` is declared in ${list(paths)}${more}; the middleware graph established ${count(finding.middleware, "middleware identity")} for it and recorded ${count(finding.unresolved, "occurrence")} it could not establish, so its protection state is \`protected\` while the identity of part of it is not established.`;

    case "api-router-inheritance-incomplete":
      return `The route \`${finding.method} ${finding.path}\` is declared in ${list(paths)}${more}, where the middleware graph recorded ${count(finding.unresolved, "router-scope registration")} it could not establish, so what the route inherits through that file's router is not established.`;

    case "dependency-manifest-without-lockfile":
      return `Ecosystem \`${finding.ecosystem}\` states ${count(finding.count, "manifest")}${list(paths)}${more} and no lockfile, so which versions the declared dependencies resolve to is not established.`;

    case "dependency-lockfile-without-manifest":
      return `Ecosystem \`${finding.ecosystem}\` states ${count(finding.count, "lockfile")}${list(paths)}${more} and no manifest, so the dependency set the lockfile resolves is not declared beside it.`;

    case "dependency-ecosystems-multiple":
      return `The repository declares dependencies in ${count(finding.count, "ecosystem")}${list(paths)}${more}. Whether each is maintained by its own toolchain is not established.`;

    case "dependency-source-unresolved":
      return `\`${path}\` was observed as a dependency source in ecosystem \`${finding.ecosystem}\` and read as \`${finding.status}\`${finding.reason === null ? "" : ` (\`${finding.reason}\`)`}, so what it declares is not established by this build. This is a statement about the source's format, not about the dependency.`;

    case "architecture-entrypoint-disconnected":
      return `\`${path}\` is entrypoint-shaped by its own file name, and the import graph establishes no import relationship for it: nothing imports it and it imports nothing, so nothing in the repository states how it is reached.`;

    case "architecture-isolated-cluster":
      return `${count(finding.count, "module file")} under \`${finding.directory}\`${list(paths)}${more} neither import nor are imported, so the established import graph relates none of them to the rest of the repository.`;

    case "architecture-module-unconnected":
      return `The container \`${finding.container}\` holds ${count(finding.manifests, "manifest")}${list(paths)}${more} and carries ${count(finding.moduleFiles, "module file")} the import graph knows about, none of which any import edge touches, so nothing in the repository states how the container relates to the rest.`;

    default:
      // Unreachable for a report this build produced (the validator rejects an undeclared
      // kind), but total on purpose: a kind this function cannot describe must not produce a
      // silent empty string.
      return `The report records a ${kind} finding in this domain.`;
  }
}

/**
 * The remediation a finding implies, rendered from its own record, or `null`.
 *
 * `null` is the common case and it is a statement, not an omission: a remediation follows only
 * from a **defect**, because a recommendation is a claim about what the repository should
 * state. Every observation therefore recommends nothing — a healthcheck the Dockerfile does not
 * declare, a release name with no test name beside it, a manifest with no lockfile, a
 * middleware identity this build could not resolve, a dependency source in a format it does not
 * interpret, an entrypoint nothing imports, a service running a prebuilt image, more than one
 * ecosystem, a workflow whose name states no purpose — because no policy here requires the
 * change that advice would presuppose. Where the finding *is* a defect, the remediation is the
 * correction the repository's own declaration implies and nothing wider.
 */
export function renderRiskRemediation(kind, finding) {
  const path = typeof finding.path === "string" ? finding.path : null;
  switch (kind) {
    case "container-compose-dockerfile-not-observed":
      return `Add \`${path}\`, or correct the declaration that names it.`;
    case "container-compose-build-context-unresolved":
      return "Point the declaration at a context and Dockerfile inside the repository.";
    default:
      return null;
  }
}

/**
 * One finding record, with its vocabulary fields filled from the tables above.
 *
 * The caller supplies the kind, the deterministic key and the evidence; everything else that
 * is a *contract* value (classification, severity, confidence, basis) and everything that is
 * *prose* (statement, remediation) is derived here, so a finding cannot be built that
 * disagrees with the tables or with its own data.
 */
function findingFor(section, kind, fields) {
  const record = { section, kind, key: fields.key, ...fields };
  record.severity = PRODUCTION_RISK_SEVERITY_BY_KIND[kind];
  record.classification = PRODUCTION_RISK_CLASSIFICATION_BY_KIND[kind];
  record.confidence = PRODUCTION_RISK_CONFIDENCE_BY_KIND[kind];
  record.basis = PRODUCTION_RISK_BASIS_BY_KIND[kind];
  record.id = `${section}:${kind}:${fields.key}`;
  record.statement = renderRiskStatement(kind, record);
  record.remediation = renderRiskRemediation(kind, record);
  return record;
}

/**
 * Build one section from already-built parts.
 *
 * Bounds are applied in one place, so no section can forget one: findings are sorted by key,
 * cut to `maxFindingsPerSection` with the cut recorded both in the section's coverage and as
 * an abstention; the section's evidence list is the union of its findings' citations; the
 * abstentions are merged, sorted and cut.
 *
 * The state is derived from four questions in a fixed order — a bound that bit, whether this
 * implementation interprets the domain, whether the section established an answer at all,
 * whether every input it reads was read in full — and `established` is derived from the state
 * rather than taken on trust, so the two can never disagree.
 */
function assembleRiskSection({
  name,
  findings,
  unknown,
  supported,
  established,
  complete,
  inventoryTruncated,
}) {
  const sorted = [...findings].sort(compareByKeys(["key"]));
  const capped = sorted.length > PRODUCTION_RISK_REPORT_LIMITS.maxFindingsPerSection;
  const retained = capped
    ? sorted.slice(0, PRODUCTION_RISK_REPORT_LIMITS.maxFindingsPerSection)
    : sorted;

  const records = mergeAbstentions(
    capped
      ? [...unknown, abstention("risk-findings-truncated", null, sorted.length - retained.length)]
      : unknown,
  );
  const unknownTruncated = records.length > PRODUCTION_RISK_REPORT_LIMITS.maxUnknownReasonsPerSection;
  const unknownRecords = unknownTruncated
    ? records.slice(0, PRODUCTION_RISK_REPORT_LIMITS.maxUnknownReasonsPerSection)
    : records;

  const truncated = capped || unknownTruncated || inventoryTruncated === true;
  const state = truncated
    ? PRODUCTION_RISK_STATES.TRUNCATED
    : !supported
      ? PRODUCTION_RISK_STATES.UNSUPPORTED
      : !established
        ? PRODUCTION_RISK_STATES.UNKNOWN
        : complete
          ? PRODUCTION_RISK_STATES.COMPLETE
          : PRODUCTION_RISK_STATES.PARTIAL;
  const answered = isEstablishedProductionState(state);

  const byKind = {};
  for (const kind of [...new Set(retained.map((entry) => entry.kind))].sort()) {
    byKind[kind] = retained.filter((entry) => entry.kind === kind).length;
  }
  const bySeverity = {
    [PRODUCTION_RISK_SEVERITIES.INFO]: retained.filter(
      (entry) => entry.severity === PRODUCTION_RISK_SEVERITIES.INFO,
    ).length,
    [PRODUCTION_RISK_SEVERITIES.LOW]: retained.filter(
      (entry) => entry.severity === PRODUCTION_RISK_SEVERITIES.LOW,
    ).length,
    [PRODUCTION_RISK_SEVERITIES.MEDIUM]: retained.filter(
      (entry) => entry.severity === PRODUCTION_RISK_SEVERITIES.MEDIUM,
    ).length,
  };

  const evidenceIds = sortedUnique(retained.flatMap((entry) => entry.evidenceIds));

  return {
    name,
    title: PRODUCTION_RISK_SECTION_TITLES[name],
    state,
    established: answered,
    counts: {
      findings: retained.length,
      byKind,
      bySeverity,
    },
    findings: retained,
    evidenceIds,
    unknown: unknownRecords,
    coverage: {
      state,
      established: answered,
      findings: retained.length,
      evidence: evidenceIds.length,
      truncated,
      unknownReasons: unknownRecords.length,
    },
  };
}

/**
 * The citation helper.
 *
 * An id the model does not carry is dropped, never invented. A finding left with no citation
 * is withheld and recorded, because a statement the model cannot prove must not be reported —
 * the phase's central rule, enforced at the one place a finding is built.
 */
function createCitation(existingIds) {
  return function cite(...ids) {
    return sortedUnique(ids.filter((id) => typeof id === "string" && existingIds.has(id))).slice(
      0,
      PRODUCTION_RISK_REPORT_LIMITS.maxEvidencePerFinding,
    );
  };
}

/** The evidence ids behind a list of inventory observations. */
function evidenceOf(observations) {
  return observations.flatMap((entry) => entry.evidenceIds ?? []);
}

/** The inventory observations of one kind. */
function observationsOf(section, kind) {
  return section.observations.filter((entry) => entry.kind === kind);
}

// ─── Environment configuration ───────────────────────────────────────────────

/**
 * Environment configuration.
 *
 * Three of the four detections rest on *absence* — no example or template beside a live
 * environment file, no sample configuration class, no second naming class — so all three are
 * emitted only while the environment section's reading was complete. A path an ignore policy
 * excluded is the case that matters most: `.env` is the canonical gitignored name, so a scan
 * that did not look at it cannot say whether a live file exists, and the section abstains
 * with the inventory report's own `environment-configuration-ignored` instead of reporting an
 * absence it did not establish.
 *
 * All four are `observations`. A file named `.env` is not a declaration that its keys must be
 * documented, a second `.env`sibling is not a declaration that one is canonical, and no
 * contract in this model states that an environment configuration must have a sample — so each
 * of them states a naming fact the scan established and claims no defect.
 */
function detectEnvironmentRisks({ section, cite, complete }) {
  const findings = [];
  const unknown = [];
  let withheld = 0;
  const evidence = (observations) => cite(...evidenceOf(observations));

  const files = observationsOf(section, ENVIRONMENT_CLASSES.FILE);
  const examples = observationsOf(section, ENVIRONMENT_CLASSES.EXAMPLE);
  const templates = observationsOf(section, ENVIRONMENT_CLASSES.TEMPLATE);
  const samples = observationsOf(section, ENVIRONMENT_CLASSES.SAMPLE);
  const duplicates = observationsOf(section, "environment-template-duplicate");

  // Record-based: one finding per duplicated class, straight from the inventory's own
  // duplicate observation.
  for (const duplicate of duplicates) {
    const cited = cite(...(duplicate.evidenceIds ?? []));
    if (cited.length === 0) {
      withheld += 1;
      continue;
    }
    const bounded = boundedPaths(duplicate.paths ?? []);
    findings.push(
      findingFor("environment", "environment-template-class-duplicated", {
        key: `duplicate:${duplicate.class}`,
        class: duplicate.class,
        count: duplicate.count ?? bounded.paths.length,
        ...bounded,
        evidenceIds: cited,
      }),
    );
  }

  // Record-based as well, but it depends on how the *classified* set reads: two classes hold
  // files while samples do not exist. It is withheld only when its own citations are missing.
  if (examples.length > 0 && templates.length > 0) {
    const cited = evidence([...examples, ...templates]);
    if (cited.length === 0) withheld += 1;
    else {
      const bounded = boundedPaths([...examples, ...templates].map((entry) => entry.path));
      findings.push(
        findingFor("environment", "environment-template-classes-conflict", {
          key: "template-classes-conflict",
          classes: [ENVIRONMENT_CLASSES.EXAMPLE, ENVIRONMENT_CLASSES.TEMPLATE],
          count: examples.length + templates.length,
          ...bounded,
          evidenceIds: cited,
        }),
      );
    }
  }

  if (!complete) {
    // Every remaining detection is an absence claim, so none of them is made.
    for (const kind of [
      "environment-file-without-template",
      "environment-configuration-without-sample",
    ]) {
      unknown.push(abstention("environment-coverage-not-complete", kind, 1));
    }
    return { findings, unknown, withheld };
  }

  if (files.length > 0 && examples.length === 0 && templates.length === 0) {
    const cited = evidence(files);
    if (cited.length === 0) withheld += 1;
    else {
      const bounded = boundedPaths(files.map((entry) => entry.path));
      findings.push(
        findingFor("environment", "environment-file-without-template", {
          key: "file-without-template",
          count: files.length,
          ...bounded,
          evidenceIds: cited,
        }),
      );
    }
  }

  if (examples.length + templates.length + files.length > 0 && samples.length === 0) {
    const cited = evidence([...files, ...examples, ...templates]);
    if (cited.length === 0) withheld += 1;
    else {
      const bounded = boundedPaths(
        [...files, ...examples, ...templates].map((entry) => entry.path),
      );
      findings.push(
        findingFor("environment", "environment-configuration-without-sample", {
          key: "configuration-without-sample",
          count: files.length + examples.length + templates.length,
          ...bounded,
          evidenceIds: cited,
        }),
      );
    }
  }

  return { findings, unknown, withheld };
}

// ─── Container configuration ─────────────────────────────────────────────────

/**
 * Container configuration.
 *
 * Two of the four detections are `risks`, and the reason is narrow: a Compose file's own
 * declaration cannot hold inside the repository that contains it. A service whose `build:` names
 * a Dockerfile the inventory does not contain, while the container reading was complete, states
 * a file that does not exist; a build declaration the classifier could not resolve inside the
 * repository states a build that cannot take place there. Both contradict the repository's own
 * contents, so neither needs a policy, a threat model or a runtime observation to be called a
 * defect, and both are `medium`.
 *
 * The other two are `observations`, and the difference is stated rather than implied:
 *
 *   - a parsed Dockerfile that declares no `HEALTHCHECK` and does not disable one proved that
 *     absence itself, instruction by instruction — and nothing in this architecture states that
 *     a healthcheck is required, nor can this build observe whether the image it builds is
 *     healthy at runtime;
 *   - a service that states an `image:` key and no `build:` states it in its own keys, and
 *     whether a prebuilt image is adequate is neither declared nor observable here.
 *
 * The Dockerfile-not-observed detection is the one that reads like a present fact and is not:
 * "the inventory contains no such file" is a claim about what the repository does **not** have,
 * so it is made only while the container reading was complete. When it was not — an incomplete
 * scan, a cut-short inventory, a definition whose instructions could not be read, a Compose file
 * whose declarations could not be established — the detection is withheld and the section says
 * which one it could not make with `container-coverage-not-complete`.
 *
 * A Dockerfile whose instructions could **not** be read is deliberately absent from the
 * findings: the inventory report already abstains with `dockerfile-structure-not-established`,
 * and an unread definition is not an unhealthy one.
 */
function detectContainerRisks({ section, cite, complete, unobservedDeclarations, imageDeclarations, unestablishedComposeSources }) {
  const findings = [];
  const unknown = [];
  let withheld = 0;

  for (const structure of observationsOf(section, "container-structure")) {
    if (structure.healthcheck !== false || structure.healthcheckDisabled === true) continue;
    const cited = cite(...(structure.evidenceIds ?? []));
    if (cited.length === 0) {
      withheld += 1;
      continue;
    }
    findings.push(
      findingFor("container", "container-healthcheck-missing", {
        key: `healthcheck-missing:${structure.path}`,
        path: structure.path,
        instructions: structure.instructions,
        evidenceIds: cited,
      }),
    );
  }

  // The registry of Compose files this build read, so a declaration is attributed to a file
  // the model observed and nothing else.
  const composeObservations = new Map(
    observationsOf(section, "container-composition").map((entry) => [entry.path, entry]),
  );

  // The one detection here that states an absence: the repository does not contain the file the
  // declaration names. It is reportable only over a reading that finished, so an incomplete
  // container reading withholds it and names it.
  const unobserved = unobservedDeclarations ?? [];
  if (unobserved.length > 0 && !complete) {
    unknown.push(
      abstention(
        "container-coverage-not-complete",
        "container-compose-dockerfile-not-observed",
        1,
      ),
    );
  }

  for (const declaration of complete ? unobserved : []) {
    const cited = cite(...(declaration.evidenceIds ?? []), ...(composeObservations.get(declaration.source)?.evidenceIds ?? []));
    if (cited.length === 0) {
      withheld += 1;
      continue;
    }
    findings.push(
      findingFor("container", "container-compose-dockerfile-not-observed", {
        key: `dockerfile-not-observed:${declaration.source}|${declaration.service}|${declaration.path}`,
        source: declaration.source,
        service: declaration.service,
        path: declaration.path,
        evidenceIds: cited,
      }),
    );
  }

  // One finding per Compose file, per classification: the classifier's own reason says which
  // defect it is, and a file cannot state the same defect twice with one meaning.
  const unresolvedBySource = new Map();
  for (const source of unestablishedComposeSources ?? []) {
    const detail = typeof source.detail === "string" ? source.detail : null;
    if (!COMPOSE_DECLARATION_DEFECTS.includes(detail)) continue;
    const list = unresolvedBySource.get(source.path) ?? [];
    list.push(source);
    unresolvedBySource.set(source.path, list);
  }
  for (const [source, records] of [...unresolvedBySource.entries()].sort()) {
    const cited = cite(
      ...records.flatMap((record) => (record.evidenceId === null ? [] : [record.evidenceId])),
      ...(composeObservations.get(source)?.evidenceIds ?? []),
    );
    if (cited.length === 0) {
      withheld += 1;
      continue;
    }
    findings.push(
      findingFor("container", "container-compose-build-context-unresolved", {
        key: `build-context-unresolved:${source}`,
        path: source,
        detail: records[0].detail,
        count: records.length,
        evidenceIds: cited,
      }),
    );
  }

  for (const image of imageDeclarations ?? []) {
    if (image.build === true) continue;
    const cited = cite(...(image.evidenceIds ?? []), ...(composeObservations.get(image.source)?.evidenceIds ?? []));
    if (cited.length === 0) {
      withheld += 1;
      continue;
    }
    findings.push(
      findingFor("container", "container-service-image-without-build", {
        key: `image-without-build:${image.source}|${image.service}`,
        source: image.source,
        service: image.service,
        evidenceIds: cited,
      }),
    );
  }

  // A Compose file whose declarations are not established is carried as an abstention by the
  // inventory report already; it is repeated here so a consumer reading only the risk report
  // sees that this domain's build statements are bounded by it. The build-context finding
  // itself needs no completeness: a declaration the classifier could not resolve inside the
  // repository states its own defect, whatever else the scan did or could not do.
  const unreadable = (unestablishedComposeSources ?? []).filter(
    (source) => !COMPOSE_DECLARATION_DEFECTS.includes(source.detail ?? null),
  ).length;
  if (unreadable > 0) {
    unknown.push(abstention("compose-build-declarations-not-established", null, unreadable));
  }

  return { findings, unknown, withheld };
}

/**
 * The classifier details that name a defect in the *repository's* declaration, as opposed to
 * a limit of this build.
 *
 * `context-outside-repository` and `dockerfile-outside-repository` are declarations this build
 * cannot check against the repository; `dockerfile-outside-context` is a build the container
 * runtime itself refuses, so treating it as anything other than a defect would be wrong. The
 * other unparsed reasons — a file that could not be read, was too large, was not text, or
 * exhausted the budget — are limits of this build, and they are abstentions, never findings.
 */
const COMPOSE_DECLARATION_DEFECTS = Object.freeze([
  "context-outside-repository",
  "dockerfile-outside-repository",
  "dockerfile-outside-context",
]);

// ─── CI configuration ────────────────────────────────────────────────────────

/**
 * CI gaps.
 *
 * Three of the four detections are absence claims over the *classified* set of workflow file
 * names, so they are made only while two things hold: the CI section read the repository
 * completely, and **no workflow name is unclassified**. The second condition is the one that
 * matters — `ci.yml` and `build.yml` are deliberately unclassified by the inventory report, so
 * a repository whose only test workflow is named `ci.yml` would otherwise be reported as having
 * no test workflow, which is exactly the "this is probably bad" inference this phase forbids.
 * When an unclassified name exists, the section abstains with the inventory report's own
 * `workflow-purpose-not-established` and names the detection it could not make.
 *
 * "More than one release name" is the exception: it claims nothing about what is absent, so it
 * is made from the classified names alone, whatever else the scan did.
 *
 * All four are `observations`. A workflow's purpose is its file name and nothing else, and no
 * contract in this model binds one purpose to another: a release-shaped name is not a
 * declaration that a test- or lint-shaped workflow must exist, and nothing states that a
 * repository may name only one release path. Each detection therefore states the naming fact it
 * proved and claims no defect — an unclassified name beside a release name still withholds the
 * absence claims, because "no test workflow" cannot be said while `ci.yml` might be one.
 */
function detectCiRisks({ section, cite, complete }) {
  const findings = [];
  const unknown = [];
  let withheld = 0;

  const workflows = observationsOf(section, "ci-workflow");
  const byPurpose = (purpose) =>
    workflows.filter((entry) => entry.purpose === purpose).map((entry) => entry.path);
  const release = byPurpose(CI_PURPOSES.RELEASE);
  const test = byPurpose(CI_PURPOSES.TEST);
  const lint = byPurpose(CI_PURPOSES.LINT);
  const unclassified = byPurpose(CI_PURPOSES.UNCLASSIFIED);
  const releaseObservations = workflows.filter((entry) => entry.purpose === CI_PURPOSES.RELEASE);

  if (release.length >= 2) {
    const cited = cite(...evidenceOf(releaseObservations));
    if (cited.length === 0) withheld += 1;
    else {
      const bounded = boundedPaths(release);
      findings.push(
        findingFor("ci", "ci-release-workflows-multiple", {
          key: "release-workflows-multiple",
          count: release.length,
          ...bounded,
          evidenceIds: cited,
        }),
      );
    }
  }

  if (workflows.length > 0 && unclassified.length === workflows.length) {
    const observations = workflows.filter((entry) => entry.purpose === CI_PURPOSES.UNCLASSIFIED);
    const cited = cite(...evidenceOf(observations));
    if (cited.length === 0) withheld += 1;
    else {
      const bounded = boundedPaths(unclassified);
      findings.push(
        findingFor("ci", "ci-workflows-unclassified", {
          key: "workflows-unclassified",
          count: unclassified.length,
          ...bounded,
          evidenceIds: cited,
        }),
      );
    }
  }

  const absentPurposes = [
    {
      kind: "ci-release-without-test",
      present: release,
      presentObservations: releaseObservations,
      missing: test,
      noun: "test",
    },
    {
      kind: "ci-release-without-lint",
      present: release,
      presentObservations: releaseObservations,
      missing: lint,
      noun: "lint",
    },
  ];

  for (const detection of absentPurposes) {
    if (detection.present.length === 0 || detection.missing.length > 0) continue;
    if (!complete) {
      unknown.push(abstention("ci-coverage-not-complete", detection.kind, 1));
      continue;
    }
    if (unclassified.length > 0) {
      unknown.push(abstention("workflow-purpose-not-established", detection.kind, unclassified.length));
      continue;
    }
    const cited = cite(...evidenceOf(detection.presentObservations));
    if (cited.length === 0) {
      withheld += 1;
      continue;
    }
    const bounded = boundedPaths(detection.present);
    findings.push(
      findingFor("ci", detection.kind, {
        key: `${detection.noun}-missing`,
        count: detection.present.length,
        ...bounded,
        evidenceIds: cited,
      }),
    );
  }

  return { findings, unknown, withheld };
}

// ─── API protection ──────────────────────────────────────────────────────────

/**
 * API protection gaps.
 *
 * Three readings of the accepted graphs, and not one claim about security:
 *
 *   - a route whose middleware graph protection is `unresolved` — middleware-shaped
 *     occurrences were seen for it and none of their identities could be established;
 *   - a route whose protection is `protected` while some occurrence on it could **not** be
 *     established — the middleware graph records both, and reporting only the resolved part
 *     would present an incomplete identity set as a complete one;
 *   - a route declared in a file where a *router*-scope registration was not established, so
 *     whatever the route inherits through that file's router is not established.
 *
 * Missing authentication, weak authorization, administrative exposure, CORS policy and rate
 * limiting are **not** detected, and cannot be: this build has no policy, no threat model and
 * no runtime observation to compare a route against.
 *
 * Every finding here is a statement about a record the graph produced, so none of them needs
 * a complete reading; a graph that was not established at all withholds all three and says so.
 *
 * All three are `observations`. Each says what the middleware graph could and could not
 * establish — "this build could not resolve this route's protection" is a fact about the
 * reading, not about the route — and no contract in this model states that a route must have
 * resolvable middleware, so none of them is reported as a defect.
 */
function detectApiRisks({ section, cite, middlewareGraph, apiGraph, middlewareEstablished }) {
  const findings = [];
  const unknown = [];
  let withheld = 0;

  if (middlewareEstablished !== true) {
    unknown.push(abstention("middleware-graph-not-established", null, 1));
    return { findings, unknown, withheld };
  }

  // The api graph's own route nodes, for the two facts the report's observation deliberately
  // does not carry: which file declares the route, and which receivers its declaration bound.
  // The receivers matter for precision — an unresolved registration on a *different* receiver in
  // the same file is not part of this route's chain, and the file-scoped reading below says so
  // instead of attributing it to the route.
  const declarationByRoute = new Map();
  for (const node of apiGraph?.nodes ?? []) {
    if (typeof node?.id !== "string") continue;
    declarationByRoute.set(node.id, {
      sourcePaths: Array.isArray(node.sourcePaths) ? [...node.sourcePaths] : [],
      receivers: Array.isArray(node.receivers) ? [...node.receivers] : [],
    });
  }

  const unresolved = Array.isArray(middlewareGraph?.unresolved) ? middlewareGraph.unresolved : [];
  const routerUnresolvedByPath = new Map();
  for (const record of unresolved) {
    if (record?.scope !== PRODUCTION_RISK_ROUTER_SCOPE) continue;
    const list = routerUnresolvedByPath.get(record.path) ?? [];
    list.push(record);
    routerUnresolvedByPath.set(record.path, list);
  }

  const routes = observationsOf(section, "api-route");
  for (const route of routes) {
    const declaration = declarationByRoute.get(route.route) ?? { sourcePaths: [], receivers: [] };
    const sources = declaration.sourcePaths;
    const bounded = boundedPaths(sources);
    // The occurrences this route's own chain produced: its route-scope middleware entries
    // (which the middleware graph records against the route) and the receiver-scope
    // registrations of the receivers it is declared on.
    const onChain = (record) =>
      record?.kind === "route-middleware"
        ? record.route === route.route
        : sources.includes(record?.path) && declaration.receivers.includes(record?.receiver);
    const routeCited = cite(...(route.evidenceIds ?? []));
    if (routeCited.length === 0) {
      withheld += 1;
      continue;
    }

    const related = unresolved.filter(onChain);
    const protectionUnresolved =
      route.protection === MIDDLEWARE_PROTECTION_STATES.UNRESOLVED;

    if (protectionUnresolved) {
      const cited = cite(...routeCited, ...related.map((record) => record.evidenceId));
      if (cited.length === 0) withheld += 1;
      else {
        findings.push(
          findingFor("api", "api-route-protection-unresolved", {
            key: `protection-unresolved:${route.route}`,
            route: route.route,
            method: route.method,
            path: route.path,
            unresolved: related.length,
            ...bounded,
            evidenceIds: cited,
          }),
        );
      }
    } else if (
      route.protection === MIDDLEWARE_PROTECTION_STATES.PROTECTED &&
      route.middlewareApplied > 0 &&
      related.length > 0
    ) {
      const cited = cite(...routeCited, ...related.map((record) => record.evidenceId));
      if (cited.length === 0) withheld += 1;
      else {
        findings.push(
          findingFor("api", "api-protected-route-partially-unresolved", {
            key: `protected-partly-unresolved:${route.route}`,
            route: route.route,
            method: route.method,
            path: route.path,
            middleware: route.middlewareApplied,
            unresolved: related.length,
            ...bounded,
            evidenceIds: cited,
          }),
        );
      }
    }

    // The third detection is *file*-scoped, not chain-scoped: an unresolved router-scope
    // registration in the file a route is declared in bounds what that file could establish
    // for every route in it, whether or not this particular route's own chain resolved. It is
    // withheld for a route whose protection is already `unresolved`, because the first finding
    // states that route's protection in full and a second finding about the same route would
    // say nothing new.
    // File-scoped by design: a router-scope registration that could not be established bounds
    // what every route in that file inherits, whether or not this particular route's own chain
    // resolved, and the statement says exactly that.
    const routerUnresolved = sources.flatMap((path) => routerUnresolvedByPath.get(path) ?? []);
    if (!protectionUnresolved && routerUnresolved.length > 0) {
      const cited = cite(...routeCited, ...routerUnresolved.map((record) => record.evidenceId));
      if (cited.length === 0) withheld += 1;
      else {
        findings.push(
          findingFor("api", "api-router-inheritance-incomplete", {
            key: `router-inheritance:${route.route}`,
            route: route.route,
            method: route.method,
            path: route.path,
            unresolved: routerUnresolved.length,
            ...bounded,
            evidenceIds: cited,
          }),
        );
      }
    }
  }

  return { findings, unknown, withheld };
}

// ─── Dependency hygiene ──────────────────────────────────────────────────────

/**
 * Dependency hygiene gaps.
 *
 * Structural only, and deliberately blind to every dependency-quality question: no
 * vulnerability database, no CVE, no package audit, no outdated-version check, no licence
 * check, no registry and no network access of any kind.
 *
 * Two of the four are absence claims — a manifest with no lockfile and a lockfile with no
 * manifest — so both are made only while the dependency reading was complete, which the
 * inventory report's own `complete` state already requires all sources to have been parsed
 * for. The other two state a present fact (more than one ecosystem; a source this build could
 * not interpret) and need nothing beyond the record.
 *
 * All four are `observations`. Whether an ecosystem must be locked, whether a lockfile must have
 * a manifest beside it, whether one ecosystem must be used rather than several, and whether a
 * source's format ought to be one this build reads are all questions this model states no
 * policy about — so the report states the structural fact and refuses the hygiene verdict.
 */
function detectDependencyRisks({ section, cite, complete }) {
  const findings = [];
  const unknown = [];
  let withheld = 0;

  const sources = observationsOf(section, "dependency-manifest");
  const ecosystems = observationsOf(section, "dependency-ecosystem");
  const byEcosystem = new Map();
  for (const source of sources) {
    const bucket = byEcosystem.get(source.ecosystem) ?? [];
    bucket.push(source);
    byEcosystem.set(source.ecosystem, bucket);
  }

  for (const source of sources) {
    if (source.status === "parsed") continue;
    const cited = cite(...(source.evidenceIds ?? []));
    if (cited.length === 0) {
      withheld += 1;
      continue;
    }
    findings.push(
      findingFor("dependencies", "dependency-source-unresolved", {
        key: `source-unresolved:${source.path}`,
        path: source.path,
        ecosystem: source.ecosystem,
        status: source.status,
        reason: source.reason ?? null,
        evidenceIds: cited,
      }),
    );
  }

  if (byEcosystem.size >= 2) {
    const cited = cite(...evidenceOf(ecosystems));
    if (cited.length === 0) withheld += 1;
    else {
      const bounded = boundedPaths([...byEcosystem.keys()]);
      findings.push(
        findingFor("dependencies", "dependency-ecosystems-multiple", {
          key: "ecosystems-multiple",
          count: byEcosystem.size,
          ...bounded,
          evidenceIds: cited,
        }),
      );
    }
  }

  for (const [ecosystem, members] of [...byEcosystem.entries()].sort()) {
    const manifests = members.filter((entry) => entry.role === "manifest");
    const lockfiles = members.filter((entry) => entry.role === "lockfile");

    if (manifests.length > 0 && lockfiles.length === 0) {
      if (!complete) {
        unknown.push(abstention("dependency-coverage-not-complete", "dependency-manifest-without-lockfile", 1));
      } else {
        const cited = cite(...evidenceOf(manifests), ...evidenceOf(ecosystems.filter((entry) => entry.ecosystem === ecosystem)));
        if (cited.length === 0) withheld += 1;
        else {
          const bounded = boundedPaths(manifests.map((entry) => entry.path));
          findings.push(
            findingFor("dependencies", "dependency-manifest-without-lockfile", {
              key: `no-lockfile:${ecosystem}`,
              ecosystem,
              count: manifests.length,
              ...bounded,
              evidenceIds: cited,
            }),
          );
        }
      }
    }

    if (lockfiles.length > 0 && manifests.length === 0) {
      if (!complete) {
        unknown.push(abstention("dependency-coverage-not-complete", "dependency-lockfile-without-manifest", 1));
      } else {
        const cited = cite(...evidenceOf(lockfiles), ...evidenceOf(ecosystems.filter((entry) => entry.ecosystem === ecosystem)));
        if (cited.length === 0) withheld += 1;
        else {
          const bounded = boundedPaths(lockfiles.map((entry) => entry.path));
          findings.push(
            findingFor("dependencies", "dependency-lockfile-without-manifest", {
              key: `no-manifest:${ecosystem}`,
              ecosystem,
              count: lockfiles.length,
              ...bounded,
              evidenceIds: cited,
            }),
          );
        }
      }
    }
  }

  return { findings, unknown, withheld };
}

// ─── Architecture integrity ──────────────────────────────────────────────────

/**
 * Architecture integrity gaps.
 *
 * Three structural readings and no verdict: an entrypoint-shaped file nothing in the import
 * graph relates to, a group of such files under one directory, and a container that holds a
 * manifest while no import edge touches any file it contains. There is no coupling score, no
 * complexity metric, no circular-dependency detection and no dead-code claim anywhere in it.
 *
 * All three are absence claims over the import graph, so all three are made only while the
 * architecture reading was complete — which the inventory report's own `complete` state
 * already requires the import graph to be complete for. And the module reading carries one
 * further condition, because it is the one that could lie: a container is reported as
 * unconnected only when the import graph actually **carries** a file inside it. A container of
 * files no import reader covers (a language this build does not read) is a place the import
 * graph says nothing about, and "nothing imports it" would be a claim from an absent
 * substrate.
 *
 * All three are `observations`. The import graph's silence about a file is a fact about a
 * relationship, and no contract in this model states that an entrypoint must be imported or that
 * every module must be reachable: "no import edge relates this" is not "this is disconnected at
 * runtime", and this report never says the latter.
 */
function detectArchitectureRisks({ section, cite, complete, architectureGraph, importGraph }) {
  const findings = [];
  const unknown = [];
  let withheld = 0;

  const isolated = new Map(
    observationsOf(section, "architecture-isolated-file").map((entry) => [entry.path, entry]),
  );

  const isolatedByDirectory = new Map();
  for (const [path] of isolated) {
    const index = path.lastIndexOf("/");
    const directory = index === -1 ? "." : path.slice(0, index);
    const list = isolatedByDirectory.get(directory) ?? [];
    list.push(path);
    isolatedByDirectory.set(directory, list);
  }

  const containerMembers = new Map();
  const nodePathById = new Map();
  for (const node of architectureGraph?.nodes ?? []) {
    if (typeof node?.id === "string" && typeof node.path === "string") {
      nodePathById.set(node.id, node.path);
    }
  }
  for (const edge of architectureGraph?.edges ?? []) {
    if (edge?.type !== ARCHITECTURE_EDGE_TYPES.CONTAINS) continue;
    const childPath = nodePathById.get(edge.to);
    if (typeof childPath !== "string") continue;
    const list = containerMembers.get(edge.from) ?? [];
    list.push(childPath);
    containerMembers.set(edge.from, list);
  }

  /** Every member of a container, including nested directories, bounded by its own depth. */
  const membersOf = (containerId) => {
    const seen = new Set();
    const frontier = [...(containerMembers.get(containerId) ?? [])];
    let depth = 0;
    while (frontier.length > 0 && depth < 32) {
      const next = [];
      for (const path of frontier) {
        if (seen.has(path)) continue;
        seen.add(path);
        for (const [id, members] of containerMembers) {
          if (id !== `directory:${path}`) continue;
          next.push(...members);
        }
      }
      frontier.length = 0;
      frontier.push(...next);
      depth += 1;
    }
    return [...seen];
  };

  const importPaths = new Set();
  const touchedByImport = new Set();
  for (const node of importGraph?.nodes ?? []) {
    if (typeof node?.path === "string") importPaths.add(node.path);
  }
  for (const edge of importGraph?.edges ?? []) {
    if (edge?.type !== IMPORT_GRAPH_EDGE_TYPES.IMPORTS) continue;
    const fromId = edge.from.startsWith("file:") ? edge.from.slice(5) : null;
    const toId = edge.to.startsWith("file:") ? edge.to.slice(5) : null;
    if (fromId !== null) touchedByImport.add(fromId);
    if (toId !== null) touchedByImport.add(toId);
  }

  if (!complete) {
    for (const kind of [
      "architecture-entrypoint-disconnected",
      "architecture-isolated-cluster",
      "architecture-module-unconnected",
    ]) {
      unknown.push(abstention("architecture-coverage-not-complete", kind, 1));
    }
    return { findings, unknown, withheld };
  }

  for (const entrypoint of observationsOf(section, "architecture-entrypoint")) {
    const witness = isolated.get(entrypoint.path);
    if (witness === undefined) continue;
    const cited = cite(...(entrypoint.evidenceIds ?? []), ...(witness.evidenceIds ?? []));
    if (cited.length === 0) {
      withheld += 1;
      continue;
    }
    findings.push(
      findingFor("architecture", "architecture-entrypoint-disconnected", {
        key: `entrypoint-disconnected:${entrypoint.path}`,
        path: entrypoint.path,
        evidenceIds: cited,
      }),
    );
  }

  for (const [directory, paths] of [...isolatedByDirectory.entries()].sort()) {
    if (paths.length < 2) continue;
    const cited = cite(...paths.flatMap((path) => isolated.get(path)?.evidenceIds ?? []));
    if (cited.length === 0) {
      withheld += 1;
      continue;
    }
    const bounded = boundedPaths(paths);
    findings.push(
      findingFor("architecture", "architecture-isolated-cluster", {
        key: `isolated-cluster:${directory}`,
        directory,
        count: paths.length,
        ...bounded,
        evidenceIds: cited,
      }),
    );
  }

  for (const module of observationsOf(section, "architecture-module")) {
    const members = membersOf(module.container);
    const moduleFiles = members.filter((path) => importPaths.has(path));
    if (moduleFiles.length === 0) continue;
    if (moduleFiles.some((path) => touchedByImport.has(path))) continue;
    const cited = cite(...(module.evidenceIds ?? []));
    if (cited.length === 0) {
      withheld += 1;
      continue;
    }
    const manifests = Array.isArray(module.manifests) ? module.manifests : [];
    const bounded = boundedPaths(manifests);
    findings.push(
      findingFor("architecture", "architecture-module-unconnected", {
        key: `module-unconnected:${module.container}`,
        container: module.container,
        manifests: module.manifestCount ?? manifests.length,
        moduleFiles: moduleFiles.length,
        ...bounded,
        evidenceIds: cited,
      }),
    );
  }

  return { findings, unknown, withheld };
}

/**
 * The risk section for one domain, from the inventory report's own section.
 *
 * The inventory section is the substrate: its observations are the findings' witnesses, its
 * coverage decides which detections may be made and its abstentions are carried verbatim, so a
 * consumer reading only the risk report still learns everything the inventory report could not
 * establish. `withheld` findings — statements whose citation the model does not carry — are
 * counted and named, never silently dropped.
 */
function buildRiskSection(name, input) {
  const section = input.section;
  // A section's *own* coverage carries no `complete` flag — completeness is the section's
  // state, one level up: `complete` is the only state that means every input it reads was read
  // in full. Reading it from the state rather than guessing at a field is what makes the
  // absence rule below hinge on the inventory report's own answer.
  const base = {
    section,
    cite: input.cite,
    complete: section.state === PRODUCTION_REPORT_STATES.COMPLETE,
  };

  let result;
  switch (name) {
    case "environment":
      result = detectEnvironmentRisks(base);
      break;
    case "container":
      result = detectContainerRisks({
        ...base,
        unobservedDeclarations: input.unobservedBuildDeclarations,
        imageDeclarations: input.serviceImageDeclarations,
        unestablishedComposeSources: input.unestablishedComposeSources,
      });
      break;
    case "ci":
      result = detectCiRisks(base);
      break;
    case "api":
      result = detectApiRisks({
        ...base,
        middlewareGraph: input.middlewareGraph,
        apiGraph: input.apiGraph,
        middlewareEstablished: input.middlewareGraph?.established === true,
      });
      break;
    case "dependencies":
      result = detectDependencyRisks(base);
      break;
    case "architecture":
      result = detectArchitectureRisks({
        ...base,
        architectureGraph: input.architectureGraph,
        importGraph: input.importGraph,
      });
      break;
    default:
      // Unreachable: the six domains are declared above and the report carries each once.
      result = { findings: [], unknown: [], withheld: 0 };
  }

  const unknown = [
    ...(section.unknown ?? []).map((record) => ({ ...record })),
    ...result.unknown,
  ];
  if (result.withheld > 0) {
    unknown.push(abstention("risk-finding-without-evidence", null, result.withheld));
  }

  return assembleRiskSection({
    name,
    findings: result.findings,
    unknown,
    supported: section.state !== PRODUCTION_REPORT_STATES.UNSUPPORTED,
    established: section.established === true,
    complete: base.complete,
    inventoryTruncated: section.coverage?.truncated === true,
  });
}

/**
 * Build the ProductionRiskReport.
 *
 * @param {object} input The accepted projections this report derives from.
 * @returns {object} A deeply frozen `ProductionRiskReport`.
 */
export function buildProductionRiskReport(input) {
  const {
    report = null,
    evidence = [],
    unobservedBuildDeclarations = [],
    serviceImageDeclarations = [],
    unestablishedComposeSources = [],
    middlewareGraph = null,
    apiGraph = null,
    architectureGraph = null,
    importGraph = null,
  } = input;

  const existing = new Set((evidence ?? []).map((record) => record.id));
  const cite = createCitation(existing);

  const inventorySections = Array.isArray(report?.sections) ? report.sections : [];
  const byName = new Map(inventorySections.map((section) => [section.name, section]));

  const sections = PRODUCTION_RISK_SECTIONS.map((name) => {
    const section = byName.get(name);
    if (section === undefined) {
      // A model that carries no report at all has no domain to derive from. Every section
      // says so, and none of them claims an absence. The state is `unknown`, not
      // `unsupported`: this build *does* interpret every one of the six domains, and the
      // missing input is the model's report, which is what the abstention names. `unsupported`
      // is reserved for a domain this implementation cannot read at all, and it stays
      // unreachable here — the validator requires it to name a declared uninterpreted basis,
      // and four of the six domains declare none.
      return assembleRiskSection({
        name,
        findings: [],
        unknown: [abstention("production-report-not-established", null, 1)],
        supported: true,
        established: false,
        complete: false,
        inventoryTruncated: false,
      });
    }
    return buildRiskSection(name, {
      section,
      cite,
      unobservedBuildDeclarations,
      serviceImageDeclarations,
      unestablishedComposeSources,
      middlewareGraph,
      apiGraph,
      architectureGraph,
      importGraph,
    });
  });

  const findings = sections.flatMap((section) => section.findings);
  const severities = {
    [PRODUCTION_RISK_SEVERITIES.INFO]: findings.filter(
      (entry) => entry.severity === PRODUCTION_RISK_SEVERITIES.INFO,
    ).length,
    [PRODUCTION_RISK_SEVERITIES.LOW]: findings.filter(
      (entry) => entry.severity === PRODUCTION_RISK_SEVERITIES.LOW,
    ).length,
    [PRODUCTION_RISK_SEVERITIES.MEDIUM]: findings.filter(
      (entry) => entry.severity === PRODUCTION_RISK_SEVERITIES.MEDIUM,
    ).length,
  };

  const unknownReasons = {};
  for (const section of sections) {
    for (const record of section.unknown) {
      unknownReasons[record.reason] = (unknownReasons[record.reason] ?? 0) + record.count;
    }
  }

  const states = sections.map((section) => section.state);
  const established = sections.some((section) => section.established === true);
  const truncated = states.some((state) => state === PRODUCTION_RISK_STATES.TRUNCATED);
  const state = truncated
    ? PRODUCTION_RISK_STATES.TRUNCATED
    : states.every((entry) => entry === PRODUCTION_RISK_STATES.COMPLETE)
      ? PRODUCTION_RISK_STATES.COMPLETE
      : established
        ? PRODUCTION_RISK_STATES.PARTIAL
        : PRODUCTION_RISK_STATES.UNKNOWN;

  const coverage = {
    state,
    established,
    complete: state === PRODUCTION_RISK_STATES.COMPLETE,
    truncated,
    sections: sections.length,
    findings: findings.length,
    evidence: sections.reduce((total, section) => total + section.evidenceIds.length, 0),
    sectionsWithFindings: sections.filter((section) => section.findings.length > 0).length,
    severities,
    unknownReasons: Object.keys(unknownReasons)
      .sort()
      .reduce((accumulator, reason) => {
        accumulator[reason] = unknownReasons[reason];
        return accumulator;
      }, {}),
    limits: { ...PRODUCTION_RISK_REPORT_LIMITS },
  };

  return deepFreeze({
    version: PRODUCTION_RISK_REPORT_VERSION,
    state,
    established,
    sections: sections.map((section) => ({ ...section })),
    findings,
    evidenceIds: sortedUnique(sections.flatMap((section) => section.evidenceIds)),
    unknowns: sections.flatMap((section) =>
      section.unknown.map((record) => ({
        section: section.name,
        reason: record.reason,
        detail: record.detail,
        count: record.count,
      })),
    ),
    coverage,
  });
}

/** Whether a state means the report established an answer. Re-exported for consumers. */
export { isEstablishedProductionState as isEstablishedRiskState };

/** The section labels the inventory report declares, re-exported for cross-checks. */
export { PRODUCTION_SECTION_TITLES };

/** The import-graph states this projection reads, re-exported so a test can pin them. */
export { IMPORT_GRAPH_STATES };
