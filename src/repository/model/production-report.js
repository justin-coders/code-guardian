/**
 * Code Guardian — Production Report (Phase 20)
 *
 * The first real **Production Readiness Auditor**. It answers six questions about
 * production engineering practice — environment configuration, container readiness, CI
 * readiness, API exposure, dependency inventory, architecture — and it answers them the
 * only way this architecture allows:
 *
 * > What concrete repository evidence proves this?
 *
 * ### It does not score, rank or grade
 *
 * There is no readiness percentage, no traffic light, no severity, no pass/fail verdict
 * and no grade anywhere in this module or in the report it produces. `PRODUCTION_REPORT_STATES`
 * says how much of the repository the report could *read*, and the per-section `unknown`
 * list says what it could not establish — never whether what it read is good. A report
 * that cannot read something says `unknown`; it never converts an unknown into a pass.
 *
 * ### Every observation cites evidence that exists
 *
 * An observation is not a sentence. It is a small closed-vocabulary record carrying the
 * ids of the observations in `model.evidence` that establish it, and the builder's
 * validation refuses a report containing an id the model does not carry. So the answer
 * to "what proves this?" is always a list of observation ids a consumer can resolve —
 * never a summary that cannot be traced.
 *
 * ### It derives, it does not observe
 *
 * Nothing here reads a file, parses source, resolves a module, starts a server, runs a
 * process, consults a network or a clock, or looks anything up in a vulnerability
 * database. It is a pure projection over facts the model already validated: the entity
 * collections, the five accepted graphs and the scan's own coverage statement. Reusing
 * those graphs is the whole point — a second, parallel notion of "which routes exist"
 * could disagree with the one the rules already consume.
 *
 * ### Six sections, and the vocabulary is closed
 *
 * The six section names, the observation kinds each may produce and the reasons each may
 * abstain with are declared here as frozen vocabularies. A consumer switches on them, so
 * a new kind or reason has to be added deliberately rather than appearing as free text.
 *
 * ### Abstention is first-class
 *
 * Three separate mechanisms keep a gap from reading as a fact:
 *
 *   - a section's `state` is `unknown` while the graph or scan behind it was never
 *     established, so an empty observation list is never mistaken for "there is none";
 *   - a section's `unknown` list names *why* it abstains — an unparsed Dockerfile, an
 *     unestablished middleware graph, a workflow whose purpose its own file name does not
 *     state — with a count, so a partial answer is visibly partial;
 *   - `coverage.complete` is false whenever any input was cut short.
 *
 * ### Determinism and bounds
 *
 * Sections appear in their declared order, observations are sorted by a documented key
 * unique within their section, evidence ids are sorted and unique, and unknown records
 * are sorted by `(reason, detail)`. Every collection is bounded
 * (`PRODUCTION_REPORT_LIMITS`), and a bound that bit is recorded rather than silently
 * applied.
 */

import { EVIDENCE_SUBJECTS } from "./evidence.js";
import { evidenceId } from "./identity.js";
import {
  ARCHITECTURE_EDGE_TYPES,
  ARCHITECTURE_NODE_KINDS,
  ARCHITECTURE_GRAPH_STATES,
  REPOSITORY_NODE_KIND,
} from "./architecture-graph.js";
import {
  API_GRAPH_EDGE_TYPES,
  API_GRAPH_STATES,
  API_UNRESOLVED_REASONS,
} from "./api-graph.js";
import { DEPENDENCY_GRAPH_STATES } from "./dependency-graph.js";
import { IMPORT_GRAPH_EDGE_TYPES, IMPORT_GRAPH_STATES } from "./import-graph.js";
import { MIDDLEWARE_GRAPH_STATES, MIDDLEWARE_PROTECTION_STATES } from "./middleware-graph.js";

/** Version of the report contract. */
export const PRODUCTION_REPORT_VERSION = "1";

/** Producer recorded in the model's metadata for this projection. */
export const PRODUCTION_REPORT_BUILDER = "phase-20-production-report";

/**
 * The report's coverage states.
 *
 * The same five-way vocabulary every accepted graph uses, with each value meaning exactly
 * one thing. The distinction that matters most is between an *empty* answer and an
 * *uninterpretable* one:
 *
 *   complete     the section's inputs were inspected successfully and it established its
 *                answer — including a legitimately **empty** answer. "This repository
 *                declares no environment artifact" is an answer, so a section that read
 *                everything and found nothing is `complete`, with zero observations
 *   partial      the section established an answer, but some relevant input was not fully
 *                established (an incomplete scan, an ignore policy that excluded a path, a
 *                source it could not interpret, a graph that was only partly built)
 *   unsupported  the section cannot answer because the relevant domain is not interpreted
 *                by this implementation — a named-but-uninterpreted framework, or a
 *                manifest/lockfile format this build does not read. Never inferred from an
 *                empty observation list: an unsupported section names the basis in its own
 *                abstentions, and cannot have established an answer
 *   unknown      the section could not establish an answer at all: the scan did not cover
 *                the repository, or nothing behind the section was built
 *   truncated    a declared bound stopped the section
 */
export const PRODUCTION_REPORT_STATES = Object.freeze({
  COMPLETE: "complete",
  PARTIAL: "partial",
  UNSUPPORTED: "unsupported",
  UNKNOWN: "unknown",
  TRUNCATED: "truncated",
});

/** The coverage-state vocabulary as a list, for validation. */
export const PRODUCTION_REPORT_STATE_VALUES = Object.freeze(
  Object.values(PRODUCTION_REPORT_STATES),
);

/** The six audit domains, in the order the report declares them. */
export const PRODUCTION_SECTIONS = Object.freeze([
  "environment",
  "container",
  "ci",
  "api",
  "dependencies",
  "architecture",
]);

/** Human-readable section labels, used in findings. */
export const PRODUCTION_SECTION_TITLES = Object.freeze({
  environment: "Environment configuration",
  container: "Container configuration",
  ci: "CI configuration",
  api: "API exposure inventory",
  dependencies: "Dependency inventory",
  architecture: "Architecture inventory",
});

/**
 * The observation kinds each section may produce.
 *
 * Closed per section: a kind invented by one section would be a contract mismatch, and
 * the validator rejects it.
 */
export const PRODUCTION_OBSERVATION_KINDS = Object.freeze({
  environment: Object.freeze([
    "environment-example",
    "environment-template",
    "environment-file",
    "sample-configuration",
    "environment-template-duplicate",
  ]),
  container: Object.freeze([
    "container-definition",
    "container-ignore",
    "container-composition",
    "container-structure",
    "container-healthcheck",
    "container-healthcheck-disabled",
    "container-multi-stage",
    "container-build-context",
  ]),
  ci: Object.freeze(["ci-provider", "ci-workflow"]),
  api: Object.freeze(["api-route", "api-handler"]),
  dependencies: Object.freeze([
    "dependency-manifest",
    "dependency-lockfile",
    "dependency-ecosystem",
  ]),
  architecture: Object.freeze([
    "architecture-layer",
    "architecture-module",
    "architecture-entrypoint",
    "architecture-isolated-file",
  ]),
});

/**
 * The reason each section may abstain with.
 *
 * Every reason is about *knowledge*, never about quality: "this Dockerfile's structure is
 * not established" is in the vocabulary; "this Dockerfile is bad" is not, and could not
 * be expressed through it.
 */
export const PRODUCTION_UNKNOWN_REASONS = Object.freeze({
  environment: Object.freeze([
    "secret-values-not-inspected",
    "environment-configuration-ignored",
    "no-environment-configuration-observed",
    "environment-configuration-not-observed",
    "configuration-inventory-truncated",
    "section-observations-truncated",
    "repository-scan-not-complete",
  ]),
  container: Object.freeze([
    "dockerfile-structure-not-established",
    "compose-build-declarations-not-established",
    "no-container-configuration-observed",
    "container-configuration-not-observed",
    "container-inventory-truncated",
    "section-observations-truncated",
    "repository-scan-not-complete",
  ]),
  ci: Object.freeze([
    "workflow-content-not-inspected",
    "workflow-purpose-not-established",
    "no-ci-configuration-observed",
    "ci-configuration-not-observed",
    "ci-inventory-truncated",
    "section-observations-truncated",
    "repository-scan-not-complete",
  ]),
  api: Object.freeze([
    "api-graph-not-established",
    "middleware-graph-not-established",
    "route-occurrence-not-established",
    "route-middleware-not-established",
    "handler-not-established",
    "api-framework-not-interpreted",
    "api-source-not-interpreted",
    "section-observations-truncated",
    "repository-scan-not-complete",
  ]),
  dependencies: Object.freeze([
    "dependency-graph-not-established",
    "dependency-source-not-established",
    "no-dependency-declaration-observed",
    "dependency-declarations-not-observed",
    "dependency-format-not-interpreted",
    "section-observations-truncated",
    "repository-scan-not-complete",
  ]),
  architecture: Object.freeze([
    "architecture-graph-not-established",
    "isolated-modules-not-established",
    "entrypoint-detection-not-established",
    "import-graph-not-established",
    "section-observations-truncated",
    "repository-scan-not-complete",
  ]),
});

/**
 * The abstention that makes a section genuinely `unsupported`.
 *
 * `unsupported` is a statement about *this implementation*, not about the repository: it says
 * the relevant domain is not interpreted here, so no answer exists. The validator therefore
 * refuses the state unless the section names the uninterpreted domain with one of these
 * reasons — an empty observation list is not a basis, and a section that read everything and
 * found nothing is `complete` instead.
 *
 * Two domains can reach it today, each from a fact the accepted graphs already state:
 *
 *   api           the graph reports no readable source (`api-source-not-interpreted`), or
 *                 every declared endpoint is in a framework this build does not read and no
 *                 route was established (`api-framework-not-interpreted`)
 *   dependencies  every dependency source is a format this build does not interpret
 *                 (`dependency-format-not-interpreted`), so nothing the repository declares
 *                 is established
 *
 * Environment, container and CI classification are name- and instruction-based with no
 * uninterpreted case, and the architecture chapter's four statements are always
 * interpretable — its graph reports `unsupported` when a complete scan finds no entity to
 * relate, which is the domain's *empty* answer, and the chapter answers `complete` for it.
 * Their lists are empty rather than absent, so a section that claimed `unsupported` without a
 * basis would be rejected rather than quietly allowed.
 */
export const PRODUCTION_UNSUPPORTED_REASONS = Object.freeze({
  environment: Object.freeze([]),
  container: Object.freeze([]),
  ci: Object.freeze([]),
  api: Object.freeze(["api-framework-not-interpreted", "api-source-not-interpreted"]),
  dependencies: Object.freeze(["dependency-format-not-interpreted"]),
  architecture: Object.freeze([]),
});

/** Every reason, keyed the other way round, for validation and tests. */
export const PRODUCTION_UNKNOWN_REASON_VALUES = Object.freeze(
  Object.keys(PRODUCTION_UNKNOWN_REASONS).reduce((accumulator, section) => {
    for (const reason of PRODUCTION_UNKNOWN_REASONS[section]) {
      accumulator[`${section}.${reason}`] = reason;
    }
    return accumulator;
  }, {}),
);

/** Hard bounds on one report. */
export const PRODUCTION_REPORT_LIMITS = Object.freeze({
  /** Observations retained per section. */
  maxObservationsPerSection: 200,
  /** Abstention records retained per section. */
  maxUnknownReasonsPerSection: 32,
  /** Evidence ids cited by one observation. */
  maxEvidencePerObservation: 16,
  /** Paths listed inside one observation. */
  maxPathsPerObservation: 16,
});

/** How an environment artifact's *name* classifies it. */
export const ENVIRONMENT_CLASSES = Object.freeze({
  EXAMPLE: "environment-example",
  TEMPLATE: "environment-template",
  FILE: "environment-file",
  SAMPLE: "sample-configuration",
});

/**
 * The closed name table that classifies an environment artifact.
 *
 * First match wins, which is what makes `.env.example` an *example* and not also an
 * environment file. The classification is derived from the file's own name and from
 * nothing else — this architecture never reads an environment file's content, and the
 * section says so in its own abstention list.
 */
const ENVIRONMENT_NAME_RULES = Object.freeze([
  {
    kind: ENVIRONMENT_CLASSES.EXAMPLE,
    matches: (name) => /^\.env\.(example|sample)$/.test(name) || /\.env\.example$/.test(name),
  },
  {
    kind: ENVIRONMENT_CLASSES.TEMPLATE,
    matches: (name) => /^\.env\.(template|dist)$/.test(name),
  },
  {
    kind: ENVIRONMENT_CLASSES.SAMPLE,
    matches: (name) =>
      /^(sample|example|template)\.[A-Za-z0-9._-]+$/i.test(name) ||
      /\.(sample|example|template)$/i.test(name) ||
      /(^|[._-])(sample|example|template)\.(json|ya?ml|toml|ini|conf|properties|xml|cfg|config|dist)$/i.test(
        name,
      ),
  },
  {
    kind: ENVIRONMENT_CLASSES.FILE,
    matches: (name) => name === ".env" || /^\.env\.[A-Za-z0-9._-]+$/.test(name),
  },
]);

/** Classify an environment artifact by its own file name. */
export function classifyEnvironmentArtifact(name) {
  for (const rule of ENVIRONMENT_NAME_RULES) {
    if (rule.matches(name)) return rule.kind;
  }
  return null;
}

/** Whether a path's own name is environment-shaped (used for the ignore check). */
export function isEnvironmentShapedName(name) {
  return name === ".env" || name.startsWith(".env.");
}

/**
 * How a CI workflow's file name classifies its purpose.
 *
 * Precedence is release → lint → test, and a name that states none of them is
 * `unclassified`. This is a **name-only** reading: the workflow body is never opened, so
 * the report says `purpose` was derived from the name and cannot claim what the workflow
 * does. `ci.yml` and `build.yml` are deliberately *not* classified — "continuous
 * integration" and "build" do not establish that tests run, and guessing would be exactly
 * the "this is probably bad" reasoning this phase forbids.
 */
export const CI_PURPOSES = Object.freeze({
  RELEASE: "release",
  LINT: "lint",
  TEST: "test",
  UNCLASSIFIED: "unclassified",
});

const CI_PURPOSE_RULES = Object.freeze([
  { purpose: CI_PURPOSES.RELEASE, words: ["release", "publish", "deploy", "deployment", "tag"] },
  {
    purpose: CI_PURPOSES.LINT,
    words: ["lint", "linting", "eslint", "format", "formatting", "prettier", "style"],
  },
  {
    purpose: CI_PURPOSES.TEST,
    words: ["test", "tests", "testing", "unit", "spec", "integration", "coverage"],
  },
]);

/** Classify a workflow file name's purpose. */
export function classifyWorkflowName(name) {
  const stem = name.replace(/\.[A-Za-z0-9]+$/, "").toLowerCase();
  const words = new Set(stem.split(/[._-]+/).filter((word) => word !== ""));
  for (const rule of CI_PURPOSE_RULES) {
    for (const word of rule.words) {
      if (words.has(word)) return rule.purpose;
    }
  }
  return CI_PURPOSES.UNCLASSIFIED;
}

/**
 * The closed entrypoint name table.
 *
 * Entrypoint detection is **name-based**, and the report says so in its abstention list:
 * no manifest field, no process argument and no runtime observation is available to this
 * build. `index.*` is deliberately absent — a file named `index.js` is a module-resolution
 * convention, not a statement that something starts there, and reporting every barrel file
 * as an entrypoint would be a claim the repository does not make.
 */
export const PRODUCTION_ENTRYPOINT_NAMES = Object.freeze([
  "main.js",
  "main.mjs",
  "main.cjs",
  "main.ts",
  "main.tsx",
  "main.py",
  "main.go",
  "main.rs",
  "main.rb",
  "app.js",
  "app.ts",
  "app.py",
  "server.js",
  "server.ts",
  "server.py",
  "cli.js",
  "cli.ts",
  "cli.py",
  "__main__.py",
]);

/** Directories whose observed files are entrypoint-shaped by convention. */
export const PRODUCTION_ENTRYPOINT_DIRECTORIES = Object.freeze(["bin", "cmd"]);

/** Whether a path is entrypoint-shaped by name. */
export function isEntrypointShapedPath(path, name) {
  if (PRODUCTION_ENTRYPOINT_NAMES.includes(name)) return true;
  return PRODUCTION_ENTRYPOINT_DIRECTORIES.some((directory) => path.startsWith(`${directory}/`));
}

/**
 * Whether a state means the report established an answer.
 *
 * `truncated` **is** an answer, and is listed deliberately: a section whose reading a bound
 * cut short still established what it read, and the truncation is recorded in the same
 * section's coverage and abstentions. Treating it as "no answer" would make the report's
 * own `established` flag disagree with its sections' — exactly the inconsistency this
 * contract exists to reject.
 *
 * `unknown` and `unsupported` are the two states that mean no answer, for two different
 * reasons: `unknown` is "nothing behind this section was established", and `unsupported` is
 * "this implementation does not interpret the domain". Neither is an answer, so neither is
 * established — and an empty answer is not one of them: a section that read everything and
 * found nothing is `complete`.
 */
export function isEstablishedProductionState(state) {
  return (
    state === PRODUCTION_REPORT_STATES.COMPLETE ||
    state === PRODUCTION_REPORT_STATES.PARTIAL ||
    state === PRODUCTION_REPORT_STATES.TRUNCATED
  );
}

function deepFreeze(value) {
  if (value === null || typeof value !== "object" || Object.isFrozen(value)) return value;
  Object.freeze(value);
  for (const key of Object.keys(value)) deepFreeze(value[key]);
  return value;
}

/**
 * Sort by a list of keys, so no two records compare equal.
 *
 * Two details matter for the contract:
 *
 *   - a missing token (`null`, `undefined`) sorts **before** any present one, exactly as a
 *     missing value reads in the validator's own ordering key. JavaScript's relational
 *     operators compare `null` with a string as `false` in *both* directions, so comparing
 *     the values directly would make the order depend on the input order and a section that
 *     ended up with both an untokened and a tokened record would fail its own contract;
 *   - comparison is by string, matching the key the validator builds from the same fields.
 */
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

/** The evidence id of a file's own inventory observation. */
function inventoryEvidenceId(path) {
  return evidenceId(EVIDENCE_SUBJECTS.INVENTORY, path);
}

/** The evidence id of a scanner-reported configuration signal. */
function configurationEvidenceId(path, signal) {
  return evidenceId(EVIDENCE_SUBJECTS.CONFIGURATION, `${signal}:${path}`);
}

/** The evidence id of a scanner-reported CI signal. */
function cicdEvidenceId(path, signal) {
  return evidenceId(EVIDENCE_SUBJECTS.CICD, `${signal}:${path}`);
}

/** The evidence id of a lockfile's resolution observation. */
function dependencyResolutionEvidenceId(path) {
  return evidenceId(EVIDENCE_SUBJECTS.DEPENDENCY, `dependency-resolution:${path}`);
}

/**
 * The report's evidence citation policy.
 *
 * An observation cites only ids the model actually carries, sorted, unique and bounded. An
 * id that is not present is *dropped*, never invented — and the caller records an
 * abstention for the observation it could not support instead of emitting it without
 * provenance.
 */
function createCitation(existingIds) {
  return function cite(...ids) {
    const unique = [...new Set(ids.filter((id) => typeof id === "string" && existingIds.has(id)))];
    return unique.sort().slice(0, PRODUCTION_REPORT_LIMITS.maxEvidencePerObservation);
  };
}

/**
 * Build one abstention record.
 *
 * @param {string} reason
 * @param {string|null} detail Bounded cause token (a path, a reason, or a vocabulary word).
 * @param {number} count
 */
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
 * The coverage state of one section.
 *
 * Four questions, in this order, and the observation count is deliberately not one of them:
 *
 *   1. did a declared bound stop the reading?            → `truncated`
 *   2. does this implementation interpret the domain?     → `unsupported` when it does not
 *   3. did the section establish an answer at all?        → `unknown` when it did not
 *   4. was every input it reads read in full?             → `complete`, else `partial`
 *
 * An established, fully-inspected section with zero observations is `complete`: "this
 * repository declares nothing in this domain" is the answer the repository gave, and
 * reporting it as `unsupported` (an admission that the domain could not be interpreted)
 * would be a different, false statement. `unsupported` is reachable only through the
 * explicit `supported` flag a section sets when its domain is genuinely not interpreted.
 *
 * @param {object} input
 * @param {boolean} input.supported This implementation interprets the domain.
 * @param {boolean} input.established The section's own question has an answer.
 * @param {boolean} input.complete Every input it reads was read in full.
 * @param {boolean} input.truncated A bound stopped the reading.
 * @returns {string} One of `PRODUCTION_REPORT_STATES`.
 */
function sectionState({ supported, established, complete, truncated }) {
  if (truncated) return PRODUCTION_REPORT_STATES.TRUNCATED;
  if (!supported) return PRODUCTION_REPORT_STATES.UNSUPPORTED;
  if (!established) return PRODUCTION_REPORT_STATES.UNKNOWN;
  if (complete) return PRODUCTION_REPORT_STATES.COMPLETE;
  return PRODUCTION_REPORT_STATES.PARTIAL;
}

/**
 * Assemble one section from already-built parts.
 *
 * Bounds are applied here, in one place, so no section can forget one: observations are
 * sorted by key, cut to `maxObservationsPerSection`, and a cut is recorded both as
 * `coverage.truncated` and as an abstention. Abstentions are merged, sorted and cut to
 * `maxUnknownReasonsPerSection`.
 */
function assembleSection({
  name,
  observations,
  unknown,
  counts,
  established,
  complete,
  supported = true,
}) {
  const sorted = [...observations].sort(compareByKeys(["key"]));
  const capped = sorted.length > PRODUCTION_REPORT_LIMITS.maxObservationsPerSection;
  const retained = capped
    ? sorted.slice(0, PRODUCTION_REPORT_LIMITS.maxObservationsPerSection)
    : sorted;

  const evidence = [...new Set(retained.flatMap((entry) => entry.evidenceIds))].sort();
  const unbounded = mergeAbstentions(unknown);
  const truncatedReasons = unbounded.length > PRODUCTION_REPORT_LIMITS.maxUnknownReasonsPerSection;
  const unknownRecords = truncatedReasons
    ? unbounded.slice(0, PRODUCTION_REPORT_LIMITS.maxUnknownReasonsPerSection)
    : unbounded;

  const dropped = sorted.length - retained.length;
  const records = capped
    ? mergeAbstentions([
        ...unknownRecords,
        abstention("section-observations-truncated", null, dropped),
      ])
    : unknownRecords;

  const state = sectionState({
    supported,
    established,
    truncated: capped || truncatedReasons,
    complete,
  });
  // Derived from the state rather than taken on trust, so the contract's
  // `established === isEstablishedProductionState(state)` can never disagree with itself.
  const answered = isEstablishedProductionState(state);

  return {
    name,
    title: PRODUCTION_SECTION_TITLES[name],
    state,
    established: answered,
    counts: { ...counts },
    observations: retained,
    evidenceIds: evidence,
    unknown: records,
    coverage: {
      state,
      established: answered,
      observations: retained.length,
      evidence: evidence.length,
      truncated: capped || truncatedReasons,
      unknownReasons: records.length,
    },
  };
}

/** Whether a value is a plain object. */
function isPlainObject(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Zero a section's count structure, keeping every key the domain declares.
 *
 * Used when a section's answer is withheld. The counts are part of the section's contract, so
 * they keep their shape — but a count of observations the section does not carry would be a
 * number that is true of nothing.
 */
function zeroCounts(value) {
  if (isPlainObject(value)) {
    const zeroed = {};
    for (const key of Object.keys(value)) zeroed[key] = zeroCounts(value[key]);
    return zeroed;
  }
  return typeof value === "boolean" ? false : 0;
}

/**
 * Withhold a section's answer because the scan behind it did not cover the repository.
 *
 * This is the phase's central rule applied where it matters most. A graph can be established
 * while the scan that produced its inputs was not: the architecture graph, for instance, is
 * built from whatever files were inventoried, so it can be internally consistent over an
 * inventory that stopped early. Reporting its observations would present a partial reading as
 * a complete one, so the section keeps only its **abstentions** — including
 * `repository-scan-not-complete`, which is exactly true of every domain — and drops every
 * observation, with the counts zeroed to match. An unestablished domain is never turned into
 * a pass, and it is never turned into an observation either.
 */
function withoutCoverage(section) {
  return assembleSection({
    name: section.name,
    observations: [],
    unknown: [...section.unknown, abstention("repository-scan-not-complete", null, 1)],
    counts: zeroCounts(section.counts),
    established: false,
    complete: false,
  });
}

/** Count occurrences of each value in a list, as a sorted-key object. */
function census(values) {
  const counts = {};
  for (const value of [...values].sort()) counts[value] = (counts[value] ?? 0) + 1;
  return counts;
}

// ─── Environment configuration ───────────────────────────────────────────────

/**
 * The environment chapter.
 *
 * Presence and name-classification only. `.env.example`, `.env.template`, a live `.env`, a
 * `.env.production` and a sample configuration file are classified by their own names, and
 * no file's content is read — not for a key, not for a value, not for a default. The
 * section therefore always abstains with `secret-values-not-inspected`, so it can never be
 * read as "this configuration is correct".
 *
 * The ignore policy is load-bearing here. `.env` is the canonical gitignored file, so when
 * a scan policy excludes an environment-shaped path the report says
 * `environment-configuration-ignored` and drops its `complete` claim: the file may exist,
 * this scan did not look, and "no environment file" would be a fabricated fact.
 */
function buildEnvironmentSection({
  files,
  configuration,
  cite,
  scanComplete,
  configurationEvidenceTruncated,
  ignoredPaths,
}) {
  const observations = [];
  const unknown = [];

  const byPath = new Map();
  for (let index = 0; index < files.length; index += 1) {
    const file = files[index];
    const kind = classifyEnvironmentArtifact(file.name);
    if (kind === null) continue;
    if (byPath.has(file.path)) continue;
    byPath.set(file.path, { path: file.path, name: file.name, kind });
  }

  const signalsByPath = new Map();
  for (const entity of configuration) {
    if (entity.signal !== "environment-example") continue;
    signalsByPath.set(entity.path, entity.signal);
  }

  for (const entry of [...byPath.values()].sort(compareByKeys(["path"]))) {
    const signal = signalsByPath.get(entry.path);
    const evidence =
      signal === undefined
        ? cite(inventoryEvidenceId(entry.path))
        : cite(inventoryEvidenceId(entry.path), configurationEvidenceId(entry.path, signal));
    if (evidence.length === 0) {
      unknown.push(
        abstention("configuration-inventory-truncated", entry.path, 1),
      );
      continue;
    }
    observations.push({
      kind: entry.kind,
      key: entry.path,
      path: entry.path,
      name: entry.name,
      basis: "file-name",
      evidenceIds: evidence,
    });
  }

  // Duplicated environment templates: two or more observed files in one example/template
  // class. Reported as one observation per class, citing every file in it, because the
  // fact being stated is about the set — "this repository states the same environment
  // template twice" — not about either file alone.
  const classes = [ENVIRONMENT_CLASSES.EXAMPLE, ENVIRONMENT_CLASSES.TEMPLATE];
  const duplicated = [];
  for (const kind of classes) {
    const members = observations.filter((entry) => entry.kind === kind);
    if (members.length < 2) continue;
    const paths = members.map((entry) => entry.path);
    duplicated.push(kind);
    observations.push({
      kind: "environment-template-duplicate",
      key: `duplicate:${kind}`,
      class: kind,
      basis: "file-name",
      count: paths.length,
      paths: paths.slice(0, PRODUCTION_REPORT_LIMITS.maxPathsPerObservation),
      pathsTruncated: paths.length > PRODUCTION_REPORT_LIMITS.maxPathsPerObservation,
      evidenceIds: [...new Set(members.flatMap((entry) => entry.evidenceIds))].sort(),
    });
  }

  // Which env-shaped paths an ignore policy excluded. The scan records them as observations
  // about the repository's policy, not as files, so their *existence* is unknown.
  const ignoredEnvironment = ignoredPaths
    .map((entry) => entry.path)
    .filter((path) => {
      const name = path.split("/").pop();
      return typeof name === "string" && isEnvironmentShapedName(name);
    })
    .sort();

  const counts = {
    examples: observations.filter((entry) => entry.kind === ENVIRONMENT_CLASSES.EXAMPLE).length,
    templates: observations.filter((entry) => entry.kind === ENVIRONMENT_CLASSES.TEMPLATE).length,
    environmentFiles: observations.filter((entry) => entry.kind === ENVIRONMENT_CLASSES.FILE).length,
    sampleConfigurations: observations.filter((entry) => entry.kind === ENVIRONMENT_CLASSES.SAMPLE)
      .length,
    duplicatedClasses: duplicated.length,
    ignoredEnvironmentPaths: ignoredEnvironment.length,
  };

  unknown.push(abstention("secret-values-not-inspected", null, 1));
  if (ignoredEnvironment.length > 0) {
    unknown.push(abstention("environment-configuration-ignored", null, ignoredEnvironment.length));
  }
  if (configurationEvidenceTruncated) {
    unknown.push(abstention("configuration-inventory-truncated", null, 1));
  }
  if (observations.length === 0) {
    unknown.push(
      abstention(
        scanComplete ? "no-environment-configuration-observed" : "environment-configuration-not-observed",
        null,
        1,
      ),
    );
  }

  return assembleSection({
    name: "environment",
    observations,
    unknown,
    counts,
    established: scanComplete,
    complete: scanComplete && !configurationEvidenceTruncated && ignoredEnvironment.length === 0,
  });
}

// ─── Container configuration ────────────────────────────────────────────────

/**
 * The container chapter.
 *
 * Observed structure only: which files are Dockerfiles, whether a `.dockerignore` and a
 * Compose file are present, the stages and healthcheck a Dockerfile's own instructions
 * declare, and which context each Compose service builds from. There is no evaluation of
 * image size, layer ordering, base-image currency, `.dockerignore` coverage or
 * reproducibility — none of those is expressible in the vocabulary, and the section says
 * `unknown` for a Dockerfile whose instructions it could not read.
 */
function buildContainerSection({
  configuration,
  dockerfileStructures,
  buildContexts,
  cite,
  scanComplete,
  configurationEvidenceTruncated,
  unestablishedComposeSources,
}) {
  const observations = [];
  const unknown = [];

  const signalKind = {
    dockerfile: "container-definition",
    "container-ignore": "container-ignore",
    "compose-file": "container-composition",
  };

  for (const entity of configuration) {
    const kind = signalKind[entity.signal];
    if (kind === undefined) continue;
    const evidence = cite(configurationEvidenceId(entity.path, entity.signal));
    if (evidence.length === 0) continue;
    // The key is kind-prefixed, not the bare path: one file legitimately contributes more
    // than one observation (a Dockerfile is both a definition and a structure), and the
    // section's keys must be unique for the ordering to be a total order.
    observations.push({
      kind,
      key: `${kind}:${entity.path}`,
      path: entity.path,
      signal: entity.signal,
      evidenceIds: evidence,
    });
  }

  const structureByPath = new Map();
  for (const record of dockerfileStructures) {
    const evidence = cite(...(record.evidenceIds ?? []));
    if (evidence.length === 0) continue;
    if (record.parsed !== true) {
      unknown.push(abstention("dockerfile-structure-not-established", record.path, 1));
      continue;
    }
    structureByPath.set(record.path, record);
    observations.push({
      kind: "container-structure",
      key: `container-structure:${record.path}`,
      path: record.path,
      stages: record.stages,
      multiStage: record.multiStage,
      stageNames: [...record.stageNames],
      healthcheck: record.healthcheck,
      healthcheckDisabled: record.healthcheckDisabled,
      instructions: record.instructions,
      basis: "dockerfile-instructions",
      evidenceIds: evidence,
    });
    if (record.healthcheck === true) {
      observations.push({
        kind: "container-healthcheck",
        key: `healthcheck:${record.path}`,
        path: record.path,
        evidenceIds: evidence,
      });
    }
    if (record.healthcheckDisabled === true) {
      observations.push({
        kind: "container-healthcheck-disabled",
        key: `healthcheck-disabled:${record.path}`,
        path: record.path,
        evidenceIds: evidence,
      });
    }
    if (record.multiStage === true) {
      observations.push({
        kind: "container-multi-stage",
        key: `multi-stage:${record.path}`,
        path: record.path,
        stages: record.stages,
        stageNames: [...record.stageNames],
        evidenceIds: evidence,
      });
    }
  }

  for (const record of buildContexts) {
    const evidence = cite(record.evidenceId);
    if (evidence.length === 0) continue;
    observations.push({
      kind: "container-build-context",
      key: `build:${record.source}|${record.service}|${record.dockerfile}`,
      source: record.source,
      service: record.service,
      path: record.dockerfile,
      context: record.context,
      evidenceIds: evidence,
    });
  }

  for (const source of unestablishedComposeSources) {
    unknown.push(abstention("compose-build-declarations-not-established", source.path, 1));
  }

  const definitions = observations.filter((entry) => entry.kind === "container-definition");
  const structures = observations.filter((entry) => entry.kind === "container-structure");

  // A Dockerfile the inventory observed but whose structure produced no record at all is a
  // projection gap: it must be reported, never silently treated as declaring nothing.
  const missingStructures = definitions.filter((entry) => !structureByPath.has(entry.path));
  if (missingStructures.length > 0) {
    unknown.push(
      abstention("dockerfile-structure-not-established", null, missingStructures.length),
    );
  }

  const counts = {
    definitions: definitions.length,
    ignores: observations.filter((entry) => entry.kind === "container-ignore").length,
    compositions: observations.filter((entry) => entry.kind === "container-composition").length,
    structures: structures.length,
    healthchecks: observations.filter((entry) => entry.kind === "container-healthcheck").length,
    healthcheckDisabled: observations.filter(
      (entry) => entry.kind === "container-healthcheck-disabled",
    ).length,
    multiStageDefinitions: observations.filter((entry) => entry.kind === "container-multi-stage")
      .length,
    stages: structures.reduce((total, entry) => total + entry.stages, 0),
    buildContexts: observations.filter((entry) => entry.kind === "container-build-context").length,
  };

  if (configurationEvidenceTruncated) {
    unknown.push(abstention("container-inventory-truncated", null, 1));
  }
  if (observations.length === 0) {
    unknown.push(
      abstention(
        scanComplete ? "no-container-configuration-observed" : "container-configuration-not-observed",
        null,
        1,
      ),
    );
  }

  return assembleSection({
    name: "container",
    observations,
    unknown,
    counts,
    established: scanComplete,
    // `missingStructures` is the load-bearing conjunct: a definition whose structure record
    // says `parsed: false` is not in `structureByPath` either, so one check covers both
    // "the file was never read" and "the read established nothing" — and the section stays
    // `partial` rather than claiming a complete reading of a definition it could not read.
    complete:
      scanComplete &&
      !configurationEvidenceTruncated &&
      missingStructures.length === 0 &&
      unestablishedComposeSources.length === 0,
  });
}

// ─── CI configuration ───────────────────────────────────────────────────────

/**
 * The CI chapter.
 *
 * Which CI providers the repository configures, how many workflow files each contributes,
 * and how each workflow's **file name** reads: release-shaped, lint-shaped, test-shaped or
 * unclassified. The workflow bodies are never opened, so the section abstains with
 * `workflow-content-not-inspected` unconditionally, and a file name that states no purpose
 * is reported as an abstention rather than guessed at. Nothing here judges whether a
 * workflow is correct, whether a step would pass, or whether the pipeline is adequate.
 */
function buildCiSection({ cicd, cite, scanComplete, ciEvidenceTruncated }) {
  const observations = [];
  const unknown = [];

  const described = [];
  for (const entity of cicd) {
    const evidence = cite(cicdEvidenceId(entity.path, entity.signal));
    if (evidence.length === 0) continue;
    const name = entity.path.split("/").pop() ?? entity.path;
    described.push({
      path: entity.path,
      provider: entity.provider,
      purpose: classifyWorkflowName(name),
      name,
      evidenceIds: evidence,
    });
  }

  for (const entry of described) {
    observations.push({
      kind: "ci-workflow",
      key: entry.path,
      path: entry.path,
      name: entry.name,
      provider: entry.provider,
      purpose: entry.purpose,
      basis: "workflow-name",
      evidenceIds: entry.evidenceIds,
    });
  }

  const providers = new Map();
  for (const entry of described) {
    const bucket = providers.get(entry.provider) ?? [];
    bucket.push(entry);
    providers.set(entry.provider, bucket);
  }
  for (const provider of [...providers.keys()].sort()) {
    const members = providers.get(provider);
    observations.push({
      kind: "ci-provider",
      key: `provider:${provider}`,
      provider,
      workflows: members.length,
      files: members
        .map((entry) => entry.path)
        .sort()
        .slice(0, PRODUCTION_REPORT_LIMITS.maxPathsPerObservation),
      filesTruncated: members.length > PRODUCTION_REPORT_LIMITS.maxPathsPerObservation,
      evidenceIds: [...new Set(members.flatMap((entry) => entry.evidenceIds))].sort(),
    });
  }

  const purposes = census(described.map((entry) => entry.purpose));
  const counts = {
    providers: providers.size,
    workflows: described.length,
    githubActionsWorkflows: described.filter((entry) => entry.provider === "github-actions").length,
    purposes: {
      [CI_PURPOSES.RELEASE]: purposes[CI_PURPOSES.RELEASE] ?? 0,
      [CI_PURPOSES.LINT]: purposes[CI_PURPOSES.LINT] ?? 0,
      [CI_PURPOSES.TEST]: purposes[CI_PURPOSES.TEST] ?? 0,
      [CI_PURPOSES.UNCLASSIFIED]: purposes[CI_PURPOSES.UNCLASSIFIED] ?? 0,
    },
  };

  if (counts.workflows > 0) {
    unknown.push(abstention("workflow-content-not-inspected", null, counts.workflows));
  }
  if (counts.purposes[CI_PURPOSES.UNCLASSIFIED] > 0) {
    unknown.push(
      abstention("workflow-purpose-not-established", null, counts.purposes[CI_PURPOSES.UNCLASSIFIED]),
    );
  }
  if (ciEvidenceTruncated) unknown.push(abstention("ci-inventory-truncated", null, 1));
  if (observations.length === 0) {
    unknown.push(
      abstention(
        scanComplete ? "no-ci-configuration-observed" : "ci-configuration-not-observed",
        null,
        1,
      ),
    );
  }

  return assembleSection({
    name: "ci",
    observations,
    unknown,
    counts,
    established: scanComplete,
    complete: scanComplete && !ciEvidenceTruncated,
  });
}

// ─── API exposure inventory ──────────────────────────────────────────────────

/**
 * The API chapter.
 *
 * A summary of the Phase 18 route graph and the Phase 19 middleware graph: how many routes
 * each method contributes, how each is handled, and each route's **structural** protection
 * state. It is an inventory, not an exposure verdict — "this route was declared and its
 * declaring file's middleware registrations were established" is the strongest claim in
 * it, and whether the route should be reachable, whether the protection is sufficient and
 * whether the handler is correct are questions this build has no evidence for.
 */
function buildApiSection({ apiGraph, middlewareGraph, symbolGraph, cite }) {
  const observations = [];
  const unknown = [];

  const symbolById = new Map(symbolGraph.nodes.map((node) => [node.id, node]));
  const protectionByRoute = new Map(
    middlewareGraph.routes.map((route) => [route.route, route.protection]),
  );
  const appliedByRoute = new Map(
    middlewareGraph.routes.map((route) => [route.route, route.middleware]),
  );

  const handlerCounts = new Map();
  const middlewareCounts = new Map();
  for (const edge of apiGraph.edges) {
    if (edge.type === API_GRAPH_EDGE_TYPES.HANDLED_BY) {
      handlerCounts.set(edge.from, (handlerCounts.get(edge.from) ?? 0) + 1);
    } else if (edge.type === API_GRAPH_EDGE_TYPES.MIDDLEWARE) {
      middlewareCounts.set(edge.from, (middlewareCounts.get(edge.from) ?? 0) + 1);
    }
  }

  for (const node of apiGraph.nodes) {
    const evidence = cite(...(node.evidenceIds ?? []));
    if (evidence.length === 0) {
      unknown.push(abstention("route-occurrence-not-established", node.path, 1));
      continue;
    }
    observations.push({
      kind: "api-route",
      key: node.id,
      route: node.id,
      method: node.method,
      path: node.path,
      frameworks: [...node.frameworks],
      handlers: handlerCounts.get(node.id) ?? 0,
      middlewareReferences: middlewareCounts.get(node.id) ?? 0,
      middlewareApplied: (appliedByRoute.get(node.id) ?? []).length,
      protection: protectionByRoute.get(node.id) ?? null,
      evidenceIds: evidence,
    });
  }

  const handlerModules = new Set();
  for (const edge of apiGraph.edges) {
    if (edge.type !== API_GRAPH_EDGE_TYPES.HANDLED_BY) continue;
    const symbol = symbolById.get(edge.to);
    const evidence = cite(...(edge.evidenceIds ?? []), ...(symbol?.evidenceIds ?? []));
    if (evidence.length === 0) continue;
    if (symbol !== undefined) handlerModules.add(symbol.fileId);
    observations.push({
      kind: "api-handler",
      key: `handler:${edge.from}|${edge.to}`,
      route: edge.from,
      symbol: edge.to,
      name: symbol?.name ?? null,
      path: symbol?.path ?? null,
      basis: "static-handler-resolution",
      evidenceIds: evidence,
    });
  }

  const methods = census(apiGraph.nodes.map((node) => node.method));
  const protections = census(
    middlewareGraph.routes.map((route) => route.protection ?? MIDDLEWARE_PROTECTION_STATES.UNKNOWN),
  );

  const routesWithoutHandler = apiGraph.nodes.filter((node) => !handlerCounts.has(node.id));
  const counts = {
    routes: apiGraph.nodes.length,
    methods,
    handlers: apiGraph.edges.filter((edge) => edge.type === API_GRAPH_EDGE_TYPES.HANDLED_BY).length,
    handlerModules: handlerModules.size,
    middlewareNodes: middlewareGraph.nodes.length,
    middlewareReferences: apiGraph.edges.filter(
      (edge) => edge.type === API_GRAPH_EDGE_TYPES.MIDDLEWARE,
    ).length,
    middlewareApplied: middlewareGraph.routes.reduce(
      (total, route) => total + route.middleware.length,
      0,
    ),
    protectedRoutes: protections[MIDDLEWARE_PROTECTION_STATES.PROTECTED] ?? 0,
    unresolvedRoutes: protections[MIDDLEWARE_PROTECTION_STATES.UNRESOLVED] ?? 0,
    unprotectedRoutes: protections[MIDDLEWARE_PROTECTION_STATES.NONE_OBSERVED] ?? 0,
    unknownProtectionRoutes: protections[MIDDLEWARE_PROTECTION_STATES.UNKNOWN] ?? 0,
    unresolvedRouteOccurrences: apiGraph.unresolved.length,
    routesWithoutHandler: routesWithoutHandler.length,
  };

  // The API domain is genuinely uninterpreted by this build in exactly two cases, and each is
  // stated with its own reason rather than inferred from an empty route list:
  //
  //   - the graph itself reports that no source could be read (module files in languages this
  //     build does not read), so nothing about their endpoints is established;
  //   - every route-shaped occurrence the repository declares was refused *because its
  //     framework is not read*, and no route was established at all — the repository states
  //     an API surface in a framework this build does not interpret, which is a different
  //     fact, and must not be reported as one: "this repository declares no endpoint" is the
  //     empty answer, not the uninterpreted one.
  //
  // A repository that mixes an unread framework with routes this build *can* establish keeps
  // its established routes and stays `partial`: only the whole domain being unread makes the
  // section `unsupported`.
  const frameworkUnsupported = apiGraph.unresolved.filter(
    (record) => record.reason === API_UNRESOLVED_REASONS.FRAMEWORK_UNSUPPORTED,
  ).length;
  const frameworkOnly =
    apiGraph.nodes.length === 0 &&
    frameworkUnsupported > 0 &&
    frameworkUnsupported === apiGraph.unresolved.length;
  const uninterpreted = apiGraph.state === API_GRAPH_STATES.UNSUPPORTED || frameworkOnly;
  if (apiGraph.state === API_GRAPH_STATES.UNSUPPORTED) {
    unknown.push(abstention("api-source-not-interpreted", null, 1));
  }
  if (frameworkOnly) {
    unknown.push(abstention("api-framework-not-interpreted", null, frameworkUnsupported));
  }

  // No "no routes" abstention: an established graph with no route is the domain's *empty*
  // answer ("this repository declares no endpoint"), which the section reports as `complete` —
  // a positive answer, not a gap. The abstention list is reserved for what the report could
  // not read or could not interpret.
  if (apiGraph.established !== true) {
    unknown.push(abstention("api-graph-not-established", null, 1));
  }
  if (middlewareGraph.established !== true) {
    unknown.push(abstention("middleware-graph-not-established", null, 1));
  }
  for (const record of apiGraph.unresolved) {
    unknown.push(abstention("route-occurrence-not-established", record.reason, 1));
  }
  if (middlewareGraph.coverage.unresolved > 0) {
    unknown.push(
      abstention("route-middleware-not-established", null, middlewareGraph.coverage.unresolved),
    );
  }
  if (counts.routesWithoutHandler > 0) {
    unknown.push(abstention("handler-not-established", null, counts.routesWithoutHandler));
  }

  return assembleSection({
    name: "api",
    observations,
    unknown,
    counts,
    supported: !uninterpreted,
    established: apiGraph.established === true,
    complete:
      apiGraph.state === API_GRAPH_STATES.COMPLETE &&
      middlewareGraph.state === MIDDLEWARE_GRAPH_STATES.COMPLETE &&
      apiGraph.unresolved.length === 0 &&
      middlewareGraph.coverage.unresolved === 0,
  });
}

// ─── Dependency inventory ────────────────────────────────────────────────────

/**
 * The dependency chapter.
 *
 * Ecosystem by ecosystem: which manifests were read, which lockfiles resolved something,
 * and how many declarations fall in each scope. There is no vulnerability analysis, no
 * outdated-version check, no licence check, no registry lookup and no network access of any
 * kind — the section reports what the manifests and lockfiles state, and abstains with the
 * bounded reason whenever a source could not be interpreted.
 */
function buildDependenciesSection({
  dependencyEntities,
  dependencySources,
  dependencyGraph,
  manifests,
  cite,
}) {
  const observations = [];
  const unknown = [];

  // Which sources the acquisition classified as lockfiles. Read from the manifest entities
  // rather than inferred from a resolution observation, so a lockfile that is present and
  // resolves nothing is still reported as present — "there is no lockfile" is a fact this
  // report must never fabricate from an empty one.
  const manifestKindByPath = new Map(manifests.map((entry) => [entry.path, entry.manifestKind]));
  const isLockfile = (path) => manifestKindByPath.get(path) === "lockfile";

  for (const source of dependencySources) {
    const evidence = cite(source.evidenceId);
    if (evidence.length === 0) {
      unknown.push(abstention("dependency-source-not-established", source.reason ?? null, 1));
      continue;
    }
    if (source.status !== "parsed") {
      unknown.push(abstention("dependency-source-not-established", source.reason ?? null, 1));
    }
    observations.push({
      kind: "dependency-manifest",
      key: `manifest:${source.path}`,
      path: source.path,
      ecosystem: source.ecosystem,
      role: isLockfile(source.path) ? "lockfile" : "manifest",
      status: source.status,
      reason: source.reason ?? null,
      truncated: source.truncated === true,
      evidenceIds: evidence,
    });
  }

  const resolutionsByPath = new Map();
  const edgeCountsByPath = new Map();
  for (const entity of dependencyEntities) {
    for (const resolution of entity.resolutions ?? []) {
      resolutionsByPath.set(
        resolution.manifestPath,
        (resolutionsByPath.get(resolution.manifestPath) ?? 0) + 1,
      );
    }
  }
  for (const edge of dependencyGraph.edges) {
    for (const id of edge.evidenceIds ?? []) {
      edgeCountsByPath.set(id, (edgeCountsByPath.get(id) ?? 0) + 1);
    }
  }

  for (const source of dependencySources) {
    const resolutionId = dependencyResolutionEvidenceId(source.path);
    const evidence = cite(resolutionId);
    if (evidence.length === 0) continue;
    observations.push({
      kind: "dependency-lockfile",
      key: `lockfile:${source.path}`,
      path: source.path,
      ecosystem: source.ecosystem,
      resolved: resolutionsByPath.get(source.path) ?? 0,
      edges: edgeCountsByPath.get(resolutionId) ?? 0,
      evidenceIds: evidence,
    });
  }

  const scopes = new Map();
  for (const entity of dependencyEntities) {
    for (const scope of entity.scopes ?? []) {
      scopes.set(scope, (scopes.get(scope) ?? 0) + 1);
    }
  }

  const byEcosystem = new Map();
  for (const source of dependencySources) {
    const bucket = byEcosystem.get(source.ecosystem) ?? [];
    bucket.push(source);
    byEcosystem.set(source.ecosystem, bucket);
  }

  for (const ecosystem of [...byEcosystem.keys()].sort()) {
    const members = byEcosystem.get(ecosystem);
    const evidence = cite(...members.map((source) => source.evidenceId));
    if (evidence.length === 0) continue;
    const entries = dependencyEntities.filter((entity) => entity.ecosystem === ecosystem);
    const ecosystemScopes = new Map();
    for (const entity of entries) {
      for (const scope of entity.scopes ?? []) {
        ecosystemScopes.set(scope, (ecosystemScopes.get(scope) ?? 0) + 1);
      }
    }
    observations.push({
      kind: "dependency-ecosystem",
      key: `ecosystem:${ecosystem}`,
      ecosystem,
      manifests: members.length,
      manifestsUnestablished: members.filter((source) => source.status !== "parsed").length,
      runtime: ecosystemScopes.get("runtime") ?? 0,
      development: ecosystemScopes.get("development") ?? 0,
      optional: ecosystemScopes.get("optional") ?? 0,
      peer: ecosystemScopes.get("peer") ?? 0,
      unknownScope: ecosystemScopes.get("unknown") ?? 0,
      declared: entries.filter((entity) => entity.declared === true).length,
      resolved: entries.filter((entity) => entity.resolved === true).length,
      evidenceIds: evidence,
    });
  }

  const counts = {
    ecosystems: byEcosystem.size,
    sources: dependencySources.length,
    parsedSources: dependencySources.filter((source) => source.status === "parsed").length,
    unestablishedSources: dependencySources.filter((source) => source.status !== "parsed").length,
    lockfiles: dependencySources.filter((source) => isLockfile(source.path)).length,
    resolvedLockfiles: observations.filter((entry) => entry.kind === "dependency-lockfile").length,
    dependencies: dependencyEntities.length,
    declared: dependencyEntities.filter((entity) => entity.declared === true).length,
    resolved: dependencyEntities.filter((entity) => entity.resolved === true).length,
    runtime: scopes.get("runtime") ?? 0,
    development: scopes.get("development") ?? 0,
    optional: scopes.get("optional") ?? 0,
    peer: scopes.get("peer") ?? 0,
    unknownScope: scopes.get("unknown") ?? 0,
    graphEdges: dependencyGraph.edges.length,
  };

  // Every dependency source being a format this build does not interpret is the one case
  // where the domain is not *interpretable*, and it is stated with an explicit reason rather
  // than inferred from an empty list. An established graph with no dependency is a different
  // answer — "this repository declares no dependency" — which the section reports as
  // `complete`, and the section's own test pins both cases apart.
  const uninterpreted = dependencyGraph.state === DEPENDENCY_GRAPH_STATES.UNSUPPORTED;
  if (uninterpreted) {
    unknown.push(abstention("dependency-format-not-interpreted", null, 1));
  }
  if (dependencyGraph.established !== true) {
    unknown.push(abstention("dependency-graph-not-established", null, 1));
  }

  return assembleSection({
    name: "dependencies",
    observations,
    unknown,
    counts,
    supported: !uninterpreted,
    established: dependencyGraph.established === true,
    complete: dependencyGraph.state === DEPENDENCY_GRAPH_STATES.COMPLETE,
  });
}

// ─── Architecture inventory ──────────────────────────────────────────────────

/**
 * The architecture chapter.
 *
 * Four structural statements and nothing else: which container holds a manifest (the
 * graph's own component notion, read from its `contains` edges), how the observed entities
 * are distributed across node kinds (the graph's layers), which observed files are
 * entrypoint-shaped **by name**, and which module files neither import nor are imported
 * (isolated), the last only when the Phase 16 import graph was actually established. There
 * is no coupling score, no cohesion metric, no circular-dependency verdict and no
 * dead-code claim anywhere in it.
 */
function buildArchitectureSection({ architectureGraph, importGraph, files, cite, scanComplete }) {
  const observations = [];
  const unknown = [];

  const childrenByParent = new Map();
  for (const edge of architectureGraph.edges) {
    if (edge.type !== ARCHITECTURE_EDGE_TYPES.CONTAINS) continue;
    const bucket = childrenByParent.get(edge.from) ?? [];
    bucket.push(edge);
    childrenByParent.set(edge.from, bucket);
  }

  const nodeKindById = new Map(architectureGraph.nodes.map((node) => [node.id, node.kind]));

  // Layers: one record per node kind the graph actually relates, citing the containment
  // edges whose child has that kind. A kind with no containment edge behind it (the
  // repository node itself) produces no layer record — there would be no evidence for it.
  const kindEdges = new Map();
  for (const edge of architectureGraph.edges) {
    if (edge.type !== ARCHITECTURE_EDGE_TYPES.CONTAINS) continue;
    const kind = nodeKindById.get(edge.to);
    if (kind === undefined) continue;
    const bucket = kindEdges.get(kind) ?? [];
    bucket.push(edge);
    kindEdges.set(kind, bucket);
  }
  for (const kind of [...kindEdges.keys()].sort()) {
    const edges = kindEdges.get(kind);
    const evidence = cite(...edges.flatMap((edge) => edge.evidenceIds ?? []));
    if (evidence.length === 0) continue;
    observations.push({
      kind: "architecture-layer",
      key: `layer:${kind}`,
      layer: kind,
      nodes: edges.length,
      evidenceIds: evidence,
    });
  }

  // Modules: a container that directly holds an observed manifest.
  for (const [containerId, edges] of [...childrenByParent.entries()].sort()) {
    const holdings = edges.filter((edge) => nodeKindById.get(edge.to) === "manifest");
    if (holdings.length === 0) continue;
    const evidence = cite(...holdings.flatMap((edge) => edge.evidenceIds ?? []));
    if (evidence.length === 0) continue;
    observations.push({
      kind: "architecture-module",
      key: `module:${containerId}`,
      container: containerId,
      manifests: holdings
        .map((edge) => edge.to)
        .sort()
        .slice(0, PRODUCTION_REPORT_LIMITS.maxPathsPerObservation),
      manifestCount: holdings.length,
      evidenceIds: evidence,
    });
  }

  // Entrypoints: name-shaped only, and the abstention below says so.
  const entrypoints = [];
  for (const file of files) {
    if (!isEntrypointShapedPath(file.path, file.name)) continue;
    const evidence = cite(inventoryEvidenceId(file.path));
    if (evidence.length === 0) continue;
    entrypoints.push(file.path);
    observations.push({
      kind: "architecture-entrypoint",
      key: `entrypoint:${file.path}`,
      path: file.path,
      name: file.name,
      basis: "file-name",
      evidenceIds: evidence,
    });
  }

  // Isolated modules: a module file with no `imports` edge in either direction. Reported
  // only when the import graph was established — "this file imports nothing and nothing
  // imports it" is a claim an unestablished graph cannot support.
  const connected = new Set();
  for (const edge of importGraph.edges) {
    if (edge.type !== IMPORT_GRAPH_EDGE_TYPES.IMPORTS) continue;
    connected.add(edge.from);
    connected.add(edge.to);
  }
  const isolated = [];
  if (importGraph.established === true) {
    for (const node of importGraph.nodes) {
      if (typeof node.path !== "string") continue;
      // An import-graph node *is* the file entity of the path it names, so the node id is
      // checked against that identity rather than trusted: a node the graph could not have
      // produced is skipped instead of reported as isolated.
      if (node.id !== `file:${node.path}`) continue;
      if (connected.has(node.id)) continue;
      const evidence = cite(inventoryEvidenceId(node.path));
      if (evidence.length === 0) continue;
      isolated.push(node.path);
      observations.push({
        kind: "architecture-isolated-file",
        key: `isolated:${node.path}`,
        path: node.path,
        basis: "import-graph",
        evidenceIds: evidence,
      });
    }
  }

  const kinds = {};
  for (const kind of ARCHITECTURE_NODE_KINDS) kinds[kind] = 0;
  for (const node of architectureGraph.nodes) {
    if (node.kind === REPOSITORY_NODE_KIND) continue;
    if (typeof node.kind !== "string") continue;
    kinds[node.kind] = (kinds[node.kind] ?? 0) + 1;
  }

  const counts = {
    nodes: architectureGraph.nodes.length,
    edges: architectureGraph.edges.length,
    containmentEdges: architectureGraph.edges.filter(
      (edge) => edge.type === ARCHITECTURE_EDGE_TYPES.CONTAINS,
    ).length,
    modules: observations.filter((entry) => entry.kind === "architecture-module").length,
    entrypoints: entrypoints.length,
    isolatedFiles: isolated.length,
    importEdges: importGraph.edges.filter(
      (edge) => edge.type === IMPORT_GRAPH_EDGE_TYPES.IMPORTS,
    ).length,
    nodeKinds: kinds,
  };

  // The architecture graph reports `unsupported` in exactly one case: a complete scan whose
  // inventory establishes no architectural entity to relate. That is not "this implementation
  // cannot interpret the domain" — the four statements this chapter makes are all
  // interpretable, and this build interprets them — it is the domain's **empty** answer, and
  // it is only reachable on a scan that finished. The chapter therefore treats it as an
  // established, complete, observation-less answer rather than inheriting the graph's word.
  const emptyInventory =
    architectureGraph.state === ARCHITECTURE_GRAPH_STATES.UNSUPPORTED && scanComplete === true;
  const established = architectureGraph.established === true || emptyInventory;

  if (!established) {
    unknown.push(abstention("architecture-graph-not-established", null, 1));
  }
  if (importGraph.established !== true) {
    unknown.push(abstention("isolated-modules-not-established", null, 1));
  }
  // An unconditional limitation, like the environment section's: entrypoints are recognised
  // by file name and by nothing else, and the report says so whether or not it found one.
  unknown.push(abstention("entrypoint-detection-not-established", null, 1));
  if (importGraph.state !== IMPORT_GRAPH_STATES.COMPLETE) {
    unknown.push(abstention("import-graph-not-established", null, 1));
  }

  return assembleSection({
    name: "architecture",
    observations,
    unknown,
    counts,
    established,
    complete:
      established &&
      (architectureGraph.state === ARCHITECTURE_GRAPH_STATES.COMPLETE || emptyInventory) &&
      importGraph.state === IMPORT_GRAPH_STATES.COMPLETE,
  });
}

/**
 * Build the ProductionReport.
 *
 * @param {object} input Every accepted projection the report reads.
 * @returns {object} A deeply frozen `ProductionReport`.
 */
export function buildProductionReport(input) {
  const {
    configuration = [],
    cicd = [],
    files = [],
    dockerfileStructures = [],
    buildContexts = [],
    unestablishedComposeSources = [],
    dependencyEntities = [],
    dependencySources = [],
    manifests = [],
    dependencyGraph,
    architectureGraph,
    apiGraph,
    middlewareGraph,
    importGraph,
    symbolGraph,
    evidence,
    scan,
    configurationEvidenceTruncated = false,
    ciEvidenceTruncated = false,
  } = input;

  const existing = new Set((evidence ?? []).map((record) => record.id));
  const cite = createCitation(existing);

  const scanComplete = scan?.complete === true && scan?.truncated !== true;
  const ignoredPaths = scan?.coverage?.ignored?.paths ?? [];

  // Every section is built from the inputs it declares, then — when the scan did not cover
  // the repository — every section's answer is withheld in one place, uniformly, so no
  // domain can be the exception that reports a partial reading as an answer.
  const built = [
    buildEnvironmentSection({
      files,
      configuration,
      cite,
      scanComplete,
      configurationEvidenceTruncated,
      ignoredPaths,
    }),
    buildContainerSection({
      configuration,
      dockerfileStructures,
      buildContexts,
      cite,
      scanComplete,
      configurationEvidenceTruncated,
      unestablishedComposeSources,
    }),
    buildCiSection({ cicd, cite, scanComplete, ciEvidenceTruncated }),
    buildApiSection({
      apiGraph: apiGraph ?? emptyGraph(),
      middlewareGraph: middlewareGraph ?? emptyGraph(),
      symbolGraph: symbolGraph ?? emptyGraph(),
      cite,
    }),
    buildDependenciesSection({
      dependencyEntities,
      dependencySources,
      manifests,
      dependencyGraph: dependencyGraph ?? emptyGraph(),
      cite,
    }),
    buildArchitectureSection({
      architectureGraph: architectureGraph ?? emptyGraph(),
      importGraph: importGraph ?? emptyGraph(),
      files,
      cite,
      scanComplete,
    }),
  ];

  const sections = scanComplete ? built : built.map(withoutCoverage);

  const unknownReasons = {};
  for (const section of sections) {
    for (const record of section.unknown) {
      unknownReasons[record.reason] = (unknownReasons[record.reason] ?? 0) + record.count;
    }
  }

  const states = sections.map((section) => section.state);
  const established = sections.some((section) => section.established === true);
  // "Complete" means every domain reached a final answer — and an *answer* is what `complete`
  // is: a section that could not answer (a domain this build does not interpret, or a
  // section with no established input) leaves the report with something it could not say, so
  // the report is `partial` when at least one section answered and `unknown` when none did.
  // This is the same rule as a section's own coverage, one level up.
  const final = states.every((state) => state === PRODUCTION_REPORT_STATES.COMPLETE);
  const truncated = states.some((state) => state === PRODUCTION_REPORT_STATES.TRUNCATED);

  const state = truncated
    ? PRODUCTION_REPORT_STATES.TRUNCATED
    : final
      ? PRODUCTION_REPORT_STATES.COMPLETE
      : established
        ? PRODUCTION_REPORT_STATES.PARTIAL
        : PRODUCTION_REPORT_STATES.UNKNOWN;

  const report = {
    version: PRODUCTION_REPORT_VERSION,
    state,
    established,
    sections: sections.map((section) => ({ ...section })),
    coverage: {
      state,
      established,
      complete: state === PRODUCTION_REPORT_STATES.COMPLETE,
      truncated,
      inspected: sections.some((section) => section.observations.length > 0),
      sections: sections.length,
      observations: sections.reduce((total, section) => total + section.observations.length, 0),
      evidence: sections.reduce((total, section) => total + section.evidenceIds.length, 0),
      unknownReasons: Object.keys(unknownReasons)
        .sort()
        .reduce((accumulator, reason) => {
          accumulator[reason] = unknownReasons[reason];
          return accumulator;
        }, {}),
      limits: { ...PRODUCTION_REPORT_LIMITS },
    },
  };

  return deepFreeze(report);
}

/** A graph-shaped empty value, so a missing projection reads as `unknown`, not as empty. */
function emptyGraph() {
  return deepFreeze({
    nodes: [],
    edges: [],
    unresolved: [],
    routes: [],
    state: PRODUCTION_REPORT_STATES.UNKNOWN,
    established: false,
    coverage: { state: PRODUCTION_REPORT_STATES.UNKNOWN, established: false, truncated: false, unresolved: 0 },
  });
}
