/**
 * Code Guardian — RepositoryModel Evidence (Phase 8D)
 *
 * The model does not invent an evidence format. Every record is a Core
 * `Evidence` object (Phase 7), so a future Finding can reference the same
 * observation ids the model exposes, and Core validation checks the nested
 * records for free.
 *
 * Three concepts stay deliberately separate (Phase 7 §Evidence):
 *
 *   observation  a record in `model.evidence` — something the scanner saw
 *   entity       a modelled object in a typed area — what the model derives
 *   relationship a deterministic connection between two entities
 *
 * Collapsing them would destroy provenance: the same observation may support
 * several entities (one manifest file is both a `file` and a `manifest`), and a
 * relationship must never be mistaken for a fact on its own.
 *
 * `provenance.deterministic` is supplied **explicitly and truthfully** by this
 * producer. Phase 8D is a pure transformation of a scanner result: it reads no
 * clock, no filesystem, no environment and no randomness, so every record it
 * emits is genuinely deterministic. The Phase 7 factory refuses to assert this on
 * a producer's behalf, and this module honours that by asserting it itself rather
 * than inheriting a default.
 *
 * `data` payloads are small, bounded and path-free. Scanner text (a branch name,
 * a package version) is copied only through a documented projection, and
 * `location.path` is always a canonical repository-relative path.
 */

import { createEvidence } from "../../core/index.js";

import { evidenceId } from "./identity.js";

/** Evidence subjects: which scanner section an observation came from. */
export const EVIDENCE_SUBJECTS = Object.freeze({
  INVENTORY: "inventory",
  MANIFEST: "manifest",
  LANGUAGE: "language",
  TEST: "test",
  CICD: "cicd",
  DOCUMENTATION: "documentation",
  CONFIGURATION: "configuration",
  GIT: "git",
  CONTENT: "content",
  DEPENDENCY: "dependency",
  IMPORT: "import",
});

/**
 * Core evidence `type` for each subject.
 *
 * The mapping is closed: a subject that is not listed here cannot produce an
 * observation, so `type` can never drift outside the Phase 7 vocabulary.
 */
export const EVIDENCE_TYPE_BY_SUBJECT = Object.freeze({
  // Inventories are files or directories; `createInventoryObservation` decides which.
  [EVIDENCE_SUBJECTS.INVENTORY]: "file",
  [EVIDENCE_SUBJECTS.MANIFEST]: "configuration",
  [EVIDENCE_SUBJECTS.LANGUAGE]: "file",
  [EVIDENCE_SUBJECTS.TEST]: "test",
  [EVIDENCE_SUBJECTS.CICD]: "workflow",
  [EVIDENCE_SUBJECTS.DOCUMENTATION]: "documentation",
  [EVIDENCE_SUBJECTS.CONFIGURATION]: "configuration",
  [EVIDENCE_SUBJECTS.GIT]: "git",
  // A content observation is *about* a file's bytes, so `configuration` is the
  // closest Core type: the Core vocabulary has no "content" type, and inventing
  // one would change the Core contract rather than extend this layer.
  [EVIDENCE_SUBJECTS.CONTENT]: "configuration",
  // Core has a `dependency` evidence type (Phase 7), so a dependency observation
  // needs no borrowed vocabulary.
  [EVIDENCE_SUBJECTS.DEPENDENCY]: "dependency",
  // Core has a `graph` evidence type (Phase 7), which is exactly what a module
  // reference is: a connection the repository establishes between two files. Using
  // it keeps the Phase 7 vocabulary closed rather than inventing an "import" type.
  [EVIDENCE_SUBJECTS.IMPORT]: "graph",
});

/**
 * Signals recorded on dependency observations.
 *
 *   SOURCE       what one manifest turned out to be as a dependency source
 *                (parsed / unsupported / failed, with its bounded problems)
 *   DECLARATION  one dependency declaration a manifest made
 *   RESOLUTION   one lockfile's resolved graph, recorded as counts
 *
 * They are separate records rather than fields of one because they answer
 * different questions: which file could be read, what it declared, and what it
 * resolved. A consumer that needs "what did the repository declare" reads
 * declarations and never has to guess from the resolution counts.
 */
export const DEPENDENCY_SIGNALS = Object.freeze({
  SOURCE: "dependency-source",
  DECLARATION: "dependency-declaration",
  RESOLUTION: "dependency-resolution",
});

/**
 * Signals recorded on content observations.
 *
 * `INSPECTION` states what the inspection did (or could not do) for one candidate;
 * `PATTERN` states which credential-shaped structure was observed. They are kept
 * apart so "the file was read and nothing matched" and "a pattern matched" are
 * different records rather than different fields of one record.
 */
export const CONTENT_SIGNALS = Object.freeze({
  INSPECTION: "content-inspection",
  PATTERN: "content-pattern",
});

/**
 * Signals recorded on container build-context observations.
 *
 * `BUILD_CONTEXT` records a Compose declaration: this Dockerfile is built from this
 * context root, by this service. `UNPARSED` records that a Compose file's build
 * declarations could *not* be established, which is why a rule must answer `unknown`
 * rather than treat the file as declaring nothing.
 */
export const CONTAINER_SIGNALS = Object.freeze({
  BUILD_CONTEXT: "compose-build-context",
  UNPARSED: "compose-unparsed",
});

/**
 * How far the bounded inspection of one candidate got.
 *
 *   inspected       the whole candidate was examined as text and no limit stopped
 *                   the examination, so "no pattern matched" is a supported claim
 *   partial         the examination was cut short (the file is larger than the
 *                   per-file limit), so "no pattern matched" is only a claim about
 *                   the prefix that was read
 *   uninspected     nothing was examined (a budget was spent, the file could not be
 *                   read, or it is not text)
 *
 * `partial` and `uninspected` are *not* evidence of a clean file, which is why they
 * are distinct values rather than a `false`.
 */
export const CONTENT_STATUSES = Object.freeze({
  INSPECTED: "inspected",
  PARTIAL: "partial",
  UNINSPECTED: "uninspected",
});

/** Why a candidate is `uninspected`. Mirrors the scanner's closed vocabulary. */
export const CONTENT_UNINSPECTED_REASONS = Object.freeze({
  BUDGET_EXHAUSTED: "budget-exhausted",
  UNREADABLE: "unreadable",
  NOT_TEXT: "not-text",
});

/**
 * Whether an evidence record is a content observation, and which kind.
 *
 * Exported so consumers (the security rule pack) can recognize content evidence
 * through the public evidence record alone, without depending on id layout.
 */
/**
 * Build the observation for one manifest's dependency source status.
 *
 * One record per manifest, always recorded — including for a manifest that could
 * not be interpreted at all. That is what lets a consumer cite the reason a
 * dependency question is `unknown` instead of asserting an absence it cannot
 * support.
 *
 * @param {object} input
 * @param {string} input.path Canonical repository-relative manifest path.
 * @param {string} input.ecosystem
 * @param {string} input.status Parsed / unsupported / failed.
 * @param {string|null} input.reason Bounded reason when not parsed.
 * @param {string|null} input.detail Bounded detail token.
 * @param {string[]} input.problems Bounded problem reason ids.
 * @returns {object} A Core Evidence object.
 */
export function createDependencySourceObservation({
  path,
  ecosystem,
  status,
  reason,
  detail,
  problems,
}) {
  return createObservation({
    subject: EVIDENCE_SUBJECTS.DEPENDENCY,
    key: `${DEPENDENCY_SIGNALS.SOURCE}:${path}`,
    type: EVIDENCE_TYPE_BY_SUBJECT[EVIDENCE_SUBJECTS.DEPENDENCY],
    path,
    data: {
      signal: DEPENDENCY_SIGNALS.SOURCE,
      ecosystem,
      status,
      reason,
      detail,
      problems: [...problems],
    },
  });
}

/**
 * Build the observation for one dependency declaration.
 *
 * The key includes the scope because a manifest may legitimately declare the same
 * dependency twice — `dependencies` and `devDependencies` in one `package.json` is
 * an error npm reports, and the model preserves both facts rather than choosing.
 *
 * @param {object} input
 * @param {string} input.path Canonical repository-relative manifest path.
 * @param {string} input.name Normalized dependency name.
 * @param {string} input.scope One of the dependency scopes.
 * @param {string|null} input.spec Declared version/specifier, or null.
 * @param {string} input.specKind How the specifier is sourced.
 * @param {boolean} input.direct Whether the manifest declares it directly.
 * @returns {object} A Core Evidence object.
 */
export function createDependencyDeclarationObservation({
  path,
  name,
  scope,
  spec,
  specKind,
  direct,
}) {
  return createObservation({
    subject: EVIDENCE_SUBJECTS.DEPENDENCY,
    key: `${DEPENDENCY_SIGNALS.DECLARATION}:${path}:${name}:${scope}`,
    type: EVIDENCE_TYPE_BY_SUBJECT[EVIDENCE_SUBJECTS.DEPENDENCY],
    path,
    data: {
      signal: DEPENDENCY_SIGNALS.DECLARATION,
      name,
      scope,
      spec,
      specKind,
      direct,
    },
  });
}

/**
 * Build the observation for one lockfile's resolved graph.
 *
 * Recorded as counts, deliberately: a lockfile for a large application resolves
 * thousands of packages, and duplicating every `(name, version)` pair into the
 * evidence list would multiply the model's size without adding a fact the
 * dependency entities do not already carry. The record states what the file
 * established (`resolved` packages, `edges`) and remains the provenance a finding
 * cites for it.
 *
 * @param {object} input
 * @param {string} input.path Canonical repository-relative manifest path.
 * @param {string} input.ecosystem
 * @param {number} input.resolved Packages the lockfile resolved.
 * @param {number} input.edges Edges the lockfile stated.
 * @returns {object} A Core Evidence object.
 */
export function createDependencyResolutionObservation({ path, ecosystem, resolved, edges }) {
  return createObservation({
    subject: EVIDENCE_SUBJECTS.DEPENDENCY,
    key: `${DEPENDENCY_SIGNALS.RESOLUTION}:${path}`,
    type: EVIDENCE_TYPE_BY_SUBJECT[EVIDENCE_SUBJECTS.DEPENDENCY],
    path,
    data: {
      signal: DEPENDENCY_SIGNALS.RESOLUTION,
      ecosystem,
      resolved,
      edges,
    },
  });
}

/**
 * Signals recorded on import observations.
 *
 * One record per module source, deliberately: the model's per-file record already
 * carries the references, their resolution and the problems, and duplicating every
 * specifier into the evidence list would multiply the model's size without adding a
 * fact. The record states what the file was as a module source (status, language,
 * why it could not be parsed, how many references were established and how many
 * module-shaped expressions could not be) and is the provenance every edge from
 * that file cites.
 */
export const IMPORT_SIGNALS = Object.freeze({
  SOURCE: "import-source",
});

export function contentObservationKind(record) {
  const signal = record?.data?.signal;
  if (signal === CONTENT_SIGNALS.INSPECTION) return CONTENT_SIGNALS.INSPECTION;
  if (signal === CONTENT_SIGNALS.PATTERN) return CONTENT_SIGNALS.PATTERN;
  return null;
}

/**
 * Build the observation for one module source's import declaration scan.
 *
 * @param {object} input
 * @param {string} input.path Canonical repository-relative path.
 * @param {string} input.language Module language id (`javascript` / `typescript`).
 * @param {string} input.status Parsed / unsupported / failed / not-inspected.
 * @param {string|null} input.reason Bounded reason when not parsed.
 * @param {string|null} input.detail Bounded detail token (a failure kind, an extension).
 * @param {number} input.references References established from this file.
 * @param {number} input.nonStatic Module-shaped expressions that could not be established.
 * @param {string[]} input.problems Bounded problem reason ids.
 * @param {boolean} input.truncated Whether a byte or token budget cut the file short.
 * @returns {object} A Core Evidence object.
 */
export function createImportSourceObservation({
  path,
  language,
  status,
  reason,
  detail,
  references,
  nonStatic,
  problems,
  truncated,
}) {
  return createObservation({
    subject: EVIDENCE_SUBJECTS.IMPORT,
    key: `${IMPORT_SIGNALS.SOURCE}:${path}`,
    type: EVIDENCE_TYPE_BY_SUBJECT[EVIDENCE_SUBJECTS.IMPORT],
    path,
    data: {
      signal: IMPORT_SIGNALS.SOURCE,
      language,
      status,
      reason,
      detail,
      references,
      nonStatic,
      problems: [...problems],
      truncated,
    },
  });
}

/** Producer recorded on every observation. */
export const EVIDENCE_SOURCE = Object.freeze({
  analyzer: "phase-8d-repository-model",
  method: "consume-scan-result",
});

/** Collector that actually observed the fact (Phase 8C). */
export const EVIDENCE_COLLECTOR = "phase-8c-repository-scanner";

/** `data.kind` values for inventory observations. */
export const INVENTORY_KINDS = Object.freeze({
  FILE: "file",
  DIRECTORY: "directory",
  SYMLINK: "symlink",
});

/**
 * Build one Core Evidence record.
 *
 * @param {object} input
 * @param {string} input.subject One of `EVIDENCE_SUBJECTS`.
 * @param {string} input.key Subject-local unique key (path or normalized name).
 * @param {string} input.type One of the Core evidence types.
 * @param {string} input.path Canonical repository-relative path.
 * @param {object} [input.data] Small structured observation payload.
 * @returns {object} A Core Evidence object.
 */
export function createObservation({ subject, key, type, path, data = {} }) {
  return createEvidence({
    id: evidenceId(subject, key),
    type,
    location: { path },
    source: { ...EVIDENCE_SOURCE },
    data: { ...data },
    provenance: {
      deterministic: true,
      collector: EVIDENCE_COLLECTOR,
    },
  });
}

/**
 * Build an inventory observation for a filesystem entity.
 *
 * @param {object} input
 * @param {string} input.path Canonical repository-relative path.
 * @param {string} input.kind One of `INVENTORY_KINDS`.
 * @param {object} [input.data]
 * @returns {object}
 */
export function createInventoryObservation({ path, kind, data = {} }) {
  return createObservation({
    subject: EVIDENCE_SUBJECTS.INVENTORY,
    key: path,
    type: kind === INVENTORY_KINDS.DIRECTORY ? "directory" : "file",
    path,
    data: { kind, ...data },
  });
}

/**
 * Build a content observation: what the bounded inspection did with one candidate.
 *
 * The payload is deliberately value-free — status, reason, byte count and the
 * pattern ids that matched. No matched text, no line, and no file byte is ever
 * copied into the model, so a secret cannot travel through the model to a finding,
 * a log or an MCP response.
 *
 * @param {object} input
 * @param {string} input.path Canonical repository-relative path.
 * @param {string} input.status One of `CONTENT_STATUSES`.
 * @param {string|null} input.reason Why the content was not inspected, or null.
 * @param {number} input.bytesInspected Bytes actually examined.
 * @returns {object}
 */
export function createContentInspectionObservation({
  path,
  status,
  reason,
  bytesInspected,
}) {
  return createObservation({
    subject: EVIDENCE_SUBJECTS.CONTENT,
    key: `${CONTENT_SIGNALS.INSPECTION}:${path}`,
    type: EVIDENCE_TYPE_BY_SUBJECT[EVIDENCE_SUBJECTS.CONTENT],
    path,
    data: {
      signal: CONTENT_SIGNALS.INSPECTION,
      status,
      reason,
      bytesInspected,
    },
  });
}

/**
 * Build one content-pattern observation: which pattern shape was observed where.
 *
 * @param {object} input
 * @param {string} input.path Canonical repository-relative path.
 * @param {string} input.patternId A pattern id from the scanner's closed vocabulary.
 * @returns {object}
 */
export function createContentPatternObservation({ path, patternId }) {
  return createObservation({
    subject: EVIDENCE_SUBJECTS.CONTENT,
    key: `${CONTENT_SIGNALS.PATTERN}:${patternId}:${path}`,
    type: EVIDENCE_TYPE_BY_SUBJECT[EVIDENCE_SUBJECTS.CONTENT],
    path,
    data: { signal: CONTENT_SIGNALS.PATTERN, pattern: patternId },
  });
}

/**
 * Build a container build-context observation.
 *
 * The evidence key includes the declaration's source and service, because the same
 * Dockerfile can legitimately be declared by two services — two true observations,
 * not a duplicate.
 *
 * @param {object} input
 * @param {string} input.path Canonical repository-relative path of the Dockerfile.
 * @param {string} input.source Compose file the declaration came from.
 * @param {string} input.service Compose service that declares it.
 * @param {string} input.contextPath Repository-relative context root.
 * @returns {object}
 */
export function createBuildContextObservation({ path, source, service, contextPath }) {
  return createObservation({
    subject: EVIDENCE_SUBJECTS.CONFIGURATION,
    key: `${CONTAINER_SIGNALS.BUILD_CONTEXT}:${source}:${service}:${path}`,
    type: EVIDENCE_TYPE_BY_SUBJECT[EVIDENCE_SUBJECTS.CONFIGURATION],
    path,
    data: {
      signal: CONTAINER_SIGNALS.BUILD_CONTEXT,
      source,
      service,
      contextPath,
    },
  });
}

/**
 * Build an observation for a scanner-reported signal in a non-inventory section.
 *
 * The evidence key is `signal:path`, matching the scan contract's own uniqueness
 * (the scanner reports at most one entry per `(path, signal)` pair), so ids are
 * unique by construction.
 *
 * @param {object} input
 * @param {string} input.subject One of `EVIDENCE_SUBJECTS`.
 * @param {string} input.path Canonical repository-relative path.
 * @param {string} input.signal Scanner signal id.
 * @param {object} [input.data]
 * @returns {object}
 */
export function createSignalObservation({ subject, path, signal, data = {} }) {
  return createObservation({
    subject,
    key: `${signal}:${path}`,
    type: EVIDENCE_TYPE_BY_SUBJECT[subject],
    path,
    data: { signal, ...data },
  });
}
