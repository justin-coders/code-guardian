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
export function contentObservationKind(record) {
  const signal = record?.data?.signal;
  if (signal === CONTENT_SIGNALS.INSPECTION) return CONTENT_SIGNALS.INSPECTION;
  if (signal === CONTENT_SIGNALS.PATTERN) return CONTENT_SIGNALS.PATTERN;
  return null;
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
