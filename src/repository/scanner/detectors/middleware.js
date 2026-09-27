/**
 * Code Guardian — Middleware Acquisition Detector (Phase 19)
 *
 * The scanner's middleware detector: it decides which inventory files are module sources,
 * reads each one through the Phase 8A boundary under an explicit byte budget, hands the text
 * to the pure scanner in `policies/middleware.js`, and returns **one record per module
 * source**.
 *
 * ### Acquisition, not resolution
 *
 * This detector answers "which middleware registrations does this file declare". It does
 * **not** resolve a middleware name to a symbol: that needs the symbol graph and the
 * repository's own declarations, and it is the model's question, because the model owns
 * identity. Keeping the split here is what stops the scanner from fabricating a middleware
 * node the repository never declared.
 *
 * ### It reads code, and says so
 *
 * This is the seventh bounded read of file bytes in the scanner, and it is bounded the same
 * way as the module, semantic and API reads: a closed extension set, a per-file byte cap, a
 * global file cap, a global byte budget and a per-file token cap, all consumed in the
 * inventory's sorted order so the scanned set is deterministic. A file beyond a budget is
 * recorded as `not-inspected`, never silently skipped, because "this file was not read" and
 * "this file registers no middleware" must never be the same fact.
 *
 * ### What it refuses to guess
 *
 * JSX and TSX are recorded as `unsupported` module sources rather than scanned as if they
 * were plain JavaScript, exactly as the semantic and API detectors do. A file whose lexer
 * failed establishes no registration at all, and the model cites that answer instead of
 * second-guessing it.
 *
 * No process, no network, no clock, no environment, no filesystem write.
 */

import {
  MIDDLEWARE_ACQUISITION_LIMITS,
  MIDDLEWARE_SOURCE_REASONS,
  MIDDLEWARE_SOURCE_STATUSES,
  isModuleFileExtension,
  isParsedModuleExtension,
  moduleLanguageOf,
  scanMiddleware,
} from "../policies/middleware.js";

/** Whether the inspected prefix is text rather than binary. */
function looksBinary(text) {
  return text.includes("\u0000");
}

/** The zero counts every record carries, so no status has a missing field. */
const NO_COUNTS = Object.freeze({
  tokens: 0,
  registrations: 0,
  mounts: 0,
  middleware: 0,
  unresolved: 0,
});

/** A record's common shape, so every status carries every field. */
function sourceRecord(file, status, extra) {
  return {
    path: file.path,
    extension: file.extension,
    language: moduleLanguageOf(file.extension),
    status,
    reason: null,
    detail: null,
    bytesInspected: 0,
    truncated: false,
    established: false,
    frameworks: [],
    unsupportedFrameworks: [],
    receivers: [],
    registrations: [],
    mounts: [],
    problems: [],
    counts: { ...NO_COUNTS },
    ...extra,
  };
}

/**
 * Scan the module sources in the inventory for their middleware registrations.
 *
 * @param {object} view Repository view built by the scanner.
 * @returns {Promise<object>} The scan result's `middleware` section.
 */
export async function detectMiddleware(view) {
  const candidates = view.files
    .filter((file) => isModuleFileExtension(file.extension))
    .slice()
    .sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));

  const records = [];
  let inspected = 0;
  let totalBytes = 0;

  for (const file of candidates) {
    if (!isParsedModuleExtension(file.extension)) {
      records.push(
        sourceRecord(file, MIDDLEWARE_SOURCE_STATUSES.UNSUPPORTED, {
          reason: MIDDLEWARE_SOURCE_REASONS.FORMAT_NOT_INTERPRETED,
          detail: file.extension,
        }),
      );
      continue;
    }

    const fileBudgetLeft = MIDDLEWARE_ACQUISITION_LIMITS.maxFiles - inspected;
    const byteBudgetLeft = MIDDLEWARE_ACQUISITION_LIMITS.maxTotalBytes - totalBytes;
    if (fileBudgetLeft <= 0 || byteBudgetLeft <= 0) {
      records.push(
        sourceRecord(file, MIDDLEWARE_SOURCE_STATUSES.NOT_INSPECTED, {
          reason: MIDDLEWARE_SOURCE_REASONS.BUDGET_EXHAUSTED,
        }),
      );
      continue;
    }

    const maxBytes = Math.min(MIDDLEWARE_ACQUISITION_LIMITS.maxFileBytes, byteBudgetLeft);
    const read = await view.read(file.path, { maxBytes });
    if (!read.ok) {
      records.push(
        sourceRecord(file, MIDDLEWARE_SOURCE_STATUSES.FAILED, {
          reason: MIDDLEWARE_SOURCE_REASONS.UNREADABLE,
          detail: typeof read.error?.kind === "string" ? read.error.kind : null,
        }),
      );
      continue;
    }

    inspected += 1;
    totalBytes += read.bytesRead;

    const bytesInspected = Number.isInteger(read.bytesRead) ? read.bytesRead : 0;
    const content = typeof read.content === "string" ? read.content : "";

    if (looksBinary(content)) {
      records.push(
        sourceRecord(file, MIDDLEWARE_SOURCE_STATUSES.FAILED, {
          reason: MIDDLEWARE_SOURCE_REASONS.NOT_TEXT,
          bytesInspected,
          truncated: read.truncated === true,
        }),
      );
      continue;
    }

    const scanned = scanMiddleware(content, {
      maxTokens: MIDDLEWARE_ACQUISITION_LIMITS.maxTokensPerFile,
    });

    records.push({
      path: file.path,
      extension: file.extension,
      language: moduleLanguageOf(file.extension),
      status: MIDDLEWARE_SOURCE_STATUSES.PARSED,
      reason: null,
      detail: null,
      bytesInspected,
      truncated: read.truncated === true || scanned.truncated === true,
      established: scanned.established === true,
      frameworks: [...scanned.frameworks],
      unsupportedFrameworks: [...scanned.unsupportedFrameworks],
      receivers: scanned.receivers.map((entry) => ({ ...entry })),
      registrations: scanned.registrations.map((registration) => ({
        receiver: registration.receiver,
        receiverKind: registration.receiverKind,
        framework: registration.framework,
        registration: registration.registration,
        scope: registration.scope,
        path: registration.path,
        hook: registration.hook,
        sequence: registration.sequence,
        conditional: registration.conditional === true,
        middleware: registration.middleware.map((entry) => ({ ...entry })),
        unresolved: registration.unresolved.map((entry) => ({ ...entry })),
      })),
      mounts: scanned.mounts.map((mount) => ({ ...mount })),
      problems: [...scanned.problems],
      counts: { ...scanned.counts },
    });
  }

  const complete = records.every(
    (record) =>
      record.status === MIDDLEWARE_SOURCE_STATUSES.PARSED &&
      record.truncated !== true &&
      record.problems.length === 0,
  );

  return {
    inspected: records.some((record) => record.status === MIDDLEWARE_SOURCE_STATUSES.PARSED),
    complete,
    truncated: records.some(
      (record) =>
        record.truncated === true ||
        (record.status !== MIDDLEWARE_SOURCE_STATUSES.PARSED &&
          record.reason === MIDDLEWARE_SOURCE_REASONS.BUDGET_EXHAUSTED),
    ),
    files: records,
    limits: { ...MIDDLEWARE_ACQUISITION_LIMITS },
  };
}
