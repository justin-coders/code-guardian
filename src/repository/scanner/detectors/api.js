/**
 * Code Guardian — API Route Acquisition Detector (Phase 18)
 *
 * The scanner's API detector: it decides which inventory files are module sources,
 * reads each one through the Phase 8A boundary under an explicit byte budget, hands the
 * text to the pure scanner in `policies/api.js`, and returns **one record per module
 * source**.
 *
 * ### Acquisition, not resolution
 *
 * This detector answers "which routes does this file declare". It does **not** resolve
 * a handler to a symbol: that needs the symbol graph and the repository's own
 * declarations, and it is the model's question, because the model owns identity.
 * Keeping the split here is what stops the scanner from inventing a handler the
 * repository never declared.
 *
 * ### It reads code, and says so
 *
 * This is the sixth bounded read of file bytes in the scanner, and it is bounded the
 * same way as the module and semantic reads: a closed extension set, a per-file byte
 * cap, a global file cap, a global byte budget and a per-file token cap, all consumed
 * in the inventory's sorted order so the scanned set is deterministic. A file beyond a
 * budget is recorded as `not-inspected`, never silently skipped, because "this file
 * was not read" and "this file declares no route" must never be the same fact.
 *
 * ### What it refuses to guess
 *
 * JSX and TSX are recorded as `unsupported` module sources rather than scanned as if
 * they were plain JavaScript, exactly as the semantic detector does. A file whose lexer
 * failed establishes no route at all, and the model cites that answer instead of
 * second-guessing it.
 *
 * No process, no network, no clock, no environment, no filesystem write.
 */

import {
  API_ACQUISITION_LIMITS,
  API_SOURCE_REASONS,
  API_SOURCE_STATUSES,
  isModuleFileExtension,
  isParsedModuleExtension,
  moduleLanguageOf,
  scanApiRoutes,
} from "../policies/api.js";

/** Whether the inspected prefix is text rather than binary. */
function looksBinary(text) {
  return text.includes("\u0000");
}

/** The zero counts every record carries, so no status has a missing field. */
const NO_COUNTS = Object.freeze({
  tokens: 0,
  routes: 0,
  shapes: 0,
  receivers: 0,
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
    aliases: [],
    receivers: [],
    routes: [],
    shapes: [],
    problems: [],
    counts: { ...NO_COUNTS },
    ...extra,
  };
}

/**
 * Scan the module sources in the inventory for their API route declarations.
 *
 * @param {object} view Repository view built by the scanner.
 * @returns {Promise<object>} The scan result's `api` section.
 */
export async function detectApi(view) {
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
        sourceRecord(file, API_SOURCE_STATUSES.UNSUPPORTED, {
          reason: API_SOURCE_REASONS.FORMAT_NOT_INTERPRETED,
          detail: file.extension,
        }),
      );
      continue;
    }

    const fileBudgetLeft = API_ACQUISITION_LIMITS.maxFiles - inspected;
    const byteBudgetLeft = API_ACQUISITION_LIMITS.maxTotalBytes - totalBytes;
    if (fileBudgetLeft <= 0 || byteBudgetLeft <= 0) {
      records.push(
        sourceRecord(file, API_SOURCE_STATUSES.NOT_INSPECTED, {
          reason: API_SOURCE_REASONS.BUDGET_EXHAUSTED,
        }),
      );
      continue;
    }

    const maxBytes = Math.min(API_ACQUISITION_LIMITS.maxFileBytes, byteBudgetLeft);
    const read = await view.read(file.path, { maxBytes });
    if (!read.ok) {
      records.push(
        sourceRecord(file, API_SOURCE_STATUSES.FAILED, {
          reason: API_SOURCE_REASONS.UNREADABLE,
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
        sourceRecord(file, API_SOURCE_STATUSES.FAILED, {
          reason: API_SOURCE_REASONS.NOT_TEXT,
          bytesInspected,
          truncated: read.truncated === true,
        }),
      );
      continue;
    }

    const scanned = scanApiRoutes(content, {
      extension: file.extension,
      maxTokens: API_ACQUISITION_LIMITS.maxTokensPerFile,
    });

    records.push({
      path: file.path,
      extension: file.extension,
      language: moduleLanguageOf(file.extension),
      status: API_SOURCE_STATUSES.PARSED,
      reason: null,
      detail: null,
      bytesInspected,
      truncated: read.truncated === true || scanned.truncated === true,
      established: scanned.established === true,
      frameworks: [...scanned.frameworks],
      unsupportedFrameworks: [...scanned.unsupportedFrameworks],
      aliases: scanned.aliases.map((entry) => ({ ...entry })),
      receivers: scanned.receivers.map((entry) => ({ ...entry })),
      routes: scanned.routes.map((route) => ({
        method: route.method,
        path: route.path,
        receiver: route.receiver,
        framework: route.framework,
        receiverKind: route.receiverKind,
        form: route.form,
        handler: route.handler === null ? null : { ...route.handler },
        middleware: route.middleware.map((entry) => ({ ...entry })),
      })),
      shapes: scanned.shapes.map((shape) => ({ ...shape })),
      problems: [...scanned.problems],
      counts: { ...scanned.counts },
    });
  }

  const complete = records.every(
    (record) =>
      record.status === API_SOURCE_STATUSES.PARSED &&
      record.truncated !== true &&
      record.problems.length === 0,
  );

  return {
    inspected: records.some((record) => record.status === API_SOURCE_STATUSES.PARSED),
    complete,
    truncated: records.some(
      (record) =>
        record.truncated === true ||
        (record.status !== API_SOURCE_STATUSES.PARSED &&
          record.reason === API_SOURCE_REASONS.BUDGET_EXHAUSTED),
    ),
    files: records,
    limits: { ...API_ACQUISITION_LIMITS },
  };
}
