/**
 * Code Guardian — Import Acquisition Detector (Phase 16)
 *
 * The scanner's import detector: it decides which inventory files are module
 * sources, reads each one through the Phase 8A boundary under an explicit byte
 * budget, hands the text to the pure tokenizer/scanner in `policies/imports.js`,
 * and returns **one record per module source**.
 *
 * ### Acquisition, not resolution
 *
 * This detector answers \"which module specifiers does this file literally state\".
 * It does **not** decide what those specifiers point at: resolution needs the
 * inventory of observed files, and that is the model's question (it owns entity
 * identity). Keeping the split here is what stops the scanner from inventing a
 * file that the walk never saw.
 *
 * ### It reads code, which is a deliberate change of scope
 *
 * Phase 8C read file bytes in exactly three places (manifests, git, content
 * candidates). This is the fourth, and it is bounded the same way: a closed
 * extension set, a per-file byte cap, a global file cap, a global byte budget and a
 * per-file token cap, all consumed in the inventory's sorted order so the parsed
 * set is deterministic. A file beyond a budget is recorded as `not-inspected`, never
 * silently skipped, because \"this file was not read\" and \"this file imports
 * nothing\" must never be the same fact.
 *
 * ### What it refuses to guess
 *
 * JSX and TSX are recorded as `unsupported` module sources rather than parsed as if
 * they were plain JavaScript: this build implements no JSX syntax, and reporting a
 * half-parsed JSX file as a fully-parsed module is precisely the kind of quiet
 * wrongness that makes a graph untrustworthy. Non-JS languages are not module
 * sources for this graph at all — the scanner's language detector already records
 * them, and this graph never claimed to cover their imports.
 *
 * No process, no network, no clock, no environment, no filesystem write.
 */

import {
  IMPORT_ACQUISITION_LIMITS,
  IMPORT_SOURCE_REASONS,
  IMPORT_SOURCE_STATUSES,
  isModuleFileExtension,
  isParsedModuleExtension,
  moduleLanguageOf,
  parseModuleReferences,
} from "../policies/imports.js";

/** Whether the inspected prefix is text rather than binary. */
function looksBinary(text) {
  return text.includes("\u0000");
}

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
    nonStatic: 0,
    nonStaticReasons: [],
    problems: [],
    references: [],
    ...extra,
  };
}

/**
 * Detect import declarations across the module sources in the inventory.
 *
 * @param {object} view Repository view built by the scanner.
 * @returns {Promise<object>} The scan result's `imports` section.
 */
export async function detectImports(view) {
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
        sourceRecord(file, IMPORT_SOURCE_STATUSES.UNSUPPORTED, {
          reason: IMPORT_SOURCE_REASONS.FORMAT_NOT_INTERPRETED,
          detail: file.extension,
        }),
      );
      continue;
    }

    const fileBudgetLeft = IMPORT_ACQUISITION_LIMITS.maxFiles - inspected;
    const byteBudgetLeft = IMPORT_ACQUISITION_LIMITS.maxTotalBytes - totalBytes;
    if (fileBudgetLeft <= 0 || byteBudgetLeft <= 0) {
      records.push(
        sourceRecord(file, IMPORT_SOURCE_STATUSES.NOT_INSPECTED, {
          reason: IMPORT_SOURCE_REASONS.BUDGET_EXHAUSTED,
        }),
      );
      continue;
    }

    const maxBytes = Math.min(IMPORT_ACQUISITION_LIMITS.maxFileBytes, byteBudgetLeft);
    const read = await view.read(file.path, { maxBytes });
    if (!read.ok) {
      records.push(
        sourceRecord(file, IMPORT_SOURCE_STATUSES.FAILED, {
          reason: IMPORT_SOURCE_REASONS.UNREADABLE,
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
        sourceRecord(file, IMPORT_SOURCE_STATUSES.FAILED, {
          reason: IMPORT_SOURCE_REASONS.NOT_TEXT,
          bytesInspected,
          truncated: read.truncated === true,
        }),
      );
      continue;
    }

    const parsed = parseModuleReferences(content, {
      extension: file.extension,
      maxTokens: IMPORT_ACQUISITION_LIMITS.maxTokensPerFile,
    });

    const nonStaticReasons = [...new Set(parsed.nonStatic.map((entry) => entry.reason))].sort();

    records.push({
      path: file.path,
      extension: file.extension,
      language: moduleLanguageOf(file.extension),
      status: IMPORT_SOURCE_STATUSES.PARSED,
      reason: null,
      detail: null,
      bytesInspected,
      // A file read only up to the byte cap, or lexed only up to the token cap, is
      // truncated: the tail of it was never read, so its references are a prefix.
      truncated: read.truncated === true || parsed.truncated === true,
      nonStatic: parsed.nonStatic.length,
      nonStaticReasons,
      problems: [...parsed.problems].sort(),
      references: parsed.references.map((reference) => ({
        kind: reference.kind,
        specifier: reference.specifier,
      })),
    });
  }

  // \"Every module source was fully interpreted\" is vacuously true when the
  // repository has no module source at all — the same honest shape the dependency
  // section uses, and the reason `inspected` and `complete` are separate facts.
  const complete = records.every(
    (record) =>
      record.status === IMPORT_SOURCE_STATUSES.PARSED &&
      record.truncated !== true &&
      record.problems.length === 0,
  );

  return {
    inspected: records.some((record) => record.status === IMPORT_SOURCE_STATUSES.PARSED),
    complete,
    truncated: records.some(
      (record) =>
        record.truncated === true ||
        (record.status !== IMPORT_SOURCE_STATUSES.PARSED &&
          record.reason === IMPORT_SOURCE_REASONS.BUDGET_EXHAUSTED),
    ),
    files: records,
    limits: { ...IMPORT_ACQUISITION_LIMITS },
  };
}
