/**
 * Code Guardian — Symbol Acquisition Detector (Phase 17)
 *
 * The scanner's semantic detector: it decides which inventory files are module
 * sources, reads each one through the Phase 8A boundary under an explicit byte
 * budget, hands the text to the pure scanner in `policies/semantics.js`, and returns
 * **one record per module source**.
 *
 * ### Acquisition, not resolution
 *
 * This detector answers "what does this file declare, export, reference and call".
 * It does **not** decide whether a reference resolves: that needs the whole
 * repository (another file's exports, the observed inventory) and it is the model's
 * question, because the model owns identity. Keeping the split here is what stops the
 * scanner from inventing a symbol the repository never declared.
 *
 * ### It reads code, and says so
 *
 * Phase 8C read file bytes in exactly three places; Phase 16 added module sources and
 * this is the fifth read, bounded the same way: a closed extension set, a per-file
 * byte cap, a global file cap, a global byte budget and a per-file token cap, all
 * consumed in the inventory's sorted order so the scanned set is deterministic. A
 * file beyond a budget is recorded as `not-inspected`, never silently skipped,
 * because "this file was not read" and "this file declares nothing" must never be
 * the same fact.
 *
 * ### What it refuses to guess
 *
 * JSX and TSX are recorded as `unsupported` module sources rather than scanned as if
 * they were plain JavaScript: this build implements no JSX syntax, and reporting a
 * half-scanned JSX file as a fully-scanned module is exactly the kind of quiet
 * wrongness that makes a semantic graph untrustworthy. The scanner itself then
 * decides, per file, whether its declarations and its resolution are *established* —
 * a file with a lexical failure establishes neither, and the model cites that
 * decision instead of second-guessing it.
 *
 * No process, no network, no clock, no environment, no filesystem write.
 */

import {
  SEMANTIC_ACQUISITION_LIMITS,
  SEMANTIC_SOURCE_REASONS,
  SEMANTIC_SOURCE_STATUSES,
  isModuleFileExtension,
  isParsedModuleExtension,
  moduleLanguageOf,
  scanModuleSemantics,
} from "../policies/semantics.js";

/** Whether the inspected prefix is text rather than binary. */
function looksBinary(text) {
  return text.includes("\u0000");
}

/** The empty establishment statement: nothing was scanned, so nothing is claimed. */
const NOTHING_ESTABLISHED = Object.freeze({
  declarations: false,
  resolution: false,
  exports: false,
});

/** The zero counts every record carries, so no status has a missing field. */
const NO_COUNTS = Object.freeze({
  declarations: 0,
  exports: 0,
  names: 0,
  references: 0,
  calls: 0,
  constructs: 0,
  tokens: 0,
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
    established: { ...NOTHING_ESTABLISHED },
    counts: { ...NO_COUNTS },
    declarations: [],
    exports: [],
    starExports: [],
    references: [],
    problems: [],
    ...extra,
  };
}

/**
 * Scan the module sources in the inventory for their semantic facts.
 *
 * @param {object} view Repository view built by the scanner.
 * @returns {Promise<object>} The scan result's `semantics` section.
 */
export async function detectSemantics(view) {
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
        sourceRecord(file, SEMANTIC_SOURCE_STATUSES.UNSUPPORTED, {
          reason: SEMANTIC_SOURCE_REASONS.FORMAT_NOT_INTERPRETED,
          detail: file.extension,
        }),
      );
      continue;
    }

    const fileBudgetLeft = SEMANTIC_ACQUISITION_LIMITS.maxFiles - inspected;
    const byteBudgetLeft = SEMANTIC_ACQUISITION_LIMITS.maxTotalBytes - totalBytes;
    if (fileBudgetLeft <= 0 || byteBudgetLeft <= 0) {
      records.push(
        sourceRecord(file, SEMANTIC_SOURCE_STATUSES.NOT_INSPECTED, {
          reason: SEMANTIC_SOURCE_REASONS.BUDGET_EXHAUSTED,
        }),
      );
      continue;
    }

    const maxBytes = Math.min(SEMANTIC_ACQUISITION_LIMITS.maxFileBytes, byteBudgetLeft);
    const read = await view.read(file.path, { maxBytes });
    if (!read.ok) {
      records.push(
        sourceRecord(file, SEMANTIC_SOURCE_STATUSES.FAILED, {
          reason: SEMANTIC_SOURCE_REASONS.UNREADABLE,
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
        sourceRecord(file, SEMANTIC_SOURCE_STATUSES.FAILED, {
          reason: SEMANTIC_SOURCE_REASONS.NOT_TEXT,
          bytesInspected,
          truncated: read.truncated === true,
        }),
      );
      continue;
    }

    const scanned = scanModuleSemantics(content, {
      extension: file.extension,
      maxTokens: SEMANTIC_ACQUISITION_LIMITS.maxTokensPerFile,
    });

    records.push({
      path: file.path,
      extension: file.extension,
      language: moduleLanguageOf(file.extension),
      status: SEMANTIC_SOURCE_STATUSES.PARSED,
      reason: null,
      detail: null,
      bytesInspected,
      // A file read only up to the byte cap, or lexed only up to a token cap, is
      // truncated: the tail of it was never read, so its declarations are a prefix.
      truncated: read.truncated === true || scanned.truncated === true,
      established: { ...scanned.established },
      counts: { ...scanned.counts },
      declarations: scanned.declarations.map((declaration) => ({
        name: declaration.name,
        kinds: [...declaration.kinds],
        keywords: [...declaration.keywords],
        exported: declaration.exported === true,
        exportNames: [...declaration.exportNames],
        callable: declaration.callable,
        constructable: declaration.constructable,
        shadowed: declaration.shadowed === true,
        reassigned: declaration.reassigned === true,
        binding:
          declaration.binding === null
            ? null
            : {
                bindingKind: declaration.binding.bindingKind,
                importedName: declaration.binding.importedName,
                specifier: declaration.binding.specifier,
                typeOnly: declaration.binding.typeOnly === true,
              },
      })),
      exports: scanned.exports.map((entry) => ({ ...entry })),
      starExports: [...scanned.starExports],
      references: scanned.references.map((entry) => ({ ...entry })),
      problems: [...scanned.problems],
    });
  }

  // "Every module source was scanned" is vacuously true when the repository has no
  // module source at all — the same honest shape the import and dependency sections
  // use, and the reason `inspected` and `complete` are separate facts.
  const complete = records.every(
    (record) =>
      record.status === SEMANTIC_SOURCE_STATUSES.PARSED &&
      record.truncated !== true &&
      record.problems.length === 0,
  );

  return {
    inspected: records.some((record) => record.status === SEMANTIC_SOURCE_STATUSES.PARSED),
    complete,
    truncated: records.some(
      (record) =>
        record.truncated === true ||
        (record.status !== SEMANTIC_SOURCE_STATUSES.PARSED &&
          record.reason === SEMANTIC_SOURCE_REASONS.BUDGET_EXHAUSTED),
    ),
    files: records,
    limits: { ...SEMANTIC_ACQUISITION_LIMITS },
  };
}
