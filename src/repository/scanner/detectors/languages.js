/**
 * Code Guardian — Language Detection (Phase 8C)
 *
 * A language is reported only when there is *file-level evidence* for it:
 *
 *   - a source file whose extension is in `LANGUAGE_EXTENSIONS`, or
 *   - a manifest/lockfile whose ecosystem implies the language.
 *
 * A directory name never implies a language. `python/` without a single `.py`,
 * manifest or lockfile produces no language claim, because the scanner collects
 * facts and must not guess.
 *
 * The extension table is deliberately bounded and documented. An extension that
 * is absent from it is simply not reported — there is no fuzzy matching, no
 * filename inspection and no content sniffing. Extending the table is a data
 * change, not a code change.
 *
 * Evidence is capped per language (`MAX_EVIDENCE_PER_SIGNAL`) and the truncation
 * is reported on the entry, so a bounded evidence list can never be mistaken for
 * the complete set of observations.
 */

import {
  capEvidence,
  compareEvidence,
  SCAN_SIGNALS,
} from "../contracts.js";

/** Source extensions mapped to a language id. Values are lower-case by design. */
export const LANGUAGE_EXTENSIONS = Object.freeze({
  ".js": "javascript",
  ".mjs": "javascript",
  ".cjs": "javascript",
  ".jsx": "javascript",
  ".ts": "typescript",
  ".mts": "typescript",
  ".cts": "typescript",
  ".tsx": "typescript",
  ".py": "python",
  ".pyi": "python",
  ".pyw": "python",
  ".ipynb": "python",
  ".java": "java",
  ".kt": "kotlin",
  ".kts": "kotlin",
  ".go": "go",
  ".rs": "rust",
  ".c": "c",
  ".h": "c",
  ".cc": "cpp",
  ".cpp": "cpp",
  ".cxx": "cpp",
  ".hpp": "cpp",
  ".hh": "cpp",
  ".hxx": "cpp",
  ".cs": "csharp",
  ".fs": "fsharp",
  ".fsx": "fsharp",
  ".fsi": "fsharp",
  ".php": "php",
  ".phtml": "php",
  ".rb": "ruby",
  ".dart": "dart",
  ".swift": "swift",
  ".scala": "scala",
  ".sh": "shell",
  ".bash": "shell",
  ".zsh": "shell",
  ".ksh": "shell",
  ".sql": "sql",
  ".html": "html",
  ".htm": "html",
  ".css": "css",
  ".scss": "css",
  ".sass": "css",
  ".less": "css",
  ".vue": "vue",
  ".svelte": "svelte",
  ".lua": "lua",
  ".pl": "perl",
  ".pm": "perl",
  ".r": "r",
  ".ex": "elixir",
  ".exs": "elixir",
});

const LANGUAGE_SIGNAL_ORDER = Object.freeze({
  [SCAN_SIGNALS.SOURCE_EXTENSION]: 0,
  [SCAN_SIGNALS.MANIFEST]: 1,
  [SCAN_SIGNALS.LOCKFILE]: 2,
});

/**
 * Detect languages from file extensions and manifest evidence.
 *
 * @param {object} view Repository view (`files` must be path-sorted).
 * @param {object[]} [manifests] Output of the manifests detector.
 * @returns {object[]} Language entries, sorted by id.
 */
export function detectLanguages(view, manifests = []) {
  const accumulated = new Map();

  const record = (id, evidence, extension) => {
    let entry = accumulated.get(id);
    if (entry === undefined) {
      entry = { id, fileCount: 0, extensions: new Set(), evidence: [] };
      accumulated.set(id, entry);
    }
    entry.evidence.push(evidence);
    if (extension !== null) {
      entry.fileCount += 1;
      entry.extensions.add(extension);
    }
  };

  for (const file of view.files) {
    const id = LANGUAGE_EXTENSIONS[file.extension];
    if (id === undefined) continue;
    record(
      id,
      { path: file.path, signal: SCAN_SIGNALS.SOURCE_EXTENSION },
      file.extension,
    );
  }

  for (const manifest of manifests) {
    const signal =
      manifest.kind === "lockfile"
        ? SCAN_SIGNALS.LOCKFILE
        : SCAN_SIGNALS.MANIFEST;
    for (const id of manifest.languages ?? []) {
      record(id, { path: manifest.path, signal }, null);
    }
  }

  return [...accumulated.values()]
    .sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0))
    .map((entry) => {
      const ordered = [...entry.evidence].sort(compareEvidence);
      const { evidence, evidenceTruncated } = capEvidence(ordered);
      return {
        id: entry.id,
        fileCount: entry.fileCount,
        extensions: [...entry.extensions].sort(),
        evidence,
        evidenceTruncated,
        signals: [...new Set(ordered.map((item) => item.signal))].sort(
          (a, b) => LANGUAGE_SIGNAL_ORDER[a] - LANGUAGE_SIGNAL_ORDER[b],
        ),
      };
    });
}
