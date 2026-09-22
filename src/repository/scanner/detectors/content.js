/**
 * Code Guardian — Content Inspection Detector (Phase 12 correction)
 *
 * Phase 12 originally read no file content at all, so a `.npmrc` holding a live
 * registry token, a `.tfvars` holding a database password and a SQL dump holding
 * `IDENTIFIED BY '…'` were all invisible: the model recorded only names. This
 * detector adds the smallest capability that closes that gap without turning the
 * scanner into a secret scanner.
 *
 * What it does, precisely:
 *
 *   - inspects a **closed candidate set** — package-manager credentials
 *     (`.npmrc`, `.pypirc`), direnv (`.envrc`), dotenv files, Terraform variable
 *     files and SQL dumps — matched against the *inventory* the walk already
 *     produced. Nothing is discovered by guessing names on disk, so an ignored
 *     path is not inspected either;
 *   - reads each candidate through the Phase 8A boundary with an explicit byte
 *     cap, so a 2 GB dump costs 64 KiB of memory, not 2 GB;
 *   - applies a **closed pattern vocabulary** of credential-shaped structures
 *     (key blocks, `name = value` assignments, URLs with inline userinfo, SQL
 *     password statements). Patterns are matched on a bounded slice of each line,
 *     so no input can make matching super-linear;
 *   - reports **which pattern** matched, never what it matched. The value, the
 *     line and the file's bytes never leave this function.
 *
 * What it deliberately does not do: no entropy analysis, no heuristics, no
 * third-party scanner, no network, no execution, no interpretation of the file's
 * format. A `pass` here means "this bounded inspection found no supported pattern",
 * which is a much weaker claim than "this file is clean" — which is exactly why the
 * candidate record carries the limits that were in force, and why a file that could
 * not be fully inspected is marked so rather than reported as clean.
 *
 * Budgeting is deterministic: files are inspected in the inventory's sorted order,
 * and the byte budget is consumed in that order, so the same repository always
 * yields the same inspected set. A budget that runs out is *recorded* per candidate
 * (`budget-exhausted`), never silently dropped.
 */

import { matchEntries } from "./match.js";

/** Hard bounds on one scan's content inspection. */
export const CONTENT_INSPECTION_LIMITS = Object.freeze({
  /** Bytes read from any single candidate. */
  maxFileBytes: 65536,
  /** Bytes read across all candidates in one scan. */
  maxTotalBytes: 262144,
  /** Candidates inspected in one scan. */
  maxFiles: 12,
  /** Longest prefix of a line any pattern is matched against. */
  maxLineBytes: 512,
  /** Lines examined per candidate. */
  maxLines: 2000,
});

/** Candidate classes, recorded so a consumer knows *why* a file was inspected. */
export const CONTENT_CANDIDATE_CLASSES = Object.freeze({
  NPM_CONFIG: "npm-config",
  PYPI_CONFIG: "pypi-config",
  DIRENV: "direnv",
  DOTENV: "dotenv",
  TERRAFORM_VARS: "terraform-vars",
  SQL_DUMP: "sql-dump",
});

/**
 * Which inventory files are candidates, most specific first.
 *
 * The table is data, not code (the same convention every other detector uses):
 * a reviewer can read the entire candidate set at a glance, and there is no way
 * for a rule to widen it at runtime.
 */
export const CONTENT_CANDIDATE_RULES = Object.freeze([
  { basename: [".npmrc"], signal: CONTENT_CANDIDATE_CLASSES.NPM_CONFIG },
  { basename: [".pypirc"], signal: CONTENT_CANDIDATE_CLASSES.PYPI_CONFIG },
  { basename: [".envrc"], signal: CONTENT_CANDIDATE_CLASSES.DIRENV },
  { basename: [".env"], signal: CONTENT_CANDIDATE_CLASSES.DOTENV },
  { basenamePattern: ".env.*", signal: CONTENT_CANDIDATE_CLASSES.DOTENV },
  { basenamePattern: "*.tfvars", signal: CONTENT_CANDIDATE_CLASSES.TERRAFORM_VARS },
  { basenamePattern: "*.tfvars.json", signal: CONTENT_CANDIDATE_CLASSES.TERRAFORM_VARS },
  // Extensions in this codebase's rule tables include the dot (they come from
  // `path.extname`), so the match is against `.sql`, not `sql`.
  { extension: [".sql"], signal: CONTENT_CANDIDATE_CLASSES.SQL_DUMP },
]);

/**
 * The closed pattern vocabulary.
 *
 * Each entry is an id plus a linear-time matcher over a bounded line prefix. A
 * pattern is a *shape*, never a value: `credential-assignment` proves that
 * something shaped like `password = …` is present, not what the password is.
 */
export const CONTENT_PATTERNS = Object.freeze([
  {
    id: "private-key-block",
    // A PEM private-key header. Public certificates carry a different header
    // ("CERTIFICATE"), so this does not fire on a certificate chain.
    matcher: /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/,
  },
  {
    id: "credential-assignment",
    // `NAME = value` / `NAME: value`, where NAME mentions a credential. Covers
    // ini- and dotenv-style files (`.pypirc`, `.envrc`, `.env`, `*.tfvars`) and
    // scoped npm settings (`//registry/:_authToken=…`).
    matcher:
      /(?:^|[\s;:"'(=/])(?:[A-Za-z0-9_.-]+[/:])*[A-Za-z0-9_.-]*(?:password|passwd|secret|token|apikey|api[_-]?key|access[_-]?key|client[_-]?secret|private[_-]?key|auth(?:token|orization)?)\s*[:=]\s*\S/i,
  },
  {
    id: "aws-credential-assignment",
    // The two AWS values that are secrets in their own right.
    matcher: /AWS_(?:SECRET_ACCESS_KEY|SESSION_TOKEN)\s*[:=]\s*\S/i,
  },
  {
    id: "basic-auth-url",
    // `scheme://user:password@host` — credentials embedded in a URL.
    matcher: /:\/\/[^\s/:@]+:[^\s/@:@]+@/,
  },
  {
    id: "sql-password-statement",
    // Passwords stated in DDL/DCL: `IDENTIFIED BY '…'`, `WITH PASSWORD '…'`.
    matcher: /(?:IDENTIFIED BY|WITH PASSWORD|SET PASSWORD)\s+\S/i,
  },
]);

/** Every pattern id this detector can report. */
export const CONTENT_PATTERN_IDS = Object.freeze(CONTENT_PATTERNS.map((entry) => entry.id));

/** Why a candidate's content was not inspected. */
export const CONTENT_INSPECTION_REASONS = Object.freeze({
  /** The byte or file budget for this scan was already spent. */
  BUDGET_EXHAUSTED: "budget-exhausted",
  /** The candidate could not be read (a filesystem condition, classified). */
  UNREADABLE: "unreadable",
  /** The candidate is not text (it contains a NUL byte in the inspected prefix). */
  NOT_TEXT: "not-text",
});

const REASON_VALUES = Object.freeze(Object.values(CONTENT_INSPECTION_REASONS));

/** Whether a value is an inspection reason this detector can produce. */
export function isContentInspectionReason(value) {
  return typeof value === "string" && REASON_VALUES.includes(value);
}

/** Whether `text` looks binary inside the inspected prefix. */
function looksBinary(text) {
  return text.includes("\u0000");
}

/**
 * Which supported patterns a text body contains, in vocabulary order.
 *
 * Matching is line-wise over a bounded prefix, so the work is bounded by
 * `maxLines × maxLineBytes × patterns` regardless of input.
 *
 * @param {string} text
 * @returns {string[]} Sorted, de-duplicated pattern ids.
 */
export function detectContentPatterns(text) {
  if (typeof text !== "string" || text === "") return [];

  const found = new Set();
  const lines = text.split("\n", CONTENT_INSPECTION_LIMITS.maxLines + 1);
  const limit = Math.min(lines.length, CONTENT_INSPECTION_LIMITS.maxLines);

  for (let index = 0; index < limit; index += 1) {
    const line = lines[index].slice(0, CONTENT_INSPECTION_LIMITS.maxLineBytes);
    for (const pattern of CONTENT_PATTERNS) {
      if (found.has(pattern.id)) continue;
      if (pattern.matcher.test(line)) found.add(pattern.id);
    }
  }

  return [...found].sort();
}

function candidateRecord(entry, candidateClass, extra) {
  return {
    path: entry.path,
    candidate: candidateClass,
    inspected: false,
    reason: null,
    bytesInspected: 0,
    truncated: false,
    patterns: [],
    ...extra,
  };
}

/**
 * Inspect the candidate set.
 *
 * @param {object} view Repository view built by the scanner.
 * @returns {Promise<object>} The scan result's `content` section.
 */
export async function detectContent(view) {
  const matches = matchEntries(CONTENT_CANDIDATE_RULES, view.files);
  const candidates = [];
  let inspectedFiles = 0;
  let totalBytes = 0;

  for (const { rule, entry } of matches) {
    const fileBudgetLeft = CONTENT_INSPECTION_LIMITS.maxFiles - inspectedFiles;
    const byteBudgetLeft = CONTENT_INSPECTION_LIMITS.maxTotalBytes - totalBytes;

    if (fileBudgetLeft <= 0 || byteBudgetLeft <= 0) {
      candidates.push(
        candidateRecord(entry, rule.signal, {
          reason: CONTENT_INSPECTION_REASONS.BUDGET_EXHAUSTED,
        }),
      );
      continue;
    }

    const maxBytes = Math.min(CONTENT_INSPECTION_LIMITS.maxFileBytes, byteBudgetLeft);
    const result = await view.read(entry.path, { maxBytes });

    if (!result.ok) {
      candidates.push(
        candidateRecord(entry, rule.signal, {
          reason: CONTENT_INSPECTION_REASONS.UNREADABLE,
        }),
      );
      continue;
    }

    inspectedFiles += 1;
    totalBytes += result.bytesRead;

    const bytesInspected = result.bytesRead;
    const truncated = result.truncated === true;
    const content = typeof result.content === "string" ? result.content : "";

    if (looksBinary(content)) {
      candidates.push(
        candidateRecord(entry, rule.signal, {
          reason: CONTENT_INSPECTION_REASONS.NOT_TEXT,
          bytesInspected,
          truncated,
        }),
      );
      continue;
    }

    candidates.push({
      path: entry.path,
      candidate: rule.signal,
      inspected: true,
      reason: null,
      bytesInspected,
      truncated,
      patterns: detectContentPatterns(content),
    });
  }

  const complete = candidates.every(
    (candidate) => candidate.inspected === true && candidate.truncated !== true,
  );

  return {
    inspected: candidates.some((candidate) => candidate.inspected === true),
    complete,
    truncated: candidates.some(
      (candidate) =>
        candidate.truncated === true ||
        candidate.reason === CONTENT_INSPECTION_REASONS.BUDGET_EXHAUSTED,
    ),
    candidates,
    limits: { ...CONTENT_INSPECTION_LIMITS },
  };
}
