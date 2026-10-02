/**
 * Code Guardian — Testing Signal Detection (Phase 8C, extended by Official
 * Roadmap Phase 11)
 *
 * Detects *evidence that tests exist*: test directories, files named after a
 * mapping the toolchains themselves use, and test configuration files.
 *
 * It deliberately does not decide whether testing is adequate, or whether the
 * detected framework is the right choice. "There is a `tests/` directory" and
 * "testing is sufficient" are different statements, and only the first is a
 * scanner fact.
 *
 * False-positive resistance is part of the rule table: a file is only a test
 * file when its name follows a convention a runner actually executes, so
 * `test-utils.js` or `latest.js` produce no signal while `auth.test.js` does.
 *
 * ### Phase 11: name is not enough for the built-in runner
 *
 * A Node project is not evidence of the Node built-in test runner: the runner is
 * established by **reading a file**, never by the project's language. Phase 11
 * therefore adds one bounded content pass over the observed *test files*: a file
 * whose source references `node:test` (or a `node --test` invocation) records the
 * `node-test` framework, which is the correction the official roadmap mandates.
 *
 * The same bounded pass records **structural flaky indicators** from the test
 * source — `Date.now()`, `Math.random()`, `setTimeout`, an outbound network call,
 * an explicit retry — as observations, never as a verdict. The roadmap asks for
 * "potential flaky patterns", so the scanner reports the structural shape it saw
 * and leaves "this test is flaky" to repeated-execution evidence this phase does
 * not produce.
 *
 * Reading is bounded exactly like the other content detectors: a per-file byte
 * cap, a global file and byte budget, the files consumed in sorted path order, and
 * anything beyond a budget left unread (which the model reads as `unknown`, not as
 * "no indicators"). No process, no network, no clock, no environment.
 */

import { capEvidence, compareEvidence, SCAN_SIGNALS } from "../contracts.js";
import { classifyTestCommand, looksBinary } from "../policies/testing.js";
import { matchEntries } from "./match.js";

/**
 * Ordered rules (most specific first). `signal` is recorded on every match so
 * consumers can tell a test *directory* from a test *file* from a *configuration*.
 */
export const TEST_RULES = Object.freeze([
  // ── Test directories (the directory entry itself is the evidence) ──────────
  { directoryName: "__tests__", signal: SCAN_SIGNALS.TEST_DIRECTORY, kind: "directory", framework: null },
  { directoryName: "tests", signal: SCAN_SIGNALS.TEST_DIRECTORY, kind: "directory", framework: null },
  { directoryName: "test", signal: SCAN_SIGNALS.TEST_DIRECTORY, kind: "directory", framework: null },
  { directoryName: "spec", signal: SCAN_SIGNALS.TEST_DIRECTORY, kind: "directory", framework: null },
  { directoryName: "specs", signal: SCAN_SIGNALS.TEST_DIRECTORY, kind: "directory", framework: null },
  { directoryName: "e2e", signal: SCAN_SIGNALS.TEST_DIRECTORY, kind: "directory", framework: null },
  { directoryName: "cypress", signal: SCAN_SIGNALS.TEST_DIRECTORY, kind: "directory", framework: "cypress" },
  { directoryName: "playwright", signal: SCAN_SIGNALS.TEST_DIRECTORY, kind: "directory", framework: "playwright" },

  // ── Test configuration (checked before file patterns) ──────────────────────
  { basename: "jest.config.js", signal: SCAN_SIGNALS.TEST_CONFIGURATION, kind: "configuration", framework: "jest" },
  { basename: "jest.config.ts", signal: SCAN_SIGNALS.TEST_CONFIGURATION, kind: "configuration", framework: "jest" },
  { basename: "jest.config.mjs", signal: SCAN_SIGNALS.TEST_CONFIGURATION, kind: "configuration", framework: "jest" },
  { basename: "jest.config.cjs", signal: SCAN_SIGNALS.TEST_CONFIGURATION, kind: "configuration", framework: "jest" },
  { basename: "jest.config.json", signal: SCAN_SIGNALS.TEST_CONFIGURATION, kind: "configuration", framework: "jest" },
  { basename: "vitest.config.ts", signal: SCAN_SIGNALS.TEST_CONFIGURATION, kind: "configuration", framework: "vitest" },
  { basename: "vitest.config.js", signal: SCAN_SIGNALS.TEST_CONFIGURATION, kind: "configuration", framework: "vitest" },
  { basename: "playwright.config.ts", signal: SCAN_SIGNALS.TEST_CONFIGURATION, kind: "configuration", framework: "playwright" },
  { basename: "playwright.config.js", signal: SCAN_SIGNALS.TEST_CONFIGURATION, kind: "configuration", framework: "playwright" },
  { basename: "cypress.config.js", signal: SCAN_SIGNALS.TEST_CONFIGURATION, kind: "configuration", framework: "cypress" },
  { basename: "cypress.config.ts", signal: SCAN_SIGNALS.TEST_CONFIGURATION, kind: "configuration", framework: "cypress" },
  { basename: "cypress.json", signal: SCAN_SIGNALS.TEST_CONFIGURATION, kind: "configuration", framework: "cypress" },
  { basename: "karma.conf.js", signal: SCAN_SIGNALS.TEST_CONFIGURATION, kind: "configuration", framework: "karma" },
  { basename: ".mocharc.js", signal: SCAN_SIGNALS.TEST_CONFIGURATION, kind: "configuration", framework: "mocha" },
  { basename: ".mocharc.json", signal: SCAN_SIGNALS.TEST_CONFIGURATION, kind: "configuration", framework: "mocha" },
  { basename: "pytest.ini", signal: SCAN_SIGNALS.TEST_CONFIGURATION, kind: "configuration", framework: "pytest" },
  { basename: "tox.ini", signal: SCAN_SIGNALS.TEST_CONFIGURATION, kind: "configuration", framework: "tox" },
  { basename: "conftest.py", signal: SCAN_SIGNALS.TEST_CONFIGURATION, kind: "configuration", framework: "pytest" },
  { basename: "phpunit.xml", signal: SCAN_SIGNALS.TEST_CONFIGURATION, kind: "configuration", framework: "phpunit" },
  { basename: "phpunit.xml.dist", signal: SCAN_SIGNALS.TEST_CONFIGURATION, kind: "configuration", framework: "phpunit" },
  { basename: ".rspec", signal: SCAN_SIGNALS.TEST_CONFIGURATION, kind: "configuration", framework: "rspec" },

  // ── Test files ────────────────────────────────────────────────────────────
  { basenamePattern: "*.test.*", signal: SCAN_SIGNALS.TEST_FILE, kind: "file", framework: null },
  { basenamePattern: "*.spec.*", signal: SCAN_SIGNALS.TEST_FILE, kind: "file", framework: null },
  { basenamePattern: "test_*.py", signal: SCAN_SIGNALS.TEST_FILE, kind: "file", framework: "pytest" },
  { basenamePattern: "*_test.py", signal: SCAN_SIGNALS.TEST_FILE, kind: "file", framework: "pytest" },
  { basenamePattern: "*_test.go", signal: SCAN_SIGNALS.TEST_FILE, kind: "file", framework: "go-test" },
  { basenamePattern: "*_test.dart", signal: SCAN_SIGNALS.TEST_FILE, kind: "file", framework: "dart-test" },
  { basenamePattern: "*_spec.rb", signal: SCAN_SIGNALS.TEST_FILE, kind: "file", framework: "rspec" },
  { basenamePattern: "*Test.java", signal: SCAN_SIGNALS.TEST_FILE, kind: "file", framework: "junit" },
  { basenamePattern: "*Tests.java", signal: SCAN_SIGNALS.TEST_FILE, kind: "file", framework: "junit" },
  { basenamePattern: "*Test.php", signal: SCAN_SIGNALS.TEST_FILE, kind: "file", framework: "phpunit" },
]);

/** Byte and file bounds on the Phase 11 content pass over test files. */
export const TESTING_ACQUISITION_LIMITS = Object.freeze({
  /** Test files whose source is read in one scan. */
  maxFiles: 200,
  /** Bytes read from any one test file. */
  maxFileBytes: 131072,
  /** Bytes read across all test files in one scan. */
  maxTotalBytes: 8 * 1024 * 1024,
});

/**
 * The source extensions whose content the pass reads. A test file in another
 * format is left with only its name-derived facts; its content is not read and no
 * framework or indicator is inferred from it.
 */
export const TEST_FILE_CONTENT_EXTENSIONS = Object.freeze([
  ".js",
  ".jsx",
  ".mjs",
  ".cjs",
  ".ts",
  ".tsx",
  ".py",
  ".rb",
  ".go",
  ".php",
  ".java",
  ".cs",
  ".fs",
  ".dart",
]);

/**
 * Structural flaky indicators, matched over the bounded source prefix.
 *
 * Every id describes a *shape*, never a verdict. `sleep-based-sync` proves a
 * timer call is present; it does not prove the test is flaky.
 */
export const TEST_FLAKY_INDICATORS = Object.freeze([
  { id: "time-dependent", matcher: /\bDate\.now\s*\(|\bnew\s+Date\s*\(|\bperformance\.now\s*\(|\bdatetime\.now\s*\(/ },
  { id: "uncontrolled-randomness", matcher: /\bMath\.random\s*\(|\brandom\.(?:random|randint)\s*\(|\brand\.Int/ },
  { id: "sleep-based-sync", matcher: /\bsetTimeout\s*\(|\bsetInterval\s*\(|\bsleep\s*\(/ },
  {
    id: "network-dependent",
    matcher: /\bfetch\s*\(|\baxios\b|\bhttp\.request\s*\(|\bhttps?\.get\s*\(|\brequests\.(?:get|post)\s*\(|\bnet\/http/,
  },
  { id: "retry-configuration", matcher: /\bretries\b|--retry\b|\bretry\s*\(/ },
]);

/** Every flaky-indicator id this detector can report. */
export const TEST_FLAKY_INDICATOR_IDS = Object.freeze(
  TEST_FLAKY_INDICATORS.map((indicator) => indicator.id),
);

/**
 * Which supported indicators a test source contains, in vocabulary order.
 *
 * @param {unknown} text
 * @returns {string[]} Sorted, de-duplicated indicator ids.
 */
export function detectTestFlakyIndicators(text) {
  if (typeof text !== "string" || text === "") return [];
  const found = new Set();
  for (const indicator of TEST_FLAKY_INDICATORS) {
    if (indicator.matcher.test(text)) found.add(indicator.id);
  }
  return [...found].sort();
}

/** Whether a test-file extension's content is read. */
function isReadableTestExtension(extension) {
  return typeof extension === "string" && TEST_FILE_CONTENT_EXTENSIONS.includes(extension);
}

/** The runner ids a test source establishes (used for the `node-test` correction). */
function runnersFromSource(text) {
  return classifyTestCommand(text).runners;
}

/**
 * Detect testing signals.
 *
 * @param {object} view Repository view.
 * @returns {Promise<{ detected: boolean, evidence: object[], evidenceTruncated: boolean,
 *   frameworks: string[], contentInspected: boolean, contentTruncated: boolean }>}
 */
export async function detectTesting(view) {
  const entries = view.directories.concat(view.files);
  const matches = matchEntries(TEST_RULES, entries);

  const evidence = [];
  const frameworks = new Set();

  for (const { rule, entry } of matches) {
    evidence.push({
      path: entry.path,
      signal: rule.signal,
      kind: rule.kind,
      framework: rule.framework,
      indicators: [],
    });
    if (rule.framework !== null) frameworks.add(rule.framework);
  }

  const ordered = evidence.sort(compareEvidence);
  const capped = capEvidence(ordered);

  // Phase 11 content pass: only over the *capped* test-file evidence, in sorted
  // order, so the read set is a deterministic function of the inventory.
  let filesRead = 0;
  let totalBytes = 0;
  let contentTruncated = false;
  let contentInspected = false;

  const fileEntries = capped.evidence.filter((entry) => entry.kind === "file");
  for (const entry of fileEntries) {
    const extension = extensionOf(entry.path);
    if (!isReadableTestExtension(extension)) continue;

    const fileBudgetLeft = TESTING_ACQUISITION_LIMITS.maxFiles - filesRead;
    const byteBudgetLeft = TESTING_ACQUISITION_LIMITS.maxTotalBytes - totalBytes;
    if (fileBudgetLeft <= 0 || byteBudgetLeft <= 0) {
      contentTruncated = true;
      break;
    }

    const maxBytes = Math.min(TESTING_ACQUISITION_LIMITS.maxFileBytes, byteBudgetLeft);
    const read = await view.read(entry.path, { maxBytes });
    if (!read.ok) continue;

    const content = typeof read.content === "string" ? read.content : "";
    if (looksBinary(content)) continue;

    filesRead += 1;
    totalBytes += Number.isInteger(read.bytesRead) ? read.bytesRead : 0;
    contentInspected = true;
    if (read.truncated === true) contentTruncated = true;

    const indicators = detectTestFlakyIndicators(content);
    if (indicators.length > 0) entry.indicators = indicators;

    // The mandated correction: the Node built-in runner is established from the
    // file's own text, and only ever fills a framework the name did not already
    // establish.
    if (entry.framework === null && runnersFromSource(content).includes("node-test")) {
      entry.framework = "node-test";
      frameworks.add("node-test");
    }
  }

  return {
    detected: capped.evidence.length > 0,
    evidence: capped.evidence,
    evidenceTruncated: capped.evidenceTruncated,
    frameworks: [...frameworks].sort(),
    contentInspected,
    contentTruncated,
  };
}

/** The lower-cased extension of a repository-relative path (POSIX, no `node:path`). */
function extensionOf(path) {
  const name = String(path).split("/").pop() ?? "";
  const dot = name.lastIndexOf(".");
  return dot <= 0 ? "" : name.slice(dot).toLowerCase();
}
