/**
 * Code Guardian — Testing Signal Detection (Phase 8C)
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
 */

import { capEvidence, compareEvidence, SCAN_SIGNALS } from "../contracts.js";
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

/**
 * Detect testing signals.
 *
 * @param {object} view Repository view.
 * @returns {{ detected: boolean, evidence: object[], evidenceTruncated: boolean, frameworks: string[] }}
 */
export function detectTesting(view) {
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
    });
    if (rule.framework !== null) frameworks.add(rule.framework);
  }

  const ordered = evidence.sort(compareEvidence);
  const capped = capEvidence(ordered);

  return {
    detected: ordered.length > 0,
    evidence: capped.evidence,
    evidenceTruncated: capped.evidenceTruncated,
    frameworks: [...frameworks].sort(),
  };
}
