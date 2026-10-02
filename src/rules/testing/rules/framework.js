/**
 * Code Guardian — Test Framework Rules (Official Roadmap Phase 11)
 *
 * Two rules for the roadmap's "test framework" domain:
 *
 *   testing.framework.unestablished        test files were observed, but no framework
 *                                          identity could be established (Fixture C)
 *   testing.framework.node-built-in-runner the Node built-in test runner was detected
 *                                          from evidence (the correction Phase 11
 *                                          mandates)
 *
 * The second rule deliberately lives in the *reportable* set even though its
 * condition is a capability rather than a defect: the roadmap requires the analyzer
 * to distinguish `detected` from `verified`, and a `detected` state is only useful
 * if it is surfaced. Its severity is `info` — the finding is a confirmation, not a
 * warning — and its wording states exactly what the evidence established: the test
 * source references `node:test` (or a configured command runs `node --test`), not
 * that the suite passes.
 */

import { createRule } from "../../../core/index.js";

import {
  TESTING_BASES,
  TESTING_CATEGORY,
  TESTING_CONFIDENCE,
  TESTING_RULE_IDS,
  TESTING_RULE_VERSION,
} from "../contracts.js";
import { frameworkInventory, frameworkNames, queryFor, testInventory } from "../signals.js";

import { absenceOutcome, evidenceIdsFor, testScope } from "./shared.js";

/** The `test` entities that report the Node built-in runner. */
function nodeTestEntities(query) {
  return testInventory(query).entities.filter((entity) => entity.frameworkId === "framework:node-test");
}

export const frameworkRules = Object.freeze([
  createRule({
    id: TESTING_RULE_IDS.FRAMEWORK_UNESTABLISHED,
    version: TESTING_RULE_VERSION,
    category: TESTING_CATEGORY,
    title: "Test files were observed without an established framework",
    description:
      "Test files matching a runner convention were observed, but no framework was established for them: no framework configuration file was observed and the file names do not determine a runner. The repository's test runner is therefore not established by this build's evidence. The finding reports the observation, not a claim that the tests do not run.",
    severity: "info",
    applicability: {},
    detect: (context) => {
      const query = queryFor(context);
      const scope = testScope(query);
      const frameworks = frameworkNames(query);

      if (frameworks.length > 0) {
        return { findings: [], evidence: [], metadata: { basis: TESTING_BASES.FILE_INVENTORY, frameworks } };
      }
      if (!scope.anyTests) {
        const gap = absenceOutcome(context, "no test artifacts were observed");
        if (gap.outcome) return gap.outcome;
        return {
          findings: [],
          evidence: [],
          metadata: { basis: TESTING_BASES.FILE_INVENTORY, state: "not_applicable" },
        };
      }

      // Tests exist but their framework is not established. Over a complete inventory
      // this is the roadmap's Fixture C; over a truncated one it is `unknown`, because
      // the framework may be declared by a test file the cap did not include.
      const gap = absenceOutcome(context, "test files were observed but no framework was established");
      if (gap.outcome) return gap.outcome;
      return {
        findings: [
          {
            confidence: TESTING_CONFIDENCE.OBSERVED_ARTIFACT,
            evidence: evidenceIdsFor(scope.tests),
            metadata: {
              basis: TESTING_BASES.FILE_INVENTORY,
              state: "unknown",
              observedTests: scope.tests.length,
            },
          },
        ],
        evidence: [],
      };
    },
    remediation: {},
    metadata: { tags: ["testing", "framework"], falsePositives: ["tests whose runner is declared outside the repository"] },
  }),

  createRule({
    id: TESTING_RULE_IDS.NODE_BUILT_IN_RUNNER,
    version: TESTING_RULE_VERSION,
    category: TESTING_CATEGORY,
    title: "The Node built-in test runner is used",
    description:
      "The Node built-in test runner was established from evidence: an observed test file references `node:test`, or a configured command runs `node --test`. This finding records the detection — it does not assert that the suite passes. Prior to Official Roadmap Phase 11 the built-in runner was omitted by language-based detection; it is now established by content, never because the project is Node.",
    severity: "info",
    applicability: {},
    detect: (context) => {
      const query = queryFor(context);
      const framework = frameworkInventory(query).entities.find((entity) => entity.name === "node-test");
      if (framework === undefined) {
        const scope = testScope(query);
        if (!scope.anyTests) {
          const gap = absenceOutcome(context, "no test artifacts were observed");
          if (gap.outcome) return gap.outcome;
        }
        return {
          findings: [],
          evidence: [],
          metadata: { basis: TESTING_BASES.TEST_CONTENT, state: "not_applicable" },
        };
      }

      const tests = nodeTestEntities(query);
      return {
        findings: [
          {
            confidence: TESTING_CONFIDENCE.OBSERVED_CONTENT,
            evidence: [...new Set([...evidenceIdsFor([framework]), ...evidenceIdsFor(tests)])].sort(),
            metadata: {
              basis: TESTING_BASES.TEST_CONTENT,
              state: "detected",
              framework: "node-test",
              tests: tests.map((entity) => entity.path).sort(),
            },
          },
        ],
        evidence: [],
      };
    },
    remediation: {},
    metadata: { tags: ["testing", "framework", "node"], falsePositives: ["a `node:test` reference in a comment or a string"] },
  }),
]);
