/**
 * Code Guardian — CI Test Execution Rule (Official Roadmap Phase 11)
 *
 * One rule for the roadmap's "CI execution" domain, and the one place the pack
 * asserts the roadmap's `verified` state:
 *
 *   a CI workflow was observed whose content contains a test invocation
 *                    → the domain is `verified` and the rule passes
 *   CI is configured but no workflow was observed executing tests
 *                    → a finding: "CI is configured but no test execution was established"
 *   a workflow could not be read
 *                    → `unknown`, never a pass and never a finding
 *
 * The rule deliberately does **not** treat the mere presence of `.github/workflows`
 * as test execution, and it does not implement the later CI/CD analyzer: it reads
 * only the testing-related fact the acquisition layer recorded.
 */

import { createRule } from "../../../core/index.js";

import {
  TESTING_BASES,
  TESTING_CATEGORY,
  TESTING_CONFIDENCE,
  TESTING_RULE_IDS,
  TESTING_RULE_VERSION,
} from "../contracts.js";
import { ciInventory, queryFor } from "../signals.js";

import { absenceOutcome, evidenceIdsFor, testScope } from "./shared.js";

export const ciRules = Object.freeze([
  createRule({
    id: TESTING_RULE_IDS.CI_TESTS_NOT_EXECUTED,
    version: TESTING_RULE_VERSION,
    category: TESTING_CATEGORY,
    title: "No test execution was established in CI",
    description:
      "The repository configures continuous integration, but no observed workflow was established to execute a test command: either the workflow content contains no recognisable test invocation, or no CI configuration was observed at all while tests exist. A workflow that runs `npm test`, `node --test`, `pytest` or another runner establishes execution; `.github/workflows` merely existing does not.",
    severity: "medium",
    applicability: {},
    detect: (context) => {
      const query = queryFor(context);
      const scope = testScope(query);
      const ci = ciInventory(query).entities;

      // A workflow that was read and contains a test invocation verifies the domain.
      if (ci.some((entity) => entity.testExecution === "detected")) {
        return {
          findings: [],
          evidence: [],
          metadata: {
            basis: TESTING_BASES.CI_CONTENT,
            state: "verified",
            providers: ci.map((entity) => entity.provider).sort(),
          },
        };
      }

      if (ci.length === 0) {
        if (!scope.anyTests) {
          const gap = absenceOutcome(context, "no test artifacts were observed");
          if (gap.outcome) return gap.outcome;
          return {
            findings: [],
            evidence: [],
            metadata: { basis: TESTING_BASES.CI_CONTENT, state: "not_applicable" },
          };
        }
        const gap = absenceOutcome(context, "no CI configuration was observed");
        if (gap.outcome) return gap.outcome;
        return {
          findings: [
            {
              confidence: TESTING_CONFIDENCE.GAP_CONDITION,
              evidence: evidenceIdsFor(scope.tests),
              metadata: { basis: TESTING_BASES.CI_CONTENT, state: "detected", configuration: "none" },
            },
          ],
          evidence: [],
        };
      }

      // CI exists but no workflow was read far enough to establish execution.
      if (ci.some((entity) => entity.testExecution === "unknown")) {
        return {
          findings: [],
          evidence: [],
          coverage: "unknown",
          reason: "a CI workflow could not be read, so whether it executes tests is not established",
        };
      }

      return {
        findings: [
          {
            confidence: TESTING_CONFIDENCE.OBSERVED_CONTENT,
            evidence: evidenceIdsFor(ci),
            metadata: {
              basis: TESTING_BASES.CI_CONTENT,
              state: "detected",
              configuration: "read-no-tests",
              providers: ci.map((entity) => entity.provider).sort(),
            },
          },
        ],
        evidence: [],
      };
    },
    remediation: {},
    metadata: { tags: ["testing", "ci"], falsePositives: ["a workflow whose test command this build does not recognise"] },
  }),
]);
