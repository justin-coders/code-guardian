/**
 * Code Guardian — Test Configuration Rule (Official Roadmap Phase 11)
 *
 * One rule for the roadmap's "test configuration" domain. It reports the *gap*: test
 * files were observed, but no test configuration file (a `jest.config.*`,
 * `vitest.config.*`, `playwright.config.*`, `pytest.ini`, `conftest.py`, …) was
 * observed. Configuration is reported as `detected`, never as `verified` — a
 * configuration file existing does not prove the configured suite runs or passes,
 * and the rules never claim otherwise.
 */

import { createRule } from "../../../core/index.js";

import {
  TESTING_BASES,
  TESTING_CATEGORY,
  TESTING_CONFIDENCE,
  TESTING_RULE_IDS,
  TESTING_RULE_VERSION,
} from "../contracts.js";
import { queryFor } from "../signals.js";

import { absenceOutcome, evidenceIdsFor, testScope } from "./shared.js";

export const configurationRules = Object.freeze([
  createRule({
    id: TESTING_RULE_IDS.CONFIGURATION_ABSENT,
    version: TESTING_RULE_VERSION,
    category: TESTING_CATEGORY,
    title: "Test files were observed without test configuration",
    description:
      "Test files were observed, but no recognised test configuration file was observed. A repository can run tests without a dedicated configuration file (many runners supply defaults), so this finding reports the observation and points at the evidence — it does not assert the tests are misconfigured.",
    severity: "info",
    applicability: {},
    detect: (context) => {
      const query = queryFor(context);
      const scope = testScope(query);

      if (scope.configurations.length > 0) {
        return {
          findings: [],
          evidence: [],
          metadata: {
            basis: TESTING_BASES.CONFIGURATION,
            state: "detected",
            configurations: scope.configurations.map((entity) => entity.path).sort(),
          },
        };
      }
      if (!scope.anyTests) {
        const gap = absenceOutcome(context, "no test artifacts were observed");
        if (gap.outcome) return gap.outcome;
        return {
          findings: [],
          evidence: [],
          metadata: { basis: TESTING_BASES.CONFIGURATION, state: "not_applicable" },
        };
      }

      const gap = absenceOutcome(context, "test files were observed but no test configuration was observed");
      if (gap.outcome) return gap.outcome;
      return {
        findings: [
          {
            confidence: TESTING_CONFIDENCE.GAP_CONDITION,
            evidence: evidenceIdsFor(scope.tests),
            metadata: {
              basis: TESTING_BASES.CONFIGURATION,
              state: "detected",
              observedTests: scope.tests.length,
            },
          },
        ],
        evidence: [],
      };
    },
    remediation: {},
    metadata: { tags: ["testing", "configuration"], falsePositives: ["a runner configured entirely through package.json fields"] },
  }),
]);
