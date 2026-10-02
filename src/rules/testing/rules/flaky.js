/**
 * Code Guardian — Potential Flaky Pattern Rule (Official Roadmap Phase 11)
 *
 * One rule for the roadmap's "potential flaky patterns" domain. It is deliberately
 * the narrowest rule in the pack: it reports a **structural indicator** the bounded
 * test-file read observed — `Date.now()`, `Math.random()`, a `setTimeout`, an
 * outbound network call, an explicit retry — and describes each as a *potential*
 * flaky pattern, never as "this test is flaky". Establishing flakiness would require
 * repeated execution evidence, which this phase does not produce.
 *
 * The indicator vocabulary is the model's own (`TEST_FLAKY_INDICATORS`), re-exported
 * from the acquisition layer; the rule reads the indicator ids the `test` entity
 * carries and never re-reads the source.
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

import { absenceOutcome, testScope } from "./shared.js";

export const flakyRules = Object.freeze([
  createRule({
    id: TESTING_RULE_IDS.FLAKY_INDICATOR,
    version: TESTING_RULE_VERSION,
    category: TESTING_CATEGORY,
    title: "A potential flaky pattern was observed in a test file",
    description:
      "A test file's source contains a structural indicator associated with flaky tests: a wall-clock read, an unseeded random source, a timer used to synchronise, an outbound network call, or an explicit retry. This is a *potential* pattern, not a verdict: the finding reports the shape the source contains, and repeated-execution evidence would be required to call a test flaky.",
    severity: "low",
    applicability: {},
    detect: (context) => {
      const query = queryFor(context);
      const scope = testScope(query);

      const findings = [];
      for (const entity of scope.files) {
        const indicators = Array.isArray(entity.indicators) ? entity.indicators : [];
        if (indicators.length === 0) continue;
        findings.push({
          confidence: TESTING_CONFIDENCE.OBSERVED_CONTENT,
          evidence: [...entity.evidenceIds],
          metadata: {
            basis: TESTING_BASES.TEST_CONTENT,
            state: "detected",
            path: entity.path,
            indicators: [...indicators].sort(),
          },
        });
      }

      if (findings.length > 0) return { findings, evidence: [], metadata: { basis: TESTING_BASES.TEST_CONTENT } };

      if (!scope.anyTests) {
        const gap = absenceOutcome(context, "no test artifacts were observed");
        if (gap.outcome) return gap.outcome;
        return {
          findings: [],
          evidence: [],
          metadata: { basis: TESTING_BASES.TEST_CONTENT, state: "not_applicable" },
        };
      }

      const gap = absenceOutcome(context, "no potential flaky indicator was observed");
      if (gap.outcome) return gap.outcome;
      return {
        findings: [],
        evidence: [],
        metadata: { basis: TESTING_BASES.TEST_CONTENT, state: "not_applicable" },
      };
    },
    remediation: {},
    metadata: {
      tags: ["testing", "flaky"],
      falsePositives: ["a timer or random source that does not affect the assertion"],
    },
  }),
]);
