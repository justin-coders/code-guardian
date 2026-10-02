/**
 * Code Guardian — Coverage Configuration Rule (Official Roadmap Phase 11)
 *
 * One rule for the roadmap's "coverage configuration" domain. It distinguishes
 * coverage *configuration* from coverage *results*: the rule can establish that a
 * coverage invocation is declared (a `test:coverage` script, a workflow running
 * `--coverage`), and it can never establish a measured percentage or a passed
 * threshold, because this phase reads no coverage output.
 *
 * The finding is only emitted when test infrastructure exists and no coverage
 * invocation was observed; the description says exactly that, so "coverage is not
 * configured" is never read as "coverage is low".
 */

import { createRule } from "../../../core/index.js";

import {
  TESTING_BASES,
  TESTING_CATEGORY,
  TESTING_CONFIDENCE,
  TESTING_RULE_IDS,
  TESTING_RULE_VERSION,
} from "../contracts.js";
import { ciInventory, nodeManifestFacts, queryFor } from "../signals.js";

import { absenceOutcome, evidenceIdsFor, testScope } from "./shared.js";

/** Every coverage-command id the repository declares across scripts and CI. */
function declaredCoverageCommands(query) {
  const commands = new Set();
  const evidenceIds = new Set();
  for (const record of nodeManifestFacts(query)) {
    if (!record.parsed) continue;
    for (const script of record.testScripts) {
      for (const id of script.coverage ?? []) commands.add(id);
      if ((script.coverage ?? []).length > 0) for (const id of record.entity.evidenceIds) evidenceIds.add(id);
    }
  }
  for (const entity of ciInventory(query).entities) {
    for (const id of entity.coverageCommands ?? []) commands.add(id);
    if ((entity.coverageCommands ?? []).length > 0) for (const id of entity.evidenceIds) evidenceIds.add(id);
  }
  return { commands: [...commands].sort(), evidenceIds: [...evidenceIds].sort() };
}

export const coverageRules = Object.freeze([
  createRule({
    id: TESTING_RULE_IDS.COVERAGE_UNCONFIGURED,
    version: TESTING_RULE_VERSION,
    category: TESTING_CATEGORY,
    title: "No coverage configuration was detected",
    description:
      "Test infrastructure was observed, but no coverage invocation was declared: no test-related script runs a coverage flag or tool (for example `--experimental-test-coverage`, `--coverage`, `nyc`, `c8`) and no observed workflow does either. This is coverage *configuration*, not coverage *results*: the repository provides no measured coverage in this build, and no percentage or threshold is asserted.",
    severity: "info",
    applicability: {},
    detect: (context) => {
      const query = queryFor(context);
      const scope = testScope(query);
      const { commands, evidenceIds } = declaredCoverageCommands(query);

      if (commands.length > 0) {
        return {
          findings: [],
          evidence: [],
          metadata: { basis: TESTING_BASES.MANIFEST_SCRIPT, state: "detected", commands },
        };
      }
      if (!scope.anyTests) {
        const gap = absenceOutcome(context, "no test artifacts were observed");
        if (gap.outcome) return gap.outcome;
        return {
          findings: [],
          evidence: [],
          metadata: { basis: TESTING_BASES.MANIFEST_SCRIPT, state: "not_applicable" },
        };
      }

      const gap = absenceOutcome(context, "test infrastructure was observed but no coverage configuration was detected");
      if (gap.outcome) return gap.outcome;
      return {
        findings: [
          {
            confidence: TESTING_CONFIDENCE.GAP_CONDITION,
            evidence: evidenceIds.length > 0 ? evidenceIds : evidenceIdsFor(scope.tests),
            metadata: { basis: TESTING_BASES.MANIFEST_SCRIPT, state: "detected", commands: [] },
          },
        ],
        evidence: [],
      };
    },
    remediation: {},
    metadata: { tags: ["testing", "coverage"], falsePositives: ["coverage enabled only in a CI matrix this build did not read"] },
  }),
]);
