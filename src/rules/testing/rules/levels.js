/**
 * Code Guardian — Test Level Rules (Official Roadmap Phase 11)
 *
 * Three rules for the roadmap's "integration testing", "E2E testing" and "test
 * isolation" domains. Each is deliberately conservative:
 *
 *   integration.undetermined  integration testing is established only from a *named*
 *                             artifact (an `integration` directory or file, a script
 *                             or CI command the acquisition layer classified
 *                             integration-level). When tests exist but their level
 *                             cannot be established, the rule abstains with `unknown`
 *                             rather than inventing a category — the roadmap's §15.
 *   e2e.undetermined          E2E testing is established from a Playwright/Cypress
 *                             configuration or directory, an `e2e` artifact or an
 *                             E2E-level command. When tests exist but no E2E evidence
 *                             was established, the rule abstains with `unknown` — the
 *                             capability can exist among the tests without a marker,
 *                             so its absence is not established (§7). Only a
 *                             repository with no testing subject at all is
 *                             `not_applicable`; an incomplete scan is `unknown`.
 *   isolation.undetermined    no evidence this build can read establishes isolation
 *                             (a test database, a container, a fixture lifecycle or a
 *                             parallel-execution setting are none of them model
 *                             facts), so the rule never claims "tests are isolated".
 *
 * None of the three reports `verified` from a configuration file: configuration
 * detected is not execution verified.
 */

import { createRule } from "../../../core/index.js";

import {
  TESTING_BASES,
  TESTING_CATEGORY,
  TESTING_CONFIDENCE,
  TESTING_RULE_IDS,
  TESTING_RULE_VERSION,
} from "../contracts.js";
import {
  ciInventory,
  frameworkNames,
  hasTestingSubject,
  nodeManifestFacts,
  queryFor,
} from "../signals.js";

import { absenceOutcome, evidenceIdsFor, testScope } from "./shared.js";

/** Whether a path names one of a vocabulary, matched on non-alphanumeric-split segments. */
function pathNames(path, words) {
  const vocabulary = new Set(words.map((word) => word.toLowerCase()));
  for (const segment of String(path ?? "").toLowerCase().split("/")) {
    for (const word of segment.split(/[^a-z0-9]+/)) {
      if (word !== "" && vocabulary.has(word)) return true;
    }
  }
  return false;
}

/** The declared test scripts the given predicate selects, with their manifest path. */
function declaredScripts(query, predicate) {
  const out = [];
  for (const record of nodeManifestFacts(query)) {
    if (!record.parsed) continue;
    for (const script of record.testScripts) {
      if (predicate(script)) out.push({ ...script, path: record.path });
    }
  }
  return out;
}

function integrationEvidence(query) {
  const scope = testScope(query);
  const artifacts = scope.tests.filter((entity) => pathNames(entity.path, ["integration"]));
  const scripts = declaredScripts(
    query,
    (script) => script.levels.includes("integration") || script.runners.includes("jest-integration"),
  );
  const ciIntegration = ciInventory(query).entities.some((entity) =>
    (entity.testLevels ?? []).includes("integration"),
  );
  return { scope, artifacts, scripts, ciIntegration };
}

function e2eEvidence(query) {
  const scope = testScope(query);
  const frameworks = frameworkNames(query).filter((name) => ["cypress", "playwright"].includes(name));
  const artifacts = scope.tests.filter((entity) => pathNames(entity.path, ["e2e", "cypress", "playwright"]));
  const scripts = declaredScripts(
    query,
    (script) => script.levels.includes("e2e") || pathNames(script.name, ["e2e"]),
  );
  const ciE2e = ciInventory(query).entities.some((entity) => (entity.testLevels ?? []).includes("e2e"));
  return { scope, frameworks, artifacts, scripts, ciE2e };
}

export const levelRules = Object.freeze([
  createRule({
    id: TESTING_RULE_IDS.INTEGRATION_UNDETERMINED,
    version: TESTING_RULE_VERSION,
    category: TESTING_CATEGORY,
    title: "Integration testing could not be established",
    description:
      "Tests were observed, but no integration-level evidence was established: no `integration` directory or file, no test script or CI command classified integration-level. Tests outside `unit/` are not assumed to be integration tests. The rule abstains rather than inventing a category — the suite's level is unknown, not absent.",
    severity: "info",
    applicability: {},
    detect: (context) => {
      const query = queryFor(context);
      const { scope, artifacts, scripts, ciIntegration } = integrationEvidence(query);

      if (!hasTestingSubject(query)) {
        const gap = absenceOutcome(context, "no test artifacts were observed");
        if (gap.outcome) return gap.outcome;
        return {
          findings: [],
          evidence: [],
          metadata: { basis: TESTING_BASES.FILE_INVENTORY, state: "not_applicable" },
        };
      }
      if (artifacts.length > 0 || scripts.length > 0 || ciIntegration) {
        return {
          findings: [],
          evidence: [],
          metadata: {
            basis: TESTING_BASES.FILE_INVENTORY,
            state: "detected",
            artifacts: artifacts.map((entity) => entity.path).sort(),
            scripts: scripts.map((script) => script.name).sort(),
          },
        };
      }

      return {
        findings: [],
        evidence: [],
        coverage: "unknown",
        reason: "tests were observed but no integration-level evidence established which of them are integration tests",
      };
    },
    remediation: {},
    metadata: { tags: ["testing", "integration"], falsePositives: ["integration tests named by no recognised convention"] },
  }),

  createRule({
    id: TESTING_RULE_IDS.E2E_UNDETERMINED,
    version: TESTING_RULE_VERSION,
    category: TESTING_CATEGORY,
    title: "End-to-end testing is not established",
    description:
      "No end-to-end testing evidence was established: no Playwright or Cypress configuration or directory, no `e2e` artifact, and no E2E-level command. A configuration file being present would be `detected`, not `verified`. When tests exist, the absence of an E2E marker does not establish the absence of E2E testing, so the domain is `unknown`; only a repository with no testing subject at all is `not_applicable`.",
    severity: "info",
    applicability: {},
    detect: (context) => {
      const query = queryFor(context);
      const { scope, frameworks, artifacts, scripts, ciE2e } = e2eEvidence(query);

      if (frameworks.length > 0 || artifacts.length > 0 || scripts.length > 0 || ciE2e) {
        return {
          findings: [],
          evidence: [],
          metadata: { basis: TESTING_BASES.CONFIGURATION, state: "detected", frameworks },
        };
      }
      if (!hasTestingSubject(query)) {
        const gap = absenceOutcome(context, "no test artifacts were observed");
        if (gap.outcome) return gap.outcome;
        return {
          findings: [],
          evidence: [],
          metadata: { basis: TESTING_BASES.CONFIGURATION, state: "not_applicable" },
        };
      }

      // Tests exist but no E2E evidence was established. The domain applies — the
      // capability can exist among the repository's tests without any marker this
      // build recognises — so the answer is `unknown`, never `not_applicable`. This is
      // the correction Official Phase 11's state semantics require.
      return {
        findings: [],
        evidence: [],
        coverage: "unknown",
        reason: "tests were observed but no end-to-end testing evidence was established",
      };
    },
    remediation: {},
    metadata: { tags: ["testing", "e2e"], falsePositives: ["an E2E harness run outside the repository"] },
  }),

  createRule({
    id: TESTING_RULE_IDS.ISOLATION_UNDETERMINED,
    version: TESTING_RULE_VERSION,
    category: TESTING_CATEGORY,
    title: "Test isolation could not be established",
    description:
      "Test files were observed, but no evidence establishes whether the tests are isolated from one another: a test database, a container, a fixture lifecycle or a parallel-execution setting are none of them facts the repository model records. The rule never claims isolation from the existence of a `tests/` directory — it reports the observation and records the abstention.",
    severity: "info",
    applicability: {},
    detect: (context) => {
      const query = queryFor(context);
      const scope = testScope(query);
      if (!hasTestingSubject(query)) {
        const gap = absenceOutcome(context, "no test artifacts were observed");
        if (gap.outcome) return gap.outcome;
        return {
          findings: [],
          evidence: [],
          metadata: { basis: TESTING_BASES.FILE_INVENTORY, state: "not_applicable" },
        };
      }
      if (scope.tests.length === 0) {
        // A testing subject exists (a declared script, a framework identity or CI test
        // execution) but no test artifact was observed to reason about, so there is no
        // evidence to cite: abstain rather than emit an evidence-less finding.
        return {
          findings: [],
          evidence: [],
          coverage: "unknown",
          reason: "a testing subject was observed, but no test artifact is available to establish isolation",
        };
      }
      // An informational finding whose state is `unknown`: the observation is
      // surfaced with its evidence, and the metadata says plainly that the answer is
      // not `isolated` and not `clean`.
      return {
        findings: [
          {
            confidence: TESTING_CONFIDENCE.GAP_CONDITION,
            evidence: evidenceIdsFor(scope.tests),
            metadata: { basis: TESTING_BASES.FILE_INVENTORY, state: "unknown" },
          },
        ],
        evidence: [],
      };
    },
    remediation: {},
    metadata: { tags: ["testing", "isolation"], falsePositives: ["isolation provided by infrastructure outside the repository"] },
  }),
]);
