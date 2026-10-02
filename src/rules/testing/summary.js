/**
 * Code Guardian — Testing Summary (Official Roadmap Phase 11)
 *
 * The analyzer's structured answer to "what testing infrastructure does this
 * repository declare, and what can be established about it". It is a pure function
 * of the frozen RepositoryModel, so two runs over the same model produce the same
 * map — no clock, no random source, no unordered iteration.
 *
 * Each of the nine roadmap domains carries a `state` drawn from the five official
 * states (`detected`, `verified`, `failed`, `unknown`, `not_applicable`) plus the
 * domain's own facts. The mapping is deliberately conservative:
 *
 *   detected        an artifact/capability was observed, but nothing established it
 *                   works
 *   verified         a test script is configured **and** CI is observed executing a
 *                   matching runner — the roadmap's own definition of verification
 *   failed           an expected operation demonstrably failed (a `package.json`
 *                   whose parse failed, so its declared scripts cannot be read)
 *   unknown          the evidence needed was not established — an incomplete scan, a
 *                   workflow that could not be read, or a framework identity the
 *                   files do not determine
 *   not_applicable   the domain has no subject over *complete* coverage (no tests, no
 *                   CI, no configuration to analyze)
 *
 * Absence over an incomplete scan is `unknown`, never `not_applicable`: missing
 * evidence is not the same as a domain that does not apply.
 */

import { ENTITY_KINDS } from "../../repository/model/index.js";

import { TESTING_STATES } from "./contracts.js";
import {
  frameworkNames,
  nodeManifestFacts,
  queryFor,
  testInventory,
  testingAbsence,
} from "./signals.js";

const STATES = TESTING_STATES;

/** Whether an entity path names one of a vocabulary, matched on path segments. */
function pathNames(path, words) {
  const vocabulary = new Set(words.map((word) => word.toLowerCase()));
  for (const segment of String(path ?? "").toLowerCase().split("/")) {
    for (const word of segment.split(/[^a-z0-9]+/)) {
      if (word !== "" && vocabulary.has(word)) return true;
    }
  }
  return false;
}

/** The union of a list of string arrays, sorted and de-duplicated. */
function unionSorted(lists) {
  const set = new Set();
  for (const list of lists) {
    for (const value of list) if (typeof value === "string") set.add(value);
  }
  return [...set].sort();
}

/**
 * Choose a domain state from whether the artifact was observed and whether the
 * model's coverage is complete enough to conclude from its absence.
 *
 * Absence over an incomplete scan is `unknown`. Absence over a complete scan is
 * `not_applicable` — there is no artifact of this domain to analyze, which is the
 * Rule Engine's own reading of "this does not apply".
 */
function stateFrom({ observed, coverageEstablished, failed = false }) {
  if (failed) return STATES.FAILED;
  if (observed) return STATES.DETECTED;
  if (coverageEstablished) return STATES.NOT_APPLICABLE;
  return STATES.UNKNOWN;
}

/**
 * Build the testing summary for an AnalysisContext.
 *
 * @param {object} context A validated AnalysisContext.
 * @returns {object} Frozen summary with one entry per roadmap domain.
 */
export function summarizeTesting(context) {
  const query = queryFor(context);
  const tests = testInventory(query).entities;
  const testFiles = tests.filter((entity) => entity.testKind === "file");
  const testDirectories = tests.filter((entity) => entity.testKind === "directory");
  const testConfigurations = tests.filter((entity) => entity.testKind === "configuration");

  const absence = testingAbsence(context);
  const frameworks = frameworkNames(query);
  const manifests = nodeManifestFacts(query);
  const ci = query.listEntities(ENTITY_KINDS.CICD).entities;

  const anyTests = tests.length > 0;
  const ciRunners = unionSorted(ci.map((entity) => entity.testRunners ?? []));
  const ciLevels = unionSorted(ci.map((entity) => entity.testLevels ?? []));
  const ciCoverage = unionSorted(ci.map((entity) => entity.coverageCommands ?? []));
  const ciExecutesTests = ci.some((entity) => entity.testExecution === "detected");
  const ciAllUnknown =
    ci.length > 0 &&
    ci.every((entity) => entity.testExecution === "unknown") &&
    !ciExecutesTests;

  // ── Framework ─────────────────────────────────────────────────────────────
  const frameworkVerifiedBy = frameworks.filter((name) => ciRunners.includes(name));
  const framework = {
    state:
      frameworks.length > 0
        ? frameworkVerifiedBy.length > 0
          ? STATES.VERIFIED
          : STATES.DETECTED
        : anyTests
          ? // Tests were observed but their framework identity cannot be established from
            // the evidence — Fixture C's "framework unknown", never a guess.
            STATES.UNKNOWN
          : absence.established
            ? STATES.NOT_APPLICABLE
            : STATES.UNKNOWN,
    frameworks,
    verifiedBy: frameworkVerifiedBy,
  };

  // ── Test files ────────────────────────────────────────────────────────────
  const filesEntry = {
    state: stateFrom({
      observed: testFiles.length > 0,
      applicable: true,
      coverageEstablished: absence.established,
    }),
    count: testFiles.length,
    directories: testDirectories.map((entity) => entity.path).sort(),
  };

  // ── Test configuration ────────────────────────────────────────────────────
  const configurationEntry = {
    state: stateFrom({
      observed: testConfigurations.length > 0,
      applicable: anyTests,
      coverageEstablished: absence.established,
    }),
    configurations: testConfigurations.map((entity) => entity.path).sort(),
  };

  // ── Test scripts ──────────────────────────────────────────────────────────
  const parsedManifests = manifests.filter((record) => record.parsed);
  const failedManifests = manifests.filter((record) => record.parseStatus === "failed");
  const declaredTestScripts = parsedManifests.flatMap((record) =>
    record.testScripts.map((script) => ({ ...script, path: record.path })),
  );
  const scriptRunners = unionSorted(declaredTestScripts.map((script) => script.runners));
  const scriptsVerified = scriptRunners.some((runner) => ciRunners.includes(runner));
  const scriptsEntry = {
    state: manifests.length === 0
      ? STATES.NOT_APPLICABLE
      : failedManifests.length > 0 && parsedManifests.length === 0
        ? STATES.FAILED
        : declaredTestScripts.length > 0
          ? scriptsVerified
            ? STATES.VERIFIED
            : STATES.DETECTED
          : parsedManifests.length > 0
            ? STATES.NOT_APPLICABLE
            : STATES.UNKNOWN,
    scripts: declaredTestScripts,
    truncated: manifests.some((record) => record.testScriptsTruncated),
  };

  // ── CI execution ──────────────────────────────────────────────────────────
  const ciEntry = {
    state: ci.length === 0
      ? STATES.NOT_APPLICABLE
      : ciExecutesTests
        ? frameworkVerifiedBy.length > 0 || scriptsVerified
          ? STATES.VERIFIED
          : STATES.DETECTED
        : ciAllUnknown
          ? STATES.UNKNOWN
          : STATES.NOT_APPLICABLE,
    providers: unionSorted(ci.map((entity) => entity.provider ?? [])),
    executesTests: ciExecutesTests,
    runners: ciRunners,
    levels: ciLevels,
  };

  // ── Coverage configuration ────────────────────────────────────────────────
  const coverageCommands = unionSorted([
    ...declaredTestScripts.map((script) => script.coverage),
    ciCoverage,
  ]);
  const coverageEntry = {
    state: stateFrom({
      observed: coverageCommands.length > 0,
      applicable: anyTests,
      coverageEstablished: absence.established,
    }),
    // Deliberately never `verified`: this phase establishes coverage *configuration*
    // and never a measured coverage percentage.
    commands: coverageCommands,
  };

  // ── Integration ───────────────────────────────────────────────────────────
  const integrationArtifacts = tests
    .filter((entity) => pathNames(entity.path, ["integration"]))
    .map((entity) => entity.path);
  const integrationScripts = declaredTestScripts
    .filter((script) => script.levels.includes("integration") || script.runners.includes("jest-integration"))
    .map((script) => script.name);
  const integrationObserved =
    integrationArtifacts.length > 0 ||
    integrationScripts.length > 0 ||
    ciLevels.includes("integration");
  const integrationEntry = {
    state: stateFrom({
      observed: integrationObserved,
      applicable: anyTests,
      coverageEstablished: absence.established,
    }),
    artifacts: [...integrationArtifacts].sort(),
    scripts: [...integrationScripts].sort(),
  };

  // ── End-to-end ────────────────────────────────────────────────────────────
  const e2eFrameworks = frameworks.filter((name) => ["cypress", "playwright"].includes(name));
  const e2eArtifacts = tests
    .filter((entity) => pathNames(entity.path, ["e2e", "cypress", "playwright"]))
    .map((entity) => entity.path);
  const e2eScripts = declaredTestScripts
    .filter((script) => script.levels.includes("e2e") || pathNames(script.name, ["e2e"]))
    .map((script) => script.name);
  const e2eObserved =
    e2eFrameworks.length > 0 ||
    e2eArtifacts.length > 0 ||
    e2eScripts.length > 0 ||
    ciLevels.includes("e2e");
  const e2eEntry = {
    state: stateFrom({
      observed: e2eObserved,
      applicable: anyTests,
      coverageEstablished: absence.established,
    }),
    frameworks: e2eFrameworks,
    artifacts: [...e2eArtifacts].sort(),
    scripts: [...e2eScripts].sort(),
  };

  // ── Test isolation ────────────────────────────────────────────────────────
  // No evidence this build can read establishes isolation: it would require a test
  // database, a container, a fixture lifecycle or a parallel-execution setting,
  // none of which the model records. The honest answer with tests present is
  // `unknown`, never "isolated" and never "not applicable".
  const isolationEntry = {
    state: anyTests ? STATES.UNKNOWN : STATES.NOT_APPLICABLE,
    evidence: [],
  };

  // ── Potential flaky patterns ──────────────────────────────────────────────
  const flakyByPath = [];
  for (const entity of testFiles) {
    const indicators = Array.isArray(entity.indicators) ? entity.indicators : [];
    if (indicators.length > 0) flakyByPath.push({ path: entity.path, indicators: [...indicators].sort() });
  }
  const flakyIndicators = unionSorted(flakyByPath.map((entry) => entry.indicators));
  const flakyEntry = {
    state: stateFrom({
      observed: flakyIndicators.length > 0,
      applicable: anyTests,
      coverageEstablished: absence.established,
    }),
    indicators: flakyIndicators,
    locations: flakyByPath.sort((a, b) => (a.path < b.path ? -1 : 1)),
  };

  return Object.freeze({
    framework: Object.freeze(framework),
    testFiles: Object.freeze(filesEntry),
    testConfiguration: Object.freeze(configurationEntry),
    testScripts: Object.freeze(scriptsEntry),
    ciExecution: Object.freeze(ciEntry),
    coverage: Object.freeze(coverageEntry),
    integration: Object.freeze(integrationEntry),
    e2e: Object.freeze(e2eEntry),
    isolation: Object.freeze(isolationEntry),
    flaky: Object.freeze(flakyEntry),
    coverageBasis: absence,
  });
}
