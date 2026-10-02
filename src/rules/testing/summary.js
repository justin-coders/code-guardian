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
 *   unknown          the domain applies but the evidence does not establish the
 *                   answer — an incomplete scan, a workflow that could not be read, a
 *                   framework identity the files do not determine, or a capability
 *                   whose markers cannot prove its absence
 *   not_applicable   the domain genuinely has no subject over *complete* coverage
 *
 * Which state an unobserved domain gets is decided by the domain's *evidence model*,
 * not by a single rule of thumb:
 *
 *   - A **closed** domain is named explicitly — a test file, a test configuration, a
 *     coverage invocation, a structural indicator. A complete scan that observed none
 *     of it establishes the domain has no subject here → `not_applicable`; an
 *     incomplete scan cannot, and the answer is `unknown`.
 *   - An **open** domain's markers cannot establish the capability's absence, because
 *     the capability can exist among the repository's tests without any marker this
 *     build recognises (integration tests named by no convention, E2E driven by a
 *     harness the repository does not configure, a test lifecycle the model does not
 *     record). When a testing subject exists, an unobserved open domain is `unknown`,
 *     never `not_applicable`; only a repository with no testing subject at all makes
 *     it `not_applicable`.
 *
 * The top-level `applicability` entry answers the prior question directly: whether the
 * repository has a testing subject at all. `not_applicable` there means exactly that —
 * there is nothing for the roadmap's testing domains to be about.
 *
 * Absence over an incomplete scan is `unknown`, never `not_applicable`: missing
 * evidence is not the same as a domain that does not apply.
 */

import { ENTITY_KINDS } from "../../repository/model/index.js";

import { TESTING_STATES } from "./contracts.js";
import {
  frameworkNames,
  hasTestingSubject,
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
 * The state of a domain whose evidence model is **closed**.
 *
 * A closed domain's artifact is named explicitly, so a complete scan that observed
 * none of it establishes the domain has no subject here → `not_applicable`. Absence
 * over an incomplete scan establishes nothing → `unknown`, never a clean absence.
 *
 * @param {{observed: boolean, coverageEstablished: boolean, failed?: boolean}} input
 * @returns {string} One of the five official states.
 */
function closedState({ observed, coverageEstablished, failed = false }) {
  if (failed) return STATES.FAILED;
  if (observed) return STATES.DETECTED;
  return coverageEstablished ? STATES.NOT_APPLICABLE : STATES.UNKNOWN;
}

/**
 * The state of a domain whose evidence model is **open**.
 *
 * An open domain's markers cannot establish the capability's absence: the capability
 * can exist among the repository's tests without any marker this build recognises. So
 * the applicability of the domain turns on whether a testing subject exists at all:
 *
 *   - no testing subject → `not_applicable` over complete coverage; `unknown` over an
 *     incomplete scan, which cannot establish that either.
 *   - testing subject exists but the domain was not observed → `unknown`. This is the
 *     correction Official Phase 11's state semantics require: absence of evidence for
 *     a capability that can exist without a marker is *not* `not_applicable`.
 *
 * @param {{observed: boolean, hasSubject: boolean, coverageEstablished: boolean}} input
 * @returns {string} One of the five official states.
 */
function openState({ observed, hasSubject, coverageEstablished }) {
  if (observed) return STATES.DETECTED;
  if (hasSubject) return STATES.UNKNOWN;
  return coverageEstablished ? STATES.NOT_APPLICABLE : STATES.UNKNOWN;
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
    state: closedState({
      observed: testFiles.length > 0,
      coverageEstablished: absence.established,
    }),
    count: testFiles.length,
    directories: testDirectories.map((entity) => entity.path).sort(),
  };

  // ── Test configuration ────────────────────────────────────────────────────
  const configurationEntry = {
    state: closedState({
      observed: testConfigurations.length > 0,
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

  // Whether the repository has a testing subject at all — the prior question the
  // open domains (integration, E2E, isolation) gate on, shared with the rules so a
  // rule's outcome and the summary's state cannot disagree.
  const subjectExists = hasTestingSubject(query);
  const applicabilityEntry = {
    state: subjectExists
      ? STATES.DETECTED
      : absence.established
        ? STATES.NOT_APPLICABLE
        : STATES.UNKNOWN,
    hasSubject: subjectExists,
    observedTests: tests.length,
  };
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
    state: closedState({
      observed: coverageCommands.length > 0,
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
    state: openState({
      observed: integrationObserved,
      hasSubject: subjectExists,
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
    state: openState({
      observed: e2eObserved,
      hasSubject: subjectExists,
      coverageEstablished: absence.established,
    }),
    frameworks: e2eFrameworks,
    artifacts: [...e2eArtifacts].sort(),
    scripts: [...e2eScripts].sort(),
  };

  // ── Test isolation ────────────────────────────────────────────────────────
  // No evidence this build can read establishes isolation: it would require a test
  // database, a container, a fixture lifecycle or a parallel-execution setting,
  // none of which the model records. So isolation is an *open* domain — never
  // observed, and `unknown` whenever a testing subject exists, never "isolated" and
  // never `not_applicable` merely because the analyzer cannot determine it.
  const isolationEntry = {
    state: openState({
      observed: false,
      hasSubject: subjectExists,
      coverageEstablished: absence.established,
    }),
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
    state: closedState({
      observed: flakyIndicators.length > 0,
      coverageEstablished: absence.established,
    }),
    indicators: flakyIndicators,
    locations: flakyByPath.sort((a, b) => (a.path < b.path ? -1 : 1)),
  };

  return Object.freeze({
    applicability: Object.freeze(applicabilityEntry),
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
