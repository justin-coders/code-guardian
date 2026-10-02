/**
 * Code Guardian — Testing Repository Signals (Official Roadmap Phase 11)
 *
 * The one place the testing rules ask the repository questions. Every read goes
 * through the Phase 11 query API over the frozen RepositoryModel: no filesystem, no
 * `node:path`, no process, no network, no scan. A rule that cannot answer a question
 * from the model reports `unknown` rather than going to look for itself.
 *
 * ### Absence is a claim, not an observation
 *
 * The absence-shaped rules can only conclude "not present", and `inventoryAbsence()`
 * decides whether the model supports it. It is deliberately conservative, and it
 * mirrors the Phase 10 security pack's rule: the scan must have covered the
 * repository completely ("the query envelope's `coverage: \"complete\"`") and no path
 * may have failed to read. Anything else leaves the answer `unknown`, which the Rule
 * Engine records as an incomplete outcome rather than a clean pass.
 *
 * ### Ignored paths do not make an answer unknown
 *
 * `node_modules`, `.git`, `dist` and a repository's own `.gitignore`d paths are
 * deliberate exclusions with a recorded reason; they are not paths the statement
 * "this repository runs its tests in CI" is about. Treating them as unknown would
 * make every real result permanently inconclusive, so their count is *reported* in
 * the audit basis instead of silently absorbed.
 */

import {
  COVERAGE_GUARANTEES,
  ENTITY_KINDS,
  createRepositoryQuery,
} from "../../repository/model/index.js";

/** Build the read-only query handle for an AnalysisContext. */
export function queryFor(context) {
  return createRepositoryQuery(context.repository);
}

/** The observed `test` entities (files, directories, configurations), sorted by id. */
export function testInventory(query) {
  return query.listEntities(ENTITY_KINDS.TEST);
}

/** Test entities that are test *files*. */
export function testFiles(query) {
  return testInventory(query).entities.filter((entity) => entity.testKind === "file");
}

/** Test entities that are test *directories*. */
export function testDirectories(query) {
  return testInventory(query).entities.filter((entity) => entity.testKind === "directory");
}

/** Test entities that are test *configurations*. */
export function testConfigurations(query) {
  return testInventory(query).entities.filter((entity) => entity.testKind === "configuration");
}

/** Every framework entity the model observed, sorted by id. */
export function frameworkInventory(query) {
  return query.listEntities(ENTITY_KINDS.FRAMEWORK);
}

/** The observed framework names, sorted. */
export function frameworkNames(query) {
  return frameworkInventory(query).entities
    .map((entity) => entity.name)
    .filter((name) => typeof name === "string")
    .sort();
}

/** The framework entity for one name, or `null`. */
export function frameworkNamed(query, name) {
  return (
    frameworkInventory(query).entities.find((entity) => entity.name === name) ?? null
  );
}

/** Every manifest entity the model observed, sorted by id. */
export function manifestInventory(query) {
  return query.listEntities(ENTITY_KINDS.MANIFEST);
}

/**
 * The Node manifests and their declared test-script facts.
 *
 * Returns one record per observed `package.json`: the path, the manifest entity, and
 * whether its metadata was parsed. A manifest whose metadata was not parsed is
 * returned too — the absence of script facts it *might* have declared is `unknown`,
 * never "declared no test script".
 */
export function nodeManifestFacts(query) {
  const records = [];
  for (const entity of manifestInventory(query).entities) {
    if (entity.ecosystemId !== "ecosystem:node") continue;
    const metadata = entity.parse?.metadata ?? null;
    records.push({
      entity,
      path: entity.path,
      parsed: entity.parse?.status === "parsed" && metadata !== null,
      parseStatus: entity.parse?.status ?? null,
      testScript: metadata?.testScript ?? null,
      testScripts: Array.isArray(metadata?.testScripts) ? metadata.testScripts : [],
      testScriptsTruncated: metadata?.testScriptsTruncated === true,
    });
  }
  return records.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
}

/** Every CI entity the model observed, sorted by id. */
export function ciInventory(query) {
  return query.listEntities(ENTITY_KINDS.CICD);
}

/**
 * Whether the repository has a testing subject at all.
 *
 * This is the prior question the *open* testing domains (integration, E2E,
 * isolation) gate on. Their markers cannot establish the capability's absence — the
 * capability can exist among the repository's tests without any marker this build
 * recognises — so an unobserved open domain is `unknown` whenever there is any
 * testing subject, and `not_applicable` only when the repository is not about testing
 * at all. A test artifact, a framework identity, a declared test script or CI test
 * execution all count.
 *
 * Pure and deterministic: it reads only the frozen model.
 *
 * @param {object} query A repository query handle.
 * @returns {boolean}
 */
export function hasTestingSubject(query) {
  if (testInventory(query).entities.length > 0) return true;
  if (frameworkInventory(query).entities.length > 0) return true;
  if (ciInventory(query).entities.some((entity) => entity.testExecution === "detected")) return true;
  return nodeManifestFacts(query).some((record) => record.parsed && record.testScripts.length > 0);
}

/**
 * A compact view of the repository's testing-relevant model facts.
 *
 * Pure and deterministic: it reads only the frozen model, consults no clock,
 * environment or random source, and returns the same shape for the same model.
 */
export function testingSignals(query) {
  const tests = testInventory(query);
  const frameworks = frameworkInventory(query);
  const ci = ciInventory(query);
  const manifests = manifestInventory(query);

  return Object.freeze({
    tests: tests.entities,
    testsCoverage: tests.coverage,
    testsTruncated: tests.truncated === true,
    testFiles: tests.entities.filter((entity) => entity.testKind === "file"),
    testDirectories: tests.entities.filter((entity) => entity.testKind === "directory"),
    testConfigurations: tests.entities.filter((entity) => entity.testKind === "configuration"),
    frameworks: frameworks.entities,
    ci: ci.entities,
    manifests: manifests.entities,
    absence: inventoryAbsence(query),
  });
}

/**
 * Whether the model supports an absence claim over the testing inventory.
 *
 * This is the file-inventory answer *plus* the evidence-cap answer: the scanner caps
 * test and CI evidence per signal, so a repository with more test files than the cap
 * carries a `test` inventory that is complete as far as it goes but not complete as
 * a *set*. An absence-shaped testing claim over such an inventory is `unknown`, never
 * a clean pass — which is exactly the difference between "no E2E test was observed"
 * and "no E2E test exists".
 *
 * @param {object} context A validated AnalysisContext.
 * @returns {{established: boolean, reason: string|null, observedFiles: number, ignoredPaths: number}}
 */
export function testingAbsence(context) {
  const fileAbsence = inventoryAbsence(createRepositoryQuery(context.repository));
  const reasons = [];
  if (!fileAbsence.established) reasons.push(fileAbsence.reason);
  if (context.repository?.tests?.evidenceTruncated === true) {
    reasons.push("the test inventory was truncated at the evidence cap");
  }
  if (context.repository?.ci?.evidenceTruncated === true) {
    reasons.push("the CI inventory was truncated at the evidence cap");
  }
  return Object.freeze({
    established: reasons.length === 0,
    reason: reasons.length === 0 ? null : reasons.join("; "),
    observedFiles: fileAbsence.observedFiles,
    ignoredPaths: fileAbsence.ignoredPaths,
  });
}

/**
 * Whether the model supports an absence claim over the file inventory.
 *
 * @param {object} query
 * @returns {{established: boolean, reason: string|null, observedFiles: number, ignoredPaths: number}}
 */
export function inventoryAbsence(query) {
  const inventory = query.listEntities(ENTITY_KINDS.FILE);
  const summary = query.coverage();
  const reasons = [];

  if (inventory.coverage !== COVERAGE_GUARANTEES.COMPLETE) {
    reasons.push(
      summary.truncated === true
        ? "the scan stopped at a limit before the inventory was complete"
        : "the scan did not cover the repository completely",
    );
  }
  if (summary.unreadableCount > 0) {
    reasons.push(`${summary.unreadableCount} path(s) could not be read`);
  }

  return Object.freeze({
    established: reasons.length === 0,
    reason: reasons.length === 0 ? null : reasons.join("; "),
    observedFiles: inventory.entities.length,
    ignoredPaths: summary.ignoredCount,
  });
}

/**
 * The evidence id of a test-related directory whose name names one of a vocabulary.
 *
 * Used by the integration/E2E rules, which may only conclude from a *named* artifact
 * or a script/command — never from "tests exist outside a `unit/` folder". Matching
 * is over the entity's own path segments, lower-cased.
 */
export function testEntitiesNaming(query, words) {
  const vocabulary = new Set(words.map((word) => word.toLowerCase()));
  return testInventory(query).entities.filter((entity) => {
    const segments = String(entity.path ?? "")
      .toLowerCase()
      .split("/");
    return segments.some((segment) => {
      for (const word of segment.split(/[^a-z0-9]+/)) {
        if (word !== "" && vocabulary.has(word)) return true;
      }
      return false;
    });
  });
}
