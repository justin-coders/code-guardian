/**
 * Code Guardian — Dependency Repository Signals (Phase 13)
 *
 * The one place dependency rules ask the repository questions. Every read goes
 * through the Phase 11 query API over the frozen RepositoryModel: no filesystem, no
 * `node:path`, no manifest parsing, no package manager, no registry, no network, no
 * process. A rule that cannot answer a question from the model reports `unknown`
 * rather than going to look for itself — which is the whole point of acquiring
 * dependency intelligence once, in the scanner.
 *
 * ### Declarations are flattened here, provenance is not
 *
 * A model dependency carries one declaration *per manifest*, so a query answer is a
 * list of `(dependency, declaration)` pairs — each with its own scope, specifier and
 * evidence ids. Flattening is a convenience; the pairing is what keeps a
 * multi-manifest repository's contradictory declarations readable side by side
 * instead of collapsed into one.
 */

import { createRepositoryQuery } from "../../repository/model/index.js";

import {
  DEPENDENCY_SIGNALS,
  compareDeclarations,
} from "./contracts.js";

/**
 * Build the read-only query handle for an AnalysisContext.
 *
 * @param {object} context A validated AnalysisContext.
 * @returns {object} A frozen query handle.
 */
export function queryFor(context) {
  return createRepositoryQuery(context.repository);
}

/**
 * Every declaration the repository's manifests made, flattened with provenance.
 *
 * Sorted by `(manifestPath, name)` so the order never depends on entity id order or
 * on object iteration — the same repository always yields the same list.
 *
 * @param {object} query
 * @returns {Array<{dependencyId: string, ecosystem: string, name: string,
 *   manifestId: string, manifestPath: string, scope: string, spec: string|null,
 *   specKind: string, direct: boolean, conditional: boolean, evidenceIds: string[]}>}
 */
export function dependencyDeclarations(query) {
  const declarations = [];

  for (const dependency of query.listDependencies().entities) {
    for (const declaration of dependency.declarations ?? []) {
      declarations.push({
        dependencyId: dependency.id,
        ecosystem: dependency.ecosystem,
        name: dependency.name,
        manifestId: declaration.manifestId,
        manifestPath: declaration.manifestPath,
        scope: declaration.scope,
        spec: declaration.spec ?? null,
        specKind: declaration.specKind,
        direct: declaration.direct === true,
        conditional: declaration.conditional === true,
        evidenceIds: [...(declaration.evidenceIds ?? [])],
      });
    }
  }

  return declarations.sort(compareDeclarations);
}

/**
 * What dependency acquisition established, and every source that stopped it.
 *
 * `unestablishedSources` is the honest half: it names each manifest whose
 * declarations were not fully interpreted, so a rule can say *why* it cannot
 * conclude instead of reporting a clean repository.
 *
 * @param {object} query
 * @returns {object} Frozen coverage statement.
 */
export function dependencyAcquisitionCoverage(query) {
  return query.dependencyCoverage();
}

/**
 * The dependency observations recorded for a dependency entity.
 *
 * Returns the model's own Evidence records — never fabricated, renamed or
 * re-provenanced. `kind` is the recorded signal, so a caller can distinguish a
 * declaration observation from a resolution one.
 *
 * @param {object} query
 * @param {string} dependencyId
 * @returns {Array<{id: string, kind: string|null, location: object, data: object}>}
 */
export function dependencyObservations(query, dependencyId) {
  const result = query.getEvidenceForEntity(dependencyId);
  const observations = [];

  for (const record of result.evidence ?? []) {
    const signal = record?.data?.signal;
    const kind =
      signal === DEPENDENCY_SIGNALS.DECLARATION ||
      signal === DEPENDENCY_SIGNALS.RESOLUTION ||
      signal === DEPENDENCY_SIGNALS.SOURCE
        ? signal
        : null;
    observations.push({ id: record.id, kind, location: record.location, data: record.data });
  }
  return observations.sort((a, b) => (a.id < b.id ? -1 : 1));
}

/**
 * Whether the model supports an absence claim over the dependency inventory.
 *
 * A claim like "no dependency is declared" is only as good as what was read: the
 * scan must have covered the repository completely *and* every dependency source
 * must have been interpreted. Ignored paths do not enter this decision for the same
 * reason they do not in the security pack — a `.gitignore`d `node_modules` is not a
 * declaration the repository made.
 *
 * @param {object} query
 * @returns {{established: boolean, reason: string|null, sources: number}}
 */
export function dependencyAbsence(query) {
  const coverage = dependencyAcquisitionCoverage(query);
  const inventory = query.coverage();
  const reasons = [];

  if (coverage.unestablishedSources.length > 0) {
    reasons.push(
      `${coverage.unestablishedSources.length} manifest(s) were not fully interpreted`,
    );
  }
  if (coverage.complete !== true) {
    // Reachable with no source named: a scan whose dependency acquisition never ran
    // (an older model) reports no sources *and* no completeness, which must not read
    // as "this repository declares nothing".
    reasons.push("dependency acquisition did not establish every manifest's declarations");
  }
  if (inventory.complete !== true) {
    reasons.push(
      inventory.truncated === true
        ? "the scan stopped at a limit before the inventory was complete"
        : "the scan did not cover the repository completely",
    );
  }

  return Object.freeze({
    established: reasons.length === 0 && coverage.complete === true,
    reason: reasons.length === 0 && coverage.complete === true ? null : reasons.join("; "),
    sources: coverage.unestablishedSources.length,
  });
}
