/**
 * Code Guardian Core — RepositoryModel Contract
 *
 * The RepositoryModel represents *observed repository facts*, never judgments.
 *
 * Correct:   configuration.envFiles = [{ path: ".env" }]
 * Incorrect: configuration.security = "bad"
 *
 * A scanner collects facts; analyzers decide whether a fact is a problem.
 *
 * The model also explicitly represents incomplete scanning so that
 * "not inspected" can never silently become "not found".
 *
 * This module defines the shape/constants/factory only. It does not scan,
 * import transports, or execute commands.
 */

/** Version of the RepositoryModel contract. */
export const REPOSITORY_MODEL_VERSION = "1";

/**
 * Required top-level areas of a RepositoryModel.
 * Each area must be present (it may be empty) so that consumers can rely on
 * the shape, but the contract requires no analysis judgments.
 */
export const REPOSITORY_MODEL_AREAS = Object.freeze([
  "identity",
  "files",
  "languages",
  "frameworks",
  "manifests",
  "dependencies",
  "scripts",
  "configuration",
  "git",
  "tests",
  "ci",
  "architecture",
  // Phase 16 — the module/import substrate: which files import which files, as
  // established by parsing supported JavaScript/TypeScript source. A required area
  // like every other one (the factory always emits it, empty by default) because a
  // consumer must be able to tell "this repository establishes no import" from "this
  // model says nothing about imports at all".
  "imports",
  // Phase 17 — the semantic substrate: which names each module declares at its top
  // level, what it exports, what its references and calls establish, and what an
  // import binding points at. A required area like every other one (the factory
  // always emits it, empty by default) because a consumer must be able to tell "this
  // repository establishes no symbol" from "this model says nothing about symbols".
  "symbols",
  "scan",
  "metadata",
]);

/** Fields every `scan` state must declare (Phase 7 Blueprint §6). */
export const SCAN_REQUIRED_FIELDS = Object.freeze([
  "complete",
  "truncated",
  "limits",
  "errors",
]);

/**
 * Default scanner limits. These are the maxima a scanner is expected to
 * declare; they are recorded in `scan.limits` so truncation is observable.
 */
export const DEFAULT_SCAN_LIMITS = Object.freeze({
  maxFiles: 10000,
  maxDepth: 20,
});

/**
 * Areas that must never be required as judgments. Exported for documentation
 * and regression tests: the fact model deliberately omits verdicts.
 */
export const REPOSITORY_MODEL_JUDGMENT_AREAS = Object.freeze([
  "security",
  "risk",
  "score",
  "grade",
  "verdict",
  "quality",
]);

/**
 * Optional areas, populated by the Phase 8D model builder.
 *
 * They are deliberately **not** part of `REPOSITORY_MODEL_AREAS`: the required
 * areas describe what any scanner can produce, whereas a model without an entity
 * graph, or without documentation signals, is still a valid model.
 * `createRepositoryModel` always emits them (empty by default) so the shape is
 * stable, and the validator only inspects them when they are present.
 *
 * Note that `architecture`, `imports` and `symbols` are *required* areas even though
 * they were populated by later phases: the distinction is not "early" versus "late"
 * but "any scanner can produce it" versus "only a model builder does".
 *
 *   documentation  the documentation artifacts the scan observed.
 *   relationships  `{ from, type, to }` deterministic entity connections.
 *   evidence       Core `Evidence` records referenced by entity ids.
 *   indexes        deterministically ordered lookup maps over the entities.
 *
 * Keeping observations (`evidence`), modelled objects (the typed areas) and
 * connections (`relationships`) as three separate structures is intentional:
 * collapsing them would destroy provenance.
 */
export const REPOSITORY_MODEL_OPTIONAL_AREAS = Object.freeze([
  "documentation",
  "relationships",
  "evidence",
  "indexes",
]);

/**
 * Build a complete RepositoryModel skeleton.
 *
 * Facts are passed in; nothing is inferred or judged. `scan.complete` defaults
 * to `false` so an unfinished scan is never reported as complete.
 *
 * @param {object} [overrides] Partial model. Unknown keys are ignored so the
 *   factory always returns the contracted shape.
 * @returns {object} A RepositoryModel-shaped object.
 */
export function createRepositoryModel(overrides = {}) {
  const scan = overrides.scan ?? {};
  const files = overrides.files ?? {};
  return {
    version: overrides.version ?? REPOSITORY_MODEL_VERSION,
    identity: overrides.identity ?? {},
    files: {
      entries: files.entries ?? [],
      count: files.count ?? 0,
      truncated: files.truncated ?? false,
    },
    languages: overrides.languages ?? [],
    frameworks: overrides.frameworks ?? [],
    manifests: overrides.manifests ?? {},
    dependencies: overrides.dependencies ?? {},
    scripts: overrides.scripts ?? {},
    configuration: overrides.configuration ?? {},
    git: overrides.git ?? {},
    tests: overrides.tests ?? {},
    ci: overrides.ci ?? {},
    architecture: overrides.architecture ?? {},
    imports: overrides.imports ?? {},
    symbols: overrides.symbols ?? {},
    scan: {
      complete: scan.complete ?? false,
      truncated: scan.truncated ?? false,
      limits: scan.limits ?? {},
      errors: scan.errors ?? [],
    },
    metadata: overrides.metadata ?? {},
    // Optional areas (see `REPOSITORY_MODEL_OPTIONAL_AREAS`).
    documentation: overrides.documentation ?? {},
    relationships: overrides.relationships ?? [],
    evidence: overrides.evidence ?? [],
    indexes: overrides.indexes ?? {},
  };
}
