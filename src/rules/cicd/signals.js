/**
 * Code Guardian — CI/CD Repository Signals (Official Roadmap Phase 13)
 *
 * The one place the CI/CD rules ask the repository questions. Every read goes through the query
 * API over the frozen RepositoryModel: no filesystem, no `node:path`, no `child_process`, no
 * network, no provider API, no scan. A rule that cannot answer a question from the model reports
 * `unknown` rather than going to look for itself, and no rule ever runs a workflow.
 *
 * ### A workflow record is a fact set *and* its coverage
 *
 * The acquisition layer classifies each workflow's content into a closed vocabulary, and it
 * records how well it managed to interpret that content. Both are part of the record here,
 * because a CI/CD fact without its coverage is exactly what turns "we could not read the
 * workflow" into "the workflow does no caching":
 *
 *   interpreted      the content was read in full — an absence is meaningful
 *   partial          the read stopped at the byte cap — presence is meaningful, absence is not
 *   not-interpreted  the content was never interpreted — nothing about it is established
 *
 * `failure` distinguishes a genuine interpretation *failure* (binary content, an errored read)
 * from a merely *bounded* read (`too-large`, `budget-exhausted`), which the phase's state
 * semantics turn into `failed` and `unknown` respectively.
 *
 * ### Absence is a claim, not an observation
 *
 * `cicdAbsence()` mirrors the discipline Phases 10–12 established: an absence-shaped CI/CD
 * claim is only supported when the scan covered the repository completely, no path failed to
 * read, and the CI inventory itself was not truncated — otherwise the answer is `unknown`.
 */

import {
  COVERAGE_GUARANTEES,
  ENTITY_KINDS,
  createRepositoryQuery,
} from "../../repository/model/index.js";

import {
  CICD_BOUNDED_READ_REASONS,
  CICD_CONTENT_STATES,
  CICD_INTERPRETATION_FAILURE_REASONS,
  CICD_PERMISSION_MODES,
} from "./contracts.js";

/** Build the read-only query handle for an AnalysisContext. */
export function queryFor(context) {
  return createRepositoryQuery(context.repository);
}

/** Sorted, de-duplicated copy of a bounded identifier array. */
function listOf(value) {
  if (!Array.isArray(value)) return Object.freeze([]);
  const out = new Set();
  for (const entry of value) if (typeof entry === "string") out.add(entry);
  return Object.freeze([...out].sort());
}

/**
 * One workflow's facts and coverage.
 *
 * @param {object} entity A `cicd` model entity.
 * @returns {object} Frozen.
 */
export function workflowRecord(entity) {
  const contentState =
    typeof entity.contentState === "string"
      ? entity.contentState
      : CICD_CONTENT_STATES.NOT_INTERPRETED;
  const reason = typeof entity.reason === "string" ? entity.reason : null;
  const testExecution = typeof entity.testExecution === "string" ? entity.testExecution : "unknown";

  return Object.freeze({
    entity,
    id: entity.id,
    path: entity.path,
    provider: typeof entity.provider === "string" ? entity.provider : null,
    contentState,
    reason,
    // A read in full: an absence is meaningful.
    interpreted: contentState === CICD_CONTENT_STATES.INTERPRETED && reason === null,
    // A truncated read: presence is meaningful, absence is not.
    partial: contentState === CICD_CONTENT_STATES.PARTIAL || reason === "too-large",
    // Never interpreted at all.
    notInterpreted: contentState === CICD_CONTENT_STATES.NOT_INTERPRETED,
    // A demonstrable interpretation *failure* (binary content, an errored read) as opposed to a
    // bounded read, which is insufficient evidence rather than a failure.
    failure: reason !== null && CICD_INTERPRETATION_FAILURE_REASONS.includes(reason),
    bounded: reason !== null && CICD_BOUNDED_READ_REASONS.includes(reason),
    // Phase 11's test-execution evidence, consumed here rather than re-derived.
    testExecution,
    testRunners: listOf(entity.testRunners),
    coverageCommands: listOf(entity.coverageCommands),
    // Phase 13's own content facts.
    triggers: listOf(entity.triggers),
    triggerRestrictions: listOf(entity.triggerRestrictions),
    permissionsMode:
      entity.permissionsMode === CICD_PERMISSION_MODES.EXPLICIT
        ? CICD_PERMISSION_MODES.EXPLICIT
        : CICD_PERMISSION_MODES.NOT_ESTABLISHED,
    // Whether the provider configures permissions at all: a provider without the concept cannot
    // be reported as having omitted a `permissions:` block.
    permissionsConfigurable: entity.permissionsConfigurable === true,
    permissions: listOf(entity.permissions),
    secretRefs: listOf(entity.secretRefs),
    dependencyInstallation: listOf(entity.dependencyInstallation),
    builds: listOf(entity.builds),
    deployments: listOf(entity.deployments),
    environments: listOf(entity.environments),
    artifacts: listOf(entity.artifacts),
    caches: listOf(entity.caches),
    rollbacks: listOf(entity.rollbacks),
    deploymentProtection: listOf(entity.deploymentProtection),
    evidenceIds: Object.freeze([...(entity.evidenceIds ?? [])].sort()),
  });
}

/**
 * Every observed CI/CD workflow, in id order.
 *
 * @param {object} query
 * @returns {object[]} Frozen workflow records.
 */
export function ciWorkflows(query) {
  return Object.freeze(
    query
      .listEntities(ENTITY_KINDS.CICD)
      .entities.map((entity) => workflowRecord(entity)),
  );
}

/** The observed CI/CD providers, sorted and de-duplicated. */
export function ciProviders(query) {
  const providers = new Set();
  for (const workflow of ciWorkflows(query)) if (workflow.provider !== null) providers.add(workflow.provider);
  return Object.freeze([...providers].sort());
}

/**
 * Every workflow's observations for one domain, as `(workflow, ids)` pairs.
 *
 * A domain's `ids` come from one flattened field name, so a rule reads the same shape for every
 * domain and never indexes into a provider-specific structure.
 *
 * @param {object[]} workflows Workflow records.
 * @param {string} field The record field naming the domain's observation list.
 * @param {(workflow: object) => string[]} [extra] Optional additional ids for the domain.
 * @returns {Array<{workflow: object, ids: string[]}>}
 */
export function observationsFor(workflows, field, extra) {
  const out = [];
  for (const workflow of workflows) {
    const ids = [...workflow[field]];
    if (typeof extra === "function") ids.push(...extra(workflow));
    if (ids.length === 0) continue;
    out.push({ workflow, ids: Object.freeze([...new Set(ids)].sort()) });
  }
  return out;
}

/**
 * Whether the model supports an absence claim about CI/CD configuration.
 *
 * @param {object} context A validated AnalysisContext.
 * @returns {{established: boolean, reason: string|null, workflows: number, coverageReason: string}}
 */
export function cicdAbsence(context) {
  const query = createRepositoryQuery(context.repository);
  const inventory = query.listEntities(ENTITY_KINDS.CICD);
  const summary = query.coverage();
  const reasons = [];

  if (inventory.coverage !== COVERAGE_GUARANTEES.COMPLETE) {
    reasons.push(
      summary.truncated === true
        ? "the scan stopped at a limit before the CI/CD inventory was complete"
        : "the scan did not cover the repository completely",
    );
  }
  if (summary.unreadableCount > 0) {
    reasons.push(`${summary.unreadableCount} path(s) could not be read`);
  }
  if (context.repository?.ci?.evidenceTruncated === true) {
    reasons.push("the CI/CD inventory was truncated at the evidence cap");
  }

  return Object.freeze({
    established: reasons.length === 0,
    reason: reasons.length === 0 ? null : reasons.join("; "),
    workflows: inventory.entities.length,
    coverageReason: inventory.coverage,
  });
}

/**
 * The union of the evidence ids of a set of workflow records, sorted.
 *
 * A finding cites the workflow's own observation — the file inventory observation the model
 * recorded for it — which is what makes the finding traceable after canonicalization.
 */
export function evidenceIdsForWorkflows(workflows) {
  const ids = new Set();
  for (const workflow of workflows) for (const id of workflow.evidenceIds) ids.add(id);
  return Object.freeze([...ids].sort());
}

/** Whether any workflow in the set was interpreted in full. */
export function anyInterpreted(workflows) {
  return workflows.some((workflow) => workflow.interpreted);
}

/** Whether any workflow in the set could not be interpreted at all. */
export function anyNotInterpreted(workflows) {
  return workflows.some((workflow) => workflow.notInterpreted);
}

/** Whether any workflow's interpretation demonstrably failed. */
export function anyFailure(workflows) {
  return workflows.some((workflow) => workflow.failure);
}

/** Whether any workflow's read was bounded rather than completed. */
export function anyBounded(workflows) {
  return workflows.some((workflow) => workflow.bounded);
}
