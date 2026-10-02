/**
 * Code Guardian — CI/CD Summary (Official Roadmap Phase 13)
 *
 * The analyzer's structured answer to "what does this repository's CI/CD configuration
 * establish". It is a pure function of the frozen RepositoryModel, so two runs over the same
 * model produce the same map — no clock, no random source, no unordered iteration.
 *
 * ### One entry per roadmap domain, plus the content coverage behind them
 *
 * Each of the twelve domains carries a `state` drawn from the five official states, the closed
 * vocabulary ids observed, the workflows that established them and the workflows read in full
 * that established nothing. `workflowContent` records the coverage the whole map rests on, and
 * `applicability` answers whether the repository has a CI/CD subject at all.
 *
 * The state ladder, applied identically to every domain:
 *
 *   verified         the workflow's content was interpreted **in full** and establishes the
 *                    behavior. Not a claim that the pipeline ran, succeeded or is safe.
 *   detected         the behavior was observed, but only from a **truncated** read — presence is
 *                    established, completeness is not.
 *   failed           at least one observed workflow's *interpretation* failed (binary content,
 *                    an errored read) and no domain observation was established.
 *   unknown          no workflow was interpreted, or the only reads were bounded; the domain
 *                    applies but evidence is insufficient. Never clean.
 *   not_applicable   no CI/CD subject at all, or every workflow was read in full and none shows
 *                    the domain's behavior.
 *
 * `failed` deliberately outranks `unknown` here and is *not* produced by a bounded read: a file
 * over the byte cap is insufficient evidence, not a failure, and a binary workflow is a real
 * interpretation failure the summary refuses to hide behind `unknown`.
 */

import { CICD_CONTENT_STATES, CICD_PERMISSION_MODES, CICD_STATES } from "./contracts.js";
import { ciProviders, ciWorkflows, queryFor, cicdAbsence } from "./signals.js";

const STATES = CICD_STATES;

/** The union of a domain's ids across the given workflows, sorted. */
function unionIds(workflows, observation) {
  const ids = new Set();
  for (const workflow of workflows) for (const id of observation(workflow)) ids.add(id);
  return [...ids].sort();
}

/**
 * The summary entry for one roadmap domain.
 *
 * @param {object[]} workflows Every observed workflow.
 * @param {(workflow: object) => string[]} observation The domain's ids for a workflow.
 * @param {boolean} absenceEstablished Whether the scan supports an absence claim at all.
 * @returns {object} Frozen.
 */
function domainEntry(workflows, observation, absenceEstablished) {
  if (workflows.length === 0) {
    return Object.freeze({
      state: absenceEstablished ? STATES.NOT_APPLICABLE : STATES.UNKNOWN,
      observed: [],
      workflows: [],
      unobserved: [],
    });
  }

  const observed = workflows.filter((workflow) => observation(workflow).length > 0);
  const interpreted = workflows.filter((workflow) => workflow.interpreted);
  const unobserved = interpreted
    .filter((workflow) => observation(workflow).length === 0)
    .map((workflow) => workflow.path)
    .sort();

  let state;
  if (observed.length > 0) {
    state = observed.some((workflow) => workflow.interpreted) ? STATES.VERIFIED : STATES.DETECTED;
  } else if (interpreted.length > 0) {
    state = STATES.NOT_APPLICABLE;
  } else {
    state = STATES.UNKNOWN;
  }

  return Object.freeze({
    state,
    observed: unionIds(workflows, observation),
    workflows: observed.map((workflow) => workflow.path).sort(),
    unobserved,
  });
}

/** The content-coverage entry the whole map rests on. */
function contentEntry(workflows, absenceEstablished) {
  const count = (predicate) => workflows.filter(predicate).length;
  const state =
    workflows.length === 0
      ? absenceEstablished
        ? STATES.NOT_APPLICABLE
        : STATES.UNKNOWN
      : workflows.some((workflow) => workflow.failure)
        ? STATES.FAILED
        : workflows.some((workflow) => workflow.bounded || workflow.partial)
          ? STATES.UNKNOWN
          : STATES.VERIFIED;

  return Object.freeze({
    state,
    workflows: workflows.length,
    interpreted: count((workflow) => workflow.interpreted),
    partial: count((workflow) => workflow.partial),
    notInterpreted: count((workflow) => workflow.notInterpreted),
    failedReads: count((workflow) => workflow.failure),
    boundedReads: count((workflow) => workflow.bounded),
    unestablished: workflows
      .filter((workflow) => !workflow.interpreted)
      .map((workflow) => workflow.path)
      .sort(),
  });
}

/**
 * Domains that only some providers give a subject.
 *
 * A provider with no permissions concept cannot be reported as having omitted a `permissions:`
 * block, so the domain is filtered to the workflows whose provider configures one — the same
 * predicate the rule uses, kept beside the observations so the two cannot disagree.
 */
const DOMAIN_APPLIES = Object.freeze({
  permissions: (workflow) => workflow.permissionsConfigurable === true,
});

/** The behavior each domain reads. One place, so the summary and the rules cannot disagree. */
const DOMAIN_OBSERVATIONS = Object.freeze({
  triggers: (workflow) => workflow.triggers,
  permissions: (workflow) =>
    workflow.permissionsMode === CICD_PERMISSION_MODES.EXPLICIT ? ["explicit"] : [],
  secrets: (workflow) => workflow.secretRefs,
  "dependency-installation": (workflow) => workflow.dependencyInstallation,
  "test-execution": (workflow) =>
    workflow.testExecution === "detected"
      ? workflow.testRunners.length > 0
        ? [...workflow.testRunners]
        : ["detected"]
      : [],
  "build-execution": (workflow) => workflow.builds,
  deployment: (workflow) => workflow.deployments,
  "environment-separation": (workflow) => workflow.environments,
  "artifact-handling": (workflow) => workflow.artifacts,
  caching: (workflow) => workflow.caches,
  rollback: (workflow) => workflow.rollbacks,
  "deployment-protection": (workflow) => workflow.deploymentProtection,
});

/**
 * Build the CI/CD summary for an AnalysisContext.
 *
 * @param {object} context A validated AnalysisContext.
 * @returns {object} Frozen summary with one entry per roadmap domain.
 */
export function summarizeCicd(context) {
  const query = queryFor(context);
  const workflows = ciWorkflows(query);
  const absence = cicdAbsence(context);

  const domains = {};
  for (const [domain, observation] of Object.entries(DOMAIN_OBSERVATIONS)) {
    // A domain may have no subject for some providers at all — permissions is the case — and the
    // summary must agree with the rule rather than reading "unobserved" as "missing".
    const applies = DOMAIN_APPLIES[domain];
    const subject = applies === undefined ? workflows : workflows.filter((workflow) => applies(workflow));
    domains[domain] = domainEntry(subject, observation, absence.established);
  }

  const deploymentObserved = domains.deployment.observed.length > 0;
  const rollbackObserved = domains.rollback.observed.length > 0;
  const protectionObserved = domains["deployment-protection"].observed.length > 0;

  return Object.freeze({
    // Whether the repository has a CI/CD subject at all — the prior question, kept separate from
    // whether any workflow's content was actually interpreted (`workflowContent` answers that).
    applicability: Object.freeze({
      state: workflows.length > 0
        ? STATES.DETECTED
        : absence.established
          ? STATES.NOT_APPLICABLE
          : STATES.UNKNOWN,
      hasSubject: workflows.length > 0,
      interpreted: workflows.filter((workflow) => workflow.interpreted).length,
      providers: ciProviders(query),
      workflows: workflows.length,
    }),
    workflowContent: contentEntry(workflows, absence.established),
    ...Object.fromEntries(Object.entries(domains).map(([domain, entry]) => [domain, entry])),
    coverageBasis: absence,
    // Three facts a consumer should not have to re-derive from three entries: whether a
    // deployment path exists at all, and whether the two domains that only matter when it does
    // have a subject.
    deploymentPath: Object.freeze({
      observed: deploymentObserved,
      rollbackObserved,
      protectionObserved,
    }),
    states: STATES,
    contentStates: CICD_CONTENT_STATES,
  });
}
