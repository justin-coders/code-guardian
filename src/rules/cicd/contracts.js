/**
 * Code Guardian — CI/CD Rule Pack Contracts (Official Roadmap Phase 13)
 *
 * The CI/CD domain's vocabulary: which rules exist, which model facts the pack reads, the
 * confidence policy its rules assert, and — most importantly — what its five states mean
 * *for CI/CD*, which is deliberately not the same thing they mean for code quality.
 *
 * ### The twelve official-roadmap domains
 *
 *   workflow triggers · permissions · secret handling · dependency installation ·
 *   test execution · build execution · deployment · environment separation ·
 *   artifact handling · caching · rollback · deployment protection
 *
 * Every rule id maps to exactly one of them, `CICD_DOMAIN_IDS` is the one place the domain
 * list is declared, and `cicdRuleSetIssues()` fails registration if a declared rule is missing
 * or an id leaves the `cicd.` namespace. A rule id appears in every finding fingerprint the
 * rule will ever produce, so renaming one is a breaking identity change.
 *
 * ### The five states, as *this* phase defines them
 *
 * The official roadmap requires the analyzer to distinguish these state kinds, and Official
 * Phase 11 and Phase 12 each defined them against their own evidence model. CI/CD is a third
 * model, and the definitions below are its own:
 *
 *   verified         an observed behavior was established from a workflow whose content was
 *                    interpreted **in full** (a complete read). `verified` is a statement about
 *                    the *evidence*, never about execution: this build runs no pipeline, so it
 *                    never means "the workflow ran", "the deployment succeeded" or "the cache
 *                    hit". It is the strongest claim Phase 13 can make.
 *   detected         the behavior was observed, but the workflow's read was **truncated** (over
 *                    the per-file byte cap): presence is established, completeness is not.
 *   failed           at least one observed workflow could not be *interpreted* at all — its
 *                    content was binary, or its read errored. That is a demonstrable
 *                    interpretation failure, and the affected domains are reported `failed`
 *                    rather than silently clean. A file that is merely **large** or beyond the
 *                    byte budget is not a failure: nothing broke, the evidence is simply
 *                    insufficient, so those domains are `unknown`.
 *   unknown          the domain applies but the evidence does not establish the answer: no
 *                    workflow was interpreted, or the only reads were bounded (`too-large`,
 *                    `budget-exhausted`). `unknown` is never clean.
 *   not_applicable   the domain genuinely has no subject: the repository has no CI/CD
 *                    configuration at all over complete coverage, or every workflow was read in
 *                    full and none shows the domain's behavior.
 *
 * `detected` therefore sits *below* `verified` on the evidence ladder, and neither of them
 * ever claims a run happened.
 *
 * ### No execution, ever
 *
 * The pack reads the frozen RepositoryModel through the query API and nothing else. It never
 * runs a workflow, a shell, a container, `kubectl`, `terraform` or a deployment command, never
 * contacts a CI provider, never authenticates, and never reads a secret's value — only the
 * *shape* of a secret reference the workflow's text states.
 */

/** Version of the pack as a whole (analyzer version, rule set revision). */
export const CICD_RULE_PACK_VERSION = "1.0.0";

/** Initial version of every rule in the pack. */
export const CICD_RULE_VERSION = "1.0.0";

/** Analyzer identity. `cicd` is the domain namespace, not a rule. */
export const CICD_ANALYZER_ID = "cicd";
export const CICD_ANALYZER_NAME = "CI/CD";
export const CICD_ANALYZER_SCOPE = "cicd";

/** Category recorded on every CI/CD finding (Core Finding contract). */
export const CICD_CATEGORY = "cicd";

/** Every CI/CD rule id must live in this namespace. */
export const CICD_RULE_ID_PREFIX = "cicd.";

/** The twelve official-roadmap domains, in fixed order. */
export const CICD_DOMAIN_IDS = Object.freeze([
  "triggers",
  "permissions",
  "secrets",
  "dependency-installation",
  "test-execution",
  "build-execution",
  "deployment",
  "environment-separation",
  "artifact-handling",
  "caching",
  "rollback",
  "deployment-protection",
]);

/**
 * The rules this pack ships — exactly one per roadmap domain.
 *
 * The pack deliberately stops at twelve: the roadmap asks for content-aware analysis of a
 * named set of concerns, not the largest possible rule set, and one stable rule per domain
 * keeps every finding's identity unambiguous.
 */
export const CICD_RULE_IDS = Object.freeze({
  TRIGGERS_UNESTABLISHED: "cicd.triggers.unestablished",
  PERMISSIONS_NOT_DECLARED: "cicd.permissions.not-declared",
  SECRETS_REFERENCED: "cicd.secrets.referenced",
  DEPENDENCIES_NOT_ESTABLISHED: "cicd.dependency-installation.not-established",
  TESTS_NOT_ESTABLISHED: "cicd.test-execution.not-established",
  BUILD_NOT_ESTABLISHED: "cicd.build-execution.not-established",
  DEPLOYMENT_OBSERVED: "cicd.deployment.observed",
  ENVIRONMENT_NOT_SEPARATED: "cicd.environment-separation.not-established",
  ARTIFACTS_NOT_HANDLED: "cicd.artifact-handling.not-established",
  CACHING_NOT_CONFIGURED: "cicd.caching.not-established",
  ROLLBACK_NOT_ESTABLISHED: "cicd.rollback.not-established",
  DEPLOYMENT_PROTECTION_NOT_ESTABLISHED: "cicd.deployment-protection.not-established",
});

/** Rule id → the roadmap domain it reports. */
export const CICD_RULE_DOMAINS = Object.freeze({
  [CICD_RULE_IDS.TRIGGERS_UNESTABLISHED]: "triggers",
  [CICD_RULE_IDS.PERMISSIONS_NOT_DECLARED]: "permissions",
  [CICD_RULE_IDS.SECRETS_REFERENCED]: "secrets",
  [CICD_RULE_IDS.DEPENDENCIES_NOT_ESTABLISHED]: "dependency-installation",
  [CICD_RULE_IDS.TESTS_NOT_ESTABLISHED]: "test-execution",
  [CICD_RULE_IDS.BUILD_NOT_ESTABLISHED]: "build-execution",
  [CICD_RULE_IDS.DEPLOYMENT_OBSERVED]: "deployment",
  [CICD_RULE_IDS.ENVIRONMENT_NOT_SEPARATED]: "environment-separation",
  [CICD_RULE_IDS.ARTIFACTS_NOT_HANDLED]: "artifact-handling",
  [CICD_RULE_IDS.CACHING_NOT_CONFIGURED]: "caching",
  [CICD_RULE_IDS.ROLLBACK_NOT_ESTABLISHED]: "rollback",
  [CICD_RULE_IDS.DEPLOYMENT_PROTECTION_NOT_ESTABLISHED]: "deployment-protection",
});

/** The five official state kinds, as this phase defines them (see the module header). */
export const CICD_STATES = Object.freeze({
  DETECTED: "detected",
  VERIFIED: "verified",
  FAILED: "failed",
  UNKNOWN: "unknown",
  NOT_APPLICABLE: "not_applicable",
});

/**
 * How well a workflow's content was interpreted.
 *
 * Re-declared from the acquisition layer rather than imported, because the rules layer must not
 * depend on the scanner; `tests/cicd-rules.test.js` builds a real model from a real scan and
 * fails if these drift.
 */
export const CICD_CONTENT_STATES = Object.freeze({
  INTERPRETED: "interpreted",
  PARTIAL: "partial",
  NOT_INTERPRETED: "not-interpreted",
});

/** The acquisition reasons that mean "interpretation failed" rather than "evidence bounded". */
export const CICD_INTERPRETATION_FAILURE_REASONS = Object.freeze(["unreadable", "not-text"]);

/** The acquisition reasons that mean "the read was bounded" — insufficient, not failed. */
export const CICD_BOUNDED_READ_REASONS = Object.freeze(["too-large", "budget-exhausted"]);

/** How a workflow's permissions were established. */
export const CICD_PERMISSION_MODES = Object.freeze({
  EXPLICIT: "explicit",
  NOT_ESTABLISHED: "not-established",
});

/**
 * Confidence policy.
 *
 * Confidence is the rule's assertion about its own evidence, never a framework default, and it
 * is chosen to match the evidence strength Phase 13's acquisition establishes:
 *
 *   OBSERVED_CONTENT      the model's bounded content read matched the workflow's own
 *                         configuration (a deployment command, a permission scope, a secret
 *                         reference). Direct evidence about the workflow's bytes.
 *   ESTABLISHED_ABSENCE   the finding asserts that a workflow, read in full, establishes none
 *                         of a domain's behavior. It rests on the extraction's completeness for
 *                         that workflow, so it is weaker than an observation.
 *   DERIVED_RELATION      the finding compares two observations (a deployment with no rollback,
 *                         a pipeline that builds and deploys but separates no environment).
 *   BOUNDED_COVERAGE      the finding reports what a *bounded* coverage permits — the partial
 *                         read or the uninterpreted workflow that made the domain unknown.
 */
export const CICD_CONFIDENCE = Object.freeze({
  OBSERVED_CONTENT: 0.9,
  ESTABLISHED_ABSENCE: 0.6,
  DERIVED_RELATION: 0.6,
  BOUNDED_COVERAGE: 0.4,
});

/**
 * The asset `metadata.basis` values this pack records — *what the observation rested on*.
 */
export const CICD_BASES = Object.freeze({
  WORKFLOW_CONTENT: "workflow-content",
  WORKFLOW_COVERAGE: "workflow-coverage",
  WORKFLOW_INVENTORY: "workflow-inventory",
});

/**
 * Decision thresholds.
 *
 *   MAX_WORKFLOW_FINDINGS  how many per-workflow findings one rule reports before it caps and
 *                          records the cap. The roadmap forbids unbounded output, and a
 *                          repository can contain many workflows.
 */
export const CICD_LIMITS = Object.freeze({
  MAX_WORKFLOW_FINDINGS: 25,
});

/**
 * The provider ids this pack can describe.
 *
 * Provider *knowledge* lives in the acquisition layer's profile table (`policies/cicd.js`), so a
 * rule reads the union of facts the model carries and never branches on a provider. This list is
 * re-declared only so `cicdRuleSetIssues` can pin the vocabulary the pack documents, and it is
 * checked against the acquisition layer by a test.
 */
export const CICD_PROVIDERS = Object.freeze([
  "appveyor",
  "aws-codebuild",
  "azure-pipelines",
  "bitbucket-pipelines",
  "buildkite",
  "circleci",
  "codefresh",
  "drone",
  "github-actions",
  "gitlab-ci",
  "google-cloud-build",
  "jenkins",
  "travis-ci",
]);
