/**
 * Code Guardian — CI/CD Acquisition Policy (Official Roadmap Phase 13)
 *
 * The scanner's one place that interprets a **workflow's content** into the closed vocabulary
 * of CI/CD facts the Phase 13 analyzer reasons about. It exists because — as the official
 * roadmap puts it — `.github/workflows exists` is not the conclusion: whether a pipeline is
 * *triggered*, *permissioned*, *installs dependencies*, *builds*, *deploys*, *separates
 * environments*, *handles artifacts*, *caches*, *rolls back* or *protects its deployments* are
 * facts about **configuration text**, not about the workflow's file name.
 *
 * ### Bounded and deterministic, not a YAML parser
 *
 * The roadmap forbids pulling a general configuration-parsing platform forward, so this is a
 * bounded, line-oriented structural read with a fixed, reviewable table:
 *
 *   - **Comments are removed first.** A `#` at line start or after whitespace begins a YAML
 *     comment (a `#` inside a quoted scalar does not), so `# run the tests` and
 *     `# TODO: deploy` establish nothing. This is the difference between a content *read* and
 *     a substring search, and the negative fixtures prove it.
 *   - **Structural facts are matched in key position.** Triggers, restrictions, permission
 *     scopes and environment declarations are matched with line-anchored patterns
 *     (`push:` under `on:`, a `permissions:` key, an `environment:` key), never by searching
 *     for a word, so `name: deploy` and `description: build` establish nothing.
 *   - **Command facts require a documented invocation.** The command vocabulary matches real
 *     command strings (`npm ci`, `kubectl apply`, `cargo build`), never a bare word, so
 *     `run: echo "build"` establishes nothing about building.
 *   - **Provider-specific structure lives in a provider profile.** The roadmap requires
 *     provider knowledge to stay modular and forbids `if github … else if gitlab …` spread
 *     through every rule: rules read the union this function returns, and adding a provider is
 *     adding a profile entry here, never editing a rule.
 *
 * ### Interpreting is not passing
 *
 * Every id below states *"this workflow's content contains this configured behavior"*. It says
 * nothing about exit status, correctness or safety: a detected deployment is not a successful
 * deployment, and a detected cache is not a correct cache key. The Phase 13 rules are worded
 * accordingly.
 *
 * ### Coverage is a first-class output
 *
 * A workflow the acquisition could not interpret (unreadable, binary, over the per-file cap,
 * beyond the byte budget) yields **no** facts, and the Phase 13 analyzer reports the affected
 * domain `unknown` — never "this workflow does no caching". A workflow whose read was
 * *truncated* is returned as well, so a domain with no observation over a partial read is
 * `unknown` rather than absent.
 */

import { TEST_RUNNER_IDS } from "./testing.js";

// ─── Domains ──────────────────────────────────────────────────────────────────

/** The twelve official-roadmap CI/CD domains, in fixed order. */
export const CICD_DOMAINS = Object.freeze([
  "triggers",
  "permissions",
  "secrets",
  "dependency-installation",
  "build-execution",
  "deployment",
  "environment-separation",
  "artifact-handling",
  "caching",
  "rollback",
  "deployment-protection",
]);

/** How well a workflow's content could be interpreted. */
export const CICD_CONTENT_STATES = Object.freeze({
  /** Read in full: an absence of a fact is meaningful. */
  INTERPRETED: "interpreted",
  /** Read but truncated at a byte cap: presence is meaningful, absence is not. */
  PARTIAL: "partial",
  /** Not interpreted at all: nothing is established. */
  NOT_INTERPRETED: "not-interpreted",
});

// ─── Trigger vocabulary (provider-neutral ids) ────────────────────────────────

/** Every trigger id a provider profile may report. */
export const CICD_TRIGGER_IDS = Object.freeze([
  "issue-comment",
  "merge-request",
  "pull-request",
  "pull-request-target",
  "push",
  "release",
  "repository-dispatch",
  "schedule",
  "workflow-call",
  "workflow-dispatch",
]);

/** Every trigger-restriction id a provider profile may report. */
export const CICD_TRIGGER_RESTRICTION_IDS = Object.freeze(["branches", "paths", "tags"]);

// ─── Permission vocabulary ────────────────────────────────────────────────────

/** How a workflow's permissions were established. */
export const CICD_PERMISSION_MODES = Object.freeze({
  /** An explicit `permissions:` key was observed. */
  EXPLICIT: "explicit",
  /** No permissions key was observed (the provider's default applies, which this build
   * cannot read). */
  NOT_ESTABLISHED: "not-established",
});

/** Permission scopes this policy can report, from a provider's documented scope names. */
export const CICD_PERMISSION_SCOPES = Object.freeze([
  "actions",
  "attestations",
  "checks",
  "contents",
  "deployments",
  "id-token",
  "issues",
  "packages",
  "pages",
  "pull-requests",
  "security-events",
  "statuses",
]);

// ─── Command vocabularies (provider-neutral) ──────────────────────────────────

/**
 * Secret-reference shapes.
 *
 * Only the *shape* of a reference is recorded — never its value, and never the secret's name
 * beyond the closed id below. A workflow's `${{ secrets.TOKEN }}` yields `secrets-context`;
 * the analyzer never sees, stores or prints `TOKEN`'s value. Secret *security* findings remain
 * the Security Analyzer's job.
 */
export const CICD_SECRET_REFERENCE_DEFINITIONS = Object.freeze([
  { id: "secrets-context", matcher: /\bsecrets\s*[.[]/, },
  { id: "oidc-token", matcher: /\bid-token[ \t]*:[ \t]*write\b|\bACTIONS_ID_TOKEN_REQUEST\b/ },
  { id: "vault", matcher: /(^|[\s;&|(])vault\s+(?:read|kv|login)\b/ },
  { id: "external-secret-manager", matcher: /\baws\s+secretsmanager\b|\bgcloud\s+secrets\b|\baz\s+keyvault\b/ },
]);

/** Dependency-installation invocations, across ecosystems. */
export const CICD_DEPENDENCY_DEFINITIONS = Object.freeze([
  { id: "npm-ci", matcher: /(^|[\s;&|(])npm\s+ci\b/ },
  { id: "npm-install", matcher: /(^|[\s;&|(])npm\s+(?:install|i)\b/ },
  { id: "pnpm-install", matcher: /(^|[\s;&|(])pnpm\s+(?:install|i|fetch)\b/ },
  { id: "yarn-install", matcher: /(^|[\s;&|(])yarn\s+(?:install|--frozen-lockfile)\b/ },
  { id: "bun-install", matcher: /(^|[\s;&|(])bun\s+install\b/ },
  { id: "pip-install", matcher: /(^|[\s;&|(])pip[0-9.]*\s+install\b/ },
  { id: "poetry-install", matcher: /(^|[\s;&|(])poetry\s+install\b/ },
  { id: "pipenv-install", matcher: /(^|[\s;&|(])pipenv\s+(?:install|sync)\b/ },
  { id: "uv-sync", matcher: /(^|[\s;&|(])uv\s+(?:sync|pip\s+install)\b/ },
  { id: "go-mod-download", matcher: /(^|[\s;&|(])go\s+mod\s+download\b/ },
  { id: "cargo-fetch", matcher: /(^|[\s;&|(])cargo\s+(?:fetch|build)\b/ },
  { id: "bundler-install", matcher: /(^|[\s;&|(])(?:bundle|bundler)\s+install\b/ },
  { id: "composer-install", matcher: /(^|[\s;&|(])composer\s+install\b/ },
  { id: "nuget-restore", matcher: /(^|[\s;&|(])nuget\s+restore\b|(^|[\s;&|(])dotnet\s+restore\b/ },
  { id: "maven-dependencies", matcher: /(^|[\s;&|(])(?:mvn|maven)\b[^\n]*\bdependency/ },
  { id: "gradle-dependencies", matcher: /(^|[\s;&|(])(?:gradle|\.\/gradlew|gradlew)\b[^\n]*\bdependencies\b/ },
]);

/** Build invocations, across ecosystems. */
export const CICD_BUILD_DEFINITIONS = Object.freeze([
  { id: "npm-run-build", matcher: /(^|[\s;&|(])npm\s+run\s+build\b/ },
  { id: "pnpm-build", matcher: /(^|[\s;&|(])pnpm\s+(?:run\s+)?build\b/ },
  { id: "yarn-build", matcher: /(^|[\s;&|(])yarn\s+(?:run\s+)?build\b/ },
  { id: "tsc-build", matcher: /(^|[\s;&|(])tsc\b[^\n]*\b(?:build|--build)\b|(^|[\s;&|(])tsc[ \t]*$/m },
  { id: "vite-build", matcher: /(^|[\s;&|(])vite\s+build\b/ },
  { id: "webpack-build", matcher: /(^|[\s;&|(])webpack\b/ },
  { id: "cargo-build", matcher: /(^|[\s;&|(])cargo\s+build\b/ },
  { id: "go-build", matcher: /(^|[\s;&|(])go\s+build\b/ },
  { id: "dotnet-build", matcher: /(^|[\s;&|(])dotnet\s+build\b|(^|[\s;&|(])msbuild\b/ },
  { id: "maven-package", matcher: /(^|[\s;&|(])(?:mvn|maven)\b[^\n]*\b(?:package|install|verify)\b/ },
  { id: "gradle-build", matcher: /(^|[\s;&|(])(?:gradle|\.\/gradlew|gradlew)\b[^\n]*\bbuild\b/ },
  { id: "make", matcher: /(^|[\s;&|(])make\b(?!file)/ },
  { id: "cmake", matcher: /(^|[\s;&|(])cmake\b/ },
  { id: "docker-build", matcher: /(^|[\s;&|(])docker\s+buildx?\b/ },
]);

/**
 * Deployment invocations.
 *
 * A deliberately bounded, documented vocabulary: the roadmap says not to support every cloud
 * platform here, and provider expansion belongs to a later phase.
 */
export const CICD_DEPLOYMENT_DEFINITIONS = Object.freeze([
  { id: "kubectl-apply", matcher: /(^|[\s;&|(])kubectl\s+(?:apply|rollout|set\s+image)\b/ },
  { id: "helm-upgrade", matcher: /(^|[\s;&|(])helm\s+(?:upgrade|install)\b/ },
  { id: "terraform-apply", matcher: /(^|[\s;&|(])terraform\s+apply\b/ },
  { id: "docker-push", matcher: /(^|[\s;&|(])docker\s+push\b/ },
  { id: "aws-cli-deploy", matcher: /(^|[\s;&|(])aws\s+(?:deploy|ecs|ecr|s3\s+sync|cloudformation|elasticbeanstalk)\b/ },
  { id: "gcloud-deploy", matcher: /(^|[\s;&|(])gcloud\s+(?:app|run|deploy|functions)\b/ },
  { id: "azure-deploy", matcher: /(^|[\s;&|(])az\s+(?:webapp|aks|deployment)\b/ },
  { id: "serverless-deploy", matcher: /(^|[\s;&|(])serverless\s+deploy\b|(^|[\s;&|(])sls\s+deploy\b/ },
  { id: "vercel-deploy", matcher: /(^|[\s;&|(])vercel\b[^\n]*\b(?:--prod|deploy)\b/ },
  { id: "netlify-deploy", matcher: /(^|[\s;&|(])netlify\s+deploy\b/ },
  { id: "firebase-deploy", matcher: /(^|[\s;&|(])firebase\s+deploy\b/ },
  { id: "ansible-playbook", matcher: /(^|[\s;&|(])ansible(?:-playbook)?\b/ },
  { id: "docker-compose-up", matcher: /(^|[\s;&|(])docker[\s-]compose\b[^\n]*\bup\b/ },
  { id: "rsync-deploy", matcher: /(^|[\s;&|(])rsync\b/ },
  { id: "ssh-deploy", matcher: /(^|[\s;&|(])ssh\b/ },
  { id: "registry-publish", matcher: /(^|[\s;&|(])npm\s+publish\b|(^|[\s;&|(])cargo\s+publish\b|(^|[\s;&|(])twine\s+upload\b|(^|[\s;&|(])gh\s+release\s+create\b/ },
]);

/** Rollback evidence — deployment restoration, never source-control revert. */
export const CICD_ROLLBACK_DEFINITIONS = Object.freeze([
  { id: "rollback-job", matcher: /^[ \t]{2,}[A-Za-z0-9_.-]*rollback[A-Za-z0-9_.-]*[ \t]*:/im },
  // A rollback *command* must appear in command position — a `run:`/`script:` value — so the
  // word `rollback` inside a job name, a description or a quoted string establishes nothing.
  { id: "rollback-command", matcher: /^[ \t]*-?[ \t]*(?:run|script|command|commands)[ \t]*:[^\n]*\brollback\b/im },
  { id: "helm-rollback", matcher: /(^|[\s;&|(])helm\s+rollback\b/ },
  { id: "kubectl-rollback", matcher: /(^|[\s;&|(])kubectl\s+rollout\s+undo\b/ },
  {
    id: "previous-version",
    matcher: /^[ \t]*-?[ \t]*(?:run|script|command|commands)[ \t]*:[^\n]*\b(?:previous[_-]?(?:version|release)|last[_-]?known[_-]?good)\b/im,
  },
  {
    id: "revert-deployment",
    matcher: /^[ \t]*-?[ \t]*(?:run|script|command|commands)[ \t]*:[^\n]*\brevert(?:ing)?\b[^\n]*\b(?:deploy|release|rollout)\b/im,
  },
]);

// ─── Artifact / cache / protection vocabulary ─────────────────────────────────

/** Artifact-handling invocations, by documented action/command. */
export const CICD_ARTIFACT_DEFINITIONS = Object.freeze([
  { id: "artifact-upload", matcher: /\bactions\/upload-artifact\b|(^|[\s;&|(])artifacts?\s+upload\b/i },
  { id: "artifact-download", matcher: /\bactions\/download-artifact\b|(^|[\s;&|(])artifacts?\s+download\b/i },
  { id: "artifact-retention", matcher: /^[ \t]{2,}retention-days[ \t]*:/m },
  { id: "release-asset", matcher: /\bsoftprops\/action-gh-release\b|\bgh\s+release\s+upload\b/ },
]);

/** Cache configuration, by documented action/command. */
export const CICD_CACHE_DEFINITIONS = Object.freeze([
  { id: "actions-cache", matcher: /\bactions\/cache(?:@|\/restore|\/save)/ },
  // The `cache:` input sits in the *same step* as the setup action, often a line or two
  // below it, so the matcher crosses a bounded number of characters but never the whole file.
  { id: "setup-node-cache", matcher: /\bactions\/setup-node\b[\s\S]{0,400}?^[ \t]{4,}cache[ \t]*:/m },
  { id: "setup-python-cache", matcher: /\bactions\/setup-python\b[\s\S]{0,400}?^[ \t]{4,}cache[ \t]*:/m },
  { id: "setup-java-cache", matcher: /\bactions\/setup-java\b[\s\S]{0,400}?^[ \t]{4,}cache[ \t]*:/m },
  { id: "setup-go-cache", matcher: /\bactions\/setup-go\b[\s\S]{0,400}?^[ \t]{4,}cache[ \t]*:/m },
  { id: "setup-dotnet-cache", matcher: /\bactions\/setup-dotnet\b[\s\S]{0,400}?^[ \t]{4,}cache[ \t]*:/m },
  { id: "provider-cache", matcher: /^[ \t]{2,}cache[ \t]*:/m },
  { id: "docker-layer-cache", matcher: /\bcache-from\b|\bcache-to\b/ },
]);

/** Deployment-protection evidence, by documented provider configuration. */
export const CICD_PROTECTION_DEFINITIONS = Object.freeze([
  { id: "environment-declaration", matcher: /^[ \t]{2,}environment[ \t]*:/im },
  { id: "required-reviewers", matcher: /\brequired[_-]?reviewers\b/i },
  { id: "manual-approval", matcher: /\bneeds?[_-]?approval\b|\bmanual[_-]?(?:approval|gate)\b/i },
  { id: "deployment-gate", matcher: /\bdeployment[_-]?(?:gate|protection)\b/i },
  { id: "concurrency-gate", matcher: /^[ \t]{2,}concurrency[ \t]*:/m },
]);

// ─── Provider profiles ────────────────────────────────────────────────────────

/**
 * Structural definitions by provider.
 *
 * Each entry maps a domain's ids to the provider's documented syntax. A provider with no
 * profile classifies only by the shared command vocabulary — its triggers, permissions and
 * protection are simply **not established**, and the analyzer says `unknown` rather than
 * inventing a negative.
 */
export const CICD_PROVIDER_PROFILES = Object.freeze({
  "github-actions": Object.freeze({
    // `on:` events, in block, inline-list or inline-scalar form.
    triggers: Object.freeze({
      push: [/^[ \t]*on[ \t]*:[ \t]*\[[^\]]*\bpush\b/m, /^[ \t]{2,}push[ \t]*:/m, /^[ \t]*on[ \t]*:[ \t]*push[ \t]*$/m],
      "pull-request": [/^[ \t]*on[ \t]*:[ \t]*\[[^\]]*\bpull_request\b/m, /^[ \t]{2,}pull_request[ \t]*:/m, /^[ \t]*on[ \t]*:[ \t]*pull_request[ \t]*$/m],
      "pull-request-target": [/^[ \t]{2,}pull_request_target[ \t]*:/m, /^[ \t]*on[ \t]*:[ \t]*pull_request_target[ \t]*$/m],
      "workflow-dispatch": [/^[ \t]{2,}workflow_dispatch[ \t]*:/m, /^[ \t]*on[ \t]*:[ \t]*workflow_dispatch[ \t]*$/m],
      schedule: [/^[ \t]{2,}schedule[ \t]*:/m, /^[ \t]*on[ \t]*:[ \t]*schedule[ \t]*$/m],
      release: [/^[ \t]{2,}release[ \t]*:/m, /^[ \t]*on[ \t]*:[ \t]*release[ \t]*$/m],
      "workflow-call": [/^[ \t]{2,}workflow_call[ \t]*:/m, /^[ \t]*on[ \t]*:[ \t]*workflow_call[ \t]*$/m],
      "repository-dispatch": [/^[ \t]{2,}repository_dispatch[ \t]*:/m, /^[ \t]*on[ \t]*:[ \t]*repository_dispatch[ \t]*$/m],
      "issue-comment": [/^[ \t]{2,}issue_comment[ \t]*:/m, /^[ \t]*on[ \t]*:[ \t]*issue_comment[ \t]*$/m],
    }),
    triggerRestrictions: Object.freeze({
      branches: [/^[ \t]{2,}(?:branches|branches-ignore)[ \t]*:/m],
      paths: [/^[ \t]{2,}(?:paths|paths-ignore)[ \t]*:/m],
      tags: [/^[ \t]{2,}tags(?:-ignore)?[ \t]*:/m],
    }),
    // A `permissions:` key is top-level or job-level, so it is matched at any indent; the
    // scopes under it are indented further.
    permissions: Object.freeze({
      mode: /^[ \t]*permissions[ \t]*:/m,
      scopes: Object.freeze({
        actions: [/^[ \t]{2,}actions[ \t]*:/m],
        attestations: [/^[ \t]{2,}attestations[ \t]*:/m],
        checks: [/^[ \t]{2,}checks[ \t]*:/m],
        contents: [/^[ \t]{2,}contents[ \t]*:/m],
        deployments: [/^[ \t]{2,}deployments[ \t]*:/m],
        "id-token": [/^[ \t]{2,}id-token[ \t]*:/m],
        issues: [/^[ \t]{2,}issues[ \t]*:/m],
        packages: [/^[ \t]{2,}packages[ \t]*:/m],
        pages: [/^[ \t]{2,}pages[ \t]*:/m],
        "pull-requests": [/^[ \t]{2,}pull-requests[ \t]*:/m],
        "security-events": [/^[ \t]{2,}security-events[ \t]*:/m],
        statuses: [/^[ \t]{2,}statuses[ \t]*:/m],
      }),
    }),
    // Environment classes are read from an `environment:` declaration's value.
    environments: Object.freeze({
      development: [/^[ \t]{2,}environment[ \t]*:[ \t]*["']?[^\n"']*\b(?:dev|development)\b/im],
      test: [/^[ \t]{2,}environment[ \t]*:[ \t]*["']?[^\n"']*\btest\b/im],
      staging: [/^[ \t]{2,}environment[ \t]*:[ \t]*["']?[^\n"']*\b(?:staging|stage|uat|preprod|pre-prod)\b/im],
      production: [/^[ \t]{2,}environment[ \t]*:[ \t]*["']?[^\n"']*\b(?:prod|production)\b/im],
    }),
  }),
  // GitLab's trigger semantics live in `only:`/`except:`/`rules:` expressions this bounded
  // read does not evaluate, so only the *presence* of such a constraint is established and
  // reported as the provider's default event. This is documented as a partial structural
  // profile: a GitLab workflow with no such key reports its triggers as not established.
  "gitlab-ci": Object.freeze({
    triggers: Object.freeze({
      push: [/^[ \t]*(?:only|except)[ \t]*:/m, /^[ \t]{2,}rules[ \t]*:/m, /^[ \t]*workflow[ \t]*:/m],
      "merge-request": [/\bmerge_requests?\b/],
      schedule: [/^[ \t]*schedules?[ \t]*:/m],
      "workflow-dispatch": [/\bwhen[ \t]*:[ \t]*manual\b/],
    }),
    triggerRestrictions: Object.freeze({
      branches: [/\bbranches\b/m],
      paths: [/^[ \t]{2,}changes[ \t]*:/m],
      tags: [/\btags\b/m],
    }),
    permissions: Object.freeze({ mode: null, scopes: Object.freeze({}) }),
  }),
});

/** Providers with a structural profile, sorted. */
export const CICD_PROFILED_PROVIDERS = Object.freeze(Object.keys(CICD_PROVIDER_PROFILES).sort());

/**
 * Whether a provider configures workflow permissions at all.
 *
 * A provider whose profile declares no permissions syntax cannot be criticised for omitting a
 * `permissions:` block — GitLab has no such concept — so the acquisition layer states the fact
 * and the permissions rule treats a provider without it as *not applicable*. This is why
 * provider knowledge lives here and not in a rule.
 *
 * @param {unknown} provider
 * @returns {boolean}
 */
export function providerConfiguresPermissions(provider) {
  const profile = CICD_PROVIDER_PROFILES[provider] ?? null;
  return profile !== null && profile.permissions.mode !== null;
}

/** Providers this policy reports as configuring permissions, sorted. */
export const CICD_PERMISSION_CONFIGURABLE_PROVIDERS = Object.freeze(
  Object.keys(CICD_PROVIDER_PROFILES)
    .filter((provider) => providerConfiguresPermissions(provider))
    .sort(),
);

// ─── Reading ──────────────────────────────────────────────────────────────────

/**
 * Remove YAML comments from workflow text.
 *
 * A `#` begins a comment when it is at line start or preceded by whitespace, and a `#` inside
 * a single- or double-quoted scalar does not. This is a bounded single pass per line — no
 * parser — and it is what keeps `# run the tests` from becoming test-execution evidence.
 *
 * @param {unknown} text
 * @returns {string}
 */
export function stripWorkflowComments(text) {
  if (typeof text !== "string" || text === "") return "";
  const lines = text.split("\n");
  const out = new Array(lines.length);
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index];
    let quote = null;
    let end = line.length;
    for (let position = 0; position < line.length; position += 1) {
      const character = line[position];
      if (quote !== null) {
        if (character === quote) quote = null;
        continue;
      }
      if (character === '"' || character === "'") {
        quote = character;
        continue;
      }
      if (character === "#" && (position === 0 || /\s/.test(line[position - 1]))) {
        end = position;
        break;
      }
    }
    out[index] = line.slice(0, end);
  }
  return out.join("\n");
}

/** Collect the ids whose single matcher matches, from a `{ id: [RegExp] }` table. */
function collectGroups(table, text) {
  const ids = new Set();
  for (const id of Object.keys(table)) {
    for (const matcher of table[id]) {
      matcher.lastIndex = 0;
      if (matcher.test(text)) {
        ids.add(id);
        break;
      }
    }
  }
  return [...ids].sort();
}

/**
 * Blank the contents of quoted scalars.
 *
 * The roadmap requires that a word inside a *string* establish nothing — `run: echo "deploy"`
 * is not a deployment and `echo "rollback"` is not a rollback. Command matching therefore
 * reads text whose single- and double-quoted regions have been emptied, while structural and
 * secret matching reads the original text: a secret reference is *always* quoted
 * (`${{ secrets.X }}`, `$CI_TOKEN`) and would otherwise disappear.
 *
 * Bounded and deterministic: two linear passes, no nested or multi-line quote state.
 *
 * @param {string} text
 * @returns {string}
 */
function blankQuotedScalars(text) {
  return text.replace(/"[^"\n]*"/g, '""').replace(/'[^'\n]*'/g, "''");
}

/** Collect ids from a `[{ id, matcher }]` list. */
function collectList(definitions, text) {
  const ids = new Set();
  for (const definition of definitions) {
    definition.matcher.lastIndex = 0;
    if (definition.matcher.test(text)) ids.add(definition.id);
  }
  return [...ids].sort();
}

/** The empty classification — what an uninterpreted workflow yields. */
function emptyClassification() {
  return Object.freeze({
    triggers: Object.freeze([]),
    triggerRestrictions: Object.freeze([]),
    permissionsMode: CICD_PERMISSION_MODES.NOT_ESTABLISHED,
    permissions: Object.freeze([]),
    secretRefs: Object.freeze([]),
    dependencyInstallation: Object.freeze([]),
    builds: Object.freeze([]),
    deployments: Object.freeze([]),
    environments: Object.freeze([]),
    artifacts: Object.freeze([]),
    caches: Object.freeze([]),
    rollbacks: Object.freeze([]),
    deploymentProtection: Object.freeze([]),
  });
}

/**
 * Classify one workflow's content into the closed CI/CD vocabulary.
 *
 * Pure and deterministic: no filesystem, clock, environment, process or network. Linear in the
 * input length (comment stripping is one pass; every matcher is a fixed linear expression).
 *
 * @param {unknown} content The workflow's text (already read by the scanner).
 * @param {{ provider?: string }} [options]
 * @returns {object} Frozen classification. Every list is sorted and de-duplicated. A provider
 *   with no structural profile yields the command-only facts and `not-established` permissions.
 */
/**
 * Whether a line ends inside an open quote.
 *
 * A bounded structural-validity signal, not a parser: a document whose scalars are unterminated
 * is one whose structure cannot be fully interpreted, so what was read establishes presence but
 * not absence. Deliberately conservative — a workflow whose quoted scalars straddle lines in a
 * form this build does not model is treated as partial rather than as valid — because the safe
 * error is to withhold an absence claim, never to make one.
 *
 * @param {string} text Comment-stripped text.
 * @returns {boolean}
 */
function hasUnterminatedQuote(text) {
  for (const line of text.split("\n")) {
    let quote = null;
    for (let index = 0; index < line.length; index += 1) {
      const character = line[index];
      if (quote !== null) {
        if (character === quote) quote = null;
        continue;
      }
      if (character === '"' || character === "'") quote = character;
    }
    if (quote !== null) return true;
  }
  return false;
}

/**
 * Whether a workflow's content was fully interpretable.
 *
 * The scanner calls the classifier and then decides the model's `contentState`: a read that hit
 * the byte cap and a document whose structure is broken are both *partial*, in that each
 * establishes presence but not absence. Exported so the acquisition layer and this policy cannot
 * disagree about what "fully interpreted" means.
 *
 * @param {string} text Comment-stripped text.
 * @returns {boolean}
 */
export function isCicdContentComplete(text) {
  return typeof text === "string" && text !== "" && !hasUnterminatedQuote(text);
}

export function classifyCicdContent(content, { provider } = {}) {
  if (typeof content !== "string" || content === "") return emptyClassification();

  const text = stripWorkflowComments(content);
  // Command facts read quote-blanked text (a word in a string is not a command); structural
  // and secret facts read the text as written (a secret reference is always quoted).
  const commandText = blankQuotedScalars(text);
  const profile = CICD_PROVIDER_PROFILES[provider] ?? null;

  const triggers = profile === null ? [] : collectGroups(profile.triggers, text);
  const triggerRestrictions =
    profile === null ? [] : collectGroups(profile.triggerRestrictions, text);
  const permissionsMode =
    profile === null || profile.permissions.mode === null || !profile.permissions.mode.test(text)
      ? CICD_PERMISSION_MODES.NOT_ESTABLISHED
      : CICD_PERMISSION_MODES.EXPLICIT;
  const permissions =
    profile === null ? [] : collectGroups(profile.permissions.scopes ?? {}, text);
  const environments = profile === null ? [] : collectGroups(profile.environments ?? {}, text);

  return Object.freeze({
    triggers: Object.freeze(triggers),
    triggerRestrictions: Object.freeze(triggerRestrictions),
    permissionsMode,
    permissions: Object.freeze(permissions),
    secretRefs: Object.freeze(collectList(CICD_SECRET_REFERENCE_DEFINITIONS, text)),
    dependencyInstallation: Object.freeze(collectList(CICD_DEPENDENCY_DEFINITIONS, commandText)),
    builds: Object.freeze(collectList(CICD_BUILD_DEFINITIONS, commandText)),
    deployments: Object.freeze(collectList(CICD_DEPLOYMENT_DEFINITIONS, commandText)),
    environments: Object.freeze(environments),
    artifacts: Object.freeze(collectList(CICD_ARTIFACT_DEFINITIONS, commandText)),
    caches: Object.freeze(collectList(CICD_CACHE_DEFINITIONS, commandText)),
    rollbacks: Object.freeze(collectList(CICD_ROLLBACK_DEFINITIONS, commandText)),
    deploymentProtection: Object.freeze(collectList(CICD_PROTECTION_DEFINITIONS, text)),
  });
}

/** Every observation id this policy can report, by domain — the closed vocabulary, for tests. */
export const CICD_OBSERVATION_IDS = Object.freeze({
  triggers: CICD_TRIGGER_IDS,
  permissions: CICD_PERMISSION_SCOPES,
  secrets: Object.freeze(CICD_SECRET_REFERENCE_DEFINITIONS.map((definition) => definition.id)),
  "dependency-installation": Object.freeze(
    CICD_DEPENDENCY_DEFINITIONS.map((definition) => definition.id),
  ),
  // Test execution is Official Phase 11's evidence, consumed rather than re-classified: this
  // vocabulary is the runner set that policy already defines.
  "test-execution": TEST_RUNNER_IDS,
  "build-execution": Object.freeze(CICD_BUILD_DEFINITIONS.map((definition) => definition.id)),
  deployment: Object.freeze(CICD_DEPLOYMENT_DEFINITIONS.map((definition) => definition.id)),
  "environment-separation": Object.freeze(["development", "test", "staging", "production"]),
  "artifact-handling": Object.freeze(CICD_ARTIFACT_DEFINITIONS.map((definition) => definition.id)),
  caching: Object.freeze(CICD_CACHE_DEFINITIONS.map((definition) => definition.id)),
  rollback: Object.freeze(CICD_ROLLBACK_DEFINITIONS.map((definition) => definition.id)),
  "deployment-protection": Object.freeze(
    CICD_PROTECTION_DEFINITIONS.map((definition) => definition.id),
  ),
});
