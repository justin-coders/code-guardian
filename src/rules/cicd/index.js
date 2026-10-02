/**
 * Code Guardian — CI/CD Rule Pack Boundary (Official Roadmap Phase 13)
 *
 * The stable import surface for the CI/CD domain. Consumers import from here rather than
 * reaching into the individual rule modules.
 *
 * ### Phase numbering: this pack is the official roadmap's Phase 13
 *
 * The official roadmap's Phase 13 is **"CI/CD Analyzer"**, and this pack plus `analyzer.js` is
 * that analyzer:
 *
 *   Repository → RepositoryModel → CICDAnalyzer → applicable rules → evidence → findings
 *
 * A bare `Phase 8C`/`Phase 11` inside this pack names this repository's *internal* architecture
 * layer or the earlier official phase whose evidence it *consumes*, never this milestone.
 *
 * ### Dependency direction
 *
 * Enforced by an architectural test in `tests/cicd-analyzer.test.js`:
 *
 *   core ← repository/model ← analysis ← rules ← rules/cicd
 *
 * The pack reads the frozen RepositoryModel through the query API and nothing else. It must
 * never import `node:fs`, `node:fs/promises`, `node:path`, `child_process`, `node:net`,
 * `node:http`, `node:https`, `node:dns`, `node:worker_threads`, the filesystem boundary, the
 * execution boundary, `src/tools.js`, `tool-registry`, a transport, or an MCP/CLI module. It
 * reads no workflow file itself, runs no command, contacts no CI provider, authenticates
 * nothing, triggers nothing, and consults no clock, random source or environment.
 *
 * ### The twelve domains, and where each rests
 *
 *   workflow triggers          trigger events and branch/path/tag restrictions the workflow states
 *   permissions                whether an explicit `permissions` block was declared, and which
 *                              scopes — a configuration fact, never a security verdict
 *   secret handling            the *shapes* of the secret references stated (a `secrets.` context,
 *                              an OIDC request, a vault command, a cloud secret manager); no
 *                              secret name or value is ever read, stored or printed
 *   dependency installation     cross-ecosystem install commands (`npm ci`, `pip install`, …)
 *   test execution             Official Phase 11's own closed runner evidence, consumed not
 *                              re-derived
 *   build execution            cross-ecosystem build commands (`npm run build`, `cargo build`, …)
 *   deployment                 bounded deployment invocations (`kubectl apply`, `helm upgrade`, …)
 *   environment separation      environment classes declared against a deployment
 *   artifact handling           upload/download actions, retention, release assets
 *   caching                    cache actions, setup-action `cache:` inputs, cache keys
 *   rollback                   deployment-restoration evidence — never a source-control revert
 *   deployment protection       protected environments, required reviewers, manual/concurrency
 *                              gates
 *
 * ### Provider modularity
 *
 * Provider knowledge lives in the acquisition layer's profile table
 * (`src/repository/scanner/policies/cicd.js`), which turns each provider's documented syntax into
 * the same closed vocabulary. The rules read that union, so no rule branches on a provider and
 * adding one is adding a profile — not editing twelve rules. A provider with no profile yields
 * command-based facts only, and its structural domains are honestly reported `unknown`.
 *
 * ### Exactly one satisfied absence, and the rest left unknown
 *
 * The twelve rules are all *confidence-bounded*: an absence is asserted only over a workflow that
 * was interpreted **in full**. A truncated read supports presence, never absence; an
 * uninterpretable workflow (binary content, an errored read) makes the affected domains `failed`;
 * a pipeline that was merely too large or beyond the byte budget makes them `unknown`. That
 * distinction is the phase's central claim, and the fixtures prove it.
 *
 * ### Limitations, stated rather than hidden
 *
 *   - **No execution, ever.** Nothing here runs a pipeline, a container, `kubectl`, `terraform`
 *     or a deployment command; nothing contacts a provider. `verified` is a statement about the
 *     *evidence* — the workflow was read in full — and never about a run succeeding.
 *   - **No YAML parser.** The acquisition read is bounded and line-oriented: comments are
 *     stripped, structural facts are matched in key position, command facts require a documented
 *     invocation, and quoted scalars establish no command. A provider idiom outside that
 *     documented vocabulary is invisible, and the rules say `unknown`/not-established rather
 *     than guessing.
 *   - **Partial provider coverage.** Only GitHub Actions and GitLab have a structural profile;
 *     every other recognised provider gets the shared command vocabulary, so its triggers,
 *     permissions and protection read `unknown`.
 *   - **No secret values.** Only the closed reference *shape* is recorded.
 *   - **No security conclusions.** Missing permissions, secret references and unprotected
 *     deploys are CI/CD configuration observations; the security reading belongs to the Security
 *     Analyzer (Official Phase 10), and this pack deliberately does not duplicate it.
 *   - **No score.** There is no CI/CD score, pipeline-health metric or deployment-risk number.
 */

export {
  CICD_ANALYZER_ID,
  CICD_ANALYZER_NAME,
  CICD_ANALYZER_SCOPE,
  CICD_BASES,
  CICD_BOUNDED_READ_REASONS,
  CICD_CATEGORY,
  CICD_CONFIDENCE,
  CICD_CONTENT_STATES,
  CICD_DOMAIN_IDS,
  CICD_INTERPRETATION_FAILURE_REASONS,
  CICD_LIMITS,
  CICD_PERMISSION_MODES,
  CICD_PROVIDERS,
  CICD_RULE_DOMAINS,
  CICD_RULE_ID_PREFIX,
  CICD_RULE_IDS,
  CICD_RULE_PACK_VERSION,
  CICD_RULE_VERSION,
  CICD_STATES,
} from "./contracts.js";

export {
  anyBounded,
  anyFailure,
  anyInterpreted,
  anyNotInterpreted,
  ciProviders,
  ciWorkflows,
  cicdAbsence,
  evidenceIdsForWorkflows,
  observationsFor,
  queryFor,
  workflowRecord,
} from "./signals.js";

export { summarizeCicd } from "./summary.js";

export { cicdRules } from "./rules/index.js";

export { createAbsenceRule, createPresenceRule, createRelationRule } from "./rules/factories.js";

export { cicdRuleSetIssues, createCicdRuleRegistry } from "./registry.js";

export { createCicdAnalyzer } from "./analyzer.js";
