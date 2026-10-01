/**
 * Code Guardian — Security Rule Pack Boundary (Official Roadmap Phase 10)
 *
 * The stable import surface for the security domain. Consumers — an MCP tool, the
 * CLI, a CI job, a future aggregate analyzer — should import from here rather than
 * reaching into the individual rule modules.
 *
 * ### Phase numbering: this pack is the official roadmap's Phase 10
 *
 * The official roadmap's Phase 10 is **"First Production Analyzer: Security"**, and this
 * pack plus `analyzer.js` is that analyzer:
 *
 *   Repository → RepositoryModel → SecurityAnalyzer → applicable rules → evidence → findings
 *
 * Older revisions of these files called themselves "Phase 12", which was this
 * repository's *internal* implementation increment. The two numbering schemes are
 * different things and both still appear in comments, so: a reference to a bare
 * component phase — `Phase 8A` filesystem boundary, `Phase 8C` scanner, `Phase 8D` model
 * builder, `Phase 9` analyzer/finding framework, `Phase 10` Rule Engine, `Phase 11` query
 * API — names the **internal** layer this pack consumes. "Official Roadmap Phase 10" (and
 * `docs/ROADMAPS/Code Guardian — Long-Term Development Roadmap.md`) is the only numbering
 * that says where the *product* is, and it is the one this pack is placed by.
 *
 * ### Dependency direction
 *
 * Unchanged, and enforced by an architectural test in `tests/security-rules.test.js`:
 *
 *   core ← repository/model ← analysis ← rules ← rules/security
 *
 * The pack reads the frozen RepositoryModel through the query API and nothing else. It
 * must never import `node:fs`, `node:path`, `child_process`, `node:net`, `node:http`,
 * `node:https`, `node:dns`, `node:worker_threads`, the filesystem boundary, the execution
 * boundary, `src/tools.js`, `tool-registry`, a transport, or an MCP/CLI module. It reads no
 * file contents of its own, runs no command, and consults no clock, random source or
 * environment: security findings here are deterministic, evidence-first, and scoped to what
 * the repository model can actually prove.
 *
 * ### Scope: an incremental initial rule set, not every security family
 *
 * The roadmap names twelve initial security families and says the exact rules "should be
 * introduced incrementally and tested against fixtures". This pack implements the ones the
 * repository model and its graph projections can establish evidence for today:
 *
 *   secrets                      sensitive-file names (dotenv, keys, keystores, credential
 *                                stores, service-account keys, Terraform state) and the
 *                                bounded content observations for credential-shaped and
 *                                key-block content
 *   sensitive data exposure      the same two, plus symlinks whose target leaves the
 *                                repository
 *   container security           a Dockerfile whose established build context has no
 *                                `.dockerignore` at its root
 *   authorization configuration  a route whose path names a privileged surface that no
 *                                `authentication` / `authorization` middleware reaches
 *   debug endpoints              a route whose path names a diagnostic surface
 *
 * Deliberately **not** implemented, because the repository establishes no evidence this
 * build can conclude from — a finding here would be fabricated, not deferred:
 *
 *   dependency vulnerabilities   needs a vulnerability database or advisory feed; the local
 *                                dependency inventory is not one, and this build has no
 *                                network acquisition
 *   unsafe command execution     needs data flow or a call-graph reading of arguments; the
 *                                symbol graph establishes names, not what a command runs
 *   unsafe CORS, insecure
 *   cookies, dangerous headers   need response/configuration *values*; the middleware graph
 *                                classifies a registration by name and reads no options
 *   CI security                  needs workflow-body parsing; CI is detected by the
 *                                workflow file's documented location only
 *   authentication configuration the middleware graph states what reaches a route, never
 *                                what a middleware enforces, so "authentication is
 *                                configured incorrectly" is not expressible
 *
 * Those gaps are bounded statements about this build, not a backlog: each belongs to a
 * later roadmap phase that adds the acquisition it needs. Nothing here is renamed or
 * renumbered by this scope note.
 *
 * ### Applicability and `unknown`, per rule
 *
 * Every rule in this pack declares an empty selector object (`applicability: {}`) and
 * decides applicability from evidence inside `detect`, which is the convention all rule
 * packs in this repository follow. The Rule Engine still owns the outcome vocabulary, and
 * these rules produce three of its values — `pass`, `violation` and `unknown` (`failed`
 * remains available to the engine for a rule that throws, and `not-applicable` is the one
 * they never produce):
 *
 *   pass         the rule's subject was established and the condition was not observed. For
 *                an absence-shaped claim this is only reachable over *complete* coverage —
 *                the rule asks `inventoryAbsence()` (or the graph's own coverage) first.
 *   violation    the condition was observed; a finding cites the model observations behind
 *                it and is never emitted from a guess.
 *   unknown      the evidence needed for either of the above was not established: an
 *                incomplete scan, a path that could not be read, an uninterpreted module
 *                format, an unresolved route, a middleware the graph could not establish, a
 *                truncated projection. The engine records `unknown` with the rule's own
 *                reason, and a run containing one is not `complete`.
 *   not-applicable
 *                **not produced by this pack.** The Rule Engine can produce it from a
 *                satisfied-or-unsatisfied selector (see `src/rules/applicability.js`), and
 *                the pack's rules deliberately declare no selector: their subjects — file
 *                names, content observations, container declarations, declared routes — are
 *                meaningful to check in every repository, so "this does not apply" has no
 *                honest basis here. A framework selector on the route rules was considered
 *                and rejected: it would report `not-applicable` for a Koa/Nest repository
 *                whose routes the API graph *cannot read*, turning "unknown" into "does not
 *                apply" — the inversion `applicability.js` warns against.
 *
 * "Not observed" therefore never reads as "not present" unless the model's own coverage
 * says the subject was read in full, and a repository whose scan was incomplete can never
 * receive a clean security result.
 */

export {
  AUTHORIZING_CLASSIFICATIONS,
  CONFIGURATION_SIGNALS,
  CONTENT_CANDIDATE_FILES,
  CONTENT_PATTERNS,
  DIAGNOSTIC_ROUTE_SEGMENTS,
  FINDING_BASES,
  FINDING_BASIS,
  PRIVILEGED_ROUTE_SEGMENTS,
  SECURITY_ANALYZER_ID,
  SECURITY_ANALYZER_NAME,
  SECURITY_ANALYZER_SCOPE,
  SECURITY_CATEGORY,
  SECURITY_CONFIDENCE,
  SECURITY_RULE_ID_PREFIX,
  SECURITY_RULE_IDS,
  SECURITY_RULE_PACK_VERSION,
  SECURITY_RULE_VERSION,
  SENSITIVE_FILE_SPECS,
} from "./contracts.js";

export {
  FILE_SPEC_CRITERIA,
  defineFileSpec,
  matchesFileSpec,
  matchesRoutePath,
} from "./matching.js";

export {
  configurationEntities,
  contentInspectionFor,
  fileInventory,
  filesMatching,
  inventoryAbsence,
  isCompleteContentInspection,
  middlewareSourceEvidenceId,
  queryFor,
  routeInventory,
  routeProtections,
  symlinkInventory,
  symlinkTargets,
} from "./signals.js";

export { routeRules, securityRules } from "./rules/index.js";

export { createSecurityRuleRegistry, securityRuleSetIssues } from "./registry.js";

export { createSecurityAnalyzer } from "./analyzer.js";
