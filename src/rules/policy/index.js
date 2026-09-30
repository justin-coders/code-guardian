/**
 * Code Guardian — Policy Rule Pack Boundary (Phase 23)
 *
 * The stable import surface for the `policy.*` namespace. Consumers — an MCP tool, the CLI, a CI
 * job, a future aggregate analyzer — should import from here rather than reaching into the
 * individual rule modules.
 *
 * Phase 23 adds one **informational** rule, `policy.preset.audit`, which reports the preset a
 * repository's policy named, the requirements it supplied and the requirements the repository
 * replaced. Phase 24 extends that same rule to name the **pack** and pinned version the preset came
 * from and whether the repository pinned it — no new rule, because the pack is part of the same
 * fact. It is not a compliance rule: the pack carries no violation, no score, no grade, no traffic
 * light, no recommendation and no severity above `info`.
 *
 * Dependency direction, unchanged from Phase 10 and enforced by an architectural test in
 * `tests/policy-presets.test.js`:
 *
 *   core ← repository/model (8D … 23) ← analysis (9) ← rules (10) ← rules/policy (23)
 *
 * The pack reads the frozen RepositoryModel through the Phase 11 query API and nothing else. It must
 * never import `node:fs`, `node:path`, `child_process`, `node:net`, `node:http`, `node:https`,
 * `node:dns`, `node:worker_threads`, the Phase 8A filesystem boundary, the Phase 8B execution
 * boundary, `src/tools.js`, `tool-registry`, a transport, an MCP/CLI module, the scanner/acquisition
 * layer, or the preset layer itself. It reads no source file, loads no preset, evaluates no
 * expression, contacts no network or registry, and never reads a clock, a random source or the
 * environment.
 */

export {
  MAX_POLICY_FINDINGS,
  POLICY_ABSTENTION_REASON_VALUES,
  POLICY_ABSTENTION_REASONS,
  POLICY_ABSTENTION_WORDING,
  POLICY_ANALYZER_ID,
  POLICY_ANALYZER_NAME,
  POLICY_ANALYZER_SCOPE,
  POLICY_BASIS,
  POLICY_CATEGORY,
  POLICY_CONFIDENCE,
  POLICY_DESCRIBED_STATES,
  POLICY_RULE_ID_PREFIX,
  POLICY_RULE_IDS,
  POLICY_RULE_PACK_VERSION,
  POLICY_RULE_SEVERITY,
  POLICY_RULE_VERSION,
  POLICY_SEVERITY_VALUES,
  POLICY_STATE_WORDING,
} from "./contracts.js";

export {
  activePack,
  activePreset,
  effectivePolicy,
  hasPolicyArea,
  policyArea,
  policyProvenance,
  queryFor,
} from "./signals.js";

export { policyAuditRules, policyRules } from "./rules/index.js";

export { createPolicyRuleRegistry, policyRuleSetIssues } from "./registry.js";

export { createPolicyAnalyzer } from "./analyzer.js";
