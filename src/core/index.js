/**
 * Code Guardian Core — Public Boundary
 *
 * One stable import boundary for the Core contract layer. Future analyzers,
 * rules, repository intelligence, and interfaces should import from
 * `src/core/index.js` instead of reaching into individual internal files.
 *
 * The Core is transport-independent: it must never import MCP, HTTP, the CLI,
 * the legacy tool registry, or `tools.js`.
 */

/** Version of the Core contract surface. */
export const CORE_CONTRACT_VERSION = "1";

/**
 * Semantics shared by every `createX()` factory in the Core.
 *
 * The Core factories are **shape/draft factories**, not guaranteed-valid
 * constructors: each returns a fully contract-shaped object and fills only
 * semantically-neutral defaults, but does not guarantee validity. In
 * particular they never fabricate security-, authorization-, detection-,
 * fingerprint-, or provenance-relevant facts. Callers must run the matching
 * `validateX()` before treating a draft as a valid contract instance.
 *
 * This is intentionally uniform: no factory is a validator, and validation is
 * always the authority on validity.
 */
export const CONTRACT_FACTORY_SEMANTICS = "draft";

// ─── Contracts ───────────────────────────────────────────────────────────────

export {
  REPOSITORY_MODEL_VERSION,
  REPOSITORY_MODEL_AREAS,
  REPOSITORY_MODEL_OPTIONAL_AREAS,
  REPOSITORY_MODEL_JUDGMENT_AREAS,
  SCAN_REQUIRED_FIELDS,
  DEFAULT_SCAN_LIMITS,
  createRepositoryModel,
} from "./contracts/repository-model.js";

export {
  EVIDENCE_TYPES,
  EVIDENCE_LOCATION_FIELDS,
  createEvidence,
} from "./contracts/evidence.js";

export {
  FINDING_SEVERITIES,
  FINDING_STATUSES,
  FINDING_STAGES,
  DEFAULT_FINDING_STATUS,
  CONFIDENCE_MIN,
  CONFIDENCE_MAX,
  isValidConfidence,
  hasFingerprint,
  createFinding,
} from "./contracts/finding.js";

export {
  VERSION_PATTERN,
  RULE_REQUIRED_FIELDS,
  RULE_APPLICABILITY_KEYS,
  RULE_METADATA_KEYS,
  createRule,
} from "./contracts/rule.js";

export {
  ANALYZER_REQUIRED_FIELDS,
  ANALYSIS_RESULT_FIELDS,
  createAnalysisResult,
  createApplicability,
} from "./contracts/analyzer.js";

export {
  ANALYSIS_CONTEXT_FIELDS,
  createAnalysisContext,
} from "./contracts/analysis-context.js";

export {
  EXECUTION_STATES,
  EXECUTION_REQUEST_FIELDS,
  EXECUTION_RESULT_FIELDS,
  DEFAULT_EXECUTION_TIMEOUT_MS,
  DEFAULT_MAX_OUTPUT_BYTES,
  DEFAULT_NETWORK_POLICY,
  DEFAULT_EXECUTION_LIMITS,
  EXECUTION_LIMIT_PRECEDENCE,
  EXECUTION_COMMAND_PRECEDENCE,
  createExecutionLimits,
  createExecutionPolicy,
  createExecutionRequest,
  createExecutionResult,
  getExecutionState,
} from "./contracts/execution.js";

// ─── Errors ──────────────────────────────────────────────────────────────────

export {
  ERROR_CATEGORIES,
  ERROR_CODES,
  CoreError,
  ValidationError,
  ConfigurationError,
  RepositoryError,
  ExecutionError,
  AnalysisError,
  isCoreError,
} from "./errors/core-error.js";

// ─── Validation ──────────────────────────────────────────────────────────────

export {
  validateRepositoryModel,
  validateEvidence,
  validateFinding,
  validateRawFinding,
  validateRule,
  validateAnalyzer,
  validateAnalyzerApplicability,
  validateAnalyzerResult,
  validateAnalysisContext,
  validateExecutionRequest,
  validateExecutionResult,
  validateExecutionPolicy,
  validateExecutionLimits,
  validateContract,
  KNOWN_CONTRACTS,
} from "./validation/contract-validation.js";
