/**
 * Code Guardian — Analysis Boundary (Phase 9)
 *
 * Stable import boundary for the analyzer framework. Future domain analyzers and
 * interface layers should import from here rather than reaching into individual
 * files.
 *
 * Dependency direction, enforced by an architectural test in
 * `tests/analyzer-framework.test.js`:
 *
 *   core  ←  repository/model (8D)  ←  analysis (9)
 *
 * This layer consumes Core contracts and the frozen RepositoryModel. It must never
 * import `node:fs`, `node:fs/promises`, `child_process`, `node:net`, `node:http`,
 * `node:https`, `src/tools.js`, `tool-registry`, a transport, or the Phase 8A
 * filesystem boundary. `node:crypto` is the single Node builtin it uses, for
 * content-free hashing of finding identity inputs (see `findings.js`), and it
 * performs no I/O of any kind.
 *
 * There is deliberately no way to execute a process from here. An analyzer that
 * eventually needs one must go through the accepted Phase 8B execution boundary in
 * a later phase; exposing a capability now would be a security decision masquerading
 * as an ergonomics improvement.
 */

export {
  ANALYZER_ENGINE_VERSION,
  ANALYZER_FAILURE_CODES,
  ANALYZER_FAILURE_KINDS,
  ANALYZER_ID_PATTERN,
  ANALYZER_RUN_STATUSES,
  ANALYZER_SCOPE_PATTERN,
  ABNORMAL_ANALYZER_STATUSES,
  ANALYSIS_JUDGMENT_KEYS,
  FINGERPRINT_KEY_METADATA_KEY,
  FINDING_FINGERPRINT_ALGORITHM,
  FINDING_FINGERPRINT_PREFIX,
  FINDING_ID_PREFIX,
  MAX_ERROR_MESSAGE_LENGTH,
  MAX_FINGERPRINT_KEY_LENGTH,
  MAX_IDENTIFIER_LENGTH,
  TERMINAL_ANALYZER_STATUSES,
} from "./contracts.js";

export {
  ANALYZER_RUN_RESULT_FIELDS,
  ANALYSIS_RUN_RESULT_FIELDS,
  analyzerResultDraftIssues,
  createAnalysisRunResult,
  createAnalyzerRunResult,
  stableAnalysisView,
  validateAnalysisRunResult,
  validateAnalyzerRunResult,
} from "./results.js";

export {
  AnalyzerConfigurationError,
  AnalyzerFrameworkError,
  AnalyzerRegistrationError,
  FAILURE_CODE_BY_KIND,
  failureEntry,
  sanitizeMessage,
} from "./errors.js";

export { analyzerDescriptorIssues, createAnalyzerRegistry } from "./registry.js";

export {
  ANALYSIS_CONTEXT_INPUT_KEYS,
  buildAnalysisContext,
  indexRulesById,
  modelEvidenceIds,
} from "./context.js";

export { describeValue, evaluateApplicability } from "./applicability.js";

export {
  deduplicateFindings,
  findingFingerprint,
  fingerprintKeyOf,
  normalizeFinding,
  orderFindings,
} from "./findings.js";

export { DEFAULT_ENGINE_OPTIONS, createAnalyzerEngine, findingsForAnalyzer, isRunComplete } from "./engine.js";

export {
  SANITIZE_LIMITS,
  TRUNCATION_MARKER,
  UNSAFE_KEYS,
  deepFreeze,
  sanitizeDeclarativeValue,
} from "./values.js";
