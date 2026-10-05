/**
 * Code Guardian — Reliability Analysis Rule Pack Contracts (Official Roadmap Phase 17)
 *
 * The reliability domain's vocabulary for the official roadmap's **Phase 17 — Reliability
 * Analyzer**, which asks for analysis of ten listed domains:
 *
 *   timeouts · retry behavior · circuit breaking · graceful shutdown · health checks ·
 *   failure handling · resource cleanup · transaction handling · queue behavior · observability
 *
 * "especially useful for backend/service repositories."
 *
 * ### Substrate vs analysis, kept apart on purpose
 *
 * The existing `src/rules/api/`, `src/rules/middleware/`, `src/rules/dependency/` and the
 * Phase 16 `api-analysis` packs state facts; the Phase 20 production report records a
 * judgement-free container inventory. This pack adds *reliability analysis* over them and never
 * renames, replaces or deletes an existing rule. No new acquisition is added: every fact this
 * pack reads is already recorded by the accepted scanner and model (see the Phase 17 ADR).
 *
 * ### What the repository can and cannot establish, stated once
 *
 * The model establishes structure, not runtime behaviour. It reads no handler body, no inline
 * option object, boots no server and probes nothing. So a reliability claim rests on one of:
 *
 *   structural   an API route / a container definition / a Dockerfile healthcheck / a middleware
 *                registration the middleware graph classified (name-derived).
 *   usage        a module imports a known reliability package **and** the symbol graph observed
 *                the module using the imported binding (calling or constructing it). Stronger
 *                than a `package.json` dependency: an import plus an observed occurrence.
 *   local-symbol a module-scope *callable* symbol whose name matches a closed vocabulary is
 *                called/referenced (name-derived, weakest evidence).
 *
 * Anything else is `unknown` with a reason. Nothing is inferred from a bare dependency name, from
 * a string or from a comment.
 *
 * ### No score, no remediation, no duplicate security/testing/CI claim
 *
 * There is no reliability score, resilience percentage, uptime prediction, grade or SLO anywhere
 * in the pack, and no rule edits or fixes anything. Security, CI/CD and testing semantics stay
 * with their owners; observability does not restate the Phase 16 `api.logging` gap.
 */

/** Version of the pack as a whole (analyzer version, rule set revision). */
export const RELIABILITY_ANALYSIS_RULE_PACK_VERSION = "1.0.0";

/** Initial version of every rule in the pack. */
export const RELIABILITY_ANALYSIS_RULE_VERSION = "1.0.0";

/** Analyzer identity. */
export const RELIABILITY_ANALYSIS_ANALYZER_ID = "reliability-analysis";
export const RELIABILITY_ANALYSIS_ANALYZER_NAME = "Reliability Analysis";
export const RELIABILITY_ANALYSIS_ANALYZER_SCOPE = "reliability-analysis";

/** Category recorded on every reliability-analysis finding (Core Finding contract). */
export const RELIABILITY_ANALYSIS_CATEGORY = "architecture";

/** Every rule id in this pack must live in this namespace. */
export const RELIABILITY_ANALYSIS_RULE_ID_PREFIX = "reliability.";

/**
 * The ten official domains, in the roadmap's own order, paired with their rule id.
 *
 * Declared centrally so a registry test can pin the pack to the roadmap list, and so a rule id
 * rename — which retires every fingerprint the rule produced — is a deliberate, visible edit.
 * The rule id is `reliability.<domain>`, a direct one-to-one mapping.
 */
export const RELIABILITY_ANALYSIS_RULE_IDS = Object.freeze({
  TIMEOUTS: "reliability.timeouts",
  RETRY_BEHAVIOR: "reliability.retry-behavior",
  CIRCUIT_BREAKING: "reliability.circuit-breaking",
  GRACEFUL_SHUTDOWN: "reliability.graceful-shutdown",
  HEALTH_CHECKS: "reliability.health-checks",
  FAILURE_HANDLING: "reliability.failure-handling",
  RESOURCE_CLEANUP: "reliability.resource-cleanup",
  TRANSACTION_HANDLING: "reliability.transaction-handling",
  QUEUE_BEHAVIOR: "reliability.queue-behavior",
  OBSERVABILITY: "reliability.observability",
});

/** The official domain list, in roadmap order, with the domain's rule id. */
export const RELIABILITY_ANALYSIS_DOMAINS = Object.freeze([
  Object.freeze({ domain: "timeouts", ruleId: RELIABILITY_ANALYSIS_RULE_IDS.TIMEOUTS }),
  Object.freeze({ domain: "retry-behavior", ruleId: RELIABILITY_ANALYSIS_RULE_IDS.RETRY_BEHAVIOR }),
  Object.freeze({ domain: "circuit-breaking", ruleId: RELIABILITY_ANALYSIS_RULE_IDS.CIRCUIT_BREAKING }),
  Object.freeze({ domain: "graceful-shutdown", ruleId: RELIABILITY_ANALYSIS_RULE_IDS.GRACEFUL_SHUTDOWN }),
  Object.freeze({ domain: "health-checks", ruleId: RELIABILITY_ANALYSIS_RULE_IDS.HEALTH_CHECKS }),
  Object.freeze({ domain: "failure-handling", ruleId: RELIABILITY_ANALYSIS_RULE_IDS.FAILURE_HANDLING }),
  Object.freeze({ domain: "resource-cleanup", ruleId: RELIABILITY_ANALYSIS_RULE_IDS.RESOURCE_CLEANUP }),
  Object.freeze({ domain: "transaction-handling", ruleId: RELIABILITY_ANALYSIS_RULE_IDS.TRANSACTION_HANDLING }),
  Object.freeze({ domain: "queue-behavior", ruleId: RELIABILITY_ANALYSIS_RULE_IDS.QUEUE_BEHAVIOR }),
  Object.freeze({ domain: "observability", ruleId: RELIABILITY_ANALYSIS_RULE_IDS.OBSERVABILITY }),
]);

/**
 * The `metadata.state` vocabulary every rule records.
 *
 *   established    a mechanism the repository uses was observed
 *   detected       a gap was established over sufficient coverage
 *   unknown        the repository does not establish enough to conclude — never read as clean
 *   not_applicable no reliability subject exists at all (a CLI tool, a pure library)
 */
export const RELIABILITY_ANALYSIS_STATES = Object.freeze({
  ESTABLISHED: "established",
  DETECTED: "detected",
  UNKNOWN: "unknown",
  NOT_APPLICABLE: "not_applicable",
});

/**
 * The applicability of the *reliability subject itself* — a separate axis from a rule's state.
 *
 *   applicable      a container definition is declared, or the API graph declares ≥ 1 route, or
 *                   the module graph uses a service-runtime package
 *   unknown         the substrate needed to decide is not established (no semantic graph; an
 *                   unsupported source format; an unestablished API graph; an incomplete scan)
 *   not_applicable  the scan is complete, the graphs are established, and no service signal
 *                   exists
 */
export const RELIABILITY_ANALYSIS_SUBJECTS = Object.freeze({
  APPLICABLE: "applicable",
  UNKNOWN: "unknown",
  NOT_APPLICABLE: "not_applicable",
});

/** The `metadata.basis` values this pack records. */
export const RELIABILITY_ANALYSIS_BASES = Object.freeze({
  SYMBOL_GRAPH: "symbol-graph",
  API_GRAPH: "api-graph",
  MIDDLEWARE_GRAPH: "middleware-graph",
  CONTAINER_REPORT: "container-report",
  SERVICE_SIGNALS: "service-signals",
});

/**
 * Confidence policy, chosen to match the *evidence strength* behind each claim.
 *
 *   OBSERVED_ARTIFACT      the repository observes an artifact (a Dockerfile healthcheck). The
 *                          artifact's existence is a fact; whether it works is not.
 *   ESTABLISHED_STRUCTURE  the finding rests on a fully established structural fact (a route).
 *   PACKAGE_USAGE          an import plus an observed call/construct occurrence.
 *   NAME_DERIVED           a name-derived local-symbol vocabulary match (or a middleware name
 *                          classification), the weakest evidence in the pack.
 */
export const RELIABILITY_ANALYSIS_CONFIDENCE = Object.freeze({
  OBSERVED_ARTIFACT: 0.9,
  ESTABLISHED_STRUCTURE: 0.8,
  PACKAGE_USAGE: 0.7,
  NAME_DERIVED: 0.5,
});

/**
 * Findings one rule run will report before it stops and records the cap.
 *
 * A cap that does bite is recorded in `metadata.capped` — never silently applied.
 */
export const RELIABILITY_ANALYSIS_LIMITS = Object.freeze({
  MAX_FINDINGS: 200,
  MAX_USAGES: 500,
  MAX_UNRESOLVED: 1000,
});

/**
 * The service-runtime packages whose *usage* establishes a backend/service subject even when the
 * repository declares no route and no container (a worker, a bare HTTP server).
 */
export const RELIABILITY_SERVICE_RUNTIME_PACKAGES = Object.freeze([
  "express",
  "fastify",
  "koa",
  "hapi",
  "@hapi/hapi",
  "restify",
  "@nestjs/core",
  "connect",
  "polka",
  "micro",
  "serve",
  "http",
  "https",
  "http2",
  "ws",
  "socket.io",
  "bullmq",
  "bull",
  "bee-queue",
  "amqplib",
  "kafkajs",
  "sqs-consumer",
  "@aws-sdk/client-sqs",
  "@google-cloud/pubsub",
  "rsmq",
]);

/**
 * The closed package vocabulary, mapping each reliability domain to the bare module specifiers
 * whose *usage* establishes a mechanism. Matched exactly against the specifier the source wrote.
 *
 * Deliberately small and conservative: a package is listed only when importing and using it is
 * itself a statement about the domain. A database client (knex, pg, …) is **not** listed under
 * transaction handling — using a database is not using a transaction — so that domain rests on a
 * local transaction-helper symbol instead.
 */
export const RELIABILITY_PACKAGE_VOCABULARY = Object.freeze({
  timeouts: Object.freeze([
    "p-timeout",
    "await-timeout",
    "connect-timeout",
    "express-timeout-handler",
    "timeout-as-promise",
    "request-timeout",
  ]),
  "retry-behavior": Object.freeze([
    "p-retry",
    "async-retry",
    "axios-retry",
    "retry",
    "promise-retry",
    "cockatiel",
    "@lifeomic/attempt",
    "exponential-backoff",
    "backoff",
  ]),
  "circuit-breaking": Object.freeze(["opossum", "cockatiel", "hystrixjs", "polly-js"]),
  "graceful-shutdown": Object.freeze([
    "@godaddy/terminus",
    "terminus",
    "stoppable",
    "http-terminator",
    "async-exit-hook",
    "signal-exit",
  ]),
  "health-checks": Object.freeze([
    "express-healthcheck",
    "@godaddy/terminus",
    "terminus",
    "@nestjs/terminus",
    "lightship",
  ]),
  "failure-handling": Object.freeze(["express-async-errors", "express-async-handler", "await-handler"]),
  "resource-cleanup": Object.freeze(["disposable", "using-statement"]),
  "transaction-handling": Object.freeze(["slonik"]),
  "queue-behavior": Object.freeze([
    "bullmq",
    "bull",
    "bee-queue",
    "better-queue",
    "amqplib",
    "kafkajs",
    "sqs-consumer",
    "@aws-sdk/client-sqs",
    "@google-cloud/pubsub",
    "rsmq",
    "agenda",
  ]),
});

/**
 * The observability dimensions, mapping a dimension to the packages whose *usage* establishes it.
 *
 * The roadmap (and §54) insists observability is multi-dimensional: logging, metrics, tracing and
 * error reporting are distinct, so the pack never collapses them into a boolean. The logging
 * dimension additionally reads the middleware graph's existing `logging` classification (reused,
 * not re-derived), and is kept apart from the Phase 16 `api.logging` request-lifecycle rule.
 */
export const RELIABILITY_OBSERVABILITY_DIMENSIONS = Object.freeze({
  logging: Object.freeze(["pino", "winston", "bunyan", "log4js", "morgan", "signale", "consola"]),
  metrics: Object.freeze([
    "prom-client",
    "statsd-client",
    "hot-shots",
    "@opentelemetry/sdk-metrics",
    "measured",
  ]),
  tracing: Object.freeze([
    "@opentelemetry/api",
    "@opentelemetry/sdk-node",
    "@opentelemetry/auto-instrumentations-node",
    "dd-trace",
    "newrelic",
    "elastic-apm-node",
  ]),
  "error-reporting": Object.freeze([
    "@sentry/node",
    "@sentry/browser",
    "rollbar",
    "@bugsnag/js",
    "@honeybadger-io/js",
  ]),
});

/**
 * The closed, conservative local-symbol vocabulary, mapping each domain to the module-scope
 * callable names whose use establishes a mechanism (name-derived, weakest evidence).
 *
 * Matched case-insensitively against the *compacted* name, and only against symbols the symbol
 * graph established as callable or constructable (a `function`, a `class`, a function-valued
 * `const`) **and** that the file actually calls, constructs or references. A plain variable named
 * `transaction`, or an unused declaration, never matches — that is what keeps a "transaction-like
 * variable name" or a "generic logger object" out of the findings.
 */
export const RELIABILITY_LOCAL_VOCABULARY = Object.freeze({
  timeouts: Object.freeze(["withTimeout", "requestTimeout", "createTimeout", "timeoutOperation"]),
  "retry-behavior": Object.freeze([
    "retry",
    "withRetry",
    "retryAsync",
    "retryOperation",
    "retryWithBackoff",
    "withBackoff",
  ]),
  "circuit-breaking": Object.freeze(["circuitBreaker", "withCircuitBreaker", "createCircuitBreaker"]),
  "graceful-shutdown": Object.freeze([
    "gracefulShutdown",
    "shutdown",
    "closeServer",
    "drain",
    "handleShutdown",
    "onShutdown",
  ]),
  "health-checks": Object.freeze(["healthCheck", "checkHealth", "readinessProbe", "livenessProbe"]),
  "failure-handling": Object.freeze([
    "errorHandler",
    "handleError",
    "onError",
    "failureHandler",
    "handleFailure",
    "errorMiddleware",
  ]),
  "resource-cleanup": Object.freeze([
    "cleanup",
    "dispose",
    "disposeResources",
    "releaseResources",
    "closeResources",
    "closeConnections",
  ]),
  "transaction-handling": Object.freeze([
    "withTransaction",
    "runInTransaction",
    "inTransaction",
    "transactional",
    "withDbTransaction",
  ]),
  "queue-behavior": Object.freeze([
    "consume",
    "consumeQueue",
    "processQueue",
    "processJob",
    "handleMessage",
    "startWorker",
  ]),
});

/**
 * Health-shaped route path segments. A route whose path contains one of these as a whole segment
 * (split on `/`) is a health-shaped endpoint. A closed set, so `/healthcare` or `/status-page`
 * never matches and no substring heuristic is used.
 */
export const RELIABILITY_HEALTH_PATH_SEGMENTS = Object.freeze([
  "health",
  "healthz",
  "health-check",
  "healthcheck",
  "live",
  "livez",
  "liveness",
  "ready",
  "readyz",
  "readiness",
  "ping",
]);

/**
 * What the container inventory establishes, read from the Phase 20 production report's own
 * judgement-free `container` section.
 */
export const RELIABILITY_CONTAINER_SECTION = "container";
