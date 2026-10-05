/**
 * Code Guardian — Reliability Analysis Analyzer Tests (official roadmap Phase 17)
 *
 * The end-to-end proof that the Reliability Analyzer works through the real pipeline:
 *
 *   Repository → Scanner(facts) → RepositoryModel → ReliabilityAnalyzer → reliability-analysis rules
 *              → evidence → findings
 *
 * Golden fixtures A–T from the Phase 17 handoff live here as real repositories written to a
 * temporary directory and scanned through the accepted scanner/model boundary. The suite's central
 * claims are the roadmap's exit criteria: all ten domains are addressed, a CLI repository is
 * `not_applicable` and receives no finding, an unsupported framework/source is `unknown` (never
 * `not_applicable`), every finding cites model evidence, an incomplete acquisition turns a
 * conclusion into `unknown` rather than clean, test-only usage is not application reliability, and
 * the pack imports no filesystem, process, network or MCP module.
 *
 * Run with: node --test tests/reliability-analysis-analyzer.test.js
 */

import { after, describe, it } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

import { scanRepository } from "../src/repository/scanner/index.js";
import { buildRepositoryModel } from "../src/repository/model/index.js";

import { buildAnalysisContext, createAnalyzerEngine, createAnalyzerRegistry } from "../src/analysis/index.js";

import {
  RELIABILITY_ANALYSIS_ANALYZER_ID,
  RELIABILITY_ANALYSIS_RULE_IDS,
  RELIABILITY_ANALYSIS_STATES,
  createReliabilityAnalysisAnalyzer,
  createReliabilityAnalysisRuleRegistry,
  createRuleEngine,
  reliabilityAnalysisRules,
} from "../src/rules/index.js";

// ─── Harness ─────────────────────────────────────────────────────────────────

const TMP_ROOT = join(tmpdir(), `cg-reliability-${process.pid}-${Date.now()}`);
let counter = 0;

function makeRepo(files = {}) {
  const root = join(TMP_ROOT, `repo-${counter++}`);
  mkdirSync(root, { recursive: true });
  for (const [relative, content] of Object.entries(files)) {
    const full = join(root, relative);
    mkdirSync(dirname(full), { recursive: true });
    writeFileSync(full, content);
  }
  return root;
}

async function scanModel(files) {
  const root = makeRepo(files);
  const scan = await scanRepository(root);
  return buildRepositoryModel(scan);
}

after(() => {
  rmSync(TMP_ROOT, { recursive: true, force: true });
});

const contextOf = (model) => buildAnalysisContext({ repository: model });

async function runAnalyzer(model) {
  const engine = createAnalyzerEngine({
    registry: createAnalyzerRegistry([createReliabilityAnalysisAnalyzer()]),
  });
  return engine.runAll(contextOf(model));
}

async function runRules(model) {
  const engine = createRuleEngine({
    registry: createReliabilityAnalysisRuleRegistry({ rules: reliabilityAnalysisRules }),
  });
  return engine.runAll(contextOf(model));
}

const summaryOf = (result) =>
  result.analyzers.find((entry) => entry.analyzer.id === RELIABILITY_ANALYSIS_ANALYZER_ID).metadata
    .reliabilityAnalysisSummary;
const stateOf = (result, domain) => summaryOf(result).domains[domain].state;
const findingsOf = (result, ruleId) => result.findings.filter((finding) => finding.ruleId === ruleId);
const statusOf = (run, ruleId) => run.rules.find((entry) => entry.rule.id === ruleId)?.status;

// ─── Fixture builders ────────────────────────────────────────────────────────

const pkg = (extra) => `${JSON.stringify({ name: "demo", version: "1.0.0", ...extra })}\n`;
const IDS = RELIABILITY_ANALYSIS_RULE_IDS;
const STATES = RELIABILITY_ANALYSIS_STATES;

// A — CLI-only repository, no service subject.
const CLI = {
  "package.json": pkg({ bin: { demo: "src/cli.js" } }),
  "src/cli.js": `export function main() { process.stdout.write("hi\\n"); }\n`,
};

// B — Express service.
const EXPRESS = {
  "package.json": pkg({ dependencies: { express: "^4.18.0" } }),
  "src/app.js": `import express from "express";
const app = express();
const listUsers = (req, res) => res.json([]);
app.get("/users", listUsers);
export default app;
`,
};

// C — Fastify service.
const FASTIFY = {
  "package.json": pkg({ dependencies: { fastify: "^4.0.0" } }),
  "src/app.js": `import fastify from "fastify";
const app = fastify();
const listUsers = (req, reply) => reply.send([]);
app.get("/users", listUsers);
export default app;
`,
};

// A minimal Express service shell reused by the mechanism fixtures, so each is a service subject.
const SERVICE_APP = {
  "src/server.js": `import express from "express";
const app = express();
const listUsers = (req, res) => res.json([]);
app.get("/users", listUsers);
export default app;
`,
};

// D — explicit request timeout via a timeout package.
const TIMEOUT = {
  "package.json": pkg({ dependencies: { express: "^4.18.0", "p-timeout": "^6.0.0" } }),
  ...SERVICE_APP,
  "src/app.js": `import pTimeout from "p-timeout";
async function work() { return 1; }
export async function handler() { return pTimeout(work(), 1000); }
`,
};

// E — retry configuration via a retry package.
const RETRY = {
  "package.json": pkg({ dependencies: { express: "^4.18.0", "p-retry": "^6.0.0" } }),
  ...SERVICE_APP,
  "src/retry.js": `import pRetry from "p-retry";
async function work() { return 1; }
export function run() { return pRetry(work); }
`,
};

// F — circuit breaker via a circuit-breaker package.
const BREAKER = {
  "package.json": pkg({ dependencies: { express: "^4.18.0", opossum: "^8.0.0" } }),
  ...SERVICE_APP,
  "src/breaker.js": `import CircuitBreaker from "opossum";
async function work() { return 1; }
export const breaker = new CircuitBreaker(work);
`,
};

// G — graceful shutdown via a named local helper.
const SHUTDOWN = {
  "package.json": pkg({ dependencies: { express: "^4.18.0" } }),
  "src/app.js": `import express from "express";
const app = express();
const listUsers = (req, res) => res.json([]);
app.get("/users", listUsers);
function gracefulShutdown() { app.close(); }
process.on("SIGTERM", gracefulShutdown);
export default app;
`,
};

// H — container healthcheck (Dockerfile HEALTHCHECK).
const DOCKER_HEALTHCHECK = {
  "package.json": pkg({ dependencies: { express: "^4.18.0" } }),
  Dockerfile: `FROM node:20
WORKDIR /app
HEALTHCHECK CMD curl -f http://localhost/health || exit 1
CMD node src/app.js
`,
  "src/app.js": `import express from "express";
const app = express();
const listUsers = (req, res) => res.json([]);
app.get("/users", listUsers);
export default app;
`,
};

// I — health endpoint.
const HEALTH_ENDPOINT = {
  "package.json": pkg({ dependencies: { express: "^4.18.0" } }),
  "src/app.js": `import express from "express";
const app = express();
const health = (req, res) => res.json({ ok: true });
app.get("/healthz", health);
export default app;
`,
};

// J — named failure handler.
const FAILURE = {
  "package.json": pkg({ dependencies: { express: "^4.18.0" } }),
  "src/app.js": `import express from "express";
const app = express();
function errorHandler(err, req, res, next) { res.status(500).end(); }
const listUsers = (req, res) => res.json([]);
app.use(errorHandler);
app.get("/users", listUsers);
export default app;
`,
};

// K — named cleanup helper that is called.
const CLEANUP = {
  "package.json": pkg({ dependencies: { express: "^4.18.0" } }),
  ...SERVICE_APP,
  "src/cleanup.js": `function cleanup() { return null; }
export function stop() { cleanup(); }
`,
};

// L — named transaction helper that is called.
const TRANSACTION = {
  "package.json": pkg({ dependencies: { express: "^4.18.0" } }),
  ...SERVICE_APP,
  "src/db.js": `async function work() { return 1; }
export async function withTransaction(fn) { return fn(); }
export async function run() { return withTransaction(work); }
`,
};

// M — queue consumer via a queue package.
const QUEUE = {
  "package.json": pkg({ dependencies: { bullmq: "^5.0.0" } }),
  "src/worker.js": `import { Worker } from "bullmq";
const worker = new Worker("jobs");
export default worker;
`,
};

// N — observability via a logging package.
const OBSERVABILITY = {
  "package.json": pkg({ dependencies: { express: "^4.18.0", pino: "^8.0.0" } }),
  ...SERVICE_APP,
  "src/log.js": `import pino from "pino";
export const logger = pino();
`,
};

const MULTIPLE = {
  "package.json": pkg({
    dependencies: {
      express: "^4.18.0",
      "p-retry": "^6.0.0",
      opossum: "^8.0.0",
      bullmq: "^5.0.0",
      pino: "^8.0.0",
      "prom-client": "^15.0.0",
    },
  }),
  Dockerfile: `FROM node:20
HEALTHCHECK CMD curl -f http://localhost/health || exit 1
`,
  "src/app.js": `import express from "express";
import pRetry from "p-retry";
import CircuitBreaker from "opossum";
import { Queue } from "bullmq";
import pino from "pino";
import { Registry } from "prom-client";
const logger = pino();
const registry = new Registry();
const app = express();
const queue = new Queue("jobs");
async function work() { return 1; }
const breaker = new CircuitBreaker(work);
async function retryWork() { return pRetry(work); }
async function withTransaction(fn) { return fn(); }
const result = withTransaction(work);
function gracefulShutdown() { queue.close(); }
process.on("SIGTERM", gracefulShutdown);
const health = (req, res) => res.json({ ok: true });
app.get("/health", health);
export default app;
`,
};

// Q — unsupported framework (Koa), but a service subject via runtime usage.
const KOA = {
  "package.json": pkg({ dependencies: { koa: "^2.14.0" } }),
  "src/app.js": `import Koa from "koa";
const app = new Koa();
export default app;
`,
};

// Q2 — unsupported source format only.
const TSX_ONLY = { "src/App.tsx": "export const App = () => null;\n" };

// P — partial acquisition: a truncated module source.
const TRUNCATED = {
  "package.json": pkg({ dependencies: { express: "^4.18.0" } }),
  "src/app.js": `import express from "express";
const app = express();
const listUsers = (req, res) => res.json([]);
app.get("/users", listUsers);
export default app;
const pad = "${"x".repeat(300000)}";
`,
};

// R — unresolved/dynamic: a module containing eval voids its name resolution.
const DYNAMIC = {
  "package.json": pkg({ dependencies: { express: "^4.18.0", "p-retry": "^6.0.0" } }),
  "src/app.js": `import express from "express";
import pRetry from "p-retry";
async function work() { return 1; }
async function retryWork() { return pRetry(work); }
const app = express();
const listUsers = (req, res) => res.json([]);
app.get("/users", listUsers);
export default app;
export { retryWork };
`,
  "src/dynamic.js": `export function dynamic(name) { return eval(name); }\n`,
};

// ─── Golden fixtures ─────────────────────────────────────────────────────────

describe("reliability analysis analyzer: applicability", () => {
  it("A — a CLI repository is not_applicable and receives no finding", async () => {
    const model = await scanModel(CLI);
    const result = await runAnalyzer(model);
    assert.equal(result.findings.length, 0);
    const summary = summaryOf(result);
    assert.equal(summary.subject, "not_applicable");
    for (const entry of Object.values(summary.domains)) {
      assert.equal(entry.state, STATES.NOT_APPLICABLE);
    }
    const run = await runRules(model);
    for (const entry of run.rules) assert.equal(entry.status, "pass");
  });

  it("B/C — an Express and a Fastify service are applicable", async () => {
    for (const files of [EXPRESS, FASTIFY]) {
      const result = await runAnalyzer(await scanModel(files));
      assert.equal(summaryOf(result).subject, "applicable");
      assert.ok(summaryOf(result).coverageBasis.apiRoutes >= 1);
    }
  });

  it("Q — an unsupported framework is applicable-via-runtime, never not_applicable", async () => {
    const result = await runAnalyzer(await scanModel(KOA));
    assert.notEqual(summaryOf(result).subject, "not_applicable");
    assert.equal(stateOf(result, "queue-behavior"), STATES.NOT_APPLICABLE);
    assert.equal(stateOf(result, "timeouts"), STATES.UNKNOWN);
  });

  it("Q2 — a repository whose sources are an uninterpreted format is unknown", async () => {
    const result = await runAnalyzer(await scanModel(TSX_ONLY));
    assert.equal(result.findings.length, 0);
    assert.equal(summaryOf(result).subject, "unknown");
  });
});

describe("reliability analysis analyzer: domain mechanisms", () => {
  it("D — a timeout package establishes timeouts", async () => {
    const result = await runAnalyzer(await scanModel(TIMEOUT));
    assert.equal(stateOf(result, "timeouts"), STATES.ESTABLISHED);
    assert.equal(findingsOf(result, IDS.TIMEOUTS).length, 1);
  });

  it("E — a retry package establishes retry behavior", async () => {
    const result = await runAnalyzer(await scanModel(RETRY));
    assert.equal(stateOf(result, "retry-behavior"), STATES.ESTABLISHED);
    assert.equal(findingsOf(result, IDS.RETRY_BEHAVIOR).length, 1);
  });

  it("F — a circuit-breaker package establishes circuit breaking", async () => {
    const result = await runAnalyzer(await scanModel(BREAKER));
    assert.equal(stateOf(result, "circuit-breaking"), STATES.ESTABLISHED);
    assert.equal(findingsOf(result, IDS.CIRCUIT_BREAKING).length, 1);
    assert.equal(findingsOf(result, IDS.CIRCUIT_BREAKING)[0].confidence, 0.7);
  });

  it("G — a named shutdown helper establishes graceful shutdown (name-derived)", async () => {
    const result = await runAnalyzer(await scanModel(SHUTDOWN));
    assert.equal(stateOf(result, "graceful-shutdown"), STATES.ESTABLISHED);
    const findings = findingsOf(result, IDS.GRACEFUL_SHUTDOWN);
    assert.equal(findings.length, 1);
    assert.equal(findings[0].confidence, 0.5);
  });

  it("H — a Dockerfile healthcheck establishes health checks (observed artifact)", async () => {
    const result = await runAnalyzer(await scanModel(DOCKER_HEALTHCHECK));
    assert.equal(stateOf(result, "health-checks"), STATES.ESTABLISHED);
    const findings = findingsOf(result, IDS.HEALTH_CHECKS);
    assert.equal(findings[0].metadata.evidenceClass, "container-healthcheck");
    assert.equal(findings[0].confidence, 0.9);
  });

  it("I — a health-shaped endpoint establishes health checks (structural indicator)", async () => {
    const result = await runAnalyzer(await scanModel(HEALTH_ENDPOINT));
    assert.equal(stateOf(result, "health-checks"), STATES.ESTABLISHED);
    const findings = findingsOf(result, IDS.HEALTH_CHECKS);
    assert.equal(findings[0].metadata.evidenceClass, "health-endpoint");
    assert.match(findings[0].description, /structural indicator/i);
    assert.equal(findings[0].confidence, 0.8);
  });

  it("J — a named error handler establishes failure handling", async () => {
    const result = await runAnalyzer(await scanModel(FAILURE));
    assert.equal(stateOf(result, "failure-handling"), STATES.ESTABLISHED);
    assert.equal(findingsOf(result, IDS.FAILURE_HANDLING).length, 1);
  });

  it("K — a called cleanup helper establishes resource cleanup", async () => {
    const result = await runAnalyzer(await scanModel(CLEANUP));
    assert.equal(stateOf(result, "resource-cleanup"), STATES.ESTABLISHED);
    assert.equal(findingsOf(result, IDS.RESOURCE_CLEANUP).length, 1);
  });

  it("L — a called transaction helper establishes transaction handling", async () => {
    const result = await runAnalyzer(await scanModel(TRANSACTION));
    assert.equal(stateOf(result, "transaction-handling"), STATES.ESTABLISHED);
    assert.equal(findingsOf(result, IDS.TRANSACTION_HANDLING).length, 1);
  });

  it("M — a constructed queue client establishes queue behavior", async () => {
    const result = await runAnalyzer(await scanModel(QUEUE));
    assert.equal(stateOf(result, "queue-behavior"), STATES.ESTABLISHED);
    assert.equal(findingsOf(result, IDS.QUEUE_BEHAVIOR).length, 1);
  });

  it("N — a logging package establishes the observability logging dimension", async () => {
    const result = await runAnalyzer(await scanModel(OBSERVABILITY));
    assert.equal(stateOf(result, "observability"), STATES.ESTABLISHED);
    const dimensions = findingsOf(result, IDS.OBSERVABILITY).map((finding) => finding.metadata.dimension);
    assert.deepEqual(dimensions, ["logging"]);
  });

  it("O — multiple mechanisms are all reported, and every domain is addressed", async () => {
    const result = await runAnalyzer(await scanModel(MULTIPLE));
    assert.equal(summaryOf(result).subject, "applicable");
    for (const domain of ["timeouts", "retry-behavior", "circuit-breaking", "graceful-shutdown", "health-checks", "failure-handling", "resource-cleanup", "transaction-handling", "queue-behavior", "observability"]) {
      assert.ok(["established", "detected", "unknown", "not_applicable"].includes(stateOf(result, domain)), domain);
    }
    assert.equal(stateOf(result, "retry-behavior"), STATES.ESTABLISHED);
    assert.equal(stateOf(result, "circuit-breaking"), STATES.ESTABLISHED);
    assert.equal(stateOf(result, "graceful-shutdown"), STATES.ESTABLISHED);
    assert.equal(stateOf(result, "health-checks"), STATES.ESTABLISHED);
    assert.equal(stateOf(result, "transaction-handling"), STATES.ESTABLISHED);
    assert.equal(stateOf(result, "queue-behavior"), STATES.ESTABLISHED);
    assert.equal(stateOf(result, "observability"), STATES.ESTABLISHED);
    // Domains with no establishing mechanism stay unknown, not clean.
    assert.equal(stateOf(result, "timeouts"), STATES.UNKNOWN);
    assert.equal(stateOf(result, "failure-handling"), STATES.UNKNOWN);
    assert.equal(stateOf(result, "resource-cleanup"), STATES.UNKNOWN);
  });
});

describe("reliability analysis analyzer: absence and coverage", () => {
  it("S — a service with no health surface reports an established absence over complete coverage", async () => {
    const result = await runAnalyzer(await scanModel(EXPRESS));
    assert.equal(stateOf(result, "health-checks"), STATES.DETECTED);
    const findings = findingsOf(result, IDS.HEALTH_CHECKS);
    assert.equal(findings.length, 1);
    assert.ok(findings[0].evidence.length > 0);
  });

  it("P/T — a truncated acquisition leaves absence unproven (unknown, not clean)", async () => {
    const model = await scanModel(TRUNCATED);
    const result = await runAnalyzer(model);
    assert.equal(stateOf(result, "health-checks"), STATES.UNKNOWN);
    assert.equal(findingsOf(result, IDS.HEALTH_CHECKS).length, 0);
    assert.equal(summaryOf(result).coverageBasis.apiGraphState, "truncated");
  });

  it("R — a dynamic-scope construct voids the usage domains (unknown, not not_applicable)", async () => {
    const model = await scanModel(DYNAMIC);
    const result = await runAnalyzer(model);
    assert.equal(stateOf(result, "retry-behavior"), STATES.UNKNOWN);
    assert.equal(stateOf(result, "queue-behavior"), STATES.UNKNOWN);
    assert.equal(findingsOf(result, IDS.RETRY_BEHAVIOR).length, 0);
  });
});

// ─── Negative fixtures ───────────────────────────────────────────────────────

describe("reliability analysis analyzer: negative fixtures", () => {
  it("does not read reliability words in comments or documentation", async () => {
    const model = await scanModel({
      ...EXPRESS,
      "src/notes.js": `// timeout retry circuit breaker shutdown transaction queue metrics trace log
/* graceful shutdown, resource cleanup, health check */
export const note = "retry timeout shutdown transaction queue log metrics trace";
`,
      "README.md": "# Reliability\ntimeout retry shutdown transaction queue observability\n",
    });
    const result = await runAnalyzer(model);
    for (const id of [
      IDS.TIMEOUTS,
      IDS.RETRY_BEHAVIOR,
      IDS.CIRCUIT_BREAKING,
      IDS.GRACEFUL_SHUTDOWN,
      IDS.QUEUE_BEHAVIOR,
      IDS.TRANSACTION_HANDLING,
      IDS.RESOURCE_CLEANUP,
      IDS.OBSERVABILITY,
    ]) {
      assert.equal(findingsOf(result, id).length, 0, id);
    }
  });

  it("does not treat setTimeout or AbortController as an application timeout", async () => {
    const model = await scanModel({
      "package.json": pkg({ dependencies: { express: "^4.18.0" } }),
      "src/app.js": `import express from "express";
const app = express();
const listUsers = (req, res) => res.json([]);
app.get("/users", listUsers);
export function schedule() { setTimeout(() => {}, 10); const c = new AbortController(); return c.signal; }
export default app;
`,
    });
    const result = await runAnalyzer(model);
    assert.equal(stateOf(result, "timeouts"), STATES.UNKNOWN);
    assert.equal(findingsOf(result, IDS.TIMEOUTS).length, 0);
  });

  it("does not read test-file retry usage as application retry", async () => {
    const model = await scanModel({
      "package.json": pkg({ dependencies: { express: "^4.18.0" } }),
      "test/retry.test.js": `import pRetry from "p-retry";
async function work() { return 1; }
export function flaky() { return pRetry(work); }
`,
      "src/app.js": `import express from "express";
const app = express();
const listUsers = (req, res) => res.json([]);
app.get("/users", listUsers);
export default app;
`,
    });
    const result = await runAnalyzer(model);
    assert.equal(stateOf(result, "retry-behavior"), STATES.UNKNOWN);
    assert.equal(findingsOf(result, IDS.RETRY_BEHAVIOR).length, 0);
  });

  it("does not treat a generic logger object as the observability logging dimension", async () => {
    const model = await scanModel({
      ...EXPRESS,
      "src/log.js": `export const logger = { info: (msg) => console.log(msg), error: (msg) => console.error(msg) };\n`,
    });
    const result = await runAnalyzer(model);
    assert.equal(stateOf(result, "observability"), STATES.UNKNOWN);
    assert.equal(findingsOf(result, IDS.OBSERVABILITY).length, 0);
  });

  it("does not treat a random catch block as failure handling", async () => {
    const model = await scanModel({
      ...EXPRESS,
      "src/work.js": `async function realWork() { return 1; }
export async function doWork() { try { return await realWork(); } catch (error) { return null; } }
`,
    });
    const result = await runAnalyzer(model);
    assert.equal(stateOf(result, "failure-handling"), STATES.UNKNOWN);
    assert.equal(findingsOf(result, IDS.FAILURE_HANDLING).length, 0);
  });

  it("does not treat transaction-like variable names as a transaction subject", async () => {
    const model = await scanModel({
      ...EXPRESS,
      "src/config.js": `export const transaction = { retries: 3 };\nexport const transactionId = "abc";\n`,
    });
    const result = await runAnalyzer(model);
    assert.equal(stateOf(result, "transaction-handling"), STATES.NOT_APPLICABLE);
    assert.equal(findingsOf(result, IDS.TRANSACTION_HANDLING).length, 0);
  });

  it("does not treat a queue package dependency alone as a queue subject", async () => {
    const model = await scanModel({
      "package.json": pkg({ dependencies: { bullmq: "^5.0.0", express: "^4.18.0" } }),
      "src/app.js": `import express from "express";
const app = express();
const listUsers = (req, res) => res.json([]);
app.get("/users", listUsers);
export default app;
`,
    });
    const result = await runAnalyzer(model);
    assert.equal(stateOf(result, "queue-behavior"), STATES.NOT_APPLICABLE);
    assert.equal(findingsOf(result, IDS.QUEUE_BEHAVIOR).length, 0);
  });
});

// ─── Evidence and fingerprints ───────────────────────────────────────────────

describe("reliability analysis analyzer: evidence and fingerprints", () => {
  it("cites only model evidence, and every cited id resolves", async () => {
    const model = await scanModel(MULTIPLE);
    const result = await runAnalyzer(model);
    assert.ok(result.findings.length > 0);
    const evidenceById = model.indexes.evidenceById;
    for (const finding of result.findings) {
      assert.ok(Array.isArray(finding.evidence), finding.ruleId);
      for (const id of finding.evidence) {
        assert.ok(evidenceById[id] !== undefined, `${finding.ruleId} cites ${id}`);
      }
    }
  });

  it("gives every finding a distinct canonical fingerprint", async () => {
    const model = await scanModel(MULTIPLE);
    const result = await runAnalyzer(model);
    assert.equal(new Set(result.findings.map((finding) => finding.fingerprint)).size, result.findings.length);
    for (const finding of result.findings) {
      assert.match(finding.fingerprint, /^cg-fp1-[0-9a-f]{32}$/);
    }
  });

  it("is deterministic, and adding an unrelated route does not renumber existing findings", async () => {
    const model = await scanModel(MULTIPLE);
    const first = await runAnalyzer(model);
    const second = await runAnalyzer(model);
    assert.deepEqual(
      first.findings.map((finding) => finding.fingerprint),
      second.findings.map((finding) => finding.fingerprint),
    );

    const before = findingsOf(first, IDS.HEALTH_CHECKS).map((finding) => finding.fingerprint).sort();
    const grown = await scanModel({
      ...MULTIPLE,
      "src/more.js": `import express from "express";
const router = express.Router();
const listItems = (req, res) => res.json([]);
router.get("/items", listItems);
export default router;
`,
    });
    const after = await runAnalyzer(grown);
    const survivors = findingsOf(after, IDS.HEALTH_CHECKS).map((finding) => finding.fingerprint);
    for (const fingerprint of before) {
      assert.equal(survivors.includes(fingerprint), true, fingerprint);
    }
  });

  it("keeps a nested container-definition fingerprint inside the Finding Engine's key charset", async () => {
    const model = await scanModel({
      "package.json": pkg({ dependencies: { express: "^4.18.0" } }),
      "docker/Dockerfile": `FROM node:20\nHEALTHCHECK CMD curl -f http://localhost/health || exit 1\n`,
      ...SERVICE_APP,
    });
    const result = await runAnalyzer(model);
    const asserted = findingsOf(result, IDS.HEALTH_CHECKS).filter(
      (finding) => finding.metadata.evidenceClass === "container-healthcheck",
    );
    // The finding must survive fingerprinting (a `#`/`/` in the key would drop it silently).
    assert.equal(asserted.length, 1);
    assert.match(asserted[0].fingerprint, /^cg-fp1-[0-9a-f]{32}$/);
  });

  it("reports only the dimensions the repository evinces", async () => {
    const model = await scanModel(MULTIPLE);
    const result = await runAnalyzer(model);
    const dimensions = new Set(findingsOf(result, IDS.OBSERVABILITY).map((finding) => finding.metadata.dimension));
    assert.equal(dimensions.has("logging"), true);
    assert.equal(dimensions.has("metrics"), true);
    assert.equal(dimensions.has("tracing"), false);
    assert.equal(dimensions.has("error-reporting"), false);
  });
});

// ─── Performance measurement ─────────────────────────────────────────────────

describe("reliability analysis analyzer: performance", () => {
  it("analyzes a representative service within a sane budget", async () => {
    const count = 150;
    const lines = [`import express from "express";`, `import pino from "pino";`, `const logger = pino();`, `const app = express();`];
    for (let i = 0; i < count; i += 1) {
      lines.push(`const h${i} = (req, res) => res.json([]);`);
      lines.push(`app.get("/r${i}", h${i});`);
    }
    lines.push("export default app;");
    const model = await scanModel({
      "package.json": pkg({ dependencies: { express: "^4.18.0", pino: "^8.0.0" } }),
      "src/app.js": `${lines.join("\n")}\n`,
    });

    const start = process.hrtime.bigint();
    const first = await runAnalyzer(model);
    const second = await runAnalyzer(model);
    const elapsedMs = Number(process.hrtime.bigint() - start) / 1e6;

    assert.ok(elapsedMs < 8000, `analyzer took ${elapsedMs.toFixed(1)}ms`);
    assert.deepEqual(
      first.findings.map((finding) => finding.fingerprint),
      second.findings.map((finding) => finding.fingerprint),
    );
    // eslint-disable-next-line no-console
    console.log(`[phase-17] two analyzer passes over ${count} routes: ${elapsedMs.toFixed(1)}ms`);
  });
});

// ─── Architectural boundary ──────────────────────────────────────────────────

describe("reliability analysis analyzer: boundaries", () => {
  const FORBIDDEN = [
    "node:fs",
    "node:fs/promises",
    "node:path",
    "child_process",
    "node:child_process",
    "node:net",
    "node:http",
    "node:https",
    "node:dns",
    "node:worker_threads",
    "tools.js",
    "tool-registry",
    "filesystem",
    "execution",
  ];

  function sourceFiles(dir) {
    const out = [];
    for (const name of readdirSync(dir)) {
      const full = join(dir, name);
      if (statSync(full).isDirectory()) out.push(...sourceFiles(full));
      else if (name.endsWith(".js")) out.push(full);
    }
    return out;
  }

  it("never imports the filesystem, process, network, MCP or legacy tools from the pack", () => {
    const packDir = join(process.cwd(), "src", "rules", "reliability-analysis");
    const specifierPattern = /(?:from\s+|require\(\s*)["']([^"']+)["']/g;
    const files = sourceFiles(packDir);
    assert.ok(files.length > 0);
    for (const file of files) {
      const text = readFileSync(file, "utf8");
      for (const match of text.matchAll(specifierPattern)) {
        const specifier = match[1];
        for (const forbidden of FORBIDDEN) {
          assert.equal(specifier.includes(forbidden), false, `${file} imports ${specifier} (forbidden: ${forbidden})`);
        }
      }
    }
  });

  it("performs no network access and consults no clock or random source", () => {
    const packDir = join(process.cwd(), "src", "rules", "reliability-analysis");
    for (const file of sourceFiles(packDir)) {
      const text = readFileSync(file, "utf8");
      assert.doesNotMatch(text, /Date\.now\(\)|Math\.random\(\)|process\.env/);
      assert.doesNotMatch(text, /\bfetch\s*\(/);
    }
  });
});
