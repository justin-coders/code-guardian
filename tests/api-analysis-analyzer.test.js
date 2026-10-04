/**
 * Code Guardian — API Analysis Analyzer Tests (official roadmap Phase 16)
 *
 * The end-to-end proof that the API Analyzer works through the real pipeline:
 *
 *   Repository → Scanner(facts) → RepositoryModel → APIAnalyzer → api-analysis rules
 *              → evidence → findings
 *
 * Golden fixtures A–T from the Phase 16 handoff live here as real repositories written to a
 * temporary directory and scanned through the accepted scanner/model boundary. The suite's
 * central claims are the roadmap's exit criteria: all thirteen domains are addressed, a CLI
 * repository is `not_applicable` and receives no finding, an unsupported framework is `unknown`
 * (never `not_applicable`), every finding cites model evidence, an incomplete acquisition turns
 * absence into `unknown` rather than clean, and the pack imports no filesystem, process, network
 * or MCP module.
 *
 * Run with: node --test tests/api-analysis-analyzer.test.js
 */

import { after, describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

import { scanRepository } from "../src/repository/scanner/index.js";
import { buildRepositoryModel } from "../src/repository/model/index.js";

import {
  buildAnalysisContext,
  createAnalyzerEngine,
  createAnalyzerRegistry,
} from "../src/analysis/index.js";

import {
  API_ANALYSIS_ANALYZER_ID,
  API_ANALYSIS_RULE_IDS,
  API_ANALYSIS_STATES,
  apiAnalysisRules,
  createApiAnalysisAnalyzer,
  createApiAnalysisRuleRegistry,
  createRuleEngine,
} from "../src/rules/index.js";

// ─── Harness ─────────────────────────────────────────────────────────────────

const TMP_ROOT = join(tmpdir(), `cg-api-analysis-${process.pid}-${Date.now()}`);
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
    registry: createAnalyzerRegistry([createApiAnalysisAnalyzer()]),
  });
  return engine.runAll(contextOf(model));
}

async function runRules(model) {
  const engine = createRuleEngine({
    registry: createApiAnalysisRuleRegistry({ rules: apiAnalysisRules }),
  });
  return engine.runAll(contextOf(model));
}

const summaryOf = (result) =>
  result.analyzers.find((entry) => entry.analyzer.id === API_ANALYSIS_ANALYZER_ID).metadata
    .apiAnalysisSummary;
const statusOf = (run, ruleId) => run.rules.find((entry) => entry.rule.id === ruleId)?.status;
const findingsOf = (result, ruleId) => result.findings.filter((finding) => finding.ruleId === ruleId);

// ─── Fixture builders ────────────────────────────────────────────────────────

const pkg = (extra) => `${JSON.stringify({ name: "demo", version: "1.0.0", ...extra })}\n`;

const CLI = {
  "package.json": pkg({ bin: { demo: "src/cli.js" } }),
  "src/cli.js": `export function main() { process.stdout.write("hi\\n"); }\n`,
};

// B — simple complete Express API with no middleware.
const EXPRESS_PLAIN = {
  "package.json": pkg({ dependencies: { express: "^4.18.0" } }),
  "src/app.js": `import express from "express";
const app = express();
const listUsers = (req, res) => res.json([]);
app.get("/users", listUsers);
export default app;
`,
};

// C — Fastify with established rate-limit and CORS middleware.
const FASTIFY_CONTROLS = {
  "package.json": pkg({ dependencies: { fastify: "^4.0.0" } }),
  "src/app.js": `import fastify from "fastify";
const app = fastify();
const rateLimiter = (req, reply, done) => done();
const corsGuard = (req, reply, done) => done();
const listUsers = (req, reply) => reply.send([]);
app.addHook("preHandler", rateLimiter);
app.addHook("onRequest", corsGuard);
app.get("/users", listUsers);
export default app;
`,
};

// D — authentication-established.
const EXPRESS_AUTH = {
  "package.json": pkg({ dependencies: { express: "^4.18.0" } }),
  "src/app.js": `import express from "express";
const app = express();
const requireAuth = (req, res, next) => next();
const listUsers = (req, res) => res.json([]);
app.use(requireAuth);
app.get("/users", listUsers);
export default app;
`,
};

// E — authentication- and authorization-established.
const EXPRESS_AUTHZ = {
  "package.json": pkg({ dependencies: { express: "^4.18.0" } }),
  "src/app.js": `import express from "express";
const app = express();
const requireAuth = (req, res, next) => next();
const requireAdmin = (req, res, next) => next();
const listAdmins = (req, res) => res.json([]);
app.use(requireAuth);
app.use(requireAdmin);
app.get("/admins", listAdmins);
export default app;
`,
};

// F — validation-established on a body-carrying route.
const EXPRESS_VALIDATION = {
  "package.json": pkg({ dependencies: { express: "^4.18.0" } }),
  "src/app.js": `import express from "express";
const app = express();
const validateBody = (req, res, next) => next();
const createUser = (req, res) => res.status(201).json({});
app.post("/users", validateBody, createUser);
export default app;
`,
};

// N — request-logging-established.
const EXPRESS_LOGGING = {
  "package.json": pkg({ dependencies: { express: "^4.18.0" } }),
  "src/app.js": `import express from "express";
const app = express();
const requestLogger = (req, res, next) => next();
const listUsers = (req, res) => res.json([]);
app.use(requestLogger);
app.get("/users", listUsers);
export default app;
`,
};

// L — OpenAPI artifact observed.
const OPENAPI_ARTIFACT = {
  ...EXPRESS_AUTH,
  "openapi.yaml": "openapi: 3.0.0\ninfo:\n  title: demo\n  version: 1.0.0\npaths: {}\n",
};

// P — partial: an uninterpreted member-call registration (`express.json()`).
const EXPRESS_MEMBER = {
  "package.json": pkg({ dependencies: { express: "^4.18.0" } }),
  "src/app.js": `import express from "express";
const app = express();
app.use(express.json());
const listUsers = (req, res) => res.json([]);
app.get("/users", listUsers);
export default app;
`,
};

// S — unresolved middleware: an inline middleware in the route's own call.
const EXPRESS_INLINE_MW = {
  "package.json": pkg({ dependencies: { express: "^4.18.0" } }),
  "src/app.js": `import express from "express";
const app = express();
const listUsers = (req, res) => res.json([]);
app.get("/users", (req, res, next) => next(), listUsers);
export default app;
`,
};

// T — dynamic/computed construct alongside a static route.
const EXPRESS_DYNAMIC = {
  "package.json": pkg({ dependencies: { express: "^4.18.0" } }),
  "src/app.js": `import express from "express";
const app = express();
const listUsers = (req, res) => res.json([]);
const name = "users";
app.get("/users", listUsers);
app.get(\`/\${name}/:id\`, listUsers);
export default app;
`,
};

// R — unsupported framework (Koa).
const KOA = {
  "package.json": pkg({ dependencies: { koa: "^2.14.0" } }),
  "src/app.js": `import Koa from "koa";
const app = new Koa();
app.get("/users", (ctx) => { ctx.body = []; });
export default app;
`,
};

// R2 — an unsupported-format-only repository (TSX).
const TSX_ONLY = { "src/App.tsx": "export const App = () => null;\n" };

// Q — truncated API acquisition: a module source larger than the per-file byte cap.
const TRUNCATED = {
  "package.json": pkg({ dependencies: { express: "^4.18.0" } }),
  "src/app.js": `import express from "express";
const app = express();
const listUsers = (req, res) => res.json([]);
app.get("/users", listUsers);
export default app;
// ${"x".repeat(300000)}
`,
};

// ─── Golden fixtures ─────────────────────────────────────────────────────────

describe("api analysis analyzer: applicability", () => {
  it("A — a CLI repository is not_applicable and receives no finding", async () => {
    const model = await scanModel(CLI);
    const result = await runAnalyzer(model);
    assert.equal(result.findings.length, 0);
    const summary = summaryOf(result);
    assert.equal(summary.subject, "not_applicable");
    for (const state of Object.values(summary.domains)) {
      assert.equal(state.state, API_ANALYSIS_STATES.NOT_APPLICABLE);
    }
    const run = await runRules(model);
    for (const entry of run.rules) assert.equal(entry.status, "pass");
  });

  it("B — a plain Express API is applicable and audits its routes", async () => {
    const model = await scanModel(EXPRESS_PLAIN);
    const result = await runAnalyzer(model);
    assert.equal(summaryOf(result).subject, "applicable");
    // No middleware at all: authentication and logging establish a gap per route.
    assert.equal(findingsOf(result, API_ANALYSIS_RULE_IDS.AUTHENTICATION).length, 1);
    assert.equal(findingsOf(result, API_ANALYSIS_RULE_IDS.LOGGING).length, 1);
  });

  it("R — an unsupported framework is unknown, never not_applicable", async () => {
    const model = await scanModel(KOA);
    const result = await runAnalyzer(model);
    assert.equal(result.findings.length, 0);
    assert.equal(summaryOf(result).subject, "unknown");
    const run = await runRules(model);
    assert.equal(statusOf(run, API_ANALYSIS_RULE_IDS.AUTHENTICATION), "unknown");
  });

  it("R2 — a repository whose sources are an uninterpreted format is unknown", async () => {
    const model = await scanModel(TSX_ONLY);
    const result = await runAnalyzer(model);
    assert.equal(result.findings.length, 0);
    assert.equal(summaryOf(result).subject, "unknown");
  });
});

describe("api analysis analyzer: structural domains", () => {
  it("C — Fastify rate-limit and CORS middleware are reported as established", async () => {
    const model = await scanModel(FASTIFY_CONTROLS);
    const result = await runAnalyzer(model);
    assert.equal(findingsOf(result, API_ANALYSIS_RULE_IDS.RATE_LIMITING).length, 1);
    assert.equal(findingsOf(result, API_ANALYSIS_RULE_IDS.CORS).length, 1);
    const summary = summaryOf(result);
    assert.equal(summary.domains["rate-limiting"].state, API_ANALYSIS_STATES.ESTABLISHED);
    assert.equal(summary.domains.cors.state, API_ANALYSIS_STATES.ESTABLISHED);
  });

  it("D — an authentication middleware suppresses the authentication gap", async () => {
    const model = await scanModel(EXPRESS_AUTH);
    const result = await runAnalyzer(model);
    assert.equal(findingsOf(result, API_ANALYSIS_RULE_IDS.AUTHENTICATION).length, 0);
    // The authentication rule passes over a complete chain; the remaining gaps (no
    // authorization, no logging) still report.
    const run = await runRules(model);
    assert.equal(statusOf(run, API_ANALYSIS_RULE_IDS.AUTHENTICATION), "pass");
    assert.equal(summaryOf(result).domains.authentication.state, API_ANALYSIS_STATES.ESTABLISHED);
  });

  it("E — authorization middleware suppresses the authorization gap", async () => {
    const model = await scanModel(EXPRESS_AUTHZ);
    const result = await runAnalyzer(model);
    assert.equal(findingsOf(result, API_ANALYSIS_RULE_IDS.AUTHORIZATION).length, 0);
    assert.equal(summaryOf(result).domains.authorization.state, API_ANALYSIS_STATES.ESTABLISHED);
  });

  it("F — a validation middleware suppresses the input-validation gap", async () => {
    const model = await scanModel(EXPRESS_VALIDATION);
    const result = await runAnalyzer(model);
    assert.equal(findingsOf(result, API_ANALYSIS_RULE_IDS.INPUT_VALIDATION).length, 0);
    assert.equal(summaryOf(result).domains["input-validation"].state, API_ANALYSIS_STATES.ESTABLISHED);
  });

  it("N — a request-logging middleware suppresses the logging gap", async () => {
    const model = await scanModel(EXPRESS_LOGGING);
    const result = await runAnalyzer(model);
    assert.equal(findingsOf(result, API_ANALYSIS_RULE_IDS.LOGGING).length, 0);
    assert.equal(summaryOf(result).domains.logging.state, API_ANALYSIS_STATES.ESTABLISHED);
  });

  it("J/K — rate limiting and CORS are presence facts, not absence verdicts", async () => {
    const model = await scanModel(EXPRESS_PLAIN);
    const result = await runAnalyzer(model);
    // A plain API establishes neither; that is not reported as a defect.
    assert.equal(findingsOf(result, API_ANALYSIS_RULE_IDS.RATE_LIMITING).length, 0);
    assert.equal(findingsOf(result, API_ANALYSIS_RULE_IDS.CORS).length, 0);
  });
});

describe("api analysis analyzer: unestablished domains", () => {
  it("G/H/I/M/O — error handling, status codes, pagination, request limits and correlation IDs abstain", async () => {
    const model = await scanModel(EXPRESS_PLAIN);
    const run = await runRules(model);
    for (const id of [
      API_ANALYSIS_RULE_IDS.ERROR_HANDLING,
      API_ANALYSIS_RULE_IDS.STATUS_CODES,
      API_ANALYSIS_RULE_IDS.PAGINATION,
      API_ANALYSIS_RULE_IDS.REQUEST_LIMITS,
      API_ANALYSIS_RULE_IDS.CORRELATION_IDS,
      API_ANALYSIS_RULE_IDS.SCHEMA_VALIDATION,
    ]) {
      assert.equal(statusOf(run, id), "unknown", id);
    }
    const result = await runAnalyzer(model);
    for (const finding of result.findings) {
      assert.equal(
        [
          API_ANALYSIS_RULE_IDS.ERROR_HANDLING,
          API_ANALYSIS_RULE_IDS.STATUS_CODES,
          API_ANALYSIS_RULE_IDS.PAGINATION,
          API_ANALYSIS_RULE_IDS.REQUEST_LIMITS,
          API_ANALYSIS_RULE_IDS.CORRELATION_IDS,
          API_ANALYSIS_RULE_IDS.SCHEMA_VALIDATION,
        ].includes(finding.ruleId),
        false,
      );
    }
  });

  it("L — an observed OpenAPI artifact is reported without a synchronisation claim", async () => {
    const model = await scanModel(OPENAPI_ARTIFACT);
    const result = await runAnalyzer(model);
    const findings = findingsOf(result, API_ANALYSIS_RULE_IDS.OPENAPI);
    assert.equal(findings.length, 1);
    assert.equal(findings[0].metadata.artifact, "openapi.yaml");
    assert.equal(findings[0].confidence, 0.9);
    assert.match(findings[0].description, /observed/i);
    assert.doesNotMatch(findings[0].description, /synchronised with the routes the API graph declares\./i);
  });
});

describe("api analysis analyzer: incomplete coverage is unknown, not clean", () => {
  it("P — an uninterpreted member-call registration makes the structural domains unknown", async () => {
    const model = await scanModel(EXPRESS_MEMBER);
    const run = await runRules(model);
    assert.equal(statusOf(run, API_ANALYSIS_RULE_IDS.AUTHENTICATION), "unknown");
    assert.equal(statusOf(run, API_ANALYSIS_RULE_IDS.LOGGING), "unknown");
    const result = await runAnalyzer(model);
    assert.equal(findingsOf(result, API_ANALYSIS_RULE_IDS.AUTHENTICATION).length, 0);
  });

  it("S — a route with unresolved middleware abstains rather than reporting absence", async () => {
    const model = await scanModel(EXPRESS_INLINE_MW);
    const run = await runRules(model);
    assert.equal(statusOf(run, API_ANALYSIS_RULE_IDS.AUTHENTICATION), "unknown");
    const result = await runAnalyzer(model);
    assert.equal(findingsOf(result, API_ANALYSIS_RULE_IDS.AUTHENTICATION).length, 0);
  });

  it("T — a computed route path leaves the route set unproven", async () => {
    const model = await scanModel(EXPRESS_DYNAMIC);
    const run = await runRules(model);
    assert.equal(statusOf(run, API_ANALYSIS_RULE_IDS.AUTHENTICATION), "unknown");
    const result = await runAnalyzer(model);
    assert.equal(findingsOf(result, API_ANALYSIS_RULE_IDS.AUTHENTICATION).length, 0);
  });

  it("Q — a truncated API acquisition leaves absence unproven", async () => {
    const model = await scanModel(TRUNCATED);
    const run = await runRules(model);
    assert.equal(statusOf(run, API_ANALYSIS_RULE_IDS.AUTHENTICATION), "unknown");
    const result = await runAnalyzer(model);
    assert.equal(findingsOf(result, API_ANALYSIS_RULE_IDS.AUTHENTICATION).length, 0);
    assert.equal(summaryOf(result).coverageBasis.apiGraphState, "truncated");
  });
});

// ─── Negative fixtures ───────────────────────────────────────────────────────

describe("api analysis analyzer: negative fixtures", () => {
  it("does not read API-shaped text in comments or strings as routes", async () => {
    const model = await scanModel({
      "package.json": pkg({ dependencies: { express: "^4.18.0" } }),
      "src/notes.js": `// app.get("/users", handler)\nconst s = "app.post('/x', handler)";\nexport const note = s;\n`,
    });
    const result = await runAnalyzer(model);
    assert.equal(result.findings.length, 0);
    assert.equal(summaryOf(result).subject, "not_applicable");
  });

  it("does not treat a generic logger as request logging", async () => {
    const model = await scanModel({
      ...EXPRESS_PLAIN,
      "src/log.js": `export const logger = { info: (msg) => console.log(msg) };\n`,
    });
    const result = await runAnalyzer(model);
    // The logger is not middleware, so the logging domain reports the request-lifecycle gap,
    // never an established request-logging fact.
    assert.equal(summaryOf(result).domains.logging.state, API_ANALYSIS_STATES.DETECTED);
    assert.equal(findingsOf(result, API_ANALYSIS_RULE_IDS.LOGGING).length, 1);
  });

  it("does not treat an unregistered function named `auth` as authentication middleware", async () => {
    const model = await scanModel({
      "package.json": pkg({ dependencies: { express: "^4.18.0" } }),
      "src/app.js": `import express from "express";
const app = express();
function auth(req, res, next) { return next(); }
const listUsers = (req, res) => res.json([]);
app.get("/users", listUsers);
export default app;
`,
    });
    const result = await runAnalyzer(model);
    // The route is registered with no middleware, so the authentication gap is real.
    assert.equal(findingsOf(result, API_ANALYSIS_RULE_IDS.AUTHENTICATION).length, 1);
    assert.equal(summaryOf(result).domains.authentication.state, API_ANALYSIS_STATES.DETECTED);
  });

  it("does not infer pagination from a `page` variable or request limits from a `limit` constant", async () => {
    const model = await scanModel({
      ...EXPRESS_PLAIN,
      "src/config.js": "export const page = 1;\nexport const limit = 25;\n",
    });
    const run = await runRules(model);
    assert.equal(statusOf(run, API_ANALYSIS_RULE_IDS.PAGINATION), "unknown");
    assert.equal(statusOf(run, API_ANALYSIS_RULE_IDS.REQUEST_LIMITS), "unknown");
    const result = await runAnalyzer(model);
    assert.equal(findingsOf(result, API_ANALYSIS_RULE_IDS.PAGINATION).length, 0);
  });

  it("does not read unrelated `cors` documentation as CORS middleware", async () => {
    const model = await scanModel({
      ...EXPRESS_PLAIN,
      "README.md": "This API mentions cors, cross-origin and swagger extensively.\n",
    });
    const result = await runAnalyzer(model);
    assert.equal(findingsOf(result, API_ANALYSIS_RULE_IDS.CORS).length, 0);
    assert.equal(findingsOf(result, API_ANALYSIS_RULE_IDS.OPENAPI).length, 0);
  });

  it("does not read a random swagger filename as an OpenAPI artifact", async () => {
    const model = await scanModel({
      ...EXPRESS_PLAIN,
      "docs/swagger-notes.md": "notes about swagger\n",
    });
    const result = await runAnalyzer(model);
    assert.equal(findingsOf(result, API_ANALYSIS_RULE_IDS.OPENAPI).length, 0);
  });
});

// ─── Evidence and fingerprints ───────────────────────────────────────────────

describe("api analysis analyzer: evidence and fingerprints", () => {
  it("cites only model evidence, and every cited id resolves", async () => {
    const model = await scanModel({ ...FASTIFY_CONTROLS, ...EXPRESS_VALIDATION });
    const result = await runAnalyzer(model);
    assert.ok(result.findings.length > 0);
    const evidenceById = model.indexes.evidenceById;
    for (const finding of result.findings) {
      assert.ok(Array.isArray(finding.evidence) && finding.evidence.length > 0, finding.ruleId);
      for (const id of finding.evidence) {
        assert.ok(evidenceById[id] !== undefined, `${finding.ruleId} cites ${id}`);
      }
    }
  });

  it("gives every finding a distinct canonical fingerprint", async () => {
    const model = await scanModel({ ...FASTIFY_CONTROLS, ...EXPRESS_AUTHZ });
    const result = await runAnalyzer(model);
    assert.equal(
      new Set(result.findings.map((finding) => finding.fingerprint)).size,
      result.findings.length,
    );
    for (const finding of result.findings) {
      assert.match(finding.fingerprint, /^cg-fp1-[0-9a-f]{32}$/);
    }
  });

  it("is deterministic, and adding an unrelated route does not renumber existing findings", async () => {
    const model = await scanModel(EXPRESS_PLAIN);
    const first = await runAnalyzer(model);
    const second = await runAnalyzer(model);
    assert.deepEqual(
      first.findings.map((finding) => finding.fingerprint),
      second.findings.map((finding) => finding.fingerprint),
    );

    const before = findingsOf(first, API_ANALYSIS_RULE_IDS.AUTHENTICATION)
      .map((finding) => finding.fingerprint)
      .sort();

    const grown = await scanModel({
      ...EXPRESS_PLAIN,
      "src/more.js": `import express from "express";
const router = express.Router();
const listItems = (req, res) => res.json([]);
router.get("/items", listItems);
export default router;
`,
    });
    const after = await runAnalyzer(grown);
    const survivors = findingsOf(after, API_ANALYSIS_RULE_IDS.AUTHENTICATION)
      .map((finding) => finding.fingerprint);
    for (const fingerprint of before) {
      assert.equal(survivors.includes(fingerprint), true, fingerprint);
    }
  });
});

// ─── Performance measurement ─────────────────────────────────────────────────

describe("api analysis analyzer: performance", () => {
  it("analyzes a representative API within a sane budget", async () => {
    const count = 150;
    const lines = [`import express from "express";`, `const app = express();`];
    const middleware = Array.from({ length: 20 }, (_, i) => `const mw${i} = (req, res, next) => next();`);
    for (const line of middleware) lines.push(line);
    for (let i = 0; i < count; i += 1) {
      lines.push(`const h${i} = (req, res) => res.json([]);`);
      lines.push(`app.get("/r${i}", mw${i % 20}, h${i});`);
    }
    lines.push("export default app;");
    const model = await scanModel({
      "package.json": pkg({ dependencies: { express: "^4.18.0" } }),
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
    console.log(`[phase-16] two analyzer passes over ${count} routes: ${elapsedMs.toFixed(1)}ms`);
  });
});

// ─── Architectural boundary ──────────────────────────────────────────────────

describe("api analysis analyzer: boundaries", () => {
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
    const packDir = join(process.cwd(), "src", "rules", "api-analysis");
    const specifierPattern = /(?:from\s+|require\(\s*)["']([^"']+)["']/g;
    const files = sourceFiles(packDir);
    assert.ok(files.length > 0);
    for (const file of files) {
      const text = readFileSync(file, "utf8");
      for (const match of text.matchAll(specifierPattern)) {
        const specifier = match[1];
        for (const forbidden of FORBIDDEN) {
          assert.equal(
            specifier.includes(forbidden),
            false,
            `${file} imports ${specifier} (forbidden: ${forbidden})`,
          );
        }
      }
    }
  });

  it("performs no network access and consults no clock or random source", () => {
    const packDir = join(process.cwd(), "src", "rules", "api-analysis");
    for (const file of sourceFiles(packDir)) {
      const text = readFileSync(file, "utf8");
      assert.doesNotMatch(text, /Date\.now\(\)|Math\.random\(\)|process\.env/);
      assert.doesNotMatch(text, /\bfetch\s*\(/);
    }
  });
});
