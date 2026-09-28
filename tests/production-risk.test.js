/**
 * Code Guardian — Production Risk Report Tests (Phase 21)
 *
 * Three fixture styles, chosen deliberately:
 *
 *   - **real repositories** written to a temporary directory and scanned through the accepted
 *     Phase 8A boundary, the Phase 8C scanner and the Phase 8D model builder, so acquisition,
 *     model, inventory report and risk report agree end to end. This is the only way to prove
 *     that what a repository literally states is what the audit reports as a gap.
 *   - **hand-built scan results** for facts a tiny repository cannot reach on demand — an
 *     incomplete scan, an unreadable manifest — so the report's abstention behaviour is stated
 *     exactly rather than inferred.
 *   - **tampering inside the model's own risk area**, because the point of the contract is that
 *     a malformed report is a validation failure instead of becoming a finding.
 *
 * The suite's central claims are the phase's central requirements: a finding states a gap the
 * repository's own evidence proves and cites that evidence, an absence is reported only over a
 * reading that finished (otherwise the detection is withheld and the domain says why), an
 * unknown input is never converted into a pass, and there is no score, grade, percentage,
 * traffic light or aggregate anywhere in the report or in the rules that consume it.
 *
 * No test starts a container, sends a request, spawns a process, contacts a network, installs a
 * package, reads a vulnerability database or writes to the repository under test.
 *
 * Run with: node --test tests/production-risk.test.js
 */

import { after, describe, it } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { ValidationError } from "../src/core/index.js";

import {
  CONTAINER_DECLARATION_LIMITS,
  createScanResult,
  scanRepository,
  validateScanResult,
} from "../src/repository/scanner/index.js";

import {
  CONTAINER_SIGNALS,
  MIDDLEWARE_GRAPH_SCOPES,
  MIDDLEWARE_PROTECTION_STATES,
  PRODUCTION_REPORT_STATES,
  PRODUCTION_RISK_BASIS_BY_KIND,
  PRODUCTION_RISK_CONFIDENCE_BY_KIND,
  PRODUCTION_RISK_CONFIDENCES,
  PRODUCTION_RISK_CONFIDENCE_VALUES,
  PRODUCTION_RISK_FINDING_KINDS,
  PRODUCTION_RISK_REPORT_LIMITS,
  PRODUCTION_RISK_REPORT_VERSION,
  PRODUCTION_RISK_ROUTER_SCOPE,
  PRODUCTION_RISK_SECTIONS,
  PRODUCTION_RISK_SECTION_TITLES,
  PRODUCTION_RISK_SEVERITIES,
  PRODUCTION_RISK_SEVERITY_BY_KIND,
  PRODUCTION_RISK_SEVERITY_VALUES,
  PRODUCTION_RISK_STATES,
  PRODUCTION_RISK_STATE_VALUES,
  PRODUCTION_RISK_UNKNOWN_REASONS,
  PRODUCTION_RISK_UNSUPPORTED_REASONS,
  PRODUCTION_SECTIONS,
  buildRepositoryModel,
  buildProductionRiskReport,
  createRepositoryQuery,
  isEstablishedRiskState,
  renderRiskRemediation,
  renderRiskStatement,
  validateRepositoryModelGraph,
} from "../src/repository/model/index.js";

import {
  buildAnalysisContext,
  createAnalyzerEngine,
  createAnalyzerRegistry,
} from "../src/analysis/index.js";

import { RULE_OUTCOME_STATUSES, createRuleEngine } from "../src/rules/index.js";

import {
  MAX_PRODUCTION_RISK_FINDINGS,
  PRODUCTION_RISK_ABSTENTION_WORDING,
  PRODUCTION_RISK_ANALYZER_ID,
  PRODUCTION_RISK_ANALYZER_NAME,
  PRODUCTION_RISK_ANALYZER_SCOPE,
  PRODUCTION_RISK_BASIS,
  PRODUCTION_RISK_CATEGORY,
  PRODUCTION_RISK_CONFIDENCE,
  PRODUCTION_RISK_CONFIDENCE_WORDING,
  PRODUCTION_RISK_DESCRIBED_ABSTENTIONS,
  PRODUCTION_RISK_DESCRIBED_CONFIDENCES,
  PRODUCTION_RISK_DESCRIBED_KINDS,
  PRODUCTION_RISK_DESCRIBED_SECTIONS,
  PRODUCTION_RISK_DESCRIBED_SEVERITIES,
  PRODUCTION_RISK_DESCRIBED_STATES,
  PRODUCTION_RISK_FINDING_WORDING,
  PRODUCTION_RISK_RULE_ID_PREFIX,
  PRODUCTION_RISK_RULE_IDS,
  PRODUCTION_RISK_RULE_PACK_VERSION,
  PRODUCTION_RISK_RULE_SEVERITIES,
  PRODUCTION_RISK_SECTION_WORDING,
  PRODUCTION_RISK_SEVERITY_WORDING,
  PRODUCTION_RISK_STATE_WORDING,
  createProductionRiskAnalyzer,
  createProductionRiskRuleRegistry,
  productionRiskAbsence,
  productionRiskCoverage,
  productionRiskRuleSetIssues,
  productionRiskRules,
  productionRiskSection,
  productionRiskSections,
} from "../src/rules/production/risk/index.js";

import { APPLICABILITY_COVERAGE } from "../src/rules/contracts.js";

// ─── Fixtures ────────────────────────────────────────────────────────────────

const HERE = dirname(fileURLToPath(import.meta.url));
const TMP = mkdtempSync(join(tmpdir(), "cg-production-risk-"));
after(() => rmSync(TMP, { recursive: true, force: true }));

let repositories = 0;

/**
 * Write a repository and scan it end to end.
 *
 * @param {Record<string, string>} files Repository-relative path → contents.
 * @returns {Promise<object>} The scan, model, query handle, context and both reports.
 */
async function scanOf(files) {
  const root = join(TMP, `repo-${repositories}`);
  repositories += 1;
  mkdirSync(root, { recursive: true });
  for (const [relative, content] of Object.entries(files)) {
    const full = join(root, relative);
    mkdirSync(dirname(full), { recursive: true });
    writeFileSync(full, content);
  }
  const scan = await scanRepository(root);
  const model = buildRepositoryModel(scan);
  return {
    root,
    scan,
    model,
    query: createRepositoryQuery(model),
    context: buildAnalysisContext({ repository: model }),
    report: model.production.report,
    risk: model.productionRisk.report,
  };
}

/** A minimal `package.json`. */
const pkg = (fields = {}) =>
  JSON.stringify({ name: "demo", version: "1.0.0", ...fields }, null, 2);

/** An npm v3 lockfile resolving the given `node_modules/<name>` entries. */
const npmLock = (entries = {}) =>
  JSON.stringify(
    { name: "demo", lockfileVersion: 3, packages: { "": { name: "demo" }, ...entries } },
    null,
    2,
  );

/** A GitHub Actions workflow body. Deliberately minimal: no workflow body is ever read. */
const workflow = (name) =>
  `name: ${name}\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ${name}\n`;

/** A Dockerfile with no healthcheck instruction. */
const plainDockerfile = ["FROM node:20", 'CMD ["node", "main.js"]', ""].join("\n");

/** A hand-built, validated scan result over a list of file paths. */
function literalScan(paths, { complete = true, truncated = false, ignored = [] } = {}) {
  const directories = new Set();
  for (const path of paths) {
    const parts = path.split("/");
    for (let index = 1; index < parts.length; index += 1) {
      directories.add(parts.slice(0, index).join("/"));
    }
  }
  return validateScanResult(
    createScanResult({
      root: "/repo",
      scannedAt: "2026-01-01T00:00:00.000Z",
      files: paths.map((path) => ({
        path,
        name: path.slice(path.lastIndexOf("/") + 1),
        extension: path.slice(path.lastIndexOf(".")),
        depth: path.split("/").length,
      })),
      directories: [...directories].sort().map((path) => ({
        path,
        name: path.slice(path.lastIndexOf("/") + 1),
        depth: path.split("/").length,
      })),
      ignored,
      statistics: {
        filesScanned: paths.length,
        directoriesScanned: directories.size,
        symlinksScanned: 0,
        ignored: ignored.length,
        unreadable: 0,
        truncatedBy: truncated ? ["file-limit"] : [],
      },
      scan: { complete, truncated, limits: { maxFiles: 10000, maxDepth: 20 }, errors: [] },
    }),
  );
}

/** Every problem the graph contract reports, or `null` when the model is valid. */
function issuesOfValidate(model) {
  try {
    validateRepositoryModelGraph(model);
    return null;
  } catch (error) {
    if (error instanceof ValidationError) return error.details?.issues ?? [];
    throw error;
  }
}

const clone = (value) => JSON.parse(JSON.stringify(value));
const sectionOf = (report, name) => report.sections.find((entry) => entry.name === name);
const riskSectionOf = (risk, name) => risk.sections.find((entry) => entry.name === name);
const findingOf = (section, kind) => section.findings.find((entry) => entry.kind === kind) ?? null;
const kindsOf = (section) => section.findings.map((entry) => entry.kind);
const reasonsOf = (section) => section.unknown.map((record) => record.reason);

/** A repository whose every domain has something to say, used by several suites. */
const FULL_REPO = {
  ".gitignore": "node_modules\n",
  ".env": "DEMO=1\n",
  ".env.example": "PORT=3000\n",
  "config.json.sample": "{}\n",
  "package.json": pkg({ dependencies: { express: "^4.18.0" } }),
  "Dockerfile": plainDockerfile,
  "docker-compose.yml": [
    "services:",
    "  web:",
    "    image: registry.internal:5000/web",
    "  api:",
    "    build:",
    "      context: ./src",
    "      dockerfile: Dockerfile.missing",
    "",
  ].join("\n"),
  ".github/workflows/release.yml": workflow("release"),
  "main.js": [
    'import express from "express";',
    'import { requireAuth } from "./src/auth.js";',
    "const app = express();",
    "app.use(requireAuth);",
    'app.get("/users", handler);',
    "export default app;",
    "",
  ].join("\n"),
  "src/auth.js": "export function requireAuth(req, res, next) { next(); }\n",
  "src/legacy/old.js": "export const old = 1;\n",
  "src/legacy/ancient.js": "export const ancient = 2;\n",
};

const { model: fullModel, report: fullReport, risk: fullRisk, query: fullQuery } =
  await scanOf(FULL_REPO);

// ─── Scanner acquisition: the two Phase 21 Compose records ───────────────────

describe("production risk: container acquisition", () => {
  it("records an `image:` key per service and whether that service also builds", async () => {
    const { scan } = await scanOf({
      "package.json": pkg(),
      "docker-compose.yml": [
        "services:",
        "  web:",
        "    image: nginx:1.2",
        "  api:",
        "    image: internal",
        "    build: .",
        "",
      ].join("\n"),
      Dockerfile: plainDockerfile,
    });
    assert.deepEqual(scan.containers.images, [
      { source: "docker-compose.yml", service: "api", build: true },
      { source: "docker-compose.yml", service: "web", build: false },
    ]);
    // The reference's text never leaves the file, in either direction.
    assert.equal(JSON.stringify(scan.containers.images).includes("nginx"), false);
    assert.equal(JSON.stringify(scan.containers.images).includes("internal"), false);
  });

  it("records a declaration naming a Dockerfile the inventory does not contain", async () => {
    const { scan } = await scanOf({
      "package.json": pkg(),
      "docker-compose.yml": ["services:", "  api:", "    build:", "      dockerfile: Dockerfile.absent", ""].join("\n"),
    });
    assert.deepEqual(scan.containers.declarations, []);
    assert.deepEqual(scan.containers.unobserved, [
      { source: "docker-compose.yml", service: "api", dockerfile: "Dockerfile.absent" },
    ]);
  });

  it("reads an uninterpretable `image:` value as a key and refuses nothing", async () => {
    // The build-declaration reading is another consumer's answer and must not move: an
    // `image:` whose value this build cannot read costs the *inventory* one record, never the
    // file's build declarations.
    const { scan } = await scanOf({
      "package.json": pkg(),
      "docker-compose.yml": ["services:", "  api:", "    image: { nested: yes }", "    build: .", ""].join("\n"),
      Dockerfile: plainDockerfile,
    });
    assert.deepEqual(scan.containers.unparsed, []);
    assert.equal(scan.containers.declarations.length, 1);
    assert.deepEqual(scan.containers.images, [
      { source: "docker-compose.yml", service: "api", build: true },
    ]);
  });

  it("projects both records as evidence located at the Compose file", async () => {
    const { model } = await scanOf({
      "package.json": pkg(),
      "docker-compose.yml": [
        "services:",
        "  web:",
        "    image: nginx",
        "  api:",
        "    build:",
        "      dockerfile: Dockerfile.absent",
        "",
      ].join("\n"),
    });
    const unobserved = model.evidence.find(
      (record) => record.data.signal === CONTAINER_SIGNALS.DECLARATION_UNOBSERVED,
    );
    assert.equal(unobserved.location.path, "docker-compose.yml");
    assert.equal(unobserved.data.dockerfile, "Dockerfile.absent");
    const image = model.evidence.find(
      (record) => record.data.signal === CONTAINER_SIGNALS.SERVICE_IMAGE,
    );
    assert.equal(image.location.path, "docker-compose.yml");
    assert.equal(image.data.service, "web");
    assert.equal(image.data.build, false);
    // No reference text travels with the record.
    assert.equal(JSON.stringify(image).includes("nginx"), false);
  });

  it("validates both lists, refusing an unsorted one and a host path", () => {
    const unsorted = createScanResult({
      root: "/repo",
      scan: { complete: true, truncated: false, limits: {}, errors: [] },
      containers: {
        inspected: true,
        unobserved: [
          { source: "b.yml", service: "a", dockerfile: "Dockerfile" },
          { source: "a.yml", service: "a", dockerfile: "Dockerfile" },
        ],
      },
    });
    assert.throws(() => validateScanResult(unsorted), ValidationError);

    const absolute = createScanResult({
      root: "/repo",
      scan: { complete: true, truncated: false, limits: {}, errors: [] },
      containers: {
        inspected: true,
        images: [{ source: "/etc", service: "web", build: false }],
      },
    });
    assert.throws(() => validateScanResult(absolute), ValidationError);

    const bounded = createScanResult({
      root: "/repo",
      scan: { complete: true, truncated: false, limits: {}, errors: [] },
      containers: {
        inspected: true,
        images: Array.from(
          { length: CONTAINER_DECLARATION_LIMITS.maxDeclarations + 1 },
          (_unused, index) => ({
            source: "docker-compose.yml",
            service: `service-${String(index).padStart(5, "0")}`,
            build: false,
          }),
        ),
      },
    });
    assert.throws(() => validateScanResult(bounded), ValidationError);
  });
});

// ─── Environment gaps ────────────────────────────────────────────────────────

describe("production risk: environment", () => {
  it("reports a live environment file with no example or template", async () => {
    const { risk } = await scanOf({ "package.json": pkg(), ".env": "DEMO=1\n" });
    const section = riskSectionOf(risk, "environment");
    const finding = findingOf(section, "environment-file-without-template");
    assert.notEqual(finding, null);
    assert.equal(finding.severity, PRODUCTION_RISK_SEVERITIES.LOW);
    assert.equal(finding.confidence, PRODUCTION_RISK_CONFIDENCES.ABSENT);
    assert.equal(finding.basis, "environment-name-table");
    assert.deepEqual(finding.paths, [".env"]);
    assert.equal(finding.count, 1);
    assert.equal(finding.statement.includes("no example or template file"), true);
    assert.equal(
      finding.remediation,
      "Add an example or template file that states the environment's keys.",
    );
    // Every citation resolves to an observation the model carries.
    const ids = new Set(fullModel.evidence.map((record) => record.id));
    assert.equal(finding.evidenceIds.every((id) => ids.has(id)), true);
  });

  it("reports a template class stated more than once", async () => {
    const { risk } = await scanOf({
      "package.json": pkg(),
      ".env.example": "PORT=3000\n",
      ".env.sample": "PORT=3000\n",
    });
    const duplicated = findingOf(
      riskSectionOf(risk, "environment"),
      "environment-template-class-duplicated",
    );
    assert.notEqual(duplicated, null);
    assert.equal(duplicated.class, "environment-example");
    assert.equal(duplicated.count, 2);
    assert.deepEqual(duplicated.paths, [".env.example", ".env.sample"]);
    assert.equal(duplicated.severity, PRODUCTION_RISK_SEVERITIES.LOW);
    assert.equal(duplicated.remediation, "Keep one file per template class.");
  });

  it("reports the template stated under two naming classes", async () => {
    const { risk } = await scanOf({
      "package.json": pkg(),
      ".env.example": "PORT=3000\n",
      ".env.template": "PORT=\n",
    });
    const conflict = findingOf(
      riskSectionOf(risk, "environment"),
      "environment-template-classes-conflict",
    );
    assert.notEqual(conflict, null);
    assert.deepEqual(conflict.classes, ["environment-example", "environment-template"]);
    assert.equal(conflict.count, 2);
    assert.equal(conflict.statement.includes("more than one naming class"), true);
  });

  it("reports environment configuration with no sample configuration class", async () => {
    const { risk } = await scanOf({ "package.json": pkg(), ".env.example": "PORT=3000\n" });
    const finding = findingOf(
      riskSectionOf(risk, "environment"),
      "environment-configuration-without-sample",
    );
    assert.notEqual(finding, null);
    assert.equal(finding.severity, PRODUCTION_RISK_SEVERITIES.INFO);
    assert.equal(finding.remediation, null);
  });

  it("reports no gap at all for a complete environment setup", async () => {
    const { risk } = await scanOf({
      "package.json": pkg(),
      ".env": "DEMO=1\n",
      ".env.example": "PORT=3000\n",
      "config.json.sample": "{}\n",
    });
    const section = riskSectionOf(risk, "environment");
    assert.deepEqual(kindsOf(section), []);
    assert.equal(section.state, PRODUCTION_REPORT_STATES.COMPLETE);
    assert.equal(section.established, true);
    // The unconditionally honest abstentions survive an otherwise complete reading.
    assert.deepEqual(reasonsOf(section), ["secret-values-not-inspected"]);
  });

  it("withholds every absence claim when an ignore policy hides an environment path", async () => {
    const { risk } = await scanOf({
      ".gitignore": ".env\n",
      "package.json": pkg(),
      ".env": "DEMO=1\n",
      ".env.example": "PORT=3000\n",
    });
    const section = riskSectionOf(risk, "environment");
    assert.deepEqual(kindsOf(section), []);
    assert.equal(section.state, PRODUCTION_REPORT_STATES.PARTIAL);
    // The inventory report's own gap is carried verbatim...
    assert.equal(reasonsOf(section).includes("environment-configuration-ignored"), true);
    // ...and each withheld absence names the detection it could not make.
    const withheld = section.unknown.filter(
      (record) => record.reason === "environment-coverage-not-complete",
    );
    assert.deepEqual(
      withheld.map((record) => record.detail).sort(),
      ["environment-configuration-without-sample", "environment-file-without-template"],
    );
  });
});

// ─── Container gaps ──────────────────────────────────────────────────────────

describe("production risk: container", () => {
  it("reports a definition whose own instructions declare no healthcheck", async () => {
    const { risk } = await scanOf({ "package.json": pkg(), Dockerfile: plainDockerfile });
    const section = riskSectionOf(risk, "container");
    const finding = findingOf(section, "container-healthcheck-missing");
    assert.notEqual(finding, null);
    assert.equal(finding.path, "Dockerfile");
    assert.equal(finding.severity, PRODUCTION_RISK_SEVERITIES.LOW);
    assert.equal(finding.confidence, PRODUCTION_RISK_CONFIDENCES.DECLARED);
    assert.equal(finding.basis, "dockerfile-instructions");
    assert.equal(finding.instructions, 2);
    assert.equal(finding.statement.includes("read from its own instructions"), true);
    assert.equal(finding.remediation, "Declare a `HEALTHCHECK` instruction in `Dockerfile`.");
  });

  it("reports nothing for a definition that declares or disables a healthcheck", async () => {
    const declared = await scanOf({
      "package.json": pkg(),
      Dockerfile: ["FROM node:20", "HEALTHCHECK CMD node hc.js", ""].join("\n"),
    });
    assert.deepEqual(kindsOf(riskSectionOf(declared.risk, "container")), []);
    assert.equal(riskSectionOf(declared.risk, "container").state, PRODUCTION_REPORT_STATES.COMPLETE);

    // `HEALTHCHECK NONE` is a declaration, not an absence: the report says so, so the audit
    // does not report a missing instruction.
    const disabled = await scanOf({
      "package.json": pkg(),
      Dockerfile: ["FROM node:20", "HEALTHCHECK NONE", ""].join("\n"),
    });
    assert.deepEqual(kindsOf(riskSectionOf(disabled.risk, "container")), []);
  });

  it("reports nothing about a definition whose instructions could not be read", async () => {
    const { risk } = await scanOf({
      "package.json": pkg(),
      Dockerfile: "FROM alpine\u0000\n",
    });
    const section = riskSectionOf(risk, "container");
    assert.deepEqual(kindsOf(section), []);
    assert.equal(reasonsOf(section).includes("dockerfile-structure-not-established"), true);
  });

  it("reports a build naming a Dockerfile the repository does not contain", async () => {
    const { risk } = await scanOf({
      "package.json": pkg(),
      "docker-compose.yml": [
        "services:",
        "  api:",
        "    build:",
        "      context: .",
        "      dockerfile: Dockerfile.absent",
        "",
      ].join("\n"),
    });
    const finding = findingOf(
      riskSectionOf(risk, "container"),
      "container-compose-dockerfile-not-observed",
    );
    assert.notEqual(finding, null);
    assert.equal(finding.source, "docker-compose.yml");
    assert.equal(finding.service, "api");
    assert.equal(finding.path, "Dockerfile.absent");
    assert.equal(finding.severity, PRODUCTION_RISK_SEVERITIES.MEDIUM);
    assert.equal(finding.statement.includes("this repository does not contain"), true);
    assert.equal(finding.remediation, "Add `Dockerfile.absent`, or correct the declaration that names it.");
  });

  it("reports a build declaration that does not resolve inside the repository", async () => {
    const { risk } = await scanOf({
      "package.json": pkg(),
      "docker-compose.yml": ["services:", "  api:", "    build:", "      context: /etc", ""].join("\n"),
    });
    const section = riskSectionOf(risk, "container");
    const finding = findingOf(section, "container-compose-build-context-unresolved");
    assert.notEqual(finding, null);
    assert.equal(finding.path, "docker-compose.yml");
    assert.equal(finding.detail, "context-outside-repository");
    assert.equal(finding.count, 1);
    assert.equal(finding.severity, PRODUCTION_RISK_SEVERITIES.MEDIUM);
    // The declaration's text is never carried, so no host path travels with the finding.
    assert.equal(JSON.stringify(finding).includes("/etc"), false);
    assert.equal(JSON.stringify(section.unknown).includes("/etc"), false);
  });

  it("reports a service stating an image with no build context, and nothing when it builds", async () => {
    const { risk } = await scanOf({
      "package.json": pkg(),
      "docker-compose.yml": ["services:", "  web:", "    image: nginx", "  api:", "    image: x", "    build: .", ""].join("\n"),
      Dockerfile: plainDockerfile,
    });
    const section = riskSectionOf(risk, "container");
    const images = section.findings.filter(
      (entry) => entry.kind === "container-service-image-without-build",
    );
    assert.equal(images.length, 1);
    assert.equal(images[0].service, "web");
    assert.equal(images[0].severity, PRODUCTION_RISK_SEVERITIES.INFO);
    assert.equal(images[0].remediation, null);
    // The service that also declares a build is inventoried by the report, not reported as a gap.
    assert.equal(
      section.findings.some((entry) => entry.service === "api"),
      false,
    );
  });

  it("reports no container gap for a definition that declares a healthcheck", async () => {
    const { risk } = await scanOf({
      "package.json": pkg(),
      Dockerfile: ["FROM node:20", "HEALTHCHECK CMD node hc.js", ""].join("\n"),
    });
    const section = riskSectionOf(risk, "container");
    assert.deepEqual(kindsOf(section), []);
    assert.equal(section.state, PRODUCTION_REPORT_STATES.COMPLETE);
  });
});

// ─── CI gaps ─────────────────────────────────────────────────────────────────

describe("production risk: ci", () => {
  it("reports a release name with neither a test nor a lint name beside it", async () => {
    const { risk } = await scanOf({
      "package.json": pkg(),
      ".github/workflows/release.yml": workflow("release"),
    });
    const section = riskSectionOf(risk, "ci");
    assert.deepEqual(kindsOf(section).sort(), ["ci-release-without-lint", "ci-release-without-test"]);
    const finding = findingOf(section, "ci-release-without-test");
    assert.deepEqual(finding.paths, [".github/workflows/release.yml"]);
    assert.equal(finding.confidence, PRODUCTION_RISK_CONFIDENCES.NAME_DERIVED);
    assert.equal(finding.basis, "workflow-name-table");
    assert.equal(finding.statement.includes("Only file names are read"), true);
    assert.equal(finding.remediation, "Add a workflow file whose name states a test purpose.");
  });

  it("reports only the absent counterpart when a test name is present", async () => {
    const { risk } = await scanOf({
      "package.json": pkg(),
      ".github/workflows/release.yml": workflow("release"),
      ".github/workflows/test.yml": workflow("test"),
    });
    assert.deepEqual(kindsOf(riskSectionOf(risk, "ci")), ["ci-release-without-lint"]);
  });

  it("reports only the absent counterpart when a lint name is present", async () => {
    const { risk } = await scanOf({
      "package.json": pkg(),
      ".github/workflows/release.yml": workflow("release"),
      ".github/workflows/lint.yml": workflow("lint"),
    });
    assert.deepEqual(kindsOf(riskSectionOf(risk, "ci")), ["ci-release-without-test"]);
  });

  it("reports more than one release name", async () => {
    const { risk } = await scanOf({
      "package.json": pkg(),
      ".github/workflows/release.yml": workflow("release"),
      ".github/workflows/publish.yml": workflow("publish"),
      ".github/workflows/test.yml": workflow("test"),
      ".github/workflows/lint.yml": workflow("lint"),
    });
    const section = riskSectionOf(risk, "ci");
    assert.deepEqual(kindsOf(section), ["ci-release-workflows-multiple"]);
    const finding = section.findings[0];
    assert.deepEqual(finding.paths, [".github/workflows/publish.yml", ".github/workflows/release.yml"]);
    assert.equal(finding.count, 2);
    assert.equal(finding.severity, PRODUCTION_RISK_SEVERITIES.LOW);
    assert.equal(finding.remediation, "Keep one release pipeline.");
  });

  it("reports unclassified names and withholds every absence claim beside them", async () => {
    const { risk } = await scanOf({
      "package.json": pkg(),
      ".github/workflows/ci.yml": workflow("ci"),
    });
    const section = riskSectionOf(risk, "ci");
    assert.deepEqual(kindsOf(section), ["ci-workflows-unclassified"]);
    assert.equal(section.findings[0].severity, PRODUCTION_RISK_SEVERITIES.INFO);
    assert.equal(section.findings[0].remediation, null);
    // `ci.yml` may well be the test pipeline, so nothing is claimed about what is absent — the
    // inventory report's own reason is carried and the risk report names the withheld detection.
    assert.equal(reasonsOf(section).includes("workflow-purpose-not-established"), true);
    assert.equal(
      section.unknown.some(
        (record) =>
          record.reason === "workflow-purpose-not-established" && record.detail === null,
      ),
      true,
    );
  });

  it("reports no CI gap for a repository that declares no workflow at all", async () => {
    const { risk } = await scanOf({ "package.json": pkg(), "main.js": "export default 1;\n" });
    const section = riskSectionOf(risk, "ci");
    assert.deepEqual(kindsOf(section), []);
    assert.equal(section.state, PRODUCTION_REPORT_STATES.COMPLETE);
    assert.equal(section.established, true);
    assert.deepEqual(
      reasonsOf(section).sort(),
      ["no-ci-configuration-observed"],
    );
  });
});

// ─── API protection gaps ─────────────────────────────────────────────────────

/** A resolved middleware module every API fixture imports. */
const AUTH_MODULE = { "src/auth.js": "export function requireAuth(req, res, next) { next(); }\n" };

/**
 * A real Express entrypoint declaring one route, with the given registrations above it.
 *
 * Every fixture in the API suite is a repository scanned end to end, so a finding reports the
 * accepted middleware graph's own protection state rather than a state a test asserted.
 */
const expressApp = (...registrations) => ({
  "package.json": pkg(),
  ...AUTH_MODULE,
  "main.js": [
    'import express from "express";',
    'import { requireAuth } from "./src/auth.js";',
    "const app = express();",
    ...registrations,
    'app.get("/users", handler);',
    "export default app;",
    "",
  ].join("\n"),
});

describe("production risk: api protection", () => {
  it("reports a route whose middleware could not be established at all", async () => {
    const { model, risk } = await scanOf(expressApp("app.use(auth.middleware);"));
    const section = riskSectionOf(risk, "api");
    const finding = findingOf(section, "api-route-protection-unresolved");
    assert.notEqual(finding, null);
    assert.equal(finding.route, "route:GET:/users");
    assert.equal(finding.method, "GET");
    assert.equal(finding.severity, PRODUCTION_RISK_SEVERITIES.MEDIUM);
    assert.equal(finding.confidence, PRODUCTION_RISK_CONFIDENCES.GRAPH_DERIVED);
    assert.equal(finding.basis, "middleware-graph-protection");
    assert.equal(finding.unresolved > 0, true);
    assert.equal(finding.evidenceIds.length > 0, true);
    // The finding's premise is the inventory route's own protection word, not a second opinion.
    const route = model.production.report.sections
      .find((entry) => entry.name === "api")
      .observations.find((entry) => entry.route === finding.route);
    assert.equal(route.protection, MIDDLEWARE_PROTECTION_STATES.UNRESOLVED);
    // A statement about what the graph could not establish, never about the route's safety.
    assert.equal(finding.statement.includes("unresolved"), true);
    assert.equal(
      finding.statement.includes("Whether anything protects it at runtime is not established."),
      true,
    );
    assert.equal(/insecure|vulnerab|weak|expos|attack/i.test(finding.statement), false);
    assert.equal(finding.remediation, null);
    assert.equal(section.state, PRODUCTION_REPORT_STATES.PARTIAL);
  });

  it("reports a protected route whose middleware identity is only partly established", async () => {
    const { risk } = await scanOf(expressApp("app.use(requireAuth);", "app.use(auth.middleware);"));
    const section = riskSectionOf(risk, "api");
    const finding = findingOf(section, "api-protected-route-partially-unresolved");
    assert.notEqual(finding, null);
    assert.equal(finding.middleware >= 1, true);
    assert.equal(finding.unresolved >= 1, true);
    assert.equal(finding.statement.includes("is `protected`"), true);
    assert.equal(finding.statement.includes("not established"), true);
    // The same route is never reported twice under two verdicts.
    assert.equal(findingOf(section, "api-route-protection-unresolved"), null);
    assert.equal(section.state, PRODUCTION_REPORT_STATES.PARTIAL);
  });

  it("reports nothing for a route whose protection resolved, while naming what it did not establish", async () => {
    const { risk } = await scanOf(expressApp("app.use(requireAuth);"));
    const section = riskSectionOf(risk, "api");
    assert.deepEqual(kindsOf(section), []);
    assert.equal(section.state, PRODUCTION_REPORT_STATES.PARTIAL);
    assert.equal(section.established, true);
    // The handler identity the inventory report could not establish survives verbatim, so
    // "no route gap" is never read as "everything about this route was established".
    assert.equal(reasonsOf(section).includes("handler-not-established"), true);
  });

  it("reports a route declared in a file where a router-scope registration was not established", async () => {
    const { model, risk } = await scanOf({
      "package.json": pkg(),
      ...AUTH_MODULE,
      "main.js": [
        'import express from "express";',
        'import { requireAuth } from "./src/auth.js";',
        "const app = express();",
        "const other = express.Router();",
        "other.use(auth.middleware);",
        "app.use(requireAuth);",
        'app.get("/users", handler);',
        "export default app;",
        "",
      ].join("\n"),
    });
    // The scope the detection trades in is the accepted middleware graph's own word for it.
    assert.equal(MIDDLEWARE_GRAPH_SCOPES.includes(PRODUCTION_RISK_ROUTER_SCOPE), true);
    const section = riskSectionOf(risk, "api");
    const finding = findingOf(section, "api-router-inheritance-incomplete");
    assert.notEqual(finding, null);
    assert.equal(finding.unresolved >= 1, true);
    assert.equal(finding.statement.includes("router-scope registration"), true);
    assert.equal(finding.statement.includes("not established"), true);
    assert.equal(finding.remediation, null);
    assert.equal(
      model.middleware.graph.unresolved.some(
        (record) => record.scope === PRODUCTION_RISK_ROUTER_SCOPE && record.path === "main.js",
      ),
      true,
    );
  });

  it("withholds every route detection for a domain this build does not interpret", async () => {
    const { risk } = await scanOf({
      "requirements.txt": "flask==3.0.0\n",
      "app.py": "from flask import Flask\napp = Flask(__name__)\n",
    });
    const section = riskSectionOf(risk, "api");
    assert.deepEqual(kindsOf(section), []);
    assert.equal(section.state, PRODUCTION_REPORT_STATES.UNSUPPORTED);
    assert.equal(section.established, false);
    assert.equal(reasonsOf(section).includes("middleware-graph-not-established"), true);
    // The state is only legal with a declared basis, and the section names one.
    const basis = PRODUCTION_RISK_UNSUPPORTED_REASONS.api;
    assert.equal(basis.length > 0, true);
  });

  it("withholds every route detection while the scan itself is incomplete", () => {
    const model = buildRepositoryModel(
      literalScan(["main.js", "package.json"], { complete: false }),
    );
    const section = riskSectionOf(model.productionRisk.report, "api");
    assert.deepEqual(kindsOf(section), []);
    assert.equal(section.state, PRODUCTION_REPORT_STATES.UNKNOWN);
    assert.equal(section.established, false);
    assert.equal(reasonsOf(section).includes("repository-scan-not-complete"), true);
  });

  it("counts a detection whose citation the model does not carry instead of reporting it uncited", async () => {
    const { model } = await scanOf(expressApp("app.use(auth.middleware);"));
    const report = clone(model.production.report);
    const api = report.sections.find((section) => section.name === "api");
    for (const observation of api.observations) observation.evidenceIds = [];
    const rebuilt = buildProductionRiskReport({
      report,
      evidence: model.evidence,
      middlewareGraph: model.middleware.graph,
      apiGraph: model.api.graph,
      architectureGraph: model.architecture.graph,
      importGraph: model.imports.graph,
    });
    const section = rebuilt.sections.find((entry) => entry.name === "api");
    assert.deepEqual(section.findings, []);
    const withheld = section.unknown.find(
      (record) => record.reason === "risk-finding-without-evidence",
    );
    assert.notEqual(withheld, undefined);
    assert.equal(withheld.count >= 1, true);
  });
});

// ─── Dependency hygiene gaps ─────────────────────────────────────────────────

describe("production risk: dependency hygiene", () => {
  it("reports a manifest with no lockfile in its ecosystem", async () => {
    const { risk } = await scanOf({
      "package.json": pkg({ dependencies: { express: "^4.18.0" } }),
      "src/a.js": "export const a = 1;\n",
    });
    const section = riskSectionOf(risk, "dependencies");
    const finding = findingOf(section, "dependency-manifest-without-lockfile");
    assert.notEqual(finding, null);
    assert.equal(finding.ecosystem, "node");
    assert.equal(finding.severity, PRODUCTION_RISK_SEVERITIES.LOW);
    assert.equal(finding.confidence, PRODUCTION_RISK_CONFIDENCES.ABSENT);
    assert.equal(finding.basis, "dependency-source-role");
    assert.deepEqual(finding.paths, ["package.json"]);
    assert.equal(
      finding.statement.includes("which versions the declared dependencies resolve to is not established"),
      true,
    );
    assert.equal(/vulnerab|CVE|outdated|unsafe|audit/i.test(finding.statement), false);
    assert.equal(finding.remediation, "Commit a lockfile for the ecosystem's manifest.");
  });

  it("reports a lockfile with no manifest", async () => {
    const { risk } = await scanOf({
      "package-lock.json": npmLock({ "node_modules/express": { version: "4.18.2" } }),
    });
    const finding = findingOf(
      riskSectionOf(risk, "dependencies"),
      "dependency-lockfile-without-manifest",
    );
    assert.notEqual(finding, null);
    assert.equal(finding.ecosystem, "node");
    assert.deepEqual(finding.paths, ["package-lock.json"]);
    assert.equal(finding.statement.includes("and no manifest"), true);
    assert.equal(finding.remediation !== null, true);
  });

  it("reports dependencies declared in more than one ecosystem", async () => {
    const { risk } = await scanOf({
      "package.json": pkg(),
      "requirements.txt": "flask==3.0.0\n",
    });
    const section = riskSectionOf(risk, "dependencies");
    const finding = findingOf(section, "dependency-ecosystems-multiple");
    assert.notEqual(finding, null);
    assert.equal(finding.count, 2);
    assert.deepEqual(finding.paths, ["node", "python"]);
    // Declared, not judged: nothing about how each ecosystem is maintained is implied.
    assert.equal(finding.severity, PRODUCTION_RISK_SEVERITIES.INFO);
    assert.equal(finding.confidence, PRODUCTION_RISK_CONFIDENCES.DECLARED);
    assert.equal(finding.statement.includes("Whether each is maintained by its own toolchain is not established."), true);
    assert.equal(finding.remediation, null);
  });

  it("reports a dependency source in a format this build could not read", async () => {
    const { risk } = await scanOf({ "package.json": "{ not json", "src/a.js": "export const a = 1;\n" });
    const finding = findingOf(
      riskSectionOf(risk, "dependencies"),
      "dependency-source-unresolved",
    );
    assert.notEqual(finding, null);
    assert.equal(finding.status, "failed");
    assert.equal(finding.reason, "invalid-json");
    assert.equal(finding.severity, PRODUCTION_RISK_SEVERITIES.INFO);
    assert.equal(
      finding.statement.includes("This is a statement about the source's format, not about the dependency."),
      true,
    );
    // Nothing is recommended: the gap is in this build's readers, not in the repository.
    assert.equal(finding.remediation, null);
  });

  it("reports no dependency gap for a manifest with its lockfile beside it", async () => {
    const { risk } = await scanOf({
      "package.json": pkg({ dependencies: { express: "^4.18.0" } }),
      "package-lock.json": npmLock({ "node_modules/express": { version: "4.18.2" } }),
      "src/a.js": "export const a = 1;\n",
    });
    const section = riskSectionOf(risk, "dependencies");
    assert.deepEqual(kindsOf(section), []);
    assert.equal(section.state, PRODUCTION_REPORT_STATES.COMPLETE);
    assert.equal(section.established, true);
  });

  it("withholds both absence claims while the dependency reading is not complete", async () => {
    const { risk } = await scanOf({ "package.json": "{ not json" });
    const section = riskSectionOf(risk, "dependencies");
    // The unread source is a present fact and is reported; the two absences are not, because
    // "there is no lockfile" cannot be said over a manifest this build could not parse.
    assert.deepEqual(kindsOf(section), ["dependency-source-unresolved"]);
    assert.equal(section.state, PRODUCTION_REPORT_STATES.UNKNOWN);
    const withheld = section.unknown.filter(
      (record) => record.reason === "dependency-coverage-not-complete",
    );
    assert.equal(
      withheld.some((record) => record.detail === "dependency-manifest-without-lockfile"),
      true,
    );
    // The unread source itself is stated rather than turned into a pass or into an absence.
    assert.equal(
      section.unknown.some((record) => record.reason === "dependency-source-not-established"),
      true,
    );
  });
});

// ─── Architecture integrity gaps ─────────────────────────────────────────────

describe("production risk: architecture integrity", () => {
  it("reports an entrypoint-shaped file no import relationship relates", async () => {
    const { risk } = await scanOf({
      "package.json": pkg(),
      "main.js": "export const main = 1;\n",
    });
    const finding = findingOf(
      riskSectionOf(risk, "architecture"),
      "architecture-entrypoint-disconnected",
    );
    assert.notEqual(finding, null);
    assert.equal(finding.path, "main.js");
    assert.equal(finding.severity, PRODUCTION_RISK_SEVERITIES.LOW);
    assert.equal(finding.confidence, PRODUCTION_RISK_CONFIDENCES.GRAPH_DERIVED);
    assert.equal(finding.basis, "import-graph-isolation");
    assert.equal(
      finding.statement.includes("nothing imports it and it imports nothing"),
      true,
    );
    assert.equal(/dead code|unused|unreachable|complex/i.test(finding.statement), false);
  });

  it("reports a group of unrelated files under one directory", async () => {
    const { risk } = await scanOf({
      "package.json": pkg(),
      "src/legacy/a.js": "export const a = 1;\n",
      "src/legacy/b.js": "export const b = 2;\n",
    });
    const finding = findingOf(
      riskSectionOf(risk, "architecture"),
      "architecture-isolated-cluster",
    );
    assert.notEqual(finding, null);
    assert.equal(finding.directory, "src/legacy");
    assert.equal(finding.count, 2);
    assert.deepEqual(finding.paths, ["src/legacy/a.js", "src/legacy/b.js"]);
    assert.equal(finding.statement.includes("neither import nor are imported"), true);
  });

  it("reports a container holding a manifest that no import edge touches", async () => {
    const { risk } = await scanOf({
      "package.json": pkg(),
      "main.js": "export const main = 1;\n",
      "tools/package.json": pkg({ name: "tools" }),
      "tools/t.js": "export const t = 1;\n",
    });
    const section = riskSectionOf(risk, "architecture");
    const finding = findingOf(section, "architecture-module-unconnected");
    assert.notEqual(finding, null);
    assert.equal(finding.container, "directory:tools");
    assert.equal(finding.moduleFiles >= 1, true);
    assert.equal(finding.statement.includes("none of which any import edge touches"), true);
  });

  it("skips a container the import graph carries no file for", async () => {
    // `tools/` holds a manifest and a file no import reader covers, so the import graph says
    // nothing about it and "nothing imports it" would be a claim from an absent substrate.
    const { risk } = await scanOf({
      "package.json": pkg(),
      "main.js": "export const main = 1;\n",
      "tools/package.json": pkg({ name: "tools" }),
      "tools/notes.txt": "tools\n",
    });
    const section = riskSectionOf(risk, "architecture");
    assert.equal(
      section.findings.every((finding) => finding.container !== "directory:tools"),
      true,
    );
  });

  it("reports no architecture gap for a connected repository", async () => {
    const { risk } = await scanOf({
      "package.json": pkg(),
      "main.js": 'import { app } from "./src/app.js";\nexport default app;\n',
      "src/app.js": "export const app = 1;\n",
    });
    const section = riskSectionOf(risk, "architecture");
    assert.deepEqual(kindsOf(section), []);
    assert.equal(section.state, PRODUCTION_REPORT_STATES.COMPLETE);
    assert.equal(section.established, true);
  });

  it("withholds every architecture claim while the import graph is incomplete", () => {
    const model = buildRepositoryModel(
      literalScan(["main.js", "package.json"], { complete: false }),
    );
    const section = riskSectionOf(model.productionRisk.report, "architecture");
    assert.deepEqual(kindsOf(section), []);
    assert.equal(section.state, PRODUCTION_REPORT_STATES.UNKNOWN);
    const withheld = section.unknown.filter(
      (record) => record.reason === "architecture-coverage-not-complete",
    );
    assert.deepEqual(
      withheld.map((record) => record.detail).sort(),
      [
        "architecture-entrypoint-disconnected",
        "architecture-isolated-cluster",
        "architecture-module-unconnected",
      ],
    );
  });
});

// ─── The projection and its query surface ────────────────────────────────────

describe("production risk report: model and query API", () => {
  it("carries six sections, in the domains' own order, each with a title and counts", () => {
    assert.deepEqual(
      fullRisk.sections.map((section) => section.name),
      [...PRODUCTION_RISK_SECTIONS],
    );
    for (const section of fullRisk.sections) {
      assert.equal(section.title, PRODUCTION_RISK_SECTION_TITLES[section.name]);
      assert.equal(section.established, isEstablishedRiskState(section.state));
      assert.equal(section.coverage.state, section.state);
      assert.equal(section.counts.findings, section.findings.length);
      assert.equal(section.coverage.findings, section.findings.length);
      assert.deepEqual(
        Object.keys(section.counts.bySeverity),
        [...PRODUCTION_RISK_SEVERITY_VALUES],
      );
    }
  });

  it("is frozen, and stays frozen at every level", () => {
    assert.equal(Object.isFrozen(fullRisk), true);
    assert.equal(Object.isFrozen(fullRisk.sections), true);
    assert.equal(Object.isFrozen(fullRisk.sections[0].findings), true);
    assert.equal(Object.isFrozen(fullRisk.coverage.severities), true);
    for (const section of fullRisk.sections) {
      for (const finding of section.findings) {
        assert.equal(Object.isFrozen(finding), true);
        assert.equal(Object.isFrozen(finding.evidenceIds), true);
      }
    }
  });

  it("derives its state from its sections and reports the same report twice", async () => {
    const { model: again, risk: second } = await scanOf(FULL_REPO);
    assert.deepEqual(second, fullRisk);
    assert.equal(second.state, fullRisk.state);
    assert.equal(again.productionRisk.state, fullRisk.state);
    assert.equal(
      fullRisk.state,
      fullRisk.sections.every((section) => section.state === PRODUCTION_RISK_STATES.COMPLETE)
        ? PRODUCTION_RISK_STATES.COMPLETE
        : fullRisk.sections.some((section) => isEstablishedRiskState(section.state))
          ? PRODUCTION_RISK_STATES.PARTIAL
          : PRODUCTION_RISK_STATES.UNKNOWN,
    );
    assert.equal(fullRisk.established, isEstablishedRiskState(fullRisk.state));
  });

  it("agrees with the inventory report it derives from", () => {
    assert.equal(
      fullRisk.coverage.findings,
      fullRisk.sections.reduce((total, section) => total + section.findings.length, 0),
    );
    assert.deepEqual(
      fullRisk.evidenceIds,
      [...new Set(fullRisk.sections.flatMap((section) => section.evidenceIds))].sort(),
    );
    assert.equal(fullRisk.coverage.sections, PRODUCTION_SECTIONS.length);
    const known = new Set(fullModel.evidence.map((record) => record.id));
    assert.equal(fullRisk.evidenceIds.every((id) => known.has(id)), true);
    // Every abstention the inventory report recorded survives in the risk section.
    for (const name of PRODUCTION_RISK_SECTIONS) {
      const inventory = sectionOf(fullReport, name);
      const risk = riskSectionOf(fullRisk, name);
      for (const record of inventory.unknown) {
        assert.equal(
          risk.unknown.some(
            (entry) => entry.reason === record.reason && entry.detail === record.detail,
          ),
          true,
          `${name}: ${record.reason}`,
        );
      }
    }
  });

  it("answers through the query API and refuses an unknown domain", () => {
    assert.equal(fullQuery.productionRiskReport(), fullRisk);
    assert.equal(fullQuery.productionRiskCoverage().state, fullRisk.state);
    for (const name of PRODUCTION_RISK_SECTIONS) {
      const section = fullQuery.productionRiskSection(name);
      assert.equal(section, riskSectionOf(fullRisk, name));
      assert.equal(Object.isFrozen(section), true);
    }
    assert.throws(() => fullQuery.productionRiskSection("containers"), (error) => {
      assert.equal(error.kind, "invalid-query");
      return true;
    });
    assert.throws(() => fullQuery.productionRiskSection(undefined), (error) => {
      assert.equal(error.kind, "invalid-query");
      return true;
    });
    // The coverage handle is a copy, so a caller cannot reach the model's own object through it.
    const coverage = fullQuery.productionRiskCoverage();
    assert.notEqual(coverage, fullRisk.coverage);
    assert.deepEqual(coverage.severities, { ...fullRisk.coverage.severities });
  });

  it("returns null rather than an empty report for a model that carries none", () => {
    const bare = { ...clone(fullModel), productionRisk: {} };
    const query = createRepositoryQuery(bare);
    assert.equal(query.productionRiskReport(), null);
    assert.equal(query.productionRiskCoverage(), null);
    assert.equal(query.productionRiskSection("api"), null);
  });

  it("never converts an unknown into a pass", () => {
    const model = buildRepositoryModel(literalScan(["package.json"], { complete: false }));
    const query = createRepositoryQuery(model);
    for (const name of PRODUCTION_RISK_SECTIONS) {
      const section = query.productionRiskSection(name);
      assert.equal(section.established, false, name);
      assert.equal(section.state, PRODUCTION_REPORT_STATES.UNKNOWN, name);
      assert.deepEqual(section.findings, [], name);
      assert.equal(section.unknown.length > 0, true, name);
    }
    assert.equal(query.productionRiskReport().established, false);
  });
});

// ─── The report contract ─────────────────────────────────────────────────────

describe("production risk report contract", () => {
  const base = () => clone(fullModel);

  it("accepts the report the builder produced", () => {
    const model = base();
    assert.equal(issuesOfValidate(model), null);
    assert.equal(validateRepositoryModelGraph(model), model);
  });

  it("rejects a risk report that is not a plain object", () => {
    const model = base();
    model.productionRisk.report = "six gaps";
    assert.notEqual(issuesOfValidate(model), null);
  });

  it("rejects an area state and an area flag that disagree", () => {
    const unknownState = base();
    unknownState.productionRisk.state = "ready";
    assert.notEqual(issuesOfValidate(unknownState), null);

    const disagreement = base();
    disagreement.productionRisk.established = !disagreement.productionRisk.established;
    assert.notEqual(issuesOfValidate(disagreement), null);
  });

  it("rejects a wrong report version and a report state that disagrees with its area", () => {
    const version = base();
    version.productionRisk.report.version = "2";
    assert.notEqual(issuesOfValidate(version), null);

    const state = base();
    state.productionRisk.report.state = PRODUCTION_RISK_STATES.UNKNOWN;
    assert.notEqual(issuesOfValidate(state), null);
  });

  it("rejects a report that drops, duplicates or reorders a domain", () => {
    const dropped = base();
    dropped.productionRisk.report.sections = dropped.productionRisk.report.sections.slice(1);
    assert.notEqual(issuesOfValidate(dropped), null);

    const duplicated = base();
    const sections = duplicated.productionRisk.report.sections;
    duplicated.productionRisk.report.sections = [...sections.slice(0, 5), sections[0]];
    assert.notEqual(issuesOfValidate(duplicated), null);

    const reordered = base();
    const swapped = [...reordered.productionRisk.report.sections];
    [swapped[0], swapped[1]] = [swapped[1], swapped[0]];
    reordered.productionRisk.report.sections = swapped;
    assert.notEqual(issuesOfValidate(reordered), null);
  });

  it("rejects a section whose title, state or established flag is not the contract's", () => {
    const title = base();
    title.productionRisk.report.sections[0].title = "Environment";
    assert.notEqual(issuesOfValidate(title), null);

    const state = base();
    state.productionRisk.report.sections[0].state = "ready";
    assert.notEqual(issuesOfValidate(state), null);

    const established = base();
    established.productionRisk.report.sections[0].established =
      !established.productionRisk.report.sections[0].established;
    assert.notEqual(issuesOfValidate(established), null);
  });

  it("rejects a finding kind a domain does not declare", () => {
    const model = base();
    const section = model.productionRisk.report.sections.find(
      (entry) => entry.findings.length > 0,
    );
    section.findings[0].kind = "architecture-module-unconnected";
    assert.notEqual(issuesOfValidate(model), null);
  });

  it("rejects a severity outside the closed vocabulary, including every escalated word", () => {
    for (const severity of ["high", "critical", "moderate"]) {
      const model = base();
      const section = model.productionRisk.report.sections.find(
        (entry) => entry.findings.length > 0,
      );
      section.findings[0].severity = severity;
      assert.notEqual(issuesOfValidate(model), null, severity);
    }
  });

  it("rejects a severity, confidence or basis that disagrees with its own kind", () => {
    const severity = base();
    const section = severity.productionRisk.report.sections.find(
      (entry) => entry.findings.length > 0,
    );
    const kind = section.findings[0].kind;
    section.findings[0].severity =
      PRODUCTION_RISK_SEVERITY_BY_KIND[kind] === PRODUCTION_RISK_SEVERITIES.LOW
        ? PRODUCTION_RISK_SEVERITIES.INFO
        : PRODUCTION_RISK_SEVERITIES.LOW;
    assert.notEqual(issuesOfValidate(severity), null);

    const confidence = base();
    const section2 = confidence.productionRisk.report.sections.find(
      (entry) => entry.findings.length > 0,
    );
    section2.findings[0].confidence = "certainly";
    assert.notEqual(issuesOfValidate(confidence), null);

    const basis = base();
    const section3 = basis.productionRisk.report.sections.find(
      (entry) => entry.findings.length > 0,
    );
    section3.findings[0].basis = "a professional opinion";
    assert.notEqual(issuesOfValidate(basis), null);
  });

  it("rejects prose that claims more than the finding's own record renders", () => {
    const statement = base();
    const section = statement.productionRisk.report.sections.find(
      (entry) => entry.findings.length > 0,
    );
    section.findings[0].statement = "The container is insecure.";
    assert.notEqual(issuesOfValidate(statement), null);

    const remediation = base();
    const section2 = remediation.productionRisk.report.sections.find(
      (entry) => entry.findings.length > 0,
    );
    section2.findings[0].remediation = "Rewrite the service.";
    assert.notEqual(issuesOfValidate(remediation), null);
  });

  it("rejects a finding whose id, key ordering or citation is not the contract's", () => {
    const id = base();
    const section = id.productionRisk.report.sections.find(
      (entry) => entry.findings.length > 0,
    );
    section.findings[0].id = `${section.name}:${section.findings[0].kind}:other`;
    assert.notEqual(issuesOfValidate(id), null);

    const ordering = base();
    const container = ordering.productionRisk.report.sections.find(
      (entry) => entry.name === "container",
    );
    container.findings[0].key = "zzzz-last";
    assert.notEqual(issuesOfValidate(ordering), null);

    const citation = base();
    const cited = citation.productionRisk.report.sections.find(
      (entry) => entry.findings.length > 0,
    );
    cited.findings[0].evidenceIds = ["evidence:does-not-exist"];
    assert.notEqual(issuesOfValidate(citation), null);

    const empty = base();
    const uncited = empty.productionRisk.report.sections.find(
      (entry) => entry.findings.length > 0,
    );
    uncited.findings[0].evidenceIds = [];
    assert.notEqual(issuesOfValidate(empty), null);
  });

  it("rejects a counts field that does not count what the section carries", () => {
    const model = base();
    model.productionRisk.report.sections[0].counts.findings += 1;
    assert.notEqual(issuesOfValidate(model), null);
  });

  it("rejects an abstention outside the domain's own vocabulary", () => {
    const model = base();
    model.productionRisk.report.sections[0].unknown.push({
      reason: "the-environment-looks-wrong",
      detail: null,
      count: 1,
    });
    assert.notEqual(issuesOfValidate(model), null);
  });

  it("rejects a section state that disagrees with its coverage", () => {
    const model = base();
    model.productionRisk.report.sections[0].coverage.state = PRODUCTION_RISK_STATES.UNKNOWN;
    assert.notEqual(issuesOfValidate(model), null);
  });

  it("rejects report-level lists that disagree with the sections they came from", () => {
    const findings = base();
    findings.productionRisk.report.findings = [];
    assert.notEqual(issuesOfValidate(findings), null);

    const evidence = base();
    evidence.productionRisk.report.evidenceIds = [];
    assert.notEqual(issuesOfValidate(evidence), null);

    const unknowns = base();
    unknowns.productionRisk.report.unknowns = [];
    assert.notEqual(issuesOfValidate(unknowns), null);
  });

  it("rejects report coverage that disagrees with the sections it summarises", () => {
    const state = base();
    state.productionRisk.report.coverage.state = PRODUCTION_RISK_STATES.UNKNOWN;
    assert.notEqual(issuesOfValidate(state), null);

    const findings = base();
    findings.productionRisk.report.coverage.findings += 1;
    assert.notEqual(issuesOfValidate(findings), null);

    const severities = base();
    severities.productionRisk.report.coverage.severities.medium += 1;
    assert.notEqual(issuesOfValidate(severities), null);
  });

  it("rejects an unsupported domain that names no uninterpreted basis", () => {
    const model = base();
    const section = model.productionRisk.report.sections.find(
      (entry) => entry.name === "api",
    );
    section.state = PRODUCTION_RISK_STATES.UNSUPPORTED;
    section.established = false;
    section.coverage.state = PRODUCTION_RISK_STATES.UNSUPPORTED;
    section.coverage.established = false;
    section.unknown = [];
    assert.notEqual(issuesOfValidate(model), null);
  });
});

// ─── The rule pack ───────────────────────────────────────────────────────────

describe("production risk rule pack", () => {
  const runOf = async (repository) => {
    const engine = createRuleEngine({
      registry: createProductionRiskRuleRegistry({ rules: productionRiskRules }),
    });
    const { model } = await scanOf(repository);
    return { model, run: await engine.runAll(buildAnalysisContext({ repository: model })) };
  };
  const ruleOf = (run, id) => run.rules.find((entry) => entry.rule.id === id);
  const riskRuleId = (name) => `production.risk.${name}`;

  it("pins the pack's identity, which every fingerprint depends on", () => {
    assert.equal(PRODUCTION_RISK_ANALYZER_ID, "production-risk");
    assert.equal(PRODUCTION_RISK_ANALYZER_NAME, "Production Risk");
    assert.equal(PRODUCTION_RISK_ANALYZER_SCOPE, "production-risk");
    assert.equal(PRODUCTION_RISK_RULE_ID_PREFIX, "production.risk.");
    assert.equal(PRODUCTION_RISK_RULE_PACK_VERSION, "1.0.0");
    assert.equal(PRODUCTION_RISK_CATEGORY, "architecture");
    assert.equal(PRODUCTION_RISK_BASIS, "static-production-risk-report");
    assert.deepEqual(Object.values(PRODUCTION_RISK_RULE_IDS).sort(), [
      "production.risk.api",
      "production.risk.architecture",
      "production.risk.ci",
      "production.risk.container",
      "production.risk.dependencies",
      "production.risk.environment",
    ]);
  });

  it("declares six rules in the risk namespace, one per audit domain", () => {
    assert.deepEqual(productionRiskRuleSetIssues(productionRiskRules), []);
    assert.deepEqual(
      Object.values(PRODUCTION_RISK_RULE_IDS),
      PRODUCTION_RISK_SECTIONS.map(riskRuleId),
    );
    assert.deepEqual(
      productionRiskRules.map((rule) => rule.id).sort(),
      Object.values(PRODUCTION_RISK_RULE_IDS).sort(),
    );
    for (const rule of productionRiskRules) {
      assert.equal(rule.id.startsWith(PRODUCTION_RISK_RULE_ID_PREFIX), true);
      assert.equal(PRODUCTION_RISK_SEVERITY_VALUES.includes(rule.severity), true);
      assert.equal(rule.severity === "high" || rule.severity === "critical", false);
      assert.equal(rule.category, PRODUCTION_RISK_CATEGORY);
      assert.deepEqual(rule.applicability, {});
      assert.deepEqual(rule.remediation, {});
      assert.equal(rule.metadata.basis, PRODUCTION_RISK_BASIS);
      assert.equal(typeof rule.detect, "function");
    }
  });

  it("describes every vocabulary the report can produce", () => {
    assert.deepEqual([...PRODUCTION_RISK_DESCRIBED_SECTIONS].sort(), [...PRODUCTION_RISK_SECTIONS].sort());
    const kinds = PRODUCTION_RISK_SECTIONS.flatMap((name) => [...PRODUCTION_RISK_FINDING_KINDS[name]]);
    assert.deepEqual([...PRODUCTION_RISK_DESCRIBED_KINDS].sort(), kinds.sort());
    assert.deepEqual(PRODUCTION_RISK_DESCRIBED_SEVERITIES, [...PRODUCTION_RISK_SEVERITY_VALUES]);
    assert.deepEqual(PRODUCTION_RISK_DESCRIBED_CONFIDENCES, [...PRODUCTION_RISK_CONFIDENCE_VALUES]);
    assert.deepEqual(PRODUCTION_RISK_DESCRIBED_STATES, [...PRODUCTION_RISK_STATE_VALUES]);
    // The abstention vocabulary is the inventory report's own reasons plus this report's.
    const described = new Set(PRODUCTION_RISK_DESCRIBED_ABSTENTIONS);
    for (const name of PRODUCTION_RISK_SECTIONS) {
      for (const reason of [
        ...PRODUCTION_RISK_UNKNOWN_REASONS[name],
        ...PRODUCTION_RISK_UNSUPPORTED_REASONS[name],
      ]) {
        assert.equal(described.has(reason), true, reason);
      }
    }
    for (const kind of kinds) {
      assert.equal(typeof PRODUCTION_RISK_FINDING_WORDING[kind], "string");
      assert.equal(PRODUCTION_RISK_SEVERITY_VALUES.includes(PRODUCTION_RISK_SEVERITY_BY_KIND[kind]), true);
      assert.equal(PRODUCTION_RISK_CONFIDENCE_VALUES.includes(PRODUCTION_RISK_CONFIDENCE_BY_KIND[kind]), true);
      assert.equal(typeof PRODUCTION_RISK_BASIS_BY_KIND[kind], "string");
    }
  });

  it("reports the report's findings, each citing its evidence", async () => {
    const { run } = await runOf(FULL_REPO);
    for (const section of fullRisk.sections) {
      const id = riskRuleId(section.name);
      const result = ruleOf(run, id);
      assert.equal(result.metadata.section, section.name, id);
      assert.equal(result.metadata.findings, section.findings.length, id);
      assert.equal(result.metadata.capped, false, id);
      for (const finding of result.findings) {
        assert.equal(PRODUCTION_RISK_SEVERITY_VALUES.includes(finding.severity), true);
        assert.equal(finding.evidence.length > 0, true);
        assert.equal(finding.metadata.basis, PRODUCTION_RISK_BASIS);
        assert.equal(typeof finding.description, "string");
        assert.equal(finding.description.length > 40, true);
        assert.equal(finding.metadata.findingId.startsWith(`${section.name}:`), true);
      }
    }
  });

  it("carries each finding's own severity, basis and remediation, and no aggregate", async () => {
    const { run } = await runOf(FULL_REPO);
    const container = ruleOf(run, riskRuleId("container"));
    const severities = new Set(container.metadata.abstentions.length >= 0 ? container.findings.map((f) => f.severity) : []);
    for (const severity of severities) {
      assert.equal(PRODUCTION_RISK_SEVERITY_VALUES.includes(severity), true);
    }
    const finding = container.findings.find(
      (entry) => entry.metadata.kind === "container-compose-dockerfile-not-observed",
    );
    assert.notEqual(finding, undefined);
    assert.equal(finding.severity, PRODUCTION_RISK_SEVERITIES.MEDIUM);
    assert.equal(finding.metadata.basisDetail, "compose-build-declaration");
    assert.equal(finding.metadata.remediationStated, true);
    assert.equal(typeof finding.metadata.statement, "string");
    // The finding contract's own remediation field stays empty: a sentence belongs in metadata.
    assert.deepEqual(finding.remediation, {});
  });

  it("abstains instead of passing for a domain the report could not establish", async () => {
    const model = buildRepositoryModel(literalScan(["package.json"], { complete: false }));
    const engine = createRuleEngine({
      registry: createProductionRiskRuleRegistry({ rules: productionRiskRules }),
    });
    const run = await engine.runAll(buildAnalysisContext({ repository: model }));
    for (const name of PRODUCTION_RISK_SECTIONS) {
      const result = ruleOf(run, riskRuleId(name));
      assert.deepEqual(result.findings, [], name);
      assert.equal(result.status, RULE_OUTCOME_STATUSES.UNKNOWN, name);
      assert.equal(result.applicability.coverage, APPLICABILITY_COVERAGE.UNKNOWN, name);
      assert.equal(typeof result.applicability.reason, "string", name);
      assert.equal(result.metadata.reportEstablished, false, name);
    }
  });

  it("reports nothing at all for an established domain whose evidence shows no gap", async () => {
    const { run } = await runOf({
      "package.json": pkg({ dependencies: { express: "^4.18.0" } }),
      "package-lock.json": npmLock({ "node_modules/express": { version: "4.18.2" } }),
      "src/a.js": "export const a = 1;\n",
    });
    const dependencies = ruleOf(run, riskRuleId("dependencies"));
    assert.deepEqual(dependencies.findings, []);
    assert.equal(dependencies.status, RULE_OUTCOME_STATUSES.PASS);
    assert.equal(dependencies.metadata.established, true);
    assert.equal(dependencies.metadata.state, PRODUCTION_REPORT_STATES.COMPLETE);
  });

  it("rejects a rule set that leaves a declared domain out", () => {
    const missing = productionRiskRules.filter(
      (rule) => rule.id !== PRODUCTION_RISK_RULE_IDS.API,
    );
    const issues = productionRiskRuleSetIssues(missing);
    assert.equal(issues.length, 1);
    assert.equal(issues[0].includes(PRODUCTION_RISK_RULE_IDS.API), true);
    assert.throws(() => createProductionRiskRuleRegistry({ rules: missing }), (error) => {
      assert.equal(error.name, "RuleRegistrationError");
      return true;
    });
    assert.throws(
      () =>
        createProductionRiskRuleRegistry({
          rules: [{ ...productionRiskRules[0], id: "production.inventory" }],
        }),
      (error) => {
        assert.equal(error.name, "RuleRegistrationError");
        return true;
      },
    );
  });

  it("answers a domain question from the model and nothing else", async () => {
    const { model } = await scanOf(FULL_REPO);
    const query = createRepositoryQuery(model);
    const described = productionRiskSections(query);
    assert.equal(described.length, PRODUCTION_RISK_SECTIONS.length);
    for (const section of described) {
      assert.equal(typeof section.title, "string");
      assert.equal(typeof section.state, "string");
      assert.equal(typeof section.counts.findings, "number");
      for (const finding of section.findings) {
        assert.equal(typeof finding.kindWording, "string");
        assert.equal(typeof finding.severityWording, "string");
        assert.equal(typeof finding.confidenceWording, "string");
        assert.equal(typeof finding.fingerprintKey, "string");
      }
    }
    for (const name of PRODUCTION_RISK_SECTIONS) {
      const absence = productionRiskAbsence(query, name);
      assert.equal(typeof absence.established, "boolean");
      if (!absence.established) assert.equal(typeof absence.reason, "string", name);
    }
    assert.equal(productionRiskCoverage(query).sections, PRODUCTION_RISK_SECTIONS.length);
  });
});

// ─── Integration with the accepted engines ───────────────────────────────────

describe("production risk integration", () => {
  it("runs as an ordinary analyzer over the accepted framework", async () => {
    const { model } = await scanOf(FULL_REPO);
    const engine = createAnalyzerEngine({
      registry: createAnalyzerRegistry([createProductionRiskAnalyzer()]),
    });
    const result = await engine.runAll(buildAnalysisContext({ repository: model }));
    assert.equal(result.analyzers.length, 1);
    assert.equal(result.analyzers[0].analyzer.id, PRODUCTION_RISK_ANALYZER_ID);
    assert.equal(result.analyzers[0].analyzer.scope, PRODUCTION_RISK_ANALYZER_SCOPE);
    assert.equal(result.analyzers[0].metadata.ruleSet.length, PRODUCTION_RISK_SECTIONS.length);
    assert.equal(result.findings.length, fullRisk.coverage.findings);
    assert.equal(
      result.findings.every((finding) => finding.ruleId.startsWith("production.risk.")),
      true,
    );
  });

  it("produces deterministic, uniquely fingerprinted findings", async () => {
    const { model } = await scanOf(FULL_REPO);
    const engine = createAnalyzerEngine({
      registry: createAnalyzerRegistry([createProductionRiskAnalyzer()]),
    });
    const first = await engine.runAll(buildAnalysisContext({ repository: model }));
    const second = await engine.runAll(buildAnalysisContext({ repository: model }));
    assert.equal(
      new Set(first.findings.map((finding) => finding.fingerprint)).size,
      first.findings.length,
    );
    assert.deepEqual(
      first.findings.map((finding) => finding.fingerprint),
      second.findings.map((finding) => finding.fingerprint),
    );
  });

  it("leaves the inventory report and its rules untouched beside it", async () => {
    const { model } = await scanOf(FULL_REPO);
    const query = createRepositoryQuery(model);
    // The two projections are separate answers over one model, and neither recomputes the other.
    assert.notEqual(query.productionRiskReport(), query.productionReport());
    assert.equal(query.productionRiskReport().sections.length, query.productionReport().sections.length);
    assert.deepEqual(
      query.productionRiskReport().sections.map((section) => section.name),
      query.productionReport().sections.map((section) => section.name),
    );
    for (const name of PRODUCTION_RISK_SECTIONS) {
      const inventory = query.productionSection(name);
      const risk = query.productionRiskSection(name);
      // Two different answers about one domain, each with its own title and its own words.
      assert.equal(risk.title, PRODUCTION_RISK_SECTION_TITLES[name], name);
      assert.equal(risk.title !== inventory.title, true, name);
      assert.equal(risk.observations, undefined, name);
    }
    // Neither projection carries a score, a grade or a percentage.
    const flat = JSON.stringify(query.productionRiskReport());
    for (const word of ["score", "grade", "percentage", "trafficLight", "readiness"]) {
      assert.equal(flat.includes(word), false, word);
    }
  });
});

// ─── The closed tables and the bound ─────────────────────────────────────────

/**
 * Every finding kind this report can produce, with the three words its own tables assign it.
 *
 * Written out as literals on purpose: a table is a *decision* the phase made, and a test that
 * read the tables back from the module would agree with any decision at all — including an
 * escalated severity, a reclassified confidence or a basis that no longer names what was read.
 */
const RISK_TABLE = Object.freeze([
  ["environment-file-without-template", "low", "absent", "environment-name-table"],
  ["environment-template-class-duplicated", "low", "name-derived", "duplicate-name-class"],
  ["environment-template-classes-conflict", "low", "name-derived", "conflicting-name-class"],
  ["environment-configuration-without-sample", "info", "absent", "environment-name-table"],
  ["container-healthcheck-missing", "low", "declared", "dockerfile-instructions"],
  ["container-compose-dockerfile-not-observed", "medium", "declared", "compose-build-declaration"],
  ["container-compose-build-context-unresolved", "medium", "declared", "compose-declaration-classification"],
  ["container-service-image-without-build", "info", "declared", "compose-service-key"],
  ["ci-release-without-test", "low", "name-derived", "workflow-name-table"],
  ["ci-release-without-lint", "low", "name-derived", "workflow-name-table"],
  ["ci-workflows-unclassified", "info", "name-derived", "workflow-name-table"],
  ["ci-release-workflows-multiple", "low", "name-derived", "workflow-name-table"],
  ["api-route-protection-unresolved", "medium", "graph-derived", "middleware-graph-protection"],
  ["api-protected-route-partially-unresolved", "medium", "graph-derived", "middleware-graph-protection"],
  ["api-router-inheritance-incomplete", "low", "graph-derived", "middleware-graph-unresolved-scope"],
  ["dependency-manifest-without-lockfile", "low", "absent", "dependency-source-role"],
  ["dependency-lockfile-without-manifest", "low", "absent", "dependency-source-role"],
  ["dependency-ecosystems-multiple", "info", "declared", "dependency-ecosystem-census"],
  ["dependency-source-unresolved", "info", "declared", "dependency-source-status"],
  ["architecture-entrypoint-disconnected", "low", "graph-derived", "import-graph-isolation"],
  ["architecture-isolated-cluster", "low", "graph-derived", "import-graph-isolation"],
  ["architecture-module-unconnected", "low", "graph-derived", "import-graph-module-connectivity"],
]);

describe("production risk: the closed tables and the bound", () => {
  it("assigns every finding kind the severity, confidence and basis the phase decided", () => {
    const declared = PRODUCTION_RISK_SECTIONS.flatMap((name) => [...PRODUCTION_RISK_FINDING_KINDS[name]]);
    assert.deepEqual(RISK_TABLE.map(([kind]) => kind).sort(), [...declared].sort());
    for (const [kind, severity, confidence, basis] of RISK_TABLE) {
      assert.equal(PRODUCTION_RISK_SEVERITY_BY_KIND[kind], severity, kind);
      assert.equal(PRODUCTION_RISK_CONFIDENCE_BY_KIND[kind], confidence, kind);
      assert.equal(PRODUCTION_RISK_BASIS_BY_KIND[kind], basis, kind);
    }
  });

  it("never escalates past `medium`, in the tables or in a report", () => {
    assert.deepEqual(
      [...new Set(Object.values(PRODUCTION_RISK_SEVERITY_BY_KIND))].sort(),
      [PRODUCTION_RISK_SEVERITIES.INFO, PRODUCTION_RISK_SEVERITIES.LOW, PRODUCTION_RISK_SEVERITIES.MEDIUM],
    );
    assert.deepEqual(
      [...PRODUCTION_RISK_SEVERITY_VALUES].sort(),
      ["info", "low", "medium"],
    );
    for (const section of fullRisk.sections) {
      for (const finding of section.findings) {
        assert.equal(["high", "critical"].includes(finding.severity), false, finding.kind);
      }
    }
  });

  it("withholds an absence claim beside a workflow name that states no purpose", async () => {
    const { risk } = await scanOf({
      "package.json": pkg(),
      ".github/workflows/release.yml": workflow("release"),
      ".github/workflows/ci.yml": workflow("ci"),
    });
    const section = riskSectionOf(risk, "ci");
    // `ci.yml` may well be the test pipeline, so neither absence is claimed.
    assert.deepEqual(kindsOf(section), []);
    assert.equal(section.established, true);
    assert.deepEqual(
      section.unknown
        .filter((record) => record.reason === "workflow-purpose-not-established")
        .map((record) => record.detail)
        .filter((detail) => detail !== null)
        .sort(),
      ["ci-release-without-lint", "ci-release-without-test"],
    );
    // The inventory report's own gap is carried verbatim beside them.
    assert.equal(
      section.unknown.some(
        (record) => record.reason === "workflow-purpose-not-established" && record.detail === null,
      ),
      true,
    );
  });

  it("withholds a build-context claim for a Compose file this build could not interpret", async () => {
    const { risk } = await scanOf({
      "package.json": pkg(),
      "Dockerfile": 'FROM node:20\nHEALTHCHECK CMD node h.js\nCMD ["node","m.js"]\n',
      "docker-compose.yml": "services:\n  a:\n    build: .\nservices:\n  b:\n    build: .\n",
    });
    const section = riskSectionOf(risk, "container");
    // An ambiguous file states no defect: it states nothing this build can read.
    assert.deepEqual(kindsOf(section), []);
    assert.equal(
      section.unknown.some((record) => record.reason === "compose-build-declarations-not-established"),
      true,
    );
  });

  it("bounds a section's findings and records the bound it reached", async () => {
    const { model } = await scanOf({ "package.json": pkg(), Dockerfile: plainDockerfile });
    const report = clone(model.production.report);
    const container = report.sections.find((section) => section.name === "container");
    const structure = container.observations.find(
      (observation) => observation.kind === "container-structure",
    );
    assert.notEqual(structure, undefined);
    // One definition per healthcheck-less Dockerfile, several hundred of them: more findings
    // than the report is allowed to carry in one domain.
    const declarations = 205;
    const extra = [];
    for (let index = 0; index < declarations; index += 1) {
      extra.push({
        ...structure,
        key: `structure:Dockerfile.${index}`,
        path: `Dockerfile.${index}`,
        healthcheck: false,
        healthcheckDisabled: false,
      });
    }
    container.observations = [
      ...container.observations.filter((observation) => observation.kind !== "container-structure"),
      ...extra,
    ];
    const rebuilt = buildProductionRiskReport({ report, evidence: model.evidence });
    const section = rebuilt.sections.find((entry) => entry.name === "container");
    assert.equal(section.findings.length, PRODUCTION_RISK_REPORT_LIMITS.maxFindingsPerSection);
    assert.equal(section.coverage.truncated, true);
    assert.equal(section.state, PRODUCTION_RISK_STATES.TRUNCATED);
    assert.equal(section.established, true);
    const truncation = section.unknown.find(
      (record) => record.reason === "risk-findings-truncated",
    );
    assert.notEqual(truncation, undefined);
    assert.equal(
      truncation.count,
      declarations - PRODUCTION_RISK_REPORT_LIMITS.maxFindingsPerSection,
    );
    // The bound is reported as a fact, and the report says so at its own level too.
    assert.equal(rebuilt.coverage.truncated, true);
    assert.equal(rebuilt.state, PRODUCTION_RISK_STATES.TRUNCATED);
  });
});

// ─── The reason for each rejection ───────────────────────────────────────────

/**
 * Assert that the model is rejected *for a named reason*.
 *
 * "Something is wrong" is too weak a claim for this contract: a check that no test can isolate
 * is a check nothing defends, so each rejection is pinned to the message the check itself
 * writes. That is what makes removing one check fail the suite even when a neighbouring check
 * would still reject the same malformed report for a different reason.
 */
function expectIssue(model, fragment) {
  const issues = issuesOfValidate(model);
  assert.notEqual(issues, null, `expected a validation failure mentioning: ${fragment}`);
  assert.equal(
    issues.some((issue) => issue.includes(fragment)),
    true,
    `no issue mentioned "${fragment}"\n  got: ${issues.join("\n  ")}`,
  );
}

describe("production risk report: why each malformed report is refused", () => {
  const base = () => clone(fullModel);
  const firstSectionWithFindings = (model) =>
    model.productionRisk.report.sections.find((entry) => entry.findings.length > 0);

  it("refuses a severity outside the closed vocabulary", () => {
    const model = base();
    firstSectionWithFindings(model).findings[0].severity = "high";
    expectIssue(model, "must be a severity this report declares");
  });

  it("refuses a severity that disagrees with its own kind", () => {
    const model = base();
    const section = firstSectionWithFindings(model);
    const kind = section.findings[0].kind;
    section.findings[0].severity =
      PRODUCTION_RISK_SEVERITY_BY_KIND[kind] === PRODUCTION_RISK_SEVERITIES.LOW
        ? PRODUCTION_RISK_SEVERITIES.INFO
        : PRODUCTION_RISK_SEVERITIES.LOW;
    expectIssue(model, "must be the severity its kind declares");
  });

  it("refuses prose that claims more than the finding's own record renders", () => {
    const statement = base();
    firstSectionWithFindings(statement).findings[0].statement = "The container is insecure.";
    expectIssue(statement, "must be the statement its own record renders");

    const remediation = base();
    firstSectionWithFindings(remediation).findings[0].remediation = "Rewrite the service.";
    expectIssue(remediation, "must be the remediation its own record renders");
  });

  it("refuses a citation the model does not carry, and a finding with none", () => {
    const missing = base();
    firstSectionWithFindings(missing).findings[0].evidenceIds = ["evidence:does-not-exist"];
    expectIssue(missing, "must name observations the model carries");

    const uncited = base();
    firstSectionWithFindings(uncited).findings[0].evidenceIds = [];
    expectIssue(uncited, "must cite at least one observation");
  });

  it("refuses findings that are not sorted by key and unique by id", () => {
    const order = base();
    firstSectionWithFindings(order).findings[0].key = "zzzz-last";
    expectIssue(order, "must be sorted by key and carry each key once");

    const identity = base();
    const finding = firstSectionWithFindings(identity).findings[0];
    finding.id = `${finding.section}:${finding.kind}:somewhere-else`;
    expectIssue(identity, "must be derived from the section, kind and key");
  });

  it("refuses a section title, a section state and an area flag that are not the contract's", () => {
    const title = base();
    title.productionRisk.report.sections[0].title = "Environment";
    expectIssue(title, "must be the declared title of the domain it reports");

    const coverage = base();
    coverage.productionRisk.report.sections[0].coverage.state = PRODUCTION_RISK_STATES.UNKNOWN;
    expectIssue(coverage, "must agree with the section state");

    const flag = base();
    flag.productionRisk.established = !flag.productionRisk.established;
    expectIssue(flag, "must agree with the state it reports");
  });

  it("refuses a domain, a section or a list the report does not carry", () => {
    const dropped = base();
    dropped.productionRisk.report.sections = dropped.productionRisk.report.sections.slice(1);
    expectIssue(dropped, "must carry every audit domain exactly once");

    const reordered = base();
    const swapped = [...reordered.productionRisk.report.sections];
    [swapped[0], swapped[1]] = [swapped[1], swapped[0]];
    reordered.productionRisk.report.sections = swapped;
    expectIssue(reordered, "must be ordered by domain and carry each once");

    const flat = base();
    flat.productionRisk.report.findings = [];
    expectIssue(flat, "must carry every section's findings");

    // The right findings, in the wrong order: the count check cannot see this one.
    const order = base();
    const swapped2 = [...order.productionRisk.report.findings];
    [swapped2[0], swapped2[1]] = [swapped2[1], swapped2[0]];
    order.productionRisk.report.findings = swapped2;
    expectIssue(order, "must be the sections' findings in order");

    const unknown = base();
    unknown.productionRisk.report.unknowns = [];
    expectIssue(unknown, "must be the sections' own abstentions");
  });

  it("refuses an abstention outside the domain's vocabulary", () => {
    const model = base();
    model.productionRisk.report.sections[0].unknown.push({
      reason: "the-environment-looks-wrong",
      detail: null,
      count: 1,
    });
    expectIssue(model, "must be a reason this domain declares");
  });

  it("refuses an unsupported domain that names no uninterpreted basis", () => {
    const model = base();
    const section = model.productionRisk.report.sections.find((entry) => entry.name === "api");
    section.state = PRODUCTION_RISK_STATES.UNSUPPORTED;
    section.established = false;
    section.coverage.state = PRODUCTION_RISK_STATES.UNSUPPORTED;
    section.coverage.established = false;
    section.unknown = [];
    expectIssue(model, "cannot be unsupported without naming the unread domain");
  });

  it("refuses counts and coverage that do not count what the section carries", () => {
    const counts = base();
    counts.productionRisk.report.sections[0].counts.findings += 1;
    expectIssue(counts, "must count the findings the section carries");

    const severities = base();
    severities.productionRisk.report.coverage.severities.medium += 1;
    expectIssue(severities, "must census the findings the report carries");

    const total = base();
    total.productionRisk.report.coverage.findings += 1;
    expectIssue(total, "must count every finding");
  });

  it("refuses a section carrying more findings than the report's own bound", () => {
    const model = base();
    const section = model.productionRisk.report.sections.find(
      (entry) => entry.findings.length > 0,
    );
    const seed = section.findings[0];
    section.findings = Array.from(
      { length: PRODUCTION_RISK_REPORT_LIMITS.maxFindingsPerSection + 1 },
      (_, index) => {
        const key = `key-${String(index).padStart(3, "0")}`;
        return { ...seed, key, id: `${section.name}:${seed.kind}:${key}` };
      },
    );
    expectIssue(model, "must stay within the report's finding bound");
  });

  it("answers every domain with an abstention when the model carries no report at all", () => {
    const report = buildProductionRiskReport({ report: null, evidence: [] });
    assert.equal(report.established, false);
    assert.equal(report.state, PRODUCTION_RISK_STATES.UNKNOWN);
    assert.equal(report.coverage.findings, 0);
    for (const section of report.sections) {
      assert.deepEqual(section.findings, [], section.name);
      assert.equal(section.state, PRODUCTION_RISK_STATES.UNKNOWN, section.name);
      assert.equal(section.established, false, section.name);
      assert.equal(
        section.unknown.some((record) => record.reason === "production-report-not-established"),
        true,
        section.name,
      );
    }
  });

  it("refuses a rule set with a rule outside the namespace, not only a missing one", () => {
    const foreign = [
      ...productionRiskRules,
      { ...productionRiskRules[0], id: "production.inventory" },
    ];
    assert.equal(
      productionRiskRuleSetIssues(foreign).some((issue) => issue.includes("namespace")),
      true,
    );
    assert.throws(() => createProductionRiskRuleRegistry({ rules: foreign }), (error) => {
      assert.equal(error.name, "RuleRegistrationError");
      return true;
    });
  });
});

// ─── Architectural direction ─────────────────────────────────────────────────

describe("production risk boundaries", () => {
  it("reads nothing outside the model, the analysis and the rules layers", () => {
    const directory = join(HERE, "..", "src", "rules", "production", "risk");
    const files = [
      "analyzer.js",
      "contracts.js",
      "index.js",
      "registry.js",
      "signals.js",
      join("rules", "audit.js"),
      join("rules", "index.js"),
    ];
    for (const file of files) {
      const text = readFileSync(join(directory, file), "utf8");
      for (const match of text.matchAll(/from\s+"([^"]+)"/g)) {
        const specifier = match[1];
        const allowed =
          specifier.startsWith("./") ||
          specifier.startsWith("../") ||
          specifier === "../../../repository/model/index.js" ||
          specifier === "../../../contracts.js" ||
          specifier === "../../../evaluation.js" ||
          specifier === "../../../../core/index.js";
        assert.ok(allowed, `${file} imports "${specifier}"`);
      }
      for (const forbidden of [
        "node:fs",
        "node:path",
        "node:child_process",
        "node:net",
        "node:http",
        "node:https",
        "node:dns",
        "node:worker_threads",
        "child_process",
        "node:os",
        "process",
      ]) {
        assert.equal(text.includes(`"${forbidden}"`), false, `${file} touches ${forbidden}`);
      }
      // Nothing in the pack reads the raw model area or a source file.
      assert.equal(text.includes("model.productionRisk"), false, file);
      assert.equal(text.includes("readFile"), false, file);
    }
  });

  it("projects the report in the model layer without reading a file", () => {
    const source = readFileSync(
      join(HERE, "..", "src", "repository", "model", "production-risk-report.js"),
      "utf8",
    );
    for (const forbidden of [
      "node:fs",
      "node:path",
      "node:child_process",
      "node:net",
      "node:http",
      "node:https",
      "node:dns",
      "node:worker_threads",
    ]) {
      assert.equal(source.includes(`"${forbidden}"`), false, forbidden);
    }
    // No score, grade, percentage or traffic light is computed anywhere in the projection.
    for (const word of ["score", "grade", "percent", "rating", "trafficLight"]) {
      assert.equal(
        new RegExp(`${word}\\s*[:=]`, "i").test(source),
        false,
        `the projection computes a ${word}`,
      );
    }
  });

  it("states a gap in prose that never claims a runtime fact", () => {
    for (const name of PRODUCTION_RISK_SECTIONS) {
      for (const kind of PRODUCTION_RISK_FINDING_KINDS[name]) {
        assert.equal(typeof PRODUCTION_RISK_FINDING_WORDING[kind], "string", kind);
        assert.equal(PRODUCTION_RISK_FINDING_WORDING[kind].length > 8, true, kind);
      }
    }
    // Every sentence the report renders is about what the repository states or what this
    // build could not establish — never about how dangerous the gap is.
    for (const section of fullRisk.sections) {
      for (const finding of section.findings) {
        assert.equal(
          /insecure|vulnerab|weak|critical|attack|danger|exploit|CVE|unsafe/i.test(
            finding.statement,
          ),
          false,
          finding.kind,
        );
        if (finding.remediation !== null) {
          assert.equal(
            /insecure|vulnerab|attack|danger|CVE|must not/i.test(finding.remediation),
            false,
            finding.kind,
          );
        }
      }
    }
  });
});
