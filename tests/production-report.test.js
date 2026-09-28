/**
 * Code Guardian — Production Report Tests (Phase 20)
 *
 * Three fixture styles, chosen deliberately:
 *
 *   - **real repositories** written to a temporary directory and scanned through the accepted
 *     Phase 8A boundary, Phase 8C scanner, Phase 8D model builder and Phase 20 projection, so
 *     acquisition, model and report agree end to end. This is the only way to prove that what
 *     a repository literally states is what the report exposes.
 *   - **hand-built scan results** for facts a tiny repository cannot reach on demand — an
 *     incomplete scan, an unreadable source, a bounded list — so the report's abstention
 *     behaviour is stated exactly rather than inferred.
 *   - **mutation-style tampering** inside the model's own production area, because the point
 *     of the contract is that a malformed report is a validation failure instead of becoming
 *     a finding.
 *
 * The suite's central claims are the phase's central requirements: every observation cites
 * evidence the model actually carries, a section the report could not establish abstains
 * instead of passing, an unknown input is never converted into a pass, and there is no score,
 * grade, readiness percentage or traffic light anywhere in the report or in the rules that
 * consume it.
 *
 * No test starts a container, sends a request, spawns a process, contacts a network,
 * installs a package, reads a vulnerability database or writes to the repository under test.
 *
 * Run with: node --test tests/production-report.test.js
 */

import { after, describe, it } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { ValidationError } from "../src/core/index.js";

import {
  DOCKERFILE_DETAILS,
  DOCKERFILE_INSPECTION_LIMITS,
  DOCKERFILE_RULES,
  DOCKERFILE_SIGNAL,
  DOCKERFILE_UNPARSED_REASONS,
  createScanResult,
  parseDockerfileStructure,
  scanRepository,
  validateScanResult,
} from "../src/repository/scanner/index.js";

import {
  CONTAINER_SIGNALS,
  DOCKERFILE_STRUCTURE_REASONS,
  EVIDENCE_SUBJECTS,
  PRODUCTION_ENTRYPOINT_DIRECTORIES,
  PRODUCTION_ENTRYPOINT_NAMES,
  PRODUCTION_OBSERVATION_KINDS,
  PRODUCTION_REPORT_LIMITS,
  PRODUCTION_REPORT_STATES,
  PRODUCTION_REPORT_STATE_VALUES,
  PRODUCTION_REPORT_VERSION,
  PRODUCTION_SECTIONS,
  PRODUCTION_SECTION_TITLES,
  PRODUCTION_UNKNOWN_REASONS,
  buildRepositoryModel,
  classifyEnvironmentArtifact,
  classifyWorkflowName,
  createRepositoryQuery,
  isEntrypointShapedPath,
  isEstablishedProductionState,
  validateRepositoryModelGraph,
} from "../src/repository/model/index.js";

import {
  buildAnalysisContext,
  createAnalyzerEngine,
  createAnalyzerRegistry,
} from "../src/analysis/index.js";

import {
  RULE_OUTCOME_STATUSES,
  createRuleEngine,
} from "../src/rules/index.js";

import {
  MAX_PRODUCTION_FINDINGS,
  PRODUCTION_ABSTENTION_WORDING,
  PRODUCTION_ANALYZER_ID,
  PRODUCTION_ANALYZER_NAME,
  PRODUCTION_ANALYZER_SCOPE,
  PRODUCTION_BASIS,
  PRODUCTION_CATEGORY,
  PRODUCTION_CONFIDENCE,
  PRODUCTION_RULE_ID_PREFIX,
  PRODUCTION_RULE_PACK_VERSION,
  PRODUCTION_DESCRIBED_ABSTENTIONS,
  PRODUCTION_DESCRIBED_OBSERVATIONS,
  PRODUCTION_DESCRIBED_SECTIONS,
  PRODUCTION_DESCRIBED_STATES,
  PRODUCTION_OBSERVATION_WORDING,
  PRODUCTION_RULE_IDS,
  PRODUCTION_SECTION_WORDING,
  PRODUCTION_STATE_WORDING,
  createProductionAnalyzer,
  createProductionRuleRegistry,
  productionAbsence,
  productionCoverage,
  productionRules,
  productionRuleSetIssues,
  productionSection,
  productionSections,
} from "../src/rules/production/index.js";

import { APPLICABILITY_COVERAGE } from "../src/rules/contracts.js";

// ─── Fixtures ────────────────────────────────────────────────────────────────

const HERE = dirname(fileURLToPath(import.meta.url));
const TMP = mkdtempSync(join(tmpdir(), "cg-production-"));
after(() => rmSync(TMP, { recursive: true, force: true }));

let repositories = 0;

/**
 * Write a repository and scan it end to end.
 *
 * @param {Record<string, string>} files Repository-relative path → contents.
 * @returns {Promise<object>} The scan, model, query handle and analysis context.
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
  };
}

/** A minimal `package.json`. */
const pkg = (fields = {}) =>
  JSON.stringify({ name: "demo", version: "1.0.0", ...fields }, null, 2);

/** An npm v3 lockfile resolving the given `node_modules/<name>` entries. */
const npmLock = (entries = {}) =>
  JSON.stringify({ name: "demo", lockfileVersion: 3, packages: { "": { name: "demo" }, ...entries } }, null, 2);

/** A GitHub Actions workflow body. */
const workflow = (name) =>
  `name: ${name}\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ${name}\n`;

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

// ─── A rich repository used by several suites ────────────────────────────────

const FULL_REPO = {
  ".gitignore": ".env\n",
  ".env": "DEMO_SECRET=not-inspected\n",
  ".env.example": "PORT=3000\n",
  ".env.template": "PORT=\n",
  ".env.sample": "PORT=3000\n",
  "config.json.sample": "{}\n",
  "package.json": pkg({
    main: "main.js",
    dependencies: { express: "^4.18.0" },
    devDependencies: { jest: "^29.0.0" },
  }),
  "package-lock.json": npmLock({ "node_modules/express": { version: "4.18.2" } }),
  ".dockerignore": "node_modules\n",
  Dockerfile: [
    "FROM node:20 AS build",
    "RUN npm ci",
    "FROM node:20-slim",
    "HEALTHCHECK --interval=30s CMD node healthcheck.js",
    'CMD ["node", "main.js"]',
    "",
  ].join("\n"),
  "Dockerfile.dev": ["FROM node:20", "HEALTHCHECK NONE", ""].join("\n"),
  // The `api` service builds from a nested context, so one build-context observation carries
  // a repository-relative context (`src`) and the other the root (`null`).
  "src/Dockerfile.api": "FROM node:20-alpine\n",
  "docker-compose.yml": ["services:", "  web:", "    build: .", "  api:", "    build:", "      context: ./src", "      dockerfile: Dockerfile.api", ""].join("\n"),
  ".github/workflows/test.yml": workflow("test"),
  ".github/workflows/release.yml": workflow("release"),
  ".github/workflows/lint.yml": workflow("lint"),
  ".github/workflows/ci.yml": workflow("ci"),
  "main.js": [
    'import express from "express";',
    'import { listUsers, requireAuth } from "./src/users.js";',
    "const app = express();",
    'app.get("/users", requireAuth, listUsers);',
    'cache.get("/not-a-route");',
    "export default app;",
    "",
  ].join("\n"),
  "src/users.js": [
    "export function listUsers() {}",
    "export function requireAuth(req, res, next) { next(); }",
    "",
  ].join("\n"),
  "src/isolated.js": "export const lonely = 1;\n",
  "bin/cli.js": "#!/usr/bin/env node\nconsole.log('hi');\n",
};

const { model: fullModel, query: fullQuery, report: fullReport } = await scanOf(FULL_REPO);

// ─── Scanner policy: Dockerfile structure ───────────────────────────────────

describe("production: Dockerfile structure acquisition", () => {
  it("shares its Dockerfile table with the configuration detector's signal", () => {
    assert.deepEqual(
      DOCKERFILE_RULES.map((rule) => rule.signal),
      [DOCKERFILE_SIGNAL, DOCKERFILE_SIGNAL],
    );
    assert.equal(DOCKERFILE_SIGNAL, "dockerfile");
  });

  it("reads build stages, named stages and a healthcheck", () => {
    const parsed = parseDockerfileStructure(
      [
        "# a comment",
        "FROM node:20 AS build",
        "RUN npm ci \\",
        "    && npm test",
        "FROM node:20-slim as runtime",
        "HEALTHCHECK --interval=30s CMD node hc.js",
        'CMD ["node", "main.js"]',
        "",
      ].join("\n"),
    );
    assert.equal(parsed.ok, true);
    assert.equal(parsed.stages, 2);
    assert.equal(parsed.multiStage, true);
    assert.deepEqual(parsed.stageNames, ["build", "runtime"]);
    assert.equal(parsed.healthcheck, true);
    assert.equal(parsed.healthcheckDisabled, false);
    // `RUN` and `CMD` are counted, never interpreted: their arguments never leave the reader.
    assert.equal(parsed.instructions, 5);
  });

  it("reads a disabled healthcheck as disabled, not as absent", () => {
    const parsed = parseDockerfileStructure("FROM alpine\nHEALTHCHECK NONE\n");
    assert.equal(parsed.ok, true);
    assert.equal(parsed.healthcheck, false);
    assert.equal(parsed.healthcheckDisabled, true);
  });

  it("reports a single-stage build as not multi-stage", () => {
    const parsed = parseDockerfileStructure("FROM alpine\nRUN echo hi\n");
    assert.equal(parsed.stages, 1);
    assert.equal(parsed.multiStage, false);
    assert.deepEqual(parsed.stageNames, []);
  });

  it("refuses a binary body, an unrecognised line, and each bound it can cross", () => {
    const binary = parseDockerfileStructure("FROM alpine\u0000");
    assert.equal(binary.ok, false);
    assert.equal(binary.reason, DOCKERFILE_UNPARSED_REASONS.NOT_TEXT);

    const line = parseDockerfileStructure("!!! not an instruction\n");
    assert.equal(line.ok, false);
    assert.equal(line.reason, DOCKERFILE_UNPARSED_REASONS.UNSUPPORTED_SYNTAX);
    assert.equal(line.detail, DOCKERFILE_DETAILS.UNRECOGNIZED_LINE);

    const longLine = parseDockerfileStructure(
      `RUN ${"a".repeat(DOCKERFILE_INSPECTION_LIMITS.maxLineBytes + 1)}`,
    );
    assert.equal(longLine.ok, false);
    assert.equal(longLine.reason, DOCKERFILE_UNPARSED_REASONS.TOO_LARGE);
    assert.equal(longLine.detail, DOCKERFILE_DETAILS.LINE_LIMIT);

    const many = parseDockerfileStructure(
      Array.from(
        { length: DOCKERFILE_INSPECTION_LIMITS.maxInstructions + 1 },
        () => "RUN echo hi",
      ).join("\n"),
    );
    assert.equal(many.ok, false);
    assert.equal(many.detail, DOCKERFILE_DETAILS.INSTRUCTION_LIMIT);

    const stages = parseDockerfileStructure(
      Array.from({ length: DOCKERFILE_INSPECTION_LIMITS.maxStages + 1 }, () => "FROM alpine").join(
        "\n",
      ),
    );
    assert.equal(stages.ok, false);
    assert.equal(stages.detail, DOCKERFILE_DETAILS.STAGE_LIMIT);
  });

  it("pins the model's refusal vocabulary to the acquisition layer's", () => {
    assert.deepEqual(
      [...DOCKERFILE_STRUCTURE_REASONS].sort(),
      Object.values(DOCKERFILE_UNPARSED_REASONS).sort(),
    );
  });

  it("records one structure observation per observed Dockerfile", () => {
    const structures = fullModel.evidence.filter(
      (record) => record.data.signal === CONTAINER_SIGNALS.DOCKERFILE,
    );
    assert.deepEqual(
      structures.map((record) => record.location.path).sort(),
      ["Dockerfile", "Dockerfile.dev", "src/Dockerfile.api"],
    );
    const main = structures.find((record) => record.location.path === "Dockerfile");
    assert.equal(main.data.stages, 2);
    assert.equal(main.data.healthcheck, true);
    const dev = structures.find((record) => record.location.path === "Dockerfile.dev");
    assert.equal(dev.data.healthcheckDisabled, true);
    assert.equal(dev.data.multiStage, false);
    // Every observed Dockerfile is read, including one no composition file declares: a
    // container definition's structure does not depend on anything declaring it used.
    const nested = structures.find((record) => record.location.path === "src/Dockerfile.api");
    assert.equal(nested.data.multiStage, false);
  });

  it("records a refusal, with its bounded reason, for a body it cannot read", async () => {
    const { model } = await scanOf({ "package.json": pkg(), Dockerfile: "FROM alpine\u0000\n" });
    const record = model.evidence.find(
      (entry) => entry.data.signal === CONTAINER_SIGNALS.DOCKERFILE_UNPARSED,
    );
    assert.equal(record.location.path, "Dockerfile");
    assert.equal(record.data.reason, DOCKERFILE_UNPARSED_REASONS.NOT_TEXT);
  });
});

// ─── Environment configuration ───────────────────────────────────────────────

describe("production: environment configuration", () => {
  const kindsOf = (report) =>
    sectionOf(report, "environment").observations.map((entry) => entry.kind);

  it("records an example file", async () => {
    const { report } = await scanOf({ "package.json": pkg(), ".env.example": "PORT=3000\n" });
    assert.equal(sectionOf(report, "environment").counts.examples, 1);
    assert.deepEqual(kindsOf(report), ["environment-example"]);
  });

  it("records a template file", async () => {
    const { report } = await scanOf({ "package.json": pkg(), ".env.template": "PORT=\n" });
    assert.equal(sectionOf(report, "environment").counts.templates, 1);
    assert.deepEqual(kindsOf(report), ["environment-template"]);
  });

  it("records both an example and a template without duplicating either", async () => {
    const { report } = await scanOf({
      "package.json": pkg(),
      ".env.example": "A=1\n",
      ".env.template": "A=\n",
    });
    const section = sectionOf(report, "environment");
    assert.equal(section.counts.examples, 1);
    assert.equal(section.counts.templates, 1);
    assert.equal(section.counts.duplicatedClasses, 0);
    assert.deepEqual(section.observations.map((entry) => entry.kind).sort(), [
      "environment-example",
      "environment-template",
    ]);
  });

  it("records a duplicated template class, citing every file in it", async () => {
    const { report } = await scanOf({
      "package.json": pkg(),
      ".env.example": "A=1\n",
      ".env.sample": "A=2\n",
    });
    const section = sectionOf(report, "environment");
    assert.equal(section.counts.duplicatedClasses, 1);
    const duplicate = section.observations.find(
      (entry) => entry.kind === "environment-template-duplicate",
    );
    assert.equal(duplicate.class, "environment-example");
    assert.equal(duplicate.count, 2);
    assert.deepEqual(duplicate.paths, [".env.example", ".env.sample"]);
    assert.equal(duplicate.evidenceIds.length >= 2, true);
  });

  it("records a sample configuration file and a live environment file", async () => {
    const sample = await scanOf({ "package.json": pkg(), "config.yaml.sample": "{}\n" });
    assert.equal(sectionOf(sample.report, "environment").counts.sampleConfigurations, 1);
    assert.deepEqual(sample.report.sections[0].observations[0].kind, "sample-configuration");

    const literal = await scanOf({ "package.json": pkg(), ".env.production": "A=1\n" });
    assert.equal(sectionOf(literal.report, "environment").counts.environmentFiles, 1);
    assert.deepEqual(literal.report.sections[0].observations[0].kind, "environment-file");
  });

  it("never claims an environment file's values, and always says so", async () => {
    const section = sectionOf(fullReport, "environment");
    const abstention = section.unknown.find(
      (record) => record.reason === "secret-values-not-inspected",
    );
    assert.deepEqual(abstention, {
      reason: "secret-values-not-inspected",
      detail: null,
      count: 1,
    });
    for (const observation of section.observations) {
      assert.equal(observation.basis, "file-name");
    }
  });

  it("abstains when an ignore policy excludes an environment-shaped path", async () => {
    const section = sectionOf(fullReport, "environment");
    assert.equal(section.coverage.state, PRODUCTION_REPORT_STATES.PARTIAL);
    assert.equal(section.counts.ignoredEnvironmentPaths, 1);
    assert.equal(
      section.unknown.some((record) => record.reason === "environment-configuration-ignored"),
      true,
    );
    // The excluded `.env` is reported as a gap, never as an observed or absent file.
    assert.equal(
      section.observations.some((entry) => entry.path === ".env"),
      false,
    );
  });

  it("abstains when the scan did not cover the repository", () => {
    const model = buildRepositoryModel(literalScan(["package.json"], { complete: false }));
    const section = sectionOf(model.production.report, "environment");
    assert.equal(section.state, PRODUCTION_REPORT_STATES.UNKNOWN);
    assert.equal(section.established, false);
    assert.equal(
      section.unknown.some((record) => record.reason === "environment-configuration-not-observed"),
      true,
    );
  });

  it("classifies artifacts by name, never by content", () => {
    assert.equal(classifyEnvironmentArtifact(".env.example"), "environment-example");
    assert.equal(classifyEnvironmentArtifact(".env.template"), "environment-template");
    assert.equal(classifyEnvironmentArtifact(".env.dist"), "environment-template");
    assert.equal(classifyEnvironmentArtifact(".env"), "environment-file");
    assert.equal(classifyEnvironmentArtifact(".env.production"), "environment-file");
    assert.equal(classifyEnvironmentArtifact("config.json.sample"), "sample-configuration");
    assert.equal(classifyEnvironmentArtifact("src/main.js"), null);
  });
});

// ─── Container configuration ────────────────────────────────────────────────

describe("production: container readiness", () => {
  it("records a container definition, an ignore file and a composition file", async () => {
    const { report } = await scanOf({
      "package.json": pkg(),
      Dockerfile: "FROM alpine\n",
      ".dockerignore": "node_modules\n",
      "docker-compose.yml": "services:\n  web:\n    build: .\n",
    });
    const section = sectionOf(report, "container");
    assert.equal(section.counts.definitions, 1);
    assert.equal(section.counts.ignores, 1);
    assert.equal(section.counts.compositions, 1);
    assert.equal(section.counts.structures, 1);
    assert.equal(section.counts.buildContexts, 1);
    assert.equal(section.state, PRODUCTION_REPORT_STATES.COMPLETE);
  });

  it("records a declared healthcheck, a disabled one, and a multi-stage build", () => {
    const section = sectionOf(fullReport, "container");
    assert.equal(section.counts.healthchecks, 1);
    assert.equal(section.counts.healthcheckDisabled, 1);
    assert.equal(section.counts.multiStageDefinitions, 1);
    assert.equal(section.counts.stages, 4);
    assert.deepEqual(
      section.observations
        .filter((entry) => entry.kind.startsWith("container-") && entry.kind !== "container-structure")
        .map((entry) => entry.kind)
        .filter((kind) => kind !== "container-definition")
        .sort(),
      [
        "container-build-context",
        "container-build-context",
        "container-composition",
        "container-healthcheck",
        "container-healthcheck-disabled",
        "container-ignore",
        "container-multi-stage",
      ],
    );
  });

  it("reports a definition's structure without interpreting its instructions", () => {
    const structure = sectionOf(fullReport, "container").observations.find(
      (entry) => entry.kind === "container-structure" && entry.path === "Dockerfile",
    );
    assert.equal(structure.stages, 2);
    assert.deepEqual(structure.stageNames, ["build"]);
    assert.equal(structure.healthcheck, true);
    assert.equal(structure.basis, "dockerfile-instructions");
    // No instruction text, no base image and no command is carried anywhere in the report.
    const json = JSON.stringify(fullReport);
    assert.equal(json.includes("npm ci"), false);
    assert.equal(json.includes("node:20"), false);
    assert.equal(json.includes("DEMO_SECRET"), false);
  });

  it("records each composition build context in full", () => {
    const contexts = sectionOf(fullReport, "container").observations.filter(
      (entry) => entry.kind === "container-build-context",
    );
    assert.deepEqual(
      contexts.map((entry) => [entry.source, entry.service, entry.path, entry.context]).sort(),
      [
        ["docker-compose.yml", "api", "src/Dockerfile.api", "src"],
        ["docker-compose.yml", "web", "Dockerfile", null],
      ],
    );
  });

  it("abstains when a Dockerfile's instructions could not be read", async () => {
    const { report } = await scanOf({ "package.json": pkg(), Dockerfile: "FROM alpine\u0000\n" });
    const section = sectionOf(report, "container");
    assert.equal(section.counts.definitions, 1);
    assert.equal(section.counts.structures, 0);
    assert.equal(section.coverage.state, PRODUCTION_REPORT_STATES.PARTIAL);
    assert.equal(
      section.unknown.some(
        (record) =>
          record.reason === "dockerfile-structure-not-established" &&
          record.detail === "Dockerfile",
      ),
      true,
    );
  });

  it("abstains when a composition file's build declarations are not established", async () => {
    const { report } = await scanOf({
      "package.json": pkg(),
      "docker-compose.yml": "services:\n\tweb:\n\t\tbuild: .\n",
    });
    const section = sectionOf(report, "container");
    assert.equal(section.counts.compositions, 1);
    assert.equal(
      section.unknown.some(
        (record) => record.reason === "compose-build-declarations-not-established",
      ),
      true,
    );
    assert.equal(section.coverage.state, PRODUCTION_REPORT_STATES.PARTIAL);
  });

  it("reports an inspected repository with no container configuration as complete", async () => {
    const { report } = await scanOf({ "package.json": pkg(), "main.js": "export default 1;\n" });
    const section = sectionOf(report, "container");
    // An inspected, empty domain is an answer — "this repository declares no container
    // configuration" — so it is `complete`. `unsupported` would claim this build cannot read
    // the domain, which is a different and false statement.
    assert.equal(section.state, PRODUCTION_REPORT_STATES.COMPLETE);
    assert.equal(section.established, true);
    assert.equal(section.coverage.truncated, false);
    assert.deepEqual(section.observations, []);
    assert.equal(section.counts.definitions, 0);
    assert.equal(
      section.unknown.some((record) => record.reason === "no-container-configuration-observed"),
      true,
    );
  });
});

// ─── CI configuration ───────────────────────────────────────────────────────

describe("production: CI readiness", () => {
  const ciOf = (report) => sectionOf(report, "ci");

  it("records a single workflow", async () => {
    const { report } = await scanOf({
      "package.json": pkg(),
      ".github/workflows/test.yml": workflow("test"),
    });
    const section = ciOf(report);
    assert.equal(section.counts.workflows, 1);
    assert.equal(section.counts.providers, 1);
    assert.equal(section.counts.githubActionsWorkflows, 1);
    assert.equal(section.counts.purposes.test, 1);
    const observation = section.observations.find((entry) => entry.kind === "ci-workflow");
    assert.equal(observation.purpose, "test");
    assert.equal(observation.basis, "workflow-name");
  });

  it("records multiple workflows and their name-derived purposes", () => {
    const section = ciOf(fullReport);
    assert.equal(section.counts.workflows, 4);
    assert.equal(section.counts.githubActionsWorkflows, 4);
    assert.deepEqual(section.counts.purposes, {
      release: 1,
      lint: 1,
      test: 1,
      unclassified: 1,
    });
  });

  it("records a release workflow and a lint workflow separately from a test workflow", () => {
    const purposes = ciOf(fullReport).observations
      .filter((entry) => entry.kind === "ci-workflow")
      .map((entry) => [entry.name, entry.purpose]);
    assert.deepEqual(purposes.sort(), [
      ["ci.yml", "unclassified"],
      ["lint.yml", "lint"],
      ["release.yml", "release"],
      ["test.yml", "test"],
    ]);
  });

  it("never claims what a workflow does, and says that it read no workflow body", () => {
    const section = ciOf(fullReport);
    assert.equal(
      section.unknown.some(
        (record) => record.reason === "workflow-content-not-inspected" && record.count === 4,
      ),
      true,
    );
    assert.equal(
      section.unknown.some(
        (record) => record.reason === "workflow-purpose-not-established" && record.count === 1,
      ),
      true,
    );
    // `ci.yml` is unclassified on purpose: its name does not establish that tests run.
    assert.equal(classifyWorkflowName("ci.yml"), "unclassified");
    assert.equal(classifyWorkflowName("unit-tests.yaml"), "test");
    assert.equal(classifyWorkflowName("publish-package.yml"), "release");
    assert.equal(classifyWorkflowName("eslint.yml"), "lint");
  });

  it("abstains when the scan did not cover the repository", () => {
    const model = buildRepositoryModel(literalScan(["package.json"], { complete: false }));
    const section = ciOf(model.production.report);
    assert.equal(section.state, PRODUCTION_REPORT_STATES.UNKNOWN);
    assert.equal(
      section.unknown.some((record) => record.reason === "ci-configuration-not-observed"),
      true,
    );
  });

  it("reports an inspected repository with no CI configuration as complete", async () => {
    const { report } = await scanOf({ "package.json": pkg(), "main.js": "export default 1;\n" });
    const section = ciOf(report);
    assert.equal(section.state, PRODUCTION_REPORT_STATES.COMPLETE);
    assert.equal(section.established, true);
    assert.deepEqual(section.observations, []);
    assert.equal(
      section.unknown.some((record) => record.reason === "no-ci-configuration-observed"),
      true,
    );
  });
});

// ─── API exposure inventory ──────────────────────────────────────────────────

describe("production: API exposure inventory", () => {
  const apiRepo = {
    "package.json": pkg(),
    "src/app.js": [
      'import express from "express";',
      'import { listUsers, requireAuth } from "./users.js";',
      "const app = express();",
      'app.get("/users", listUsers);',
      'app.post("/users", requireAuth, listUsers);',
      'cache.get("/not-a-route");',
      "export default app;",
      "",
    ].join("\n"),
    "src/users.js": [
      "export function listUsers() {}",
      "export function requireAuth(req, res, next) { next(); }",
      "",
    ].join("\n"),
  };

  it("generates a route inventory with handlers, methods and middleware", async () => {
    const { report } = await scanOf(apiRepo);
    const section = sectionOf(report, "api");
    const routes = section.observations.filter((entry) => entry.kind === "api-route");
    assert.deepEqual(
      routes.map((entry) => [entry.method, entry.path]).sort(),
      [
        ["GET", "/users"],
        ["POST", "/users"],
      ],
    );
    assert.deepEqual(section.counts.methods, { GET: 1, POST: 1 });
    assert.equal(section.counts.handlers, 2);
    assert.equal(section.counts.handlerModules, 1);
    assert.equal(section.counts.routesWithoutHandler, 0);
  });

  it("summarises middleware structurally, never as a protection verdict", async () => {
    const { report } = await scanOf(apiRepo);
    const section = sectionOf(report, "api");
    assert.equal(section.counts.middlewareReferences, 1);
    assert.equal(section.counts.middlewareApplied, 1);
    assert.equal(section.counts.middlewareNodes, 1);
    assert.equal(section.counts.protectedRoutes, 1);
    assert.equal(section.counts.unprotectedRoutes, 1);
    const post = section.observations.find(
      (entry) => entry.kind === "api-route" && entry.method === "POST",
    );
    assert.equal(post.protection, "protected");
    const get = section.observations.find(
      (entry) => entry.kind === "api-route" && entry.method === "GET",
    );
    assert.equal(get.protection, "none-observed");
  });

  it("reports a route-shaped occurrence that was not established as an endpoint", async () => {
    const { report } = await scanOf(apiRepo);
    const section = sectionOf(report, "api");
    assert.equal(section.counts.routes, 2);
    assert.equal(section.counts.unresolvedRouteOccurrences >= 1, true);
    assert.equal(
      section.unknown.some((record) => record.reason === "route-occurrence-not-established"),
      true,
    );
    // `cache.get("/not-a-route")` is never presented as an endpoint.
    assert.equal(
      section.observations.some((entry) => entry.path === "/not-a-route"),
      false,
    );
  });

  it("records the resolved handler of each route", async () => {
    const { report } = await scanOf(apiRepo);
    const handlers = sectionOf(report, "api").observations.filter(
      (entry) => entry.kind === "api-handler",
    );
    assert.deepEqual(handlers.map((entry) => entry.name).sort(), ["listUsers", "listUsers"]);
    assert.equal(handlers.every((entry) => entry.basis === "static-handler-resolution"), true);
  });

  it("abstains when no API graph was established", () => {
    const model = buildRepositoryModel(literalScan(["package.json"], { complete: false }));
    const section = sectionOf(model.production.report, "api");
    assert.equal(section.state, PRODUCTION_REPORT_STATES.UNKNOWN);
    assert.equal(
      section.unknown.some((record) => record.reason === "api-graph-not-established"),
      true,
    );
  });
});

// ─── Dependency inventory ────────────────────────────────────────────────────

describe("production: dependency inventory", () => {
  it("summarises an npm ecosystem and its scopes", async () => {
    const { report } = await scanOf({
      "package.json": pkg({ dependencies: { express: "^4.18.0" }, devDependencies: { jest: "^29.0.0" } }),
    });
    const section = sectionOf(report, "dependencies");
    assert.equal(section.counts.ecosystems, 1);
    assert.equal(section.counts.dependencies, 2);
    assert.equal(section.counts.runtime, 1);
    assert.equal(section.counts.development, 1);
    const ecosystem = section.observations.find(
      (entry) => entry.kind === "dependency-ecosystem",
    );
    assert.deepEqual(
      [ecosystem.ecosystem, ecosystem.runtime, ecosystem.development],
      ["node", 1, 1],
    );
  });

  it("records a lockfile that resolved something", async () => {
    const { report } = await scanOf({
      "package.json": pkg({ dependencies: { express: "^4.18.0" } }),
      "package-lock.json": npmLock({ "node_modules/express": { version: "4.18.2" } }),
    });
    const section = sectionOf(report, "dependencies");
    assert.equal(section.counts.lockfiles, 1);
    assert.equal(section.counts.resolvedLockfiles, 1);
    const lockfile = section.observations.find((entry) => entry.kind === "dependency-lockfile");
    assert.equal(lockfile.path, "package-lock.json");
    assert.equal(lockfile.resolved >= 1, true);
  });

  it("reports a lockfile that resolves nothing as present, not as absent", async () => {
    const { report } = await scanOf({
      "package.json": pkg({ dependencies: { express: "^4.18.0" } }),
      "package-lock.json": npmLock(),
    });
    const section = sectionOf(report, "dependencies");
    assert.equal(section.counts.lockfiles, 1);
    assert.equal(section.counts.resolvedLockfiles, 0);
    const manifest = section.observations.find(
      (entry) => entry.kind === "dependency-manifest" && entry.path === "package-lock.json",
    );
    assert.equal(manifest.role, "lockfile");
  });

  it("reports pnpm and yarn lockfiles by presence, and abstains when one is unreadable", async () => {
    const pnpm = await scanOf({
      "package.json": pkg({ dependencies: { express: "^4.18.0" } }),
      "pnpm-lock.yaml": "lockfileVersion: '6.0'\n",
    });
    assert.equal(sectionOf(pnpm.report, "dependencies").counts.lockfiles, 1);
    assert.equal(
      sectionOf(pnpm.report, "dependencies").observations.some(
        (entry) => entry.kind === "dependency-manifest" && entry.role === "lockfile",
      ),
      true,
    );

    const yarn = await scanOf({
      "package.json": pkg({ dependencies: { express: "^4.18.0" } }),
      "yarn.lock": 'express@^4.18.0:\n  version "4.18.2"\n',
    });
    const section = sectionOf(yarn.report, "dependencies");
    assert.equal(section.counts.lockfiles, 1);
    assert.equal(
      section.unknown.some((record) => record.reason === "dependency-source-not-established"),
      true,
    );
  });

  it("reports a mixed repository as two ecosystems", async () => {
    const { report } = await scanOf({
      "package.json": pkg({ dependencies: { express: "^4.18.0" } }),
      "pyproject.toml": '[project]\nname = "demo"\ndependencies = ["requests>=2"]\n',
    });
    const section = sectionOf(report, "dependencies");
    assert.equal(section.counts.ecosystems, 2);
    assert.deepEqual(
      section.observations
        .filter((entry) => entry.kind === "dependency-ecosystem")
        .map((entry) => entry.ecosystem)
        .sort(),
      ["node", "python"],
    );
  });

  it("performs no vulnerability, currency or licence analysis", () => {
    const section = sectionOf(fullReport, "dependencies");
    assert.equal(section.coverage.state, PRODUCTION_REPORT_STATES.COMPLETE);
    const json = JSON.stringify(section).toLowerCase();
    for (const forbidden of ["cve", "vulnerab", "advisory", "license", "outdated", "severity"]) {
      assert.equal(json.includes(forbidden), false, forbidden);
    }
  });

  it("abstains when no dependency graph was established", () => {
    const model = buildRepositoryModel(literalScan(["package.json"], { complete: false }));
    const section = sectionOf(model.production.report, "dependencies");
    assert.equal(section.state, PRODUCTION_REPORT_STATES.UNKNOWN);
    assert.equal(
      section.unknown.some((record) => record.reason === "dependency-graph-not-established"),
      true,
    );
  });
});

// ─── Architecture inventory ──────────────────────────────────────────────────

describe("production: architecture inventory", () => {
  it("records layers as a census of observed entity kinds", async () => {
    const { report } = await scanOf(FULL_REPO);
    const section = sectionOf(report, "architecture");
    const layers = section.observations.filter((entry) => entry.kind === "architecture-layer");
    assert.equal(layers.some((entry) => entry.layer === "directory"), true);
    assert.equal(layers.some((entry) => entry.layer === "file"), true);
    assert.equal(layers.every((entry) => entry.nodes > 0), true);
    assert.equal(typeof section.counts.nodeKinds.directory, "number");
  });

  it("records modules as containers that directly hold a manifest", async () => {
    const { report } = await scanOf({
      "package.json": pkg(),
      "packages/app/package.json": pkg({ name: "app" }),
    });
    const section = sectionOf(report, "architecture");
    const modules = section.observations.filter((entry) => entry.kind === "architecture-module");
    assert.equal(section.counts.modules >= 2, true);
    assert.equal(
      modules.some((entry) => entry.manifests.includes("manifest:packages/app/package.json")),
      true,
    );
  });

  it("records entrypoint-shaped files by name, and says the detection is name-based", () => {
    const section = sectionOf(fullReport, "architecture");
    assert.deepEqual(
      section.observations
        .filter((entry) => entry.kind === "architecture-entrypoint")
        .map((entry) => entry.path)
        .sort(),
      ["bin/cli.js", "main.js"],
    );
    assert.equal(
      section.observations
        .filter((entry) => entry.kind === "architecture-entrypoint")
        .every((entry) => entry.basis === "file-name"),
      true,
    );
    assert.equal(
      section.unknown.some((record) => record.reason === "entrypoint-detection-not-established"),
      true,
    );
    assert.equal(isEntrypointShapedPath("src/index.js", "index.js"), false);
    assert.equal(isEntrypointShapedPath("bin/tool", "tool"), true);
    assert.equal(PRODUCTION_ENTRYPOINT_NAMES.includes("main.py"), true);
    assert.deepEqual(PRODUCTION_ENTRYPOINT_DIRECTORIES, ["bin", "cmd"]);
  });

  it("records files with no import relationship, only when the graph was established", () => {
    const section = sectionOf(fullReport, "architecture");
    assert.deepEqual(
      section.observations
        .filter((entry) => entry.kind === "architecture-isolated-file")
        .map((entry) => entry.path)
        .sort(),
      ["bin/cli.js", "src/isolated.js"],
    );
    assert.equal(section.unknown.some((record) => record.reason === "isolated-modules-not-established"), false);
  });

  it("abstains about isolation when the import graph was not established", () => {
    const model = buildRepositoryModel(literalScan(["main.js"], { complete: false }));
    const section = sectionOf(model.production.report, "architecture");
    assert.equal(
      section.unknown.some((record) => record.reason === "isolated-modules-not-established"),
      true,
    );
    assert.equal(
      section.observations.some((entry) => entry.kind === "architecture-isolated-file"),
      false,
    );
  });

  it("performs no coupling, cohesion or dead-code analysis", () => {
    const json = JSON.stringify(sectionOf(fullReport, "architecture")).toLowerCase();
    for (const forbidden of ["coupling", "cohesion", "dead-code", "smell", "circular"]) {
      assert.equal(json.includes(forbidden), false, forbidden);
    }
  });
});

// ─── An empty answer is not an uninterpreted domain ──────────────────────────

/**
 * The distinction this suite exists for.
 *
 * A section whose inputs were inspected and which establishes **nothing** has answered: the
 * repository declares nothing in that domain. That is `complete`. `unsupported` means
 * something else entirely — this implementation cannot interpret the domain — and must never
 * be produced by an empty observation list.
 */
describe("production: empty answers versus uninterpreted domains", () => {
  const UNRELATED_REPO = {
    "README.md": "# demo\n",
    "LICENSE": "MIT\n",
    "docs/notes.txt": "prose, not source\n",
  };
  const CLEAN_REPO = { "package.json": pkg(), "src/app.js": "export const value = 1;\n" };
  const NO_MANIFEST_REPO = { "src/app.js": "export const value = 1;\n" };
  const UNREAD_LANGUAGE_REPO = {
    "package.json": pkg(),
    "src/routes.rb": 'get "/rb" do\nend\n',
    "src/routes.php": "<?php Route::get('/php', f());\n",
  };
  const UNSUPPORTED_FRAMEWORK_REPO = {
    "package.json": pkg(),
    "src/koa.js": [
      'import Koa from "koa";',
      "const app = new Koa();",
      'app.get("/koa-route", handler);',
      "function handler() {}\n",
    ].join("\n"),
  };

  /** An inspected, empty answer: complete, established, nothing observed, nothing hidden. */
  const assertEmptyAnswer = (section) => {
    assert.equal(section.state, PRODUCTION_REPORT_STATES.COMPLETE, section.name);
    assert.equal(section.established, true, section.name);
    assert.deepEqual(section.observations, [], section.name);
    assert.deepEqual(section.evidenceIds, [], section.name);
    assert.equal(section.coverage.truncated, false, section.name);
    assert.equal(section.coverage.state, PRODUCTION_REPORT_STATES.COMPLETE, section.name);
    assert.equal(
      section.unknown.some((record) =>
        ["section-observations-truncated", "repository-scan-not-complete"].includes(record.reason),
      ),
      false,
      section.name,
    );
  };

  it("an empty repository answers all six domains as complete", async () => {
    const { model, report } = await scanOf({});
    // The architecture graph's own word for "a complete scan found no entity to relate" is
    // `unsupported`. The report does not inherit that word: the domain *was* interpreted, and
    // the honest answer is an empty one.
    assert.equal(model.architecture.graph.state, "unsupported");
    for (const name of PRODUCTION_SECTIONS) assertEmptyAnswer(sectionOf(report, name));
    assert.equal(report.state, PRODUCTION_REPORT_STATES.COMPLETE);
    assert.equal(report.established, true);
    assert.equal(report.coverage.observations, 0);
    assert.equal(report.coverage.inspected, false);
  });

  it("a repository of unrelated files answers every domain", async () => {
    const { report } = await scanOf(UNRELATED_REPO);
    for (const name of PRODUCTION_SECTIONS) {
      assert.equal(sectionOf(report, name).state, PRODUCTION_REPORT_STATES.COMPLETE, name);
    }
    for (const name of ["environment", "container", "ci", "api", "dependencies"]) {
      assertEmptyAnswer(sectionOf(report, name));
    }
    assert.equal(report.state, PRODUCTION_REPORT_STATES.COMPLETE);
  });

  it("a complete scan with no environment artifact is complete, not unsupported", async () => {
    const { report } = await scanOf(CLEAN_REPO);
    const section = sectionOf(report, "environment");
    assertEmptyAnswer(section);
    assert.equal(section.counts.examples, 0);
    assert.equal(section.counts.templates, 0);
    assert.equal(
      section.unknown.some((record) => record.reason === "no-environment-configuration-observed"),
      true,
    );
  });

  it("a complete scan with no container artifact is complete, not unsupported", async () => {
    const { report } = await scanOf(CLEAN_REPO);
    const section = sectionOf(report, "container");
    assertEmptyAnswer(section);
    assert.equal(section.counts.definitions, 0);
    assert.equal(section.counts.compositions, 0);
  });

  it("a complete scan with no CI artifact is complete, not unsupported", async () => {
    const { report } = await scanOf(CLEAN_REPO);
    const section = sectionOf(report, "ci");
    assertEmptyAnswer(section);
    assert.equal(section.counts.workflows, 0);
    assert.equal(section.counts.providers, 0);
  });

  it("a complete scan with no API route is complete, not unsupported", async () => {
    const { model, report } = await scanOf(CLEAN_REPO);
    assert.equal(model.api.graph.state, "complete");
    assert.equal(model.api.graph.coverage.routes, 0);
    const section = sectionOf(report, "api");
    assertEmptyAnswer(section);
    assert.equal(section.counts.routes, 0);
    assert.equal(section.counts.handlers, 0);
  });

  it("a complete scan with no dependency declaration is complete, not unsupported", async () => {
    const { model, report } = await scanOf(NO_MANIFEST_REPO);
    assert.equal(model.dependencies.graph.state, "complete");
    assert.equal(model.dependencies.graph.established, true);
    const section = sectionOf(report, "dependencies");
    assertEmptyAnswer(section);
    assert.equal(section.counts.sources, 0);
    assert.equal(section.counts.ecosystems, 0);
  });

  it("a complete scan with no architectural relationship is complete, not unsupported", async () => {
    const { model, report } = await scanOf({});
    // Nothing to relate: the graph carries no containment edge at all.
    assert.equal(model.architecture.graph.edges.length, 0);
    const section = sectionOf(report, "architecture");
    assertEmptyAnswer(section);
    assert.equal(section.counts.containmentEdges, 0);
    assert.equal(section.counts.modules, 0);
    assert.equal(section.counts.entrypoints, 0);
    assert.equal(section.counts.isolatedFiles, 0);
  });

  it("never infers unsupported from an empty observation list", async () => {
    const reports = await Promise.all(
      [{}, UNRELATED_REPO, CLEAN_REPO, NO_MANIFEST_REPO].map(async (fixture) =>
        (await scanOf(fixture)).report,
      ),
    );
    for (const report of reports) {
      for (const name of PRODUCTION_SECTIONS) {
        const section = sectionOf(report, name);
        assert.notEqual(section.state, PRODUCTION_REPORT_STATES.UNSUPPORTED, name);
      }
    }
  });

  it("reports an unsupported framework as unsupported, with its basis", async () => {
    const { model, report } = await scanOf(UNSUPPORTED_FRAMEWORK_REPO);
    const section = sectionOf(report, "api");
    assert.equal(section.state, PRODUCTION_REPORT_STATES.UNSUPPORTED);
    assert.equal(section.established, false);
    assert.deepEqual(section.observations, []);
    assert.equal(section.counts.routes, 0);
    assert.equal(
      section.unknown.some((record) => record.reason === "api-framework-not-interpreted"),
      true,
    );
    // The graph established what it could see; the *domain* is what this build cannot read.
    assert.equal(model.api.graph.unresolved[0].reason, "framework-unsupported");
    assert.equal(report.established, true);
    assert.equal(report.state, PRODUCTION_REPORT_STATES.PARTIAL);
  });

  it("reports unread source languages as unsupported, with their own basis", async () => {
    const { model, report } = await scanOf(UNREAD_LANGUAGE_REPO);
    assert.equal(model.api.graph.state, "unsupported");
    const section = sectionOf(report, "api");
    assert.equal(section.state, PRODUCTION_REPORT_STATES.UNSUPPORTED);
    assert.equal(section.established, false);
    assert.equal(
      section.unknown.some((record) => record.reason === "api-source-not-interpreted"),
      true,
    );
  });

  it("reports an uninterpreted dependency format as unsupported, with its basis", async () => {
    const { model, report } = await scanOf({ "pnpm-lock.yaml": "lockfileVersion: '9.0'\n" });
    assert.equal(model.dependencies.graph.state, "unsupported");
    const section = sectionOf(report, "dependencies");
    assert.equal(section.state, PRODUCTION_REPORT_STATES.UNSUPPORTED);
    assert.equal(section.established, false);
    assert.equal(
      section.unknown.some((record) => record.reason === "dependency-format-not-interpreted"),
      true,
    );
    // The artifact the inventory *did* observe is still reported with its own evidence:
    // observing a file is a different statement from interpreting it.
    assert.equal(
      section.observations.some((entry) => entry.path === "pnpm-lock.yaml"),
      true,
    );
    assert.equal(report.state, PRODUCTION_REPORT_STATES.PARTIAL);
  });

  it("keeps a partly unread domain partial rather than unsupported", async () => {
    const { report } = await scanOf({
      "package.json": pkg(),
      "src/app.js": [
        'import express from "express";',
        "const app = express();",
        'app.get("/users", listUsers);',
        "function listUsers(req, res) {}",
        "",
      ].join("\n"),
      "src/koa.js": [
        'import Koa from "koa";',
        "const koa = new Koa();",
        'koa.get("/koa-route", handler);',
        "function handler() {}",
        "",
      ].join("\n"),
    });
    const section = sectionOf(report, "api");
    // This build read the Express routes, so the domain *is* interpreted: the unread
    // framework is a gap inside the answer, not a reason to refuse it.
    assert.equal(section.state, PRODUCTION_REPORT_STATES.PARTIAL);
    assert.equal(section.established, true);
    assert.equal(
      section.observations.some((entry) => entry.kind === "api-route"),
      true,
    );
    assert.equal(
      section.unknown.some((record) => record.reason === "route-occurrence-not-established"),
      true,
    );
  });
});

// ─── Report shape, model, query API and engines ──────────────────────────────

describe("production report: model and query API", () => {
  it("is a six-section report in the model's contracted area", () => {
    assert.equal(fullModel.production.report.version, PRODUCTION_REPORT_VERSION);
    assert.equal(fullModel.production.state, fullReport.state);
    assert.equal(fullModel.production.established, fullReport.established);
    assert.equal(fullModel.production.detected, fullReport.coverage.observations > 0);
    assert.deepEqual(
      fullReport.sections.map((section) => section.name),
      [...PRODUCTION_SECTIONS],
    );
    assert.deepEqual(
      fullReport.sections.map((section) => section.title),
      PRODUCTION_SECTIONS.map((name) => PRODUCTION_SECTION_TITLES[name]),
    );
  });

  it("is deeply frozen, so no consumer can mutate the model's answer", () => {
    assert.equal(Object.isFrozen(fullReport), true);
    assert.equal(Object.isFrozen(fullReport.sections), true);
    assert.equal(Object.isFrozen(fullReport.sections[0]), true);
    assert.equal(Object.isFrozen(fullReport.sections[0].observations), true);
    assert.equal(Object.isFrozen(fullReport.sections[0].coverage), true);
  });

  it("cites evidence the model carries, on every observation", () => {
    const ids = new Set(fullModel.evidence.map((record) => record.id));
    let observations = 0;
    for (const section of fullReport.sections) {
      assert.equal(section.evidenceIds.length > 0 || section.observations.length === 0, true);
      for (const observation of section.observations) {
        observations += 1;
        assert.equal(observation.evidenceIds.length > 0, true);
        for (const id of observation.evidenceIds) assert.equal(ids.has(id), true, id);
      }
      assert.deepEqual(
        section.evidenceIds,
        [...new Set(section.observations.flatMap((entry) => entry.evidenceIds))].sort(),
      );
    }
    assert.equal(observations, fullReport.coverage.observations);
  });

  it("cites evidence of the subject the observation is actually about", () => {
    // "What concrete repository evidence proves this?" is only answered if the evidence is
    // about the same thing the observation states: a workflow must cite the CI observation,
    // a container artifact the configuration observation, an entrypoint the file's own
    // inventory record. Citing *some* existing evidence would satisfy existence and prove
    // nothing, so the subject is checked, not just the id.
    // An evidence id is `evidence:<subject>:<key>` (the model folds the subject into the id
    // rather than repeating it as a field), so the subject of a citation is read from the id
    // the model actually carries.
    const subjectOf = (id) => id.split(":")[1];
    const environment = [EVIDENCE_SUBJECTS.INVENTORY, EVIDENCE_SUBJECTS.CONFIGURATION];
    const expected = {
      "environment-example": environment,
      "environment-template": environment,
      // A live `environment-file` is the one kind this repository state does not carry — its
      // `.env` is ignored by the repository's own policy, and the environment suite proves
      // that case on a fixture that states one.
      "sample-configuration": environment,
      "environment-template-duplicate": environment,
      "container-definition": [EVIDENCE_SUBJECTS.CONFIGURATION],
      "container-ignore": [EVIDENCE_SUBJECTS.CONFIGURATION],
      "container-composition": [EVIDENCE_SUBJECTS.CONFIGURATION],
      "container-structure": [EVIDENCE_SUBJECTS.CONFIGURATION],
      "container-healthcheck": [EVIDENCE_SUBJECTS.CONFIGURATION],
      "container-healthcheck-disabled": [EVIDENCE_SUBJECTS.CONFIGURATION],
      "container-multi-stage": [EVIDENCE_SUBJECTS.CONFIGURATION],
      "container-build-context": [EVIDENCE_SUBJECTS.CONFIGURATION],
      "ci-workflow": [EVIDENCE_SUBJECTS.CICD],
      "ci-provider": [EVIDENCE_SUBJECTS.CICD],
      "architecture-entrypoint": [EVIDENCE_SUBJECTS.INVENTORY],
      "architecture-isolated-file": [EVIDENCE_SUBJECTS.INVENTORY],
    };
    let checked = 0;
    for (const section of fullReport.sections) {
      for (const observation of section.observations) {
        const allowed = expected[observation.kind];
        if (allowed === undefined) continue;
        for (const id of observation.evidenceIds) {
          assert.equal(
            allowed.includes(subjectOf(id)),
            true,
            `${observation.kind} cites ${subjectOf(id)} (${id})`,
          );
          checked += 1;
        }
      }
    }
    // Every described kind has to have actually been checked, or the table above would be
    // documentation rather than a test.
    for (const kind of Object.keys(expected)) {
      assert.equal(
        fullReport.sections.some((section) =>
          section.observations.some((observation) => observation.kind === kind),
        ),
        true,
        kind,
      );
    }
    assert.equal(checked >= 10, true);
  });

  it("is deterministic: two scans of one repository state agree", async () => {
    const first = await scanOf(FULL_REPO);
    const second = await scanOf(FULL_REPO);
    const strip = (report) => {
      const copy = clone(report);
      // Evidence ids are content-addressed, so they may differ only if the inventory did.
      return copy;
    };
    assert.deepEqual(strip(first.report), strip(second.report));
  });

  it("orders sections, observations, evidence and abstentions deterministically", () => {
    for (const section of fullReport.sections) {
      const keys = section.observations.map((entry) => entry.key);
      assert.deepEqual(keys, [...keys].sort(), section.name);
      assert.equal(new Set(keys).size, keys.length, section.name);
      assert.deepEqual(section.evidenceIds, [...new Set(section.evidenceIds)].sort());
      const abstentionKeys = section.unknown.map((record) => `${record.reason}\u0000${record.detail ?? ""}`);
      assert.deepEqual(abstentionKeys, [...abstentionKeys].sort(), section.name);
    }
  });

  it("answers productionReport, productionCoverage and productionSection", () => {
    assert.equal(fullQuery.productionReport(), fullReport);
    const coverage = fullQuery.productionCoverage();
    assert.equal(coverage.state, fullReport.state);
    assert.equal(coverage.sections, PRODUCTION_SECTIONS.length);
    assert.equal(coverage.observations, fullReport.coverage.observations);
    assert.equal(Object.isFrozen(coverage), true);

    for (const name of PRODUCTION_SECTIONS) {
      const section = fullQuery.productionSection(name);
      assert.equal(section.name, name);
      assert.equal(section, sectionOf(fullReport, name));
      assert.equal(Object.isFrozen(section), true);
    }
  });

  it("treats an unknown domain name as a programmer error, never as an empty section", () => {
    assert.throws(() => fullQuery.productionSection("containers"), (error) => {
      assert.equal(error.kind, "invalid-query");
      return true;
    });
    assert.throws(() => fullQuery.productionSection(undefined), (error) => {
      assert.equal(error.kind, "invalid-query");
      return true;
    });
  });

  it("returns null for a model that carries no report", () => {
    const bare = { ...clone(fullModel), production: {} };
    const query = createRepositoryQuery(bare);
    assert.equal(query.productionReport(), null);
    assert.equal(query.productionCoverage(), null);
    assert.equal(query.productionSection("environment"), null);
  });

  it("never converts an unknown into a pass", () => {
    const model = buildRepositoryModel(literalScan(["package.json"], { complete: false }));
    const query = createRepositoryQuery(model);
    for (const name of PRODUCTION_SECTIONS) {
      const section = query.productionSection(name);
      assert.equal(section.established, false, name);
      assert.equal(section.state, PRODUCTION_REPORT_STATES.UNKNOWN, name);
      assert.equal(section.observations.length, 0, name);
      assert.equal(section.unknown.length > 0, true, name);
      assert.equal(productionAbsence(query, name).established, false, name);
    }
    assert.equal(model.production.report.state, PRODUCTION_REPORT_STATES.UNKNOWN);
    assert.equal(model.production.report.established, false);
  });

  it("carries no score, grade, percentage or traffic light anywhere", () => {
    const json = JSON.stringify(fullReport).toLowerCase();
    for (const forbidden of [
      "score",
      "grade",
      "readiness",
      "percent",
      "traffic",
      "pass\"",
      "fail\"",
      "verdict",
      "quality",
      "severity",
    ]) {
      assert.equal(json.includes(forbidden), false, forbidden);
    }
    assert.deepEqual(Object.keys(fullReport).sort(), [
      "coverage",
      "established",
      "sections",
      "state",
      "version",
    ]);
  });

  it("pins the report's state vocabulary to the established coverage vocabulary", () => {
    assert.deepEqual(PRODUCTION_REPORT_STATE_VALUES, [
      "complete",
      "partial",
      "unsupported",
      "unknown",
      "truncated",
    ]);
    assert.equal(isEstablishedProductionState(PRODUCTION_REPORT_STATES.COMPLETE), true);
    assert.equal(isEstablishedProductionState(PRODUCTION_REPORT_STATES.PARTIAL), true);
    assert.equal(isEstablishedProductionState(PRODUCTION_REPORT_STATES.TRUNCATED), true);
    // The two states that mean "no answer", for two different reasons: nothing was
    // established, or the domain is not interpreted by this build. An *empty* answer is
    // neither — it is `complete`.
    assert.equal(isEstablishedProductionState(PRODUCTION_REPORT_STATES.UNKNOWN), false);
    assert.equal(isEstablishedProductionState(PRODUCTION_REPORT_STATES.UNSUPPORTED), false);
  });

  it("bounds every collection and records a bound that bit", async () => {
    // 260 isolated modules: the architecture section has more to say than the report will
    // carry, which is the one case where a bound has to be visible.
    const files = { "package.json": pkg() };
    for (let index = 0; index < 260; index += 1) {
      files[`src/module-${String(index).padStart(3, "0")}.js`] = `export const value${index} = ${index};\n`;
    }
    const { report } = await scanOf(files);
    const section = sectionOf(report, "architecture");
    assert.equal(
      section.observations.length,
      PRODUCTION_REPORT_LIMITS.maxObservationsPerSection,
    );
    assert.equal(section.coverage.truncated, true);
    assert.equal(section.state, PRODUCTION_REPORT_STATES.TRUNCATED);
    assert.equal(
      section.unknown.some((record) => record.reason === "section-observations-truncated"),
      true,
    );
  });
});

// ─── Rule Engine and Analyzer Engine ─────────────────────────────────────────

describe("production rule pack", () => {
  const runOf = async (repository) => {
    const engine = createRuleEngine({
      registry: createProductionRuleRegistry({ rules: productionRules }),
    });
    const { model } = await scanOf(repository);
    return { model, run: await engine.runAll(buildAnalysisContext({ repository: model })) };
  };
  const ruleOf = (run, id) => run.rules.find((entry) => entry.rule.id === id);

  it("pins the pack's identity, which every fingerprint depends on", () => {
    assert.equal(PRODUCTION_ANALYZER_ID, "production");
    assert.equal(PRODUCTION_ANALYZER_NAME, "Production");
    assert.equal(PRODUCTION_ANALYZER_SCOPE, "production");
    assert.equal(PRODUCTION_RULE_ID_PREFIX, "production.");
    assert.equal(PRODUCTION_RULE_PACK_VERSION, "1.0.0");
    assert.equal(PRODUCTION_CATEGORY, "architecture");
    assert.equal(PRODUCTION_BASIS, "static-production-report");
    assert.equal(typeof PRODUCTION_CONFIDENCE.OBSERVED_REPOSITORY_FACT, "number");
    assert.deepEqual(Object.values(PRODUCTION_RULE_IDS).sort(), [
      "production.api.inventory",
      "production.architecture.inventory",
      "production.ci.inventory",
      "production.container.inventory",
      "production.dependencies.inventory",
      "production.environment.inventory",
    ]);
  });

  it("declares six rules in the production namespace, one per audit domain", () => {
    assert.deepEqual(productionRuleSetIssues(productionRules), []);
    assert.deepEqual(
      Object.values(PRODUCTION_RULE_IDS),
      PRODUCTION_SECTIONS.map((name) => `production.${name}.inventory`),
    );
    assert.deepEqual(
      productionRules.map((rule) => rule.id).sort(),
      Object.values(PRODUCTION_RULE_IDS).sort(),
    );
    for (const rule of productionRules) {
      assert.equal(rule.id.startsWith("production."), true);
      assert.equal(rule.severity, "info");
      assert.equal(rule.category, PRODUCTION_CATEGORY);
      assert.deepEqual(rule.applicability, {});
      assert.deepEqual(rule.remediation, {});
      assert.equal(rule.metadata.basis, PRODUCTION_BASIS);
      assert.equal(typeof rule.detect, "function");
    }
  });

  it("describes every vocabulary the report can produce", () => {
    assert.deepEqual([...PRODUCTION_DESCRIBED_SECTIONS].sort(), [...PRODUCTION_SECTIONS].sort());
    const kinds = PRODUCTION_SECTIONS.flatMap((name) => [...PRODUCTION_OBSERVATION_KINDS[name]]);
    assert.deepEqual([...PRODUCTION_DESCRIBED_OBSERVATIONS].sort(), kinds.sort());
    // A section-independent abstention (`section-observations-truncated`,
    // `repository-scan-not-complete`) is declared by every domain, so the comparison is over
    // the reason *values*, not over their occurrences.
    const reasons = PRODUCTION_SECTIONS.flatMap((name) => [...PRODUCTION_UNKNOWN_REASONS[name]]);
    assert.deepEqual([...PRODUCTION_DESCRIBED_ABSTENTIONS].sort(), [...new Set(reasons)].sort());
    assert.deepEqual(PRODUCTION_DESCRIBED_STATES, [...PRODUCTION_REPORT_STATE_VALUES]);
    for (const name of PRODUCTION_SECTIONS) {
      assert.equal(typeof PRODUCTION_SECTION_WORDING[name], "string");
    }
    for (const state of PRODUCTION_REPORT_STATE_VALUES) {
      assert.equal(typeof PRODUCTION_STATE_WORDING[state], "string");
    }
    for (const kind of kinds) assert.equal(typeof PRODUCTION_OBSERVATION_WORDING[kind], "string");
    for (const reason of reasons) {
      assert.equal(typeof PRODUCTION_ABSTENTION_WORDING[reason], "string");
    }
  });

  it("reports one finding per observation, each citing its evidence", async () => {
    const { run } = await runOf(FULL_REPO);
    for (const section of fullReport.sections) {
      const id = `production.${section.name}.inventory`;
      const result = ruleOf(run, id);
      assert.equal(result.status, RULE_OUTCOME_STATUSES.VIOLATION, id);
      assert.equal(result.findings.length, section.observations.length, id);
      assert.deepEqual(
        result.findings.map((finding) => finding.metadata.kind),
        section.observations.map((observation) => observation.kind),
        id,
      );
      for (const finding of result.findings) {
        assert.equal(finding.severity, "info");
        assert.equal(finding.metadata.basis, PRODUCTION_BASIS);
        assert.equal(finding.evidence.length > 0, true);
        assert.equal(typeof finding.description, "string");
        assert.equal(finding.description.length > 40, true);
      }
    }
  });

  it("records the section's state and abstentions in every detection's metadata", async () => {
    const { run } = await runOf(FULL_REPO);
    const environment = ruleOf(run, PRODUCTION_RULE_IDS.ENVIRONMENT_INVENTORY);
    assert.equal(environment.metadata.section, "environment");
    assert.equal(environment.metadata.state, PRODUCTION_REPORT_STATES.PARTIAL);
    assert.equal(
      environment.metadata.abstentions.some(
        (record) => record.reason === "environment-configuration-ignored",
      ),
      true,
    );
    assert.equal(
      environment.metadata.abstentions.every(
        (record) => typeof PRODUCTION_ABSTENTION_WORDING[record.reason] === "string",
      ),
      true,
    );
    assert.equal(environment.metadata.capped, false);
    assert.equal(environment.metadata.established, true);
  });

  it("abstains instead of passing for a domain the report could not establish", async () => {
    const model = buildRepositoryModel(literalScan(["package.json"], { complete: false }));
    const engine = createRuleEngine({
      registry: createProductionRuleRegistry({ rules: productionRules }),
    });
    const run = await engine.runAll(buildAnalysisContext({ repository: model }));
    for (const name of PRODUCTION_SECTIONS) {
      const result = ruleOf(run, `production.${name}.inventory`);
      assert.deepEqual(result.findings, [], name);
      assert.equal(result.status, RULE_OUTCOME_STATUSES.UNKNOWN, name);
      assert.equal(result.applicability.coverage, APPLICABILITY_COVERAGE.UNKNOWN, name);
      assert.equal(typeof result.applicability.reason, "string", name);
    }
  });

  it("reports an established, empty domain as a pass rather than as a gap", async () => {
    const { run } = await runOf({ "package.json": pkg(), "main.js": "export default 1;\n" });
    const container = ruleOf(run, PRODUCTION_RULE_IDS.CONTAINER_INVENTORY);
    assert.deepEqual(container.findings, []);
    // The domain was inspected and is empty: a `complete`, established answer, so the rule
    // passes on it.
    assert.equal(container.metadata.state, PRODUCTION_REPORT_STATES.COMPLETE);
    assert.equal(container.metadata.established, true);
    assert.equal(container.status, RULE_OUTCOME_STATUSES.PASS);
  });

  it("abstains for a domain this build does not interpret", async () => {
    const { run } = await runOf({
      "package.json": pkg(),
      "src/koa.js": [
        'import Koa from "koa";',
        "const app = new Koa();",
        'app.get("/koa-route", handler);',
        "function handler() {}",
        "",
      ].join("\n"),
    });
    const api = ruleOf(run, PRODUCTION_RULE_IDS.API_INVENTORY);
    assert.deepEqual(api.findings, []);
    assert.equal(api.metadata.state, PRODUCTION_REPORT_STATES.UNSUPPORTED);
    assert.equal(api.metadata.established, false);
    assert.equal(api.status, RULE_OUTCOME_STATUSES.UNKNOWN);
    assert.equal(api.applicability.coverage, APPLICABILITY_COVERAGE.UNKNOWN);
    assert.equal(
      api.metadata.abstentions.some(
        (record) => record.reason === "api-framework-not-interpreted",
      ),
      true,
    );
  });

  it("caps a large section and says that it did", async () => {
    const files = { "package.json": pkg() };
    for (let index = 0; index < MAX_PRODUCTION_FINDINGS + 5; index += 1) {
      files[`config-${index}.json.sample`] = "{}\n";
    }
    const { run } = await runOf(files);
    const environment = ruleOf(run, PRODUCTION_RULE_IDS.ENVIRONMENT_INVENTORY);
    assert.equal(environment.findings.length, MAX_PRODUCTION_FINDINGS);
    assert.equal(environment.metadata.capped, true);
    assert.equal(
      environment.metadata.abstentions.some(
        (record) => record.reason === "section-observations-truncated",
      ),
      true,
    );
  });

  it("produces deterministic, uniquely fingerprinted findings", async () => {
    const { model } = await scanOf(FULL_REPO);
    const engine = createAnalyzerEngine({
      registry: createAnalyzerRegistry([createProductionAnalyzer()]),
    });
    const analyzed = await engine.runAll(buildAnalysisContext({ repository: model }));
    assert.equal(
      new Set(analyzed.findings.map((finding) => finding.fingerprint)).size,
      analyzed.findings.length,
    );
    assert.equal(
      analyzed.findings.every((finding) => finding.ruleId.startsWith("production.")),
      true,
    );
  });

  it("runs as an ordinary analyzer over the accepted framework", async () => {
    const { model } = await scanOf(FULL_REPO);
    const engine = createAnalyzerEngine({
      registry: createAnalyzerRegistry([createProductionAnalyzer()]),
    });
    const result = await engine.runAll(buildAnalysisContext({ repository: model }));
    assert.equal(result.analyzers.length, 1);
    assert.equal(result.analyzers[0].analyzer.id, PRODUCTION_ANALYZER_ID);
    assert.equal(result.analyzers[0].analyzer.scope, PRODUCTION_ANALYZER_SCOPE);
    assert.equal(result.analyzers[0].metadata.ruleSet.length, PRODUCTION_SECTIONS.length);
    assert.equal(result.analyzers[0].findings.length, fullReport.coverage.observations);
    assert.equal(result.findings.length, fullReport.coverage.observations);
  });

  it("rejects a rule set that leaves a declared domain out", () => {
    const missing = productionRules.filter(
      (rule) => rule.id !== PRODUCTION_RULE_IDS.API_INVENTORY,
    );
    const issues = productionRuleSetIssues(missing);
    assert.equal(issues.length, 1);
    assert.equal(issues[0].includes(PRODUCTION_RULE_IDS.API_INVENTORY), true);
    assert.throws(() => createProductionRuleRegistry({ rules: missing }), (error) => {
      assert.equal(error.name, "RuleRegistrationError");
      return true;
    });
    assert.throws(
      () => createProductionRuleRegistry({ rules: [{ ...productionRules[0], id: "other.rule" }] }),
      (error) => {
        assert.equal(error.name, "RuleRegistrationError");
        return true;
      },
    );
  });

  it("reads the same sections through the query API as the report carries", () => {
    const sections = productionSections(fullQuery);
    assert.deepEqual(
      sections.map((section) => section.name),
      [...PRODUCTION_SECTIONS],
    );
    for (const section of sections) {
      assert.equal(productionSection(fullQuery, section.name).name, section.name);
      for (const observation of section.observations) {
        assert.equal(observation.fingerprintKey.startsWith(`production:${section.name}:`), true);
      }
    }
  });

  it("consumes the report only through the query API", () => {
    const source = readFileSync(
      join(HERE, "..", "src", "rules", "production", "signals.js"),
      "utf8",
    );
    assert.equal(source.includes("model.production"), false);
    assert.equal(source.includes("node:fs"), false);
  });

  it("imports nothing outside the model, the analysis and rules layers", () => {
    const directory = join(HERE, "..", "src", "rules", "production");
    const files = [
      "analyzer.js",
      "contracts.js",
      "index.js",
      "registry.js",
      "signals.js",
      join("rules", "index.js"),
      join("rules", "inventory.js"),
    ];
    for (const file of files) {
      const text = readFileSync(join(directory, file), "utf8");
      for (const match of text.matchAll(/from\s+"([^"]+)"/g)) {
        const specifier = match[1];
        const allowed =
          specifier.startsWith("./") ||
          specifier.startsWith("../") ||
          specifier === "../../repository/model/index.js" ||
          specifier === "../../core/index.js";
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
      ]) {
        assert.equal(text.includes(`"${forbidden}"`), false, `${file} references ${forbidden}`);
      }
      assert.equal(/\bnew Date\b/.test(text), false, `${file} must not construct a Date`);
      assert.equal(/\bfetch\(/.test(text), false, `${file} must not fetch`);
    }
  });
});

// ─── Contract: a malformed report is a validation failure ────────────────────

describe("production report contract", () => {
  const base = () => clone(fullModel);

  it("accepts the report the builder produced", () => {
    const model = base();
    assert.equal(issuesOfValidate(model), null);
    assert.equal(validateRepositoryModelGraph(model), model);
  });

  it("rejects a report that is not a plain object", () => {
    const model = base();
    model.production.report = "a summary";
    assert.notEqual(issuesOfValidate(model), null);
  });

  it("rejects an unknown area state", () => {
    const model = base();
    model.production.state = "ready";
    assert.notEqual(issuesOfValidate(model), null);
  });

  it("rejects an area whose established flag disagrees with its state", () => {
    const model = base();
    model.production.established = !model.production.established;
    assert.notEqual(issuesOfValidate(model), null);
  });

  it("rejects a wrong report version", () => {
    const model = base();
    model.production.report.version = "2";
    assert.notEqual(issuesOfValidate(model), null);
  });

  it("rejects a report state that disagrees with its area", () => {
    const model = base();
    model.production.report.state = PRODUCTION_REPORT_STATES.COMPLETE;
    // The exact issue, not merely "something failed": several checks object to a report whose
    // state was rewritten, and a suite that accepted any of them could not tell this contract
    // from the coverage agreement that follows from it.
    assert.equal(
      issuesOfValidate(model).includes(
        "production.report.state: must agree with the area it belongs to",
      ),
      true,
    );
  });

  it("accepts an inspected, empty section as complete", async () => {
    // The conflation this contract must not make: an established answer of "nothing here"
    // is `complete`, and a section is allowed to carry zero observations while saying so.
    const { model } = await scanOf({
      "package.json": pkg(),
      "src/app.js": "export const value = 1;\n",
    });
    assert.deepEqual(issuesOfValidate(model), null);
    const container = sectionOf(model.production.report, "container");
    assert.equal(container.state, PRODUCTION_REPORT_STATES.COMPLETE);
    assert.equal(container.established, true);
    assert.equal(container.observations.length, 0);
  });

  it("rejects an unsupported section that names no uninterpreted domain", () => {
    const model = base();
    // Index 3 is the API domain, whose section answered this repository's routes.
    const section = model.production.report.sections[3];
    assert.equal(section.name, "api");
    section.state = PRODUCTION_REPORT_STATES.UNSUPPORTED;
    section.coverage.state = PRODUCTION_REPORT_STATES.UNSUPPORTED;
    section.established = false;
    // Nothing in this section says the *domain* cannot be interpreted, so the state is an
    // unsupported claim rather than an unsupported fact.
    assert.equal(
      issuesOfValidate(model).includes(
        "production.report.sections[3].unknown: cannot be unsupported without naming the unread domain",
      ),
      true,
    );
  });

  it("rejects a report that drops an audit domain", () => {
    const model = base();
    model.production.report.sections.pop();
    assert.notEqual(issuesOfValidate(model), null);
  });

  it("rejects a report that states one domain twice", () => {
    const model = base();
    model.production.report.sections[1] = clone(model.production.report.sections[0]);
    assert.notEqual(issuesOfValidate(model), null);
  });

  it("rejects a reordered report", () => {
    const model = base();
    const [first, second] = model.production.report.sections;
    model.production.report.sections[0] = second;
    model.production.report.sections[1] = first;
    assert.notEqual(issuesOfValidate(model), null);
  });

  it("rejects a section with the wrong title", () => {
    const model = base();
    model.production.report.sections[0].title = "Environment";
    assert.notEqual(issuesOfValidate(model), null);
  });

  it("rejects a section with an unknown state", () => {
    const model = base();
    model.production.report.sections[0].state = "mostly-fine";
    assert.notEqual(issuesOfValidate(model), null);
  });

  it("rejects a section whose established flag disagrees with its state", () => {
    const model = base();
    const section = model.production.report.sections[0];
    section.established = !section.established;
    assert.notEqual(issuesOfValidate(model), null);
  });

  it("rejects a section whose counts are not an object", () => {
    const model = base();
    model.production.report.sections[0].counts = 4;
    assert.notEqual(issuesOfValidate(model), null);
  });

  it("rejects a negative count", () => {
    const model = base();
    model.production.report.sections[0].counts.examples = -1;
    assert.notEqual(issuesOfValidate(model), null);
  });

  it("rejects a non-numeric nested count", () => {
    const model = base();
    const section = model.production.report.sections.find((entry) => entry.name === "api");
    section.counts.methods.GET = "one";
    assert.notEqual(issuesOfValidate(model), null);
  });

  it("rejects an observation kind the domain does not declare", () => {
    const model = base();
    model.production.report.sections[0].observations[0].kind = "environment-secret";
    assert.notEqual(issuesOfValidate(model), null);
  });

  it("rejects an observation kind borrowed from another domain", () => {
    const model = base();
    model.production.report.sections[0].observations[0].kind = "container-definition";
    assert.notEqual(issuesOfValidate(model), null);
  });

  it("rejects an empty observation key", () => {
    const model = base();
    model.production.report.sections[0].observations[0].key = "";
    assert.notEqual(issuesOfValidate(model), null);
  });

  it("rejects observations that are not sorted by key", () => {
    const model = base();
    const section = model.production.report.sections[0];
    section.observations.reverse();
    assert.notEqual(issuesOfValidate(model), null);
  });

  it("rejects a duplicated observation key", () => {
    const model = base();
    const section = model.production.report.sections.find((entry) => entry.name === "container");
    section.observations.push(clone(section.observations[0]));
    assert.notEqual(issuesOfValidate(model), null);
  });

  it("rejects an observation with no evidence", () => {
    const model = base();
    model.production.report.sections[0].observations[0].evidenceIds = [];
    assert.notEqual(issuesOfValidate(model), null);
  });

  it("rejects an observation citing evidence the model does not carry", () => {
    const model = base();
    const section = model.production.report.sections[0];
    section.observations[0].evidenceIds = ["evidence:inventory:not-a-file"];
    section.evidenceIds = ["evidence:inventory:not-a-file"];
    assert.notEqual(issuesOfValidate(model), null);
  });

  it("rejects evidence ids that are not sorted and unique", () => {
    const model = base();
    const section = model.production.report.sections.find(
      (entry) => entry.evidenceIds.length > 1,
    );
    section.evidenceIds.reverse();
    assert.notEqual(issuesOfValidate(model), null);
  });

  it("rejects an observation citing more evidence than the report may carry", () => {
    const model = base();
    const section = model.production.report.sections[0];
    const ids = model.evidence.map((record) => record.id);
    section.observations[0].evidenceIds = [
      ...ids.slice(0, PRODUCTION_REPORT_LIMITS.maxEvidencePerObservation + 1),
    ].sort();
    section.evidenceIds = [
      ...new Set([
        ...section.evidenceIds,
        ...section.observations[0].evidenceIds,
      ]),
    ].sort();
    assert.notEqual(issuesOfValidate(model), null);
  });

  it("rejects a section evidence list that is not the union of its observations", () => {
    const model = base();
    const section = model.production.report.sections[0];
    section.evidenceIds = [...section.evidenceIds, "evidence:inventory:package.json"].sort();
    // The citation is real evidence the model carries, so only the union rule can reject it:
    // the section claims provenance its observations do not support.
    assert.equal(
      issuesOfValidate(model).includes(
        "production.report.sections[0].evidenceIds: must be the union of its observations' citations",
      ),
      true,
    );
  });

  it("rejects an abstention reason the domain does not declare", () => {
    const model = base();
    model.production.report.sections[0].unknown[0].reason = "looks-fine-to-me";
    assert.notEqual(issuesOfValidate(model), null);
  });

  it("rejects an abstention with a zero count", () => {
    const model = base();
    model.production.report.sections[0].unknown[0].count = 0;
    assert.notEqual(issuesOfValidate(model), null);
  });

  it("rejects abstentions that are not sorted", () => {
    const model = base();
    const section = model.production.report.sections.find(
      (entry) => entry.unknown.length > 1,
    );
    section.unknown.reverse();
    assert.notEqual(issuesOfValidate(model), null);
  });

  it("rejects a duplicated abstention", () => {
    const model = base();
    const section = model.production.report.sections[0];
    section.unknown.push(clone(section.unknown[0]));
    section.coverage.unknownReasons += 1;
    assert.notEqual(issuesOfValidate(model), null);
  });

  it("rejects an unbounded abstention list", () => {
    const model = base();
    const section = model.production.report.sections[0];
    while (
      section.unknown.length <=
      PRODUCTION_REPORT_LIMITS.maxUnknownReasonsPerSection + 1
    ) {
      section.unknown.push({
        reason: "secret-values-not-inspected",
        detail: `detail-${section.unknown.length}`,
        count: 1,
      });
    }
    section.unknown.sort((a, b) =>
      `${a.reason}\u0000${a.detail}` < `${b.reason}\u0000${b.detail}` ? -1 : 1,
    );
    section.coverage.unknownReasons = section.unknown.length;
    assert.notEqual(issuesOfValidate(model), null);
  });

  it("rejects section coverage that disagrees with its own records", () => {
    const counts = base();
    counts.production.report.sections[0].coverage.observations += 1;
    assert.notEqual(issuesOfValidate(counts), null);

    const evidence = base();
    evidence.production.report.sections[0].coverage.evidence += 1;
    assert.notEqual(issuesOfValidate(evidence), null);

    const reasons = base();
    reasons.production.report.sections[0].coverage.unknownReasons += 1;
    assert.notEqual(issuesOfValidate(reasons), null);

    const state = base();
    state.production.report.sections[0].coverage.state = PRODUCTION_REPORT_STATES.UNKNOWN;
    assert.notEqual(issuesOfValidate(state), null);

    const truncated = base();
    truncated.production.report.sections[0].coverage.truncated = "no";
    assert.notEqual(issuesOfValidate(truncated), null);
  });

  it("rejects a state that disagrees with what the section actually established", () => {
    const unsupported = base();
    unsupported.production.report.sections[0].state = PRODUCTION_REPORT_STATES.UNSUPPORTED;
    unsupported.production.report.sections[0].coverage.state =
      PRODUCTION_REPORT_STATES.UNSUPPORTED;
    assert.notEqual(issuesOfValidate(unsupported), null);

    const empty = base();
    const section = empty.production.report.sections[0];
    section.observations = [];
    section.evidenceIds = [];
    section.coverage.observations = 0;
    section.coverage.evidence = 0;
    assert.notEqual(issuesOfValidate(empty), null);

    const unknown = base();
    unknown.production.report.sections[0].state = PRODUCTION_REPORT_STATES.UNKNOWN;
    unknown.production.report.sections[0].established = true;
    unknown.production.report.sections[0].coverage.state = PRODUCTION_REPORT_STATES.UNKNOWN;
    assert.notEqual(issuesOfValidate(unknown), null);

    const truncated = base();
    truncated.production.report.sections[0].state = PRODUCTION_REPORT_STATES.TRUNCATED;
    truncated.production.report.sections[0].coverage.state =
      PRODUCTION_REPORT_STATES.TRUNCATED;
    assert.notEqual(issuesOfValidate(truncated), null);
  });

  it("rejects a truncation the section never reached", () => {
    const model = base();
    const section = model.production.report.sections[0];
    section.unknown.push({ reason: "section-observations-truncated", detail: null, count: 5 });
    section.coverage.unknownReasons += 1;
    assert.notEqual(issuesOfValidate(model), null);
  });

  it("rejects report coverage that disagrees with the report", () => {
    const state = base();
    state.production.report.coverage.state = PRODUCTION_REPORT_STATES.COMPLETE;
    assert.notEqual(issuesOfValidate(state), null);

    const complete = base();
    complete.production.report.coverage.complete = true;
    assert.notEqual(issuesOfValidate(complete), null);

    const sections = base();
    sections.production.report.coverage.sections -= 1;
    assert.notEqual(issuesOfValidate(sections), null);

    const observations = base();
    observations.production.report.coverage.observations += 1;
    assert.notEqual(issuesOfValidate(observations), null);

    const inspected = base();
    inspected.production.report.coverage.inspected = false;
    assert.notEqual(issuesOfValidate(inspected), null);

    const evidence = base();
    evidence.production.report.coverage.evidence += 1;
    assert.notEqual(issuesOfValidate(evidence), null);
  });

  it("rejects an abstention census that does not total the sections", () => {
    const missing = base();
    delete missing.production.report.coverage.unknownReasons["secret-values-not-inspected"];
    assert.notEqual(issuesOfValidate(missing), null);

    const wrong = base();
    wrong.production.report.coverage.unknownReasons["secret-values-not-inspected"] = 99;
    assert.notEqual(issuesOfValidate(wrong), null);

    const unsorted = base();
    unsorted.production.report.coverage.unknownReasons = Object.fromEntries(
      Object.entries(unsorted.production.report.coverage.unknownReasons).reverse(),
    );
    assert.notEqual(issuesOfValidate(unsorted), null);
  });

  it("rejects a detected flag that disagrees with the observations", () => {
    const model = base();
    model.production.detected = !model.production.detected;
    assert.notEqual(issuesOfValidate(model), null);
  });

  it("rejects a report state that does not follow from its sections", () => {
    // Every section now reaches a final answer while the report still says `partial`: the
    // report's own state no longer follows from what its sections established.
    const model = base();
    for (const section of model.production.report.sections) {
      if (section.state !== PRODUCTION_REPORT_STATES.PARTIAL) continue;
      section.state = PRODUCTION_REPORT_STATES.COMPLETE;
      section.coverage.state = PRODUCTION_REPORT_STATES.COMPLETE;
    }
    assert.notEqual(issuesOfValidate(model), null);
  });

  it("rejects an area coverage statement that disagrees with the report", () => {
    const observations = base();
    observations.production.coverage.observations += 1;
    assert.notEqual(issuesOfValidate(observations), null);

    const state = base();
    state.production.coverage.state = PRODUCTION_REPORT_STATES.COMPLETE;
    assert.notEqual(issuesOfValidate(state), null);
  });

  it("rejects a section that is not a plain object", () => {
    const model = base();
    model.production.report.sections[0] = "environment";
    assert.notEqual(issuesOfValidate(model), null);
  });

  it("rejects a section missing a contracted field", () => {
    for (const field of ["name", "title", "state", "established", "coverage", "unknown"]) {
      const model = base();
      delete model.production.report.sections[0][field];
      assert.notEqual(issuesOfValidate(model), null, field);
    }
  });

  it("treats a malformed report as a validation failure, never a finding", async () => {
    const model = base();
    model.production.report.sections[0].unknown[0].reason = "not-a-reason";
    assert.throws(() => validateRepositoryModelGraph(model), ValidationError);

    const { run } = await (async () => {
      const engine = createRuleEngine({
        registry: createProductionRuleRegistry({ rules: productionRules }),
      });
      return { run: await engine.runAll(buildAnalysisContext({ repository: fullModel })) };
    })();
    for (const name of PRODUCTION_SECTIONS) {
      const result = run.rules.find((entry) => entry.rule.id === `production.${name}.inventory`);
      assert.equal(
        result.findings.every((finding) => finding.severity === "info"),
        true,
        name,
      );
      assert.equal(result.errors.length, 0, name);
    }
  });

  it("validates every section of the report the builder produced, unmutated", () => {
    assert.deepEqual(issuesOfValidate(base()), null);
    for (const name of PRODUCTION_SECTIONS) {
      assert.equal(sectionOf(fullReport, name).coverage.state, sectionOf(fullReport, name).state);
    }
  });
});
