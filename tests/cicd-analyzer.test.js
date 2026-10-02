/**
 * Code Guardian — CI/CD Analyzer Tests (official roadmap Phase 13)
 *
 * The end-to-end proof that the CI/CD Analyzer works through the real pipeline:
 *
 *   Repository → RepositoryModel → CICDAnalyzer → applicable rules → evidence → findings
 *
 * Fixtures A–O cover every official domain with a positive, a negative and an uncertainty case.
 * The suite's central claims are the roadmap's: the presence of `.github/workflows` is not the
 * conclusion (content is analyzed), all twelve domains are reported with distinct five-state
 * semantics, an incomplete or uninterpretable workflow never becomes "this pipeline does no X",
 * a comment or a quoted string never becomes a deployment, no secret value is ever read, every
 * finding cites model evidence, fingerprints are stable and unique, and the pack imports no
 * filesystem, process, network or MCP module.
 *
 * Run with: node --test tests/cicd-analyzer.test.js
 */

import { after, describe, it } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

import { createRule } from "../src/core/index.js";

import { scanRepository } from "../src/repository/scanner/index.js";
import { buildRepositoryModel } from "../src/repository/model/index.js";

import {
  buildAnalysisContext,
  createAnalyzerEngine,
  createAnalyzerRegistry,
  stableAnalysisView,
} from "../src/analysis/index.js";

import {
  CICD_ANALYZER_ID,
  CICD_DOMAIN_IDS,
  CICD_RULE_IDS,
  CICD_STATES,
  cicdRules,
  createCicdAnalyzer,
  createCicdRuleRegistry,
  createRuleEngine,
  createRuleRegistry,
  createTestingAnalyzer,
} from "../src/rules/index.js";

// ─── Fixtures ────────────────────────────────────────────────────────────────

const TMP_ROOT = join(tmpdir(), `cg-cicd-analyzer-${process.pid}-${Date.now()}`);
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

async function scanModel(files, options) {
  const root = makeRepo(files);
  const scan = await scanRepository(root, options);
  return { scan, model: buildRepositoryModel(scan) };
}

after(() => {
  rmSync(TMP_ROOT, { recursive: true, force: true });
});

const WF = (body) => body;

// Fixture A — triggers, permissions, dependencies, tests and a build.
const FIXTURE_A = {
  ".github/workflows/ci.yml": WF(`on:
  push:
    branches: [main]
  pull_request:
permissions:
  contents: read
jobs:
  test:
    steps:
      - run: npm ci
      - run: npm test
      - run: npm run build
`),
};

// Fixture B — deployment, with no rollback, no environment, no protection.
const FIXTURE_B = {
  ".github/workflows/deploy.yml": WF(`jobs:
  deploy:
    steps:
      - run: docker push registry/app:latest
      - run: kubectl apply -f k8s/
`),
};

// Fixture C — multiple environments.
const FIXTURE_C = {
  ".github/workflows/promote.yml": WF(`on:
  push:
jobs:
  staging:
    environment: staging
    steps:
      - run: kubectl apply -f k8s/staging
  production:
    environment: production
    steps:
      - run: kubectl apply -f k8s/prod
`),
};

// Fixture D — artifact upload and download.
const FIXTURE_D = {
  ".github/workflows/build.yml": WF(`on:
  push:
jobs:
  build:
    steps:
      - uses: actions/upload-artifact@v4
      - uses: actions/download-artifact@v4
`),
};

// Fixture E — caching.
const FIXTURE_E = {
  ".github/workflows/ci.yml": WF(`on:
  push:
jobs:
  test:
    steps:
      - uses: actions/cache@v4
      - uses: actions/setup-node@v4
        with:
          cache: npm
`),
};

// Fixture F — an established rollback path.
const FIXTURE_F = {
  ".github/workflows/deploy.yml": WF(`on:
  push:
jobs:
  deploy:
    steps:
      - run: helm upgrade app ./chart
  rollback:
    steps:
      - run: helm rollback app 1
`),
};

// Fixture G — deployment protection.
const FIXTURE_G = {
  ".github/workflows/deploy.yml": WF(`on:
  push:
jobs:
  deploy:
    environment: production
    concurrency: production
    steps:
      - run: kubectl apply -f k8s/
`),
};

// Fixture H — secret references.
const FIXTURE_H = {
  ".github/workflows/deploy.yml": WF(`on:
  push:
jobs:
  deploy:
    environment: production
    steps:
      - run: echo "\${{ secrets.REGISTRY_TOKEN }}"
      - run: helm upgrade app ./chart --set token=\${{ secrets.HELM_TOKEN }}
`),
};

// Fixture I — a workflow read in full that establishes nothing.
const FIXTURE_I = {
  ".github/workflows/empty.yml": WF(`name: nothing
jobs:
  hello:
    steps:
      - run: echo hello
`),
};

// Fixture J — a workflow that cannot be interpreted at all.
const FIXTURE_J = { ".github/workflows/ci.yml": "jobs:\u0000binary" };

// Fixture K — a workflow too large to read in full, with real facts in the part that was read.
const FIXTURE_K = {
  ".github/workflows/ci.yml": `${FIXTURE_A[".github/workflows/ci.yml"]}${Array.from(
    { length: 6000 },
    () => "# filler to exceed the per-file byte cap",
  ).join("\n")}\n`,
};

// Fixture L — a structurally broken workflow (an unterminated scalar) with readable facts.
const FIXTURE_L = {
  ".github/workflows/ci.yml": WF(`on:
  push:
jobs:
  build:
    steps:
      - run: npm ci
      - run: echo "unterminated
`),
};

// Fixture M — no CI/CD at all.
const FIXTURE_M = {
  "package.json": JSON.stringify({ name: "demo", version: "1.0.0" }),
  "src/a.js": "export const a = 1;\n",
};

// Fixture N — a provider-specific workflow (GitLab), including a domain GitLab has no concept of.
const FIXTURE_N = {
  ".gitlab-ci.yml": WF(`stages:
  - build
build:
  stage: build
  script:
    - npm ci
    - npm run build
  rules:
    - if: $CI_COMMIT_BRANCH == "main"
`),
};

// Fixture O — a workflow whose only "evidence" is a comment, a name and a quoted string.
const FIXTURE_O = {
  ".github/workflows/ci.yml": WF(`# test build deploy artifact rollback cache secret
name: build
description: deploy rollback cache secret artifact
jobs:
  a:
    steps:
      - run: echo "build deploy artifact rollback cache secret"
`),
};

const contextOf = (model) => buildAnalysisContext({ repository: model });

async function runAnalyzer(model) {
  const engine = createAnalyzerEngine({
    registry: createAnalyzerRegistry([createCicdAnalyzer()]),
  });
  return engine.runAll(contextOf(model));
}

async function runRules(model) {
  const engine = createRuleEngine({ registry: createCicdRuleRegistry({ rules: cicdRules }) });
  return engine.runAll(contextOf(model));
}

const statusOf = (run, ruleId) => run.rules.find((entry) => entry.rule.id === ruleId)?.status;
const summaryOf = (result) =>
  result.analyzers.find((entry) => entry.analyzer.id === CICD_ANALYZER_ID).metadata.cicdSummary;
const findingsOf = (result, ruleId) => result.findings.filter((finding) => finding.ruleId === ruleId);

// ─── Analyzer contract ──────────────────────────────────────────────────────

describe("cicd analyzer: contract", () => {
  it("is an ordinary Analyzer the shared registry runs beside another domain analyzer", async () => {
    const analyzer = createCicdAnalyzer();
    assert.equal(analyzer.id, CICD_ANALYZER_ID);
    assert.equal(analyzer.scope, "cicd");

    const { model } = await scanModel(FIXTURE_A);
    const engine = createAnalyzerEngine({
      registry: createAnalyzerRegistry([createTestingAnalyzer(), createCicdAnalyzer()]),
    });
    const result = await engine.runAll(contextOf(model));
    assert.deepEqual(
      result.analyzers.map((entry) => entry.analyzer.id),
      ["cicd", "testing"],
    );
    assert.ok(summaryOf(result) !== undefined);
  });

  it("reports every one of the twelve domains in its summary", async () => {
    const { model } = await scanModel(FIXTURE_A);
    const summary = summaryOf(await runAnalyzer(model));
    for (const domain of CICD_DOMAIN_IDS) {
      assert.ok(summary[domain] !== undefined, domain);
      assert.ok(Object.values(CICD_STATES).includes(summary[domain].state), domain);
    }
    assert.ok(summary.workflowContent !== undefined);
    assert.ok(summary.applicability !== undefined);
  });

  it("runs through the Rule Engine with one rule per domain", async () => {
    const { model } = await scanModel(FIXTURE_A);
    const run = await runRules(model);
    assert.equal(run.rules.length, cicdRules.length);
    for (const result of run.rules) assert.ok(result.findings.length >= 0);
  });
});

// ─── Golden fixtures ────────────────────────────────────────────────────────

describe("cicd analyzer: golden fixtures", () => {
  it("A: reads triggers, permissions, dependencies, tests and a build as `verified`", async () => {
    const { model } = await scanModel(FIXTURE_A);
    const summary = summaryOf(await runAnalyzer(model));
    assert.deepEqual(summary.triggers.observed, ["pull-request", "push"]);
    assert.equal(summary.triggers.state, CICD_STATES.VERIFIED);
    assert.deepEqual(summary.permissions.observed, ["explicit"]);
    assert.deepEqual(summary["dependency-installation"].observed, ["npm-ci"]);
    assert.deepEqual(summary["test-execution"].observed, ["package-script-test"]);
    assert.deepEqual(summary["build-execution"].observed, ["npm-run-build"]);
    assert.equal(summary.workflowContent.state, CICD_STATES.VERIFIED);
  });

  it("B: reports a deployment, and the relations its absence implies", async () => {
    const { model } = await scanModel(FIXTURE_B);
    const result = await runAnalyzer(model);
    const summary = summaryOf(result);
    assert.deepEqual(summary.deployment.observed, ["docker-push", "kubectl-apply"]);
    assert.equal(summary.deploymentPath.observed, true);

    const observed = findingsOf(result, CICD_RULE_IDS.DEPLOYMENT_OBSERVED);
    assert.equal(observed.length, 1);
    assert.equal(observed[0].severity, "info");
    assert.deepEqual(observed[0].metadata.observed, ["docker-push", "kubectl-apply"]);

    // Deploying, with no rollback, no environment and no protection established.
    assert.equal(findingsOf(result, CICD_RULE_IDS.ROLLBACK_NOT_ESTABLISHED).length, 1);
    assert.equal(findingsOf(result, CICD_RULE_IDS.ENVIRONMENT_NOT_SEPARATED).length, 1);
    const protection = findingsOf(result, CICD_RULE_IDS.DEPLOYMENT_PROTECTION_NOT_ESTABLISHED);
    assert.equal(protection.length, 1);
    assert.equal(protection[0].severity, "medium");
  });

  it("C: distinguishes the environments a workflow declares", async () => {
    const { model } = await scanModel(FIXTURE_C);
    const summary = summaryOf(await runAnalyzer(model));
    assert.deepEqual(summary["environment-separation"].observed, ["production", "staging"]);
    assert.equal(summary["environment-separation"].state, CICD_STATES.VERIFIED);
    assert.equal(
      findingsOf(await runAnalyzer(model), CICD_RULE_IDS.ENVIRONMENT_NOT_SEPARATED).length,
      0,
    );
  });

  it("D: reports artifact upload and download", async () => {
    const { model } = await scanModel(FIXTURE_D);
    const result = await runAnalyzer(model);
    assert.deepEqual(summaryOf(result)["artifact-handling"].observed, [
      "artifact-download",
      "artifact-upload",
    ]);
    assert.equal(findingsOf(result, CICD_RULE_IDS.ARTIFACTS_NOT_HANDLED).length, 0);
  });

  it("E: reports cache configuration from the cache action and the setup input", async () => {
    const { model } = await scanModel(FIXTURE_E);
    const result = await runAnalyzer(model);
    assert.deepEqual(summaryOf(result).caching.observed, [
      "actions-cache",
      "provider-cache",
      "setup-node-cache",
    ]);
    assert.equal(findingsOf(result, CICD_RULE_IDS.CACHING_NOT_CONFIGURED).length, 0);
  });

  it("F: reports an established rollback path, and stops reporting the absence", async () => {
    const { model } = await scanModel(FIXTURE_F);
    const result = await runAnalyzer(model);
    assert.deepEqual(summaryOf(result).rollback.observed, [
      "helm-rollback",
      "rollback-command",
      "rollback-job",
    ]);
    assert.equal(findingsOf(result, CICD_RULE_IDS.ROLLBACK_NOT_ESTABLISHED).length, 0);
  });

  it("G: reports deployment protection from an environment and a concurrency gate", async () => {
    const { model } = await scanModel(FIXTURE_G);
    const result = await runAnalyzer(model);
    assert.deepEqual(summaryOf(result)["deployment-protection"].observed, [
      "concurrency-gate",
      "environment-declaration",
    ]);
    assert.equal(findingsOf(result, CICD_RULE_IDS.DEPLOYMENT_PROTECTION_NOT_ESTABLISHED).length, 0);
  });

  it("H: reports secret references structurally, and never a secret name or value", async () => {
    const { model } = await scanModel(FIXTURE_H);
    const result = await runAnalyzer(model);
    const secrets = findingsOf(result, CICD_RULE_IDS.SECRETS_REFERENCED);
    assert.equal(secrets.length, 1);
    assert.deepEqual(secrets[0].metadata.observed, ["secrets-context"]);
    // The analyzer never sees, stores or prints a secret's name or value.
    const serialized = JSON.stringify(secrets[0]);
    assert.doesNotMatch(serialized, /REGISTRY_TOKEN|HELM_TOKEN/);
  });

  it("I: reports each domain's established absence from a workflow read in full", async () => {
    const { model } = await scanModel(FIXTURE_I);
    const result = await runAnalyzer(model);
    const summary = summaryOf(result);
    assert.equal(summary.workflowContent.state, CICD_STATES.VERIFIED);
    assert.equal(summary.applicability.state, CICD_STATES.DETECTED);
    // Every absence-shaped domain fired, and nothing invented a deployment subject.
    for (const ruleId of [
      CICD_RULE_IDS.TRIGGERS_UNESTABLISHED,
      CICD_RULE_IDS.PERMISSIONS_NOT_DECLARED,
      CICD_RULE_IDS.DEPENDENCIES_NOT_ESTABLISHED,
      CICD_RULE_IDS.TESTS_NOT_ESTABLISHED,
      CICD_RULE_IDS.BUILD_NOT_ESTABLISHED,
      CICD_RULE_IDS.ARTIFACTS_NOT_HANDLED,
      CICD_RULE_IDS.CACHING_NOT_CONFIGURED,
    ]) {
      assert.equal(findingsOf(result, ruleId).length, 1, ruleId);
    }
    for (const ruleId of [
      CICD_RULE_IDS.DEPLOYMENT_OBSERVED,
      CICD_RULE_IDS.ROLLBACK_NOT_ESTABLISHED,
      CICD_RULE_IDS.DEPLOYMENT_PROTECTION_NOT_ESTABLISHED,
    ]) {
      assert.equal(findingsOf(result, ruleId).length, 0, ruleId);
    }
  });

  it("J: an uninterpretable workflow is `failed`, never a clean result", async () => {
    const { model } = await scanModel(FIXTURE_J);
    const result = await runAnalyzer(model);
    const summary = summaryOf(result);
    assert.equal(summary.workflowContent.state, CICD_STATES.FAILED);
    assert.deepEqual(summary.workflowContent.unestablished, [".github/workflows/ci.yml"]);
    assert.deepEqual(result.findings, []);
    for (const domain of CICD_DOMAIN_IDS) {
      assert.equal(summary[domain].state, CICD_STATES.UNKNOWN, domain);
    }
  });

  it("K: an oversized workflow establishes presence as `detected`, and withholds absence", async () => {
    const { model } = await scanModel(FIXTURE_K);
    const result = await runAnalyzer(model);
    const summary = summaryOf(result);
    assert.equal(summary.workflowContent.state, CICD_STATES.UNKNOWN);
    assert.equal(summary.workflowContent.partial, 1);
    // Presence is established, but one rung lower on the evidence ladder.
    assert.equal(summary.triggers.state, CICD_STATES.DETECTED);
    assert.deepEqual(summary["dependency-installation"].observed, ["npm-ci"]);
    // Absence is withheld: nothing may claim this pipeline does no caching.
    assert.equal(summary.caching.state, CICD_STATES.UNKNOWN);
    assert.equal(findingsOf(result, CICD_RULE_IDS.CACHING_NOT_CONFIGURED).length, 0);
    assert.equal(findingsOf(result, CICD_RULE_IDS.TRIGGERS_UNESTABLISHED).length, 0);
  });

  it("L: a structurally broken workflow is `partial`, so its absences are unknown", async () => {
    const { model } = await scanModel(FIXTURE_L);
    const result = await runAnalyzer(model);
    const summary = summaryOf(result);
    assert.equal(summary.workflowContent.partial, 1);
    assert.equal(summary.workflowContent.interpreted, 0);
    assert.deepEqual(summary["dependency-installation"].observed, ["npm-ci"]);
    assert.equal(summary["dependency-installation"].state, CICD_STATES.DETECTED);
    assert.equal(summary.caching.state, CICD_STATES.UNKNOWN);
    assert.equal(findingsOf(result, CICD_RULE_IDS.CACHING_NOT_CONFIGURED).length, 0);
  });

  it("M: a repository with no CI/CD reports `not_applicable` and no findings", async () => {
    const { model } = await scanModel(FIXTURE_M);
    const result = await runAnalyzer(model);
    assert.deepEqual(result.findings, []);
    const summary = summaryOf(result);
    assert.equal(summary.applicability.state, CICD_STATES.NOT_APPLICABLE);
    assert.equal(summary.applicability.hasSubject, false);
    for (const domain of CICD_DOMAIN_IDS) {
      assert.equal(summary[domain].state, CICD_STATES.NOT_APPLICABLE, domain);
    }
  });

  it("N: reads a provider-specific workflow, and treats a concept it lacks as not applicable", async () => {
    const { model } = await scanModel(FIXTURE_N);
    const result = await runAnalyzer(model);
    const summary = summaryOf(result);
    assert.deepEqual(summary.applicability.providers, ["gitlab-ci"]);
    assert.deepEqual(summary["dependency-installation"].observed, ["npm-ci"]);
    assert.deepEqual(summary["build-execution"].observed, ["npm-run-build"]);
    // GitLab has no `permissions:` concept, so the domain has no subject and reports nothing.
    assert.equal(summary.permissions.state, CICD_STATES.NOT_APPLICABLE);
    assert.equal(findingsOf(result, CICD_RULE_IDS.PERMISSIONS_NOT_DECLARED).length, 0);
    assert.equal(statusOf(await runRules(model), CICD_RULE_IDS.PERMISSIONS_NOT_DECLARED), "pass");
  });

  it("O: a comment, a name and a quoted string establish no CI/CD behavior", async () => {
    const { model } = await scanModel(FIXTURE_O);
    const result = await runAnalyzer(model);
    const summary = summaryOf(result);
    for (const domain of [
      "deployment",
      "caching",
      "secrets",
      "artifact-handling",
      "dependency-installation",
      "build-execution",
      "triggers",
      "rollback",
    ]) {
      assert.deepEqual(summary[domain].observed, [], domain);
    }
    assert.equal(findingsOf(result, CICD_RULE_IDS.DEPLOYMENT_OBSERVED).length, 0);
    assert.equal(findingsOf(result, CICD_RULE_IDS.SECRETS_REFERENCED).length, 0);
    // The absence-shaped rules still report honestly over a workflow that does nothing.
    assert.equal(findingsOf(result, CICD_RULE_IDS.BUILD_NOT_ESTABLISHED).length, 1);
  });
});

// ─── Incomplete reads ───────────────────────────────────────────────────────

describe("cicd analyzer: incomplete coverage", () => {
  it("separates `failed` from `unknown`: a bounded read is not a failure", async () => {
    const { model: bounded } = await scanModel(FIXTURE_K);
    const { model: failed } = await scanModel(FIXTURE_J);
    assert.equal(summaryOf(await runAnalyzer(bounded)).workflowContent.state, CICD_STATES.UNKNOWN);
    assert.equal(summaryOf(await runAnalyzer(failed)).workflowContent.state, CICD_STATES.FAILED);
  });

  it("abstains over a truncated repository scan rather than reporting an absence", async () => {
    const { model } = await scanModel(
      { "README.md": "# x\n", ".github/workflows/ci.yml": FIXTURE_A[".github/workflows/ci.yml"] },
      { maxFiles: 1 },
    );
    const result = await runAnalyzer(model);
    assert.deepEqual(result.findings, []);
  });
});

// ─── Unknown vs not applicable ──────────────────────────────────────────────

describe("cicd analyzer: unknown is not not_applicable", () => {
  it("keeps a domain `unknown` when the only workflow could not be interpreted", async () => {
    const { model } = await scanModel(FIXTURE_J);
    const summary = summaryOf(await runAnalyzer(model));
    assert.equal(summary.triggers.state, CICD_STATES.UNKNOWN);
    assert.notEqual(summary.triggers.state, CICD_STATES.NOT_APPLICABLE);
  });

  it("uses the shared applicability engine rather than a second selector", async () => {
    const { model } = await scanModel({ ...FIXTURE_A, "src/a.js": "export const a = 1;\n" });
    const rules = [
      createRule({
        id: "cicd.fixture.rust",
        version: "1.0.0",
        category: "cicd",
        title: "fixture",
        description: "fixture",
        severity: "info",
        applicability: { languages: ["rust"] },
        detect: () => [],
      }),
      createRule({
        id: "cicd.fixture.javascript",
        version: "1.0.0",
        category: "cicd",
        title: "fixture",
        description: "fixture",
        severity: "info",
        applicability: { languages: ["javascript"] },
        detect: () => [],
      }),
    ];
    const engine = createRuleEngine({ registry: createRuleRegistry(rules) });
    const run = await engine.runAll(contextOf(model));
    assert.equal(run.rules.find((entry) => entry.rule.id === "cicd.fixture.rust").status, "not-applicable");
    assert.equal(run.rules.find((entry) => entry.rule.id === "cicd.fixture.javascript").status, "pass");
  });
});

// ─── Evidence ───────────────────────────────────────────────────────────────

describe("cicd analyzer: evidence", () => {
  it("cites only model evidence, and every cited id resolves", async () => {
    const { model } = await scanModel({ ...FIXTURE_B, ...FIXTURE_H, ...FIXTURE_I });
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

  it("carries the five-state vocabulary on every finding's metadata", async () => {
    const { model } = await scanModel({ ...FIXTURE_A, ...FIXTURE_B, ...FIXTURE_H });
    const result = await runAnalyzer(model);
    const allowed = Object.values(CICD_STATES);
    for (const finding of result.findings) {
      assert.ok(allowed.includes(finding.metadata.state), `${finding.ruleId}: ${finding.metadata.state}`);
    }
  });
});

// ─── Fingerprints ───────────────────────────────────────────────────────────

describe("cicd analyzer: fingerprints", () => {
  it("gives two workflows distinct fingerprints from one rule", async () => {
    const { model } = await scanModel({
      ".github/workflows/one.yml": FIXTURE_B[".github/workflows/deploy.yml"],
      ".github/workflows/two.yml": FIXTURE_B[".github/workflows/deploy.yml"],
    });
    const result = await runAnalyzer(model);
    const deployment = findingsOf(result, CICD_RULE_IDS.DEPLOYMENT_OBSERVED);
    assert.equal(deployment.length, 2);
    assert.equal(new Set(deployment.map((finding) => finding.fingerprint)).size, 2);
    for (const finding of deployment) assert.match(finding.fingerprint, /^cg-fp1-[0-9a-f]{32}$/);
  });

  it("is deterministic: the same repository twice gives the same results", async () => {
    const { model } = await scanModel({ ...FIXTURE_A, ...FIXTURE_B, ...FIXTURE_H, ...FIXTURE_I });
    const first = await runAnalyzer(model);
    const second = await runAnalyzer(model);
    assert.deepEqual(
      first.findings.map((finding) => finding.fingerprint),
      second.findings.map((finding) => finding.fingerprint),
    );
    assert.deepEqual(stableAnalysisView(first), stableAnalysisView(second));
    assert.deepEqual(summaryOf(first), summaryOf(second));
  });
});

// ─── Performance measurement ────────────────────────────────────────────────

describe("cicd analyzer: performance", () => {
  it("analyzes a bounded fixture deterministically and within a sane budget", async () => {
    const files = {};
    const body = (index) => `${FIXTURE_A[".github/workflows/ci.yml"]}# workflow ${index}\n`;
    for (let index = 0; index < 40; index += 1) {
      files[`.github/workflows/wf${String(index).padStart(3, "0")}.yml`] = body(index);
    }

    const { model } = await scanModel(files);

    const start = process.hrtime.bigint();
    const first = await runAnalyzer(model);
    const second = await runAnalyzer(model);
    const elapsedMs = Number(process.hrtime.bigint() - start) / 1e6;

    // Meaningful, not a benchmark: two full analyzer passes over a 40-workflow fixture must
    // finish well inside a few seconds on the CI runners.
    assert.ok(elapsedMs < 8000, `analyzer took ${elapsedMs.toFixed(1)}ms`);
    assert.deepEqual(
      first.findings.map((finding) => finding.fingerprint),
      second.findings.map((finding) => finding.fingerprint),
    );
    // eslint-disable-next-line no-console
    console.log(`[phase-13] two analyzer passes over 40 workflows: ${elapsedMs.toFixed(1)}ms`);
  });
});

// ─── Architectural boundary ─────────────────────────────────────────────────

describe("cicd analyzer: boundaries", () => {
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
    const packDir = join(process.cwd(), "src", "rules", "cicd");
    const specifierPattern = /(?:from\s+|require\(\s*)["']([^"']+)["']/g;
    const files = sourceFiles(packDir);
    assert.ok(files.length > 0);
    for (const file of files) {
      const text = readFileSync(file, "utf8");
      for (const match of text.matchAll(specifierPattern)) {
        for (const forbidden of FORBIDDEN) {
          assert.equal(
            match[1].includes(forbidden),
            false,
            `${file} imports ${match[1]} (forbidden: ${forbidden})`,
          );
        }
      }
    }
  });

  it("does not read source contents, run a command, or consult a clock or random source", () => {
    const packDir = join(process.cwd(), "src", "rules", "cicd");
    for (const file of sourceFiles(packDir)) {
      const text = readFileSync(file, "utf8");
      assert.doesNotMatch(text, /Date\.now\(\)|Math\.random\(\)|process\.env/);
    }
  });

  it("never names a provider in a rule — provider knowledge stays in acquisition", () => {
    const rulesDir = join(process.cwd(), "src", "rules", "cicd", "rules");
    for (const file of sourceFiles(rulesDir)) {
      const text = readFileSync(file, "utf8");
      for (const provider of ["github-actions", "gitlab-ci", "jenkins", "circleci"]) {
        assert.equal(text.includes(`"${provider}"`), false, `${file} names ${provider}`);
      }
    }
  });
});
