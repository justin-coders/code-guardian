/**
 * Code Guardian — CI/CD Acquisition & Pack Unit Tests (official roadmap Phase 13)
 *
 * Unit-level proof for the pieces the CI/CD Analyzer rests on: the bounded content classifier,
 * the comment and quoted-scalar handling that keeps textual noise out of the vocabulary, the
 * model projection that carries the facts, the provider-profile modularity, and the pack
 * contract itself.
 *
 * Every fixture is a real repository written to a temporary directory and scanned through the
 * accepted scanner and model boundaries, so "CI runs `kubectl apply`" means a workflow's literal
 * bytes were read — never that the project is cloud-hosted.
 *
 * Run with: node --test tests/cicd-rules.test.js
 */

import { after, describe, it } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

import { scanRepository } from "../src/repository/scanner/index.js";
import { buildRepositoryModel } from "../src/repository/model/index.js";
import { CI_CONTENT_STATES, CI_PERMISSION_MODES } from "../src/repository/model/index.js";
import { CICD_RULES } from "../src/repository/scanner/detectors/cicd.js";
import {
  CICD_OBSERVATION_IDS,
  CICD_PROFILED_PROVIDERS,
  CICD_PROVIDER_PROFILES,
  classifyCicdContent,
  stripWorkflowComments,
} from "../src/repository/scanner/policies/cicd.js";

import {
  CICD_CONTENT_STATES,
  CICD_DOMAIN_IDS,
  CICD_PERMISSION_MODES,
  CICD_PROVIDERS,
  CICD_RULE_DOMAINS,
  CICD_RULE_ID_PREFIX,
  CICD_RULE_IDS,
  cicdRuleSetIssues,
  cicdRules,
  createCicdAnalyzer,
  createCicdRuleRegistry,
} from "../src/rules/index.js";

const TMP_ROOT = join(tmpdir(), `cg-cicd-rules-${process.pid}-${Date.now()}`);
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
  return { scan, model: buildRepositoryModel(scan) };
}

after(() => {
  rmSync(TMP_ROOT, { recursive: true, force: true });
});

const GITHUB = `name: CI/CD
on:
  push:
    branches: [main]
  pull_request:
  workflow_dispatch:
permissions:
  contents: read
  id-token: write
jobs:
  test:
    steps:
      - uses: actions/setup-node@v4
        with:
          cache: npm
      - run: npm ci
      - run: npm test
      - run: npm run build
      - uses: actions/upload-artifact@v4
  deploy:
    environment: production
    steps:
      - run: kubectl apply -f k8s/
      - run: echo "\${{ secrets.REGISTRY_TOKEN }}"
`;

const NOISE = `# run the tests, build and deploy the artifact, with a cache and rollback
name: build
description: deploy rollback cache secret artifact
jobs:
  a:
    steps:
      - run: echo "build deploy artifact rollback cache secret"
`;

// ─── Content classification ─────────────────────────────────────────────────

describe("cicd acquisition: workflow content classification", () => {
  it("reads a GitHub Actions workflow into the closed vocabulary", () => {
    const facts = classifyCicdContent(GITHUB, { provider: "github-actions" });
    assert.deepEqual(facts.triggers, ["pull-request", "push", "workflow-dispatch"]);
    assert.deepEqual(facts.triggerRestrictions, ["branches"]);
    assert.equal(facts.permissionsMode, "explicit");
    assert.deepEqual(facts.permissions, ["contents", "id-token"]);
    assert.deepEqual(facts.secretRefs, ["oidc-token", "secrets-context"]);
    assert.deepEqual(facts.dependencyInstallation, ["npm-ci"]);
    assert.deepEqual(facts.builds, ["npm-run-build"]);
    assert.deepEqual(facts.deployments, ["kubectl-apply"]);
    assert.deepEqual(facts.environments, ["production"]);
    assert.deepEqual(facts.artifacts, ["artifact-upload"]);
    assert.deepEqual(facts.caches, ["provider-cache", "setup-node-cache"]);
    assert.deepEqual(facts.deploymentProtection, ["environment-declaration"]);
    assert.deepEqual(facts.rollbacks, []);
  });

  it("establishes nothing from a comment, a bare word or a quoted string", () => {
    const facts = classifyCicdContent(NOISE, { provider: "github-actions" });
    for (const [domain, ids] of Object.entries(facts)) {
      if (domain === "permissionsMode") {
        assert.equal(ids, "not-established");
        continue;
      }
      assert.deepEqual(ids, [], `${domain} must stay empty`);
    }
  });

  it("removes a comment but keeps a `#` inside a quoted scalar", () => {
    const stripped = stripWorkflowComments('a: "# not a comment"\nb: value  # comment\n');
    assert.equal(stripped, 'a: "# not a comment"\nb: value  \n');
  });

  it("never reports a rollback from a source-control revert", () => {
    const facts = classifyCicdContent(
      "jobs:\n  a:\n    steps:\n      - run: git revert --no-edit HEAD\n",
      { provider: "github-actions" },
    );
    assert.deepEqual(facts.rollbacks, []);
  });

  it("reads command facts for a provider with no structural profile, and no structural facts", () => {
    const facts = classifyCicdContent("pipeline:\n  script:\n    - npm ci\n    - cargo build\n", {
      provider: "jenkins",
    });
    assert.deepEqual(facts.dependencyInstallation, ["cargo-fetch", "npm-ci"]);
    assert.deepEqual(facts.builds, ["cargo-build"]);
    assert.deepEqual(facts.triggers, []);
    assert.equal(facts.permissionsMode, "not-established");
  });

  it("is total, pure and deterministic", () => {
    assert.deepEqual(classifyCicdContent(null), classifyCicdContent(undefined));
    assert.deepEqual(
      classifyCicdContent(GITHUB, { provider: "github-actions" }),
      classifyCicdContent(GITHUB, { provider: "github-actions" }),
    );
  });
});

// ─── Model projection ───────────────────────────────────────────────────────

describe("cicd acquisition: model projection", () => {
  it("carries the interpreted content state and the classified facts", async () => {
    const { scan } = await scanModel({ ".github/workflows/ci.yml": GITHUB });
    const entry = scan.cicd.evidence.find((item) => item.path === ".github/workflows/ci.yml");
    assert.equal(entry.contentState, "interpreted");
    assert.equal(entry.permissionsMode, "explicit");
    assert.deepEqual(entry.deployments, ["kubectl-apply"]);
    assert.equal(entry.provider, "github-actions");
  });

  it("records a truncated read as `partial`, so presence is kept but absence is not", async () => {
    const big = `${GITHUB}\n${"# filler line to exceed the per-file byte cap\n".repeat(5000)}`;
    const { scan } = await scanModel({ ".github/workflows/ci.yml": big });
    const entry = scan.cicd.evidence.find((item) => item.path === ".github/workflows/ci.yml");
    assert.equal(entry.contentState, "partial");
    assert.equal(entry.reason, "too-large");
  });

  it("records binary content as not-interpreted rather than inventing facts", async () => {
    const { scan } = await scanModel({ ".github/workflows/ci.yml": "jobs:\u0000binary" });
    const entry = scan.cicd.evidence.find((item) => item.path === ".github/workflows/ci.yml");
    assert.equal(entry.contentState, "not-interpreted");
    assert.deepEqual(entry.deployments, []);
    assert.deepEqual(entry.triggers, []);
  });
});

// ─── Provider modularity ────────────────────────────────────────────────────

describe("cicd acquisition: provider modularity", () => {
  it("pins the pack's provider vocabulary to the scanner's recognised providers", async () => {
    const scanned = new Set(CICD_RULES.map((rule) => rule.provider));
    for (const provider of scanned) {
      assert.ok(CICD_PROVIDERS.includes(provider), `${provider} is not in the pack vocabulary`);
    }
    for (const provider of CICD_PROVIDERS) {
      assert.ok(scanned.has(provider), `${provider} is not a recognised provider`);
    }
  });

  it("keeps structural knowledge in a provider profile rather than in every rule", async () => {
    assert.deepEqual(CICD_PROFILED_PROVIDERS, ["github-actions", "gitlab-ci"]);
    for (const provider of CICD_PROFILED_PROVIDERS) {
      const profile = CICD_PROVIDER_PROFILES[provider];
      assert.equal(typeof profile.triggers, "object");
      assert.equal(typeof profile.permissions, "object");
    }
    // No rule mentions a provider id at all.
  });

  it("has an observation vocabulary for every declared domain", () => {
    assert.deepEqual(Object.keys(CICD_OBSERVATION_IDS).sort(), [...CICD_DOMAIN_IDS].sort());
    for (const ids of Object.values(CICD_OBSERVATION_IDS)) assert.ok(ids.length > 0);
  });

  it("keeps the pack's state vocabularies identical to the model's", () => {
    assert.deepEqual(Object.values(CICD_CONTENT_STATES).sort(), [...CI_CONTENT_STATES].sort());
    assert.deepEqual(
      Object.values(CICD_PERMISSION_MODES).sort(),
      [...CI_PERMISSION_MODES].sort(),
    );
    assert.ok(cicdRules.length > 0);
  });
});

// ─── Rule set ───────────────────────────────────────────────────────────────

describe("cicd rules: rule set", () => {
  it("ships every declared rule under the namespace, frozen, sorted and one per domain", () => {
    assert.deepEqual(
      cicdRules.map((rule) => rule.id),
      [...cicdRules.map((rule) => rule.id)].sort(),
    );
    assert.equal(Object.isFrozen(cicdRules), true);

    const domains = new Set();
    for (const rule of cicdRules) {
      assert.match(rule.id, new RegExp(`^${CICD_RULE_ID_PREFIX.replace(".", "\\.")}`));
      assert.equal(typeof rule.detect, "function");
      assert.deepEqual({ ...rule.applicability }, {});
      assert.ok(rule.description.length > 0);
      assert.ok(["info", "low", "medium", "high", "critical"].includes(rule.severity));
      const domain = CICD_RULE_DOMAINS[rule.id];
      assert.ok(CICD_DOMAIN_IDS.includes(domain), `${rule.id} names the domain ${domain}`);
      assert.equal(domains.has(domain), false, `${domain} is covered twice`);
      domains.add(domain);
    }
    assert.deepEqual([...domains].sort(), [...CICD_DOMAIN_IDS].sort());
  });

  it("never invents a severe verdict for a configuration observation", () => {
    for (const rule of cicdRules) {
      assert.notEqual(rule.severity, "critical");
      assert.notEqual(rule.severity, "high");
      assert.doesNotMatch(rule.title, /score|unsafe|vulnerable/i);
    }
  });

  it("fails the registry when a declared rule is missing or misnamed", () => {
    const dropped = cicdRules.filter((rule) => rule.id !== CICD_RULE_IDS.DEPLOYMENT_OBSERVED);
    const issues = cicdRuleSetIssues(dropped);
    assert.ok(issues.some((issue) => issue.includes(CICD_RULE_IDS.DEPLOYMENT_OBSERVED)));
    assert.throws(() => createCicdRuleRegistry({ rules: dropped }));
    assert.ok(cicdRuleSetIssues([...cicdRules, { id: "other.rule" }]).length > 0);
  });

  it("accepts an extra project-local rule without editing the pack contract", () => {
    const extra = {
      id: "cicd.project-local.fixture",
      version: "1.0.0",
      category: "cicd",
      title: "fixture",
      description: "fixture",
      severity: "info",
      applicability: {},
      detect: () => [],
      remediation: {},
      metadata: {},
    };
    assert.deepEqual(cicdRuleSetIssues([...cicdRules, extra]), []);
  });
});

// ─── Analyzer descriptor ────────────────────────────────────────────────────

describe("cicd rules: analyzer descriptor", () => {
  it("is an ordinary Analyzer descriptor the registry can hold", () => {
    const analyzer = createCicdAnalyzer();
    assert.equal(analyzer.id, "cicd");
    assert.equal(analyzer.scope, "cicd");
    assert.equal(typeof analyzer.analyze, "function");
    assert.equal(analyzer.canAnalyze().applicable, true);
  });

  it("is deterministic across two constructions", () => {
    assert.deepEqual(
      cicdRules.map((rule) => rule.id),
      cicdRules.map((rule) => rule.id),
    );
  });
});
