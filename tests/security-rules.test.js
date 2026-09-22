/**
 * Code Guardian — Security Rule Pack Tests (Phase 12)
 *
 * The pack is exercised against **real** Phase 8D models built from hand-built
 * ScanResults, so every rule runs against the contract it will actually receive —
 * real scanner evidence ids, real coverage semantics — without touching the
 * filesystem or executing anything.
 *
 * Two pipelines are driven on purpose:
 *
 *   rule engine    rule-level status, findings, evidence and failures — what the
 *                  security rules themselves concluded.
 *   analyzer       the same rules through the Phase 9 Analyzer Engine, so the
 *                  canonical findings and fingerprints are produced by the accepted
 *                  Finding Engine rather than by anything the pack owns.
 *
 * Run with: node --test tests/security-rules.test.js
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { ValidationError, createEvidence, createRule } from "../src/core/index.js";

import { SCAN_SIGNALS, createScanResult } from "../src/repository/scanner/index.js";
import {
  SYMLINK_TARGET_KINDS,
  buildRepositoryModel,
  getEvidence,
} from "../src/repository/model/index.js";

import {
  buildAnalysisContext,
  createAnalyzerEngine,
  createAnalyzerRegistry,
  stableAnalysisView,
} from "../src/analysis/index.js";

import {
  APPLICABILITY_COVERAGE,
  CONFIGURATION_SIGNALS,
  FINDING_BASIS,
  RULE_FAILURE_KINDS,
  RULE_OUTCOME_STATUSES,
  RuleRegistrationError,
  CONTENT_PATTERNS,
  FINDING_BASES,
  SECURITY_ANALYZER_ID,
  SECURITY_CATEGORY,
  SECURITY_CONFIDENCE,
  SECURITY_RULE_IDS,
  SECURITY_RULE_VERSION,
  SENSITIVE_FILE_SPECS,
  createRuleEngine,
  createSecurityAnalyzer,
  createSecurityRuleRegistry,
  defineFileSpec,
  matchesFileSpec,
  securityRuleSetIssues,
  securityRules,
} from "../src/rules/index.js";

// ─── Fixtures: real RepositoryModels ─────────────────────────────────────────

const ISO = "2026-01-01T00:00:00.000Z";
const byPath = (a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0);
const evidenceKey = (entry) => `${entry.path}\u0000${entry.signal}`;
const byEvidenceKey = (a, b) => {
  const left = evidenceKey(a);
  const right = evidenceKey(b);
  return left === right ? 0 : left < right ? -1 : 1;
};

function toEntry(path, isDirectory = false) {
  const name = path.split("/").pop();
  const dot = name.lastIndexOf(".");
  return {
    path,
    name,
    isDirectory,
    extension: isDirectory || dot <= 0 ? "" : name.slice(dot).toLowerCase(),
    depth: path.split("/").length,
  };
}

/** Every ancestor directory of a file path, so a fixture cannot omit a parent. */
function ancestorPaths(path) {
  const segments = path.split("/").slice(0, -1);
  return segments.map((_segment, index) => segments.slice(0, index + 1).join("/"));
}

const sig = (path, signal, extra = {}) => ({ path, signal, ...extra });

/**
 * Build a model from a file list plus scan state.
 *
 * Directories are derived from the file paths (the model builder rejects a file
 * whose parent was not observed), and every collection is sorted, so fixtures stay
 * declarative and stay valid.
 */
function modelOf({
  paths,
  configuration = [],
  ignored = [],
  errors = [],
  symlinks = [],
  content = [],
  complete = true,
  truncated = false,
} = {}) {
  const directories = [...new Set(paths.flatMap(ancestorPaths))]
    .concat(symlinks.flatMap((entry) => ancestorPaths(entry.path)))
    .filter((path, index, all) => all.indexOf(path) === index)
    .sort();
  return buildRepositoryModel(
    createScanResult({
      root: "/scan-root",
      scannedAt: ISO,
      files: paths.map((path) => toEntry(path)).sort(byPath),
      directories: directories.map((path) => toEntry(path, true)),
      symlinks: symlinks.map((entry) => symlinkEntry(entry.path, entry.target)).sort(byPath),
      content: contentSection(content),
      ignored: ignored.map((entry) => ({ ...entry })).sort(byPath),
      configuration: {
        detected: configuration.length > 0,
        evidence: configuration.map(([path, signal]) => sig(path, signal)).sort(byEvidenceKey),
        evidenceTruncated: false,
      },
      statistics: {
        filesScanned: paths.length,
        directoriesScanned: directories.length,
        symlinksScanned: symlinks.length,
        ignored: ignored.length,
        unreadable: errors.length,
        truncatedBy: truncated ? ["file-limit"] : [],
      },
      scan: {
        complete,
        truncated,
        limits: { maxFiles: 10000, maxDepth: 20 },
        errors,
      },
    }),
  );
}

/** A symlink inventory entry, defaulting to a link whose target stays inside. */
function symlinkEntry(path, target = { kind: SYMLINK_TARGET_KINDS.INSIDE, path: "src/app.js", reason: null }) {
  return {
    path,
    name: path.split("/").pop(),
    depth: path.split("/").length,
    target,
  };
}

/**
 * A content-inspection candidate, as the scanner emits it.
 *
 * `pattern` is a *pattern id*, never a value: the scanner's records are value-free
 * by construction, and the fixtures keep that property so a leak test proves
 * something about the pack rather than about the fixture.
 */
function candidate(path, { patterns = [], inspected = true, reason = null, truncated = false, candidateClass = "dotenv", bytesInspected = 40 } = {}) {
  return {
    path,
    candidate: candidateClass,
    inspected,
    reason,
    bytesInspected,
    truncated,
    patterns,
  };
}

/** Wrap candidate records in the scan result's `content` section. */
function contentSection(candidates) {
  return {
    inspected: candidates.some((entry) => entry.inspected),
    complete: candidates.every((entry) => entry.inspected && !entry.truncated),
    truncated: candidates.some(
      (entry) => entry.truncated || entry.reason === "budget-exhausted",
    ),
    candidates: [...candidates].sort(byPath),
    limits: { maxFileBytes: 65536, maxTotalBytes: 262144, maxFiles: 12 },
  };
}

/** A base repository with nothing security-relevant in it. */
const BASE_PATHS = ["README.md", "package.json", "src/app.js"];

const CLEAN = modelOf({ paths: BASE_PATHS });

/** Everything the pack can detect, plus the look-alikes it must ignore. */
const SENSITIVE_PATHS = [
  ".env",
  ".env.example",
  ".netrc",
  ".npmrc",
  "Dockerfile",
  "apps/web/.env",
  "id_rsa",
  "id_rsa.pub",
  "package.json",
  "secrets.tfvars",
  "server.pem",
  "service-account.json",
  "store.p12",
  "terraform.tfstate",
];

/**
 * The content the scanner inspected in the sensitive fixture.
 *
 * Three candidates were examined and matched nothing (so the pack has complete
 * information about them and stays quiet), one holds a credential assignment and one
 * inlines a private-key block. Only pattern ids appear — the values never exist in a
 * fixture, an observation or a finding.
 */
const SENSITIVE_CONTENT = [
  candidate(".env"),
  candidate(".env.example"),
  candidate("apps/web/.env"),
  candidate(".npmrc", {
    candidateClass: "npm-config",
    patterns: [CONTENT_PATTERNS.CREDENTIAL_ASSIGNMENT],
  }),
  candidate("secrets.tfvars", {
    candidateClass: "terraform-vars",
    patterns: [CONTENT_PATTERNS.PRIVATE_KEY_BLOCK],
  }),
];

/** One symlink whose target escapes the repository. */
const SENSITIVE_SYMLINKS = [
  { path: "escape", target: { kind: SYMLINK_TARGET_KINDS.OUTSIDE, path: null, reason: null } },
];

const SENSITIVE = modelOf({
  paths: SENSITIVE_PATHS,
  configuration: [["Dockerfile", CONFIGURATION_SIGNALS.DOCKERFILE]],
  symlinks: SENSITIVE_SYMLINKS,
  content: SENSITIVE_CONTENT,
});

/** Same sensitive files, but the scan stopped at a limit. */
const SENSITIVE_PARTIAL = modelOf({
  paths: SENSITIVE_PATHS,
  configuration: [["Dockerfile", CONFIGURATION_SIGNALS.DOCKERFILE]],
  symlinks: SENSITIVE_SYMLINKS,
  content: SENSITIVE_CONTENT,
  complete: false,
  truncated: true,
});

/** A clean inventory the scan did not finish. */
const CLEAN_PARTIAL = modelOf({ paths: BASE_PATHS, complete: false, truncated: true });

/** A complete inventory containing one path that could not be read. */
const CLEAN_UNREADABLE = modelOf({
  paths: BASE_PATHS,
  errors: [
    {
      kind: "filesystem-error",
      code: "CG_FS_PERMISSION_DENIED",
      operation: "listDirectory",
      path: "secrets",
    },
  ],
});

/** A complete inventory that deliberately excluded a path by policy. */
const CLEAN_IGNORED = modelOf({
  paths: BASE_PATHS,
  ignored: [{ path: "vendor", policy: "default-directory" }],
});

/** Container build with no ignore file beside it. */
const DOCKER_UNPROTECTED = modelOf({
  paths: ["Dockerfile", "package.json"],
  configuration: [["Dockerfile", CONFIGURATION_SIGNALS.DOCKERFILE]],
});

/** Container build with an ignore file in the same directory. */
const DOCKER_PROTECTED = modelOf({
  paths: [".dockerignore", "Dockerfile", "package.json"],
  configuration: [
    ["Dockerfile", CONFIGURATION_SIGNALS.DOCKERFILE],
    [".dockerignore", CONFIGURATION_SIGNALS.CONTAINER_IGNORE],
  ],
});

/** An ignore file that exists, but not beside the Dockerfile. */
const DOCKER_ELSEWHERE = modelOf({
  paths: ["Dockerfile", "package.json", "src/.dockerignore", "src/app.js"],
  configuration: [
    ["Dockerfile", CONFIGURATION_SIGNALS.DOCKERFILE],
    ["src/.dockerignore", CONFIGURATION_SIGNALS.CONTAINER_IGNORE],
  ],
});

// ─── Helpers ─────────────────────────────────────────────────────────────────

const contextOf = (model) => buildAnalysisContext({ repository: model });

/** Run the rules through the Phase 10 engine and return the rule run result. */
async function runRules(model, { rules = securityRules, failFast = false } = {}) {
  const engine = createRuleEngine({ registry: createSecurityRuleRegistry({ rules }), failFast });
  return engine.runAll(contextOf(model));
}

/** Run the pack through the Phase 9 Analyzer Engine and return the analysis result. */
async function runAnalyzer(model, { rules = securityRules, failFast = false } = {}) {
  const engine = createAnalyzerEngine({
    registry: createAnalyzerRegistry([createSecurityAnalyzer({ rules, failFast })]),
  });
  return engine.runAll(contextOf(model));
}

const statusOf = (run, ruleId) => run.rules.find((entry) => entry.rule.id === ruleId)?.status;
const resultOf = (run, ruleId) => run.rules.find((entry) => entry.rule.id === ruleId);
const ruleIdsOf = (run) => run.rules.map((entry) => entry.rule.id);
const findingPaths = (findings) => findings.map((finding) => finding.metadata.path).sort();

const EXPECTED_RULE_IDS = [
  "security.configuration.container-ignore",
  "security.exposure.symlink-escape",
  "security.sensitive-content.credential-assignment",
  "security.sensitive-content.private-key-material",
  "security.sensitive-file.credentials",
  "security.sensitive-file.dotenv",
  "security.sensitive-file.key-material",
  "security.sensitive-file.keystore",
  "security.sensitive-file.private-key",
  "security.sensitive-file.service-account",
  "security.sensitive-file.terraform-state",
];

// ─── Rule set ────────────────────────────────────────────────────────────────

describe("security pack: rule set", () => {
  it("ships exactly the declared rules, in deterministic id order", () => {
    assert.deepEqual(
      securityRules.map((rule) => rule.id),
      EXPECTED_RULE_IDS,
    );
    assert.deepEqual([...Object.values(SECURITY_RULE_IDS)].sort(), EXPECTED_RULE_IDS);
    assert.equal(securityRuleSetIssues(securityRules).length, 0);
  });

  it("declares the pack contract on every rule", () => {
    for (const rule of securityRules) {
      assert.equal(rule.version, SECURITY_RULE_VERSION);
      assert.equal(rule.category, SECURITY_CATEGORY);
      // Universally applicable: a selector here would skip the check on exactly the
      // repositories that look unusual, which is where a missed secret hurts most.
      assert.deepEqual({ ...rule.applicability }, {});
      // Phase 12 detects; remediation belongs to a later phase.
      assert.deepEqual({ ...rule.remediation }, {});
      // Every rule states which kind of observation it rests on.
      assert.ok(Object.values(FINDING_BASES).includes(rule.metadata.basis), rule.id);
      assert.ok(["info", "low", "medium", "high", "critical"].includes(rule.severity));
      assert.equal(typeof rule.detect, "function");
    }
  });

  it("refuses a rule id outside the security namespace", () => {
    const issues = securityRuleSetIssues([
      ...securityRules,
      createRule({
        id: "testing.not-security",
        version: "1.0.0",
        category: "testing",
        title: "t",
        severity: "low",
        applicability: {},
        detect: () => [],
        remediation: {},
        metadata: {},
      }),
    ]);
    assert.ok(issues.some((issue) => issue.includes("security.")));
  });

  it("refuses a pack that dropped a declared rule", () => {
    const withoutDotenv = securityRules.filter(
      (rule) => rule.id !== SECURITY_RULE_IDS.DOTENV,
    );
    assert.throws(
      () => createSecurityRuleRegistry({ rules: withoutDotenv }),
      (error) => {
        assert.ok(error instanceof RuleRegistrationError);
        assert.ok(
          error.details.issues.some((issue) => issue.includes(SECURITY_RULE_IDS.DOTENV)),
        );
        return true;
      },
    );
  });

  it("refuses a renamed declared rule", () => {
    const renamed = securityRules.map((rule) =>
      rule.id === SECURITY_RULE_IDS.DOTENV ? { ...rule, id: "security.sensitive-file.envfile" } : rule,
    );
    assert.throws(() => createSecurityRuleRegistry({ rules: renamed }), RuleRegistrationError);
  });

  it("refuses a duplicate id and a malformed descriptor", () => {
    assert.throws(
      () => createSecurityRuleRegistry({ rules: [...securityRules, securityRules[0]] }),
      RuleRegistrationError,
    );
    assert.throws(
      () =>
        createSecurityRuleRegistry({
          rules: securityRules.map((rule) =>
            rule.id === SECURITY_RULE_IDS.DOTENV ? { ...rule, version: "1" } : rule,
          ),
        }),
      RuleRegistrationError,
    );
    assert.throws(() => createSecurityRuleRegistry({ rules: "nope" }), RuleRegistrationError);
  });

  it("registers extra project rules alongside the pack, sorted by id", () => {
    const project = createRule({
      id: "security.project.custom-check",
      version: "1.0.0",
      category: SECURITY_CATEGORY,
      title: "Project check",
      severity: "low",
      applicability: {},
      detect: () => [],
      remediation: {},
      metadata: {},
    });
    const registry = createSecurityRuleRegistry({ rules: [...securityRules, project] });
    assert.equal(registry.size, securityRules.length + 1);
    assert.deepEqual([...registry.ids()], [...registry.ids()].sort());
    assert.ok(registry.has("security.project.custom-check"));
  });

  it("hands out frozen rules a caller cannot mutate into a different run", () => {
    const registry = createSecurityRuleRegistry({ rules: securityRules });
    const rule = registry.get(SECURITY_RULE_IDS.DOTENV);
    assert.ok(Object.isFrozen(rule));
    assert.throws(() => {
      "use strict";
      rule.severity = "info";
    }, TypeError);
    assert.equal(registry.get(SECURITY_RULE_IDS.DOTENV).severity, "high");
  });
});

// ─── Filename matching ───────────────────────────────────────────────────────

describe("security pack: filename matching", () => {
  const fileOf = (path) => toEntry(path);
  const dotenv = defineFileSpec(SENSITIVE_FILE_SPECS.dotenv, { name: "dotenv" });
  const privateKey = defineFileSpec(SENSITIVE_FILE_SPECS.privateKey, { name: "privateKey" });
  const keyMaterial = defineFileSpec(SENSITIVE_FILE_SPECS.keyMaterial, { name: "keyMaterial" });
  const credentials = defineFileSpec(SENSITIVE_FILE_SPECS.credentials, { name: "credentials" });
  const terraform = defineFileSpec(SENSITIVE_FILE_SPECS.terraformState, { name: "terraform" });

  it("matches live dotenv files and refuses the committed template family", () => {
    for (const path of [".env", ".env.local", ".env.production", "apps/web/.env", ".env.backup"]) {
      assert.equal(matchesFileSpec(dotenv, fileOf(path)), true, `${path} must match`);
    }
    for (const path of [
      ".env.example",
      ".env.sample",
      ".env.template",
      ".env.dist",
      ".environment",
      "docs/env.md",
    ]) {
      assert.equal(matchesFileSpec(dotenv, fileOf(path)), false, `${path} must not match`);
    }
  });

  it("matches private keys but not their public halves", () => {
    assert.equal(matchesFileSpec(privateKey, fileOf("id_rsa")), true);
    assert.equal(matchesFileSpec(privateKey, fileOf(".ssh/id_ed25519")), true);
    assert.equal(matchesFileSpec(privateKey, fileOf("keys/putty.ppk")), true);
    assert.equal(matchesFileSpec(privateKey, fileOf("id_rsa.pub")), false);
    assert.equal(matchesFileSpec(privateKey, fileOf("ssh_host_rsa_key.pub")), false);
  });

  it("matches case-insensitively, because a missed key is a false negative", () => {
    assert.equal(matchesFileSpec(privateKey, fileOf("ID_RSA")), true);
    assert.equal(matchesFileSpec(keyMaterial, fileOf("SERVER.PEM")), true);
    assert.equal(matchesFileSpec(dotenv, fileOf(".ENV")), true);
  });

  it("matches credential stores by segment without swallowing their config", () => {
    assert.equal(matchesFileSpec(credentials, fileOf(".aws/credentials")), true);
    assert.equal(matchesFileSpec(credentials, fileOf(".aws/config")), false);
    assert.equal(matchesFileSpec(credentials, fileOf(".netrc")), true);
    assert.equal(matchesFileSpec(credentials, fileOf("service/config.json")), false);
  });

  it("matches state files by suffix, including the backup", () => {
    assert.equal(matchesFileSpec(terraform, fileOf("terraform.tfstate")), true);
    assert.equal(matchesFileSpec(terraform, fileOf("envs/prod.tfstate")), true);
    assert.equal(matchesFileSpec(terraform, fileOf("terraform.tfstate.backup")), true);
    assert.equal(matchesFileSpec(terraform, fileOf("state.json")), false);
  });

  it("rejects malformed specs instead of matching everything or nothing", () => {
    assert.throws(() => defineFileSpec({}), ValidationError);
    assert.throws(() => defineFileSpec({ nope: [".env"] }), ValidationError);
    assert.throws(() => defineFileSpec({ basenames: ".env" }), ValidationError);
    assert.throws(() => defineFileSpec({ basenames: [""] }), ValidationError);
    assert.throws(() => defineFileSpec("nope"), ValidationError);
  });

  it("matches only the entity it was handed, and tolerates anything else", () => {
    assert.equal(matchesFileSpec(dotenv, fileOf(".env")), true);
    assert.equal(matchesFileSpec(dotenv, undefined), false);
    assert.equal(matchesFileSpec(dotenv, { path: "src" }), false);
  });
});

// ─── Golden: clean repository ────────────────────────────────────────────────

describe("security pack: clean repository", () => {
  it("reports nothing, and every rule passes with its audit basis recorded", async () => {
    const run = await runRules(CLEAN);

    assert.deepEqual(run.findings, []);
    assert.deepEqual(run.evidence, []);
    assert.equal(run.complete, true);
    assert.deepEqual(ruleIdsOf(run), EXPECTED_RULE_IDS);
    for (const entry of run.rules) {
      assert.equal(entry.status, RULE_OUTCOME_STATUSES.PASS, entry.rule.id);
      assert.ok(Object.values(FINDING_BASES).includes(entry.metadata.basis), entry.rule.id);
    }
    for (const entry of run.rules) {
      if (entry.rule.id === SECURITY_RULE_IDS.CONTAINER_IGNORE) {
        assert.equal(entry.metadata.dockerfiles, 0);
        continue;
      }
      // The clean fixture carries no symlink and no content candidate, so the rules
      // that could have said something about either rest on the file inventory.
      assert.equal(entry.metadata.observedFiles, BASE_PATHS.length, entry.rule.id);
      assert.equal(entry.metadata.ignoredPaths, 0);
    }
    assert.equal(run.metadata.repositoryCoverage, "complete");
  });

  it("reports the ignored paths a clean outcome rests on", async () => {
    const run = await runRules(CLEAN_IGNORED);
    const entry = resultOf(run, SECURITY_RULE_IDS.DOTENV);
    assert.equal(entry.status, RULE_OUTCOME_STATUSES.PASS);
    // Policy exclusions are visible rather than silent.
    assert.equal(entry.metadata.ignoredPaths, 1);
  });
});

// ─── Golden: sensitive repository ────────────────────────────────────────────

describe("security pack: sensitive repository", () => {
  it("reports every sensitive artifact once, and ignores the look-alikes", async () => {
    const run = await runRules(SENSITIVE);

    // One per rule, plus a second dotenv file nested deeper in the tree, plus the
    // three findings the corrections added (credential content, key-block content
    // and the escaping symlink).
    assert.equal(run.findings.length, 12);
    assert.equal(run.complete, true);

    const byRule = new Map();
    for (const finding of run.findings) {
      byRule.set(finding.ruleId, [...(byRule.get(finding.ruleId) ?? []), finding]);
    }

    assert.deepEqual([...byRule.keys()].sort(), EXPECTED_RULE_IDS);
    assert.deepEqual(findingPaths(byRule.get(SECURITY_RULE_IDS.DOTENV)), [
      ".env",
      "apps/web/.env",
    ]);
    assert.deepEqual(findingPaths(byRule.get(SECURITY_RULE_IDS.PRIVATE_KEY)), ["id_rsa"]);
    assert.deepEqual(findingPaths(byRule.get(SECURITY_RULE_IDS.KEY_MATERIAL)), ["server.pem"]);
    assert.deepEqual(findingPaths(byRule.get(SECURITY_RULE_IDS.KEYSTORE)), ["store.p12"]);
    assert.deepEqual(findingPaths(byRule.get(SECURITY_RULE_IDS.CREDENTIALS)), [".netrc"]);
    assert.deepEqual(findingPaths(byRule.get(SECURITY_RULE_IDS.SERVICE_ACCOUNT)), [
      "service-account.json",
    ]);
    assert.deepEqual(findingPaths(byRule.get(SECURITY_RULE_IDS.TERRAFORM_STATE)), [
      "terraform.tfstate",
    ]);
    assert.deepEqual(findingPaths(byRule.get(SECURITY_RULE_IDS.CONTAINER_IGNORE)), ["Dockerfile"]);
    assert.deepEqual(findingPaths(byRule.get(SECURITY_RULE_IDS.CREDENTIAL_CONTENT)), [
      ".npmrc",
    ]);
    assert.deepEqual(findingPaths(byRule.get(SECURITY_RULE_IDS.PRIVATE_KEY_CONTENT)), [
      "secrets.tfvars",
    ]);
    assert.deepEqual(findingPaths(byRule.get(SECURITY_RULE_IDS.SYMLINK_ESCAPE)), ["escape"]);

    // `.env.example` and `id_rsa.pub` are observed and deliberately not reported.
    assert.equal(run.findings.some((finding) => finding.metadata.path === ".env.example"), false);
    assert.equal(run.findings.some((finding) => finding.metadata.path === "id_rsa.pub"), false);
  });

  it("carries the declared severity, confidence and evidence on each violation", async () => {
    const run = await runRules(SENSITIVE);

    const expected = {
      [SECURITY_RULE_IDS.DOTENV]: ["high", SECURITY_CONFIDENCE.OBSERVED_ARTIFACT, ".env"],
      [SECURITY_RULE_IDS.PRIVATE_KEY]: ["high", SECURITY_CONFIDENCE.OBSERVED_ARTIFACT, "id_rsa"],
      [SECURITY_RULE_IDS.KEY_MATERIAL]: [
        "medium",
        SECURITY_CONFIDENCE.OBSERVED_ARTIFACT,
        "server.pem",
      ],
      [SECURITY_RULE_IDS.KEYSTORE]: ["high", SECURITY_CONFIDENCE.OBSERVED_ARTIFACT, "store.p12"],
      [SECURITY_RULE_IDS.CREDENTIALS]: ["high", SECURITY_CONFIDENCE.OBSERVED_ARTIFACT, ".netrc"],
      [SECURITY_RULE_IDS.SERVICE_ACCOUNT]: [
        "high",
        SECURITY_CONFIDENCE.OBSERVED_ARTIFACT,
        "service-account.json",
      ],
      [SECURITY_RULE_IDS.TERRAFORM_STATE]: [
        "high",
        SECURITY_CONFIDENCE.OBSERVED_ARTIFACT,
        "terraform.tfstate",
      ],
      [SECURITY_RULE_IDS.CONTAINER_IGNORE]: [
        "medium",
        SECURITY_CONFIDENCE.DERIVED_CONDITION,
        "Dockerfile",
      ],
    };

    for (const [ruleId, [severity, confidence, path]] of Object.entries(expected)) {
      const entry = resultOf(run, ruleId);
      assert.equal(entry.status, RULE_OUTCOME_STATUSES.VIOLATION, ruleId);
      assert.equal(entry.rule.severity, severity, ruleId);
      const finding = entry.findings.find((candidate) => candidate.metadata.path === path);
      assert.ok(finding, `${ruleId} must report ${path}`);
      assert.equal(finding.severity, severity);
      assert.equal(finding.confidence, confidence);
      assert.equal(finding.category, SECURITY_CATEGORY);
      assert.ok(finding.evidence.length > 0);
      assert.ok(Object.values(FINDING_BASES).includes(finding.metadata.basis));
    }
  });

  it("reports content findings with their pattern, and never the matched value", async () => {
    const run = await runRules(SENSITIVE);

    const credential = resultOf(run, SECURITY_RULE_IDS.CREDENTIAL_CONTENT);
    assert.equal(credential.status, RULE_OUTCOME_STATUSES.VIOLATION);
    assert.deepEqual(credential.findings[0].metadata.patterns, [
      CONTENT_PATTERNS.CREDENTIAL_ASSIGNMENT,
    ]);
    assert.equal(credential.findings[0].metadata.basis, FINDING_BASES.CONTENT);
    assert.equal(credential.findings[0].confidence, SECURITY_CONFIDENCE.OBSERVED_CONTENT);

    const keyBlock = resultOf(run, SECURITY_RULE_IDS.PRIVATE_KEY_CONTENT);
    assert.equal(keyBlock.status, RULE_OUTCOME_STATUSES.VIOLATION);
    assert.deepEqual(keyBlock.findings[0].metadata.patterns, [CONTENT_PATTERNS.PRIVATE_KEY_BLOCK]);

    // The candidate files that matched nothing are inspected, not unknown: the pack
    // has complete information and stays silent.
    assert.equal(credential.metadata.unresolved, 0);
    // Every candidate was fully inspected: the three that matched nothing, the one
    // this rule reports, and the one the key-block rule reports.
    assert.equal(credential.metadata.inspected, 5);
  });

  it("produces an independent finding per artifact, so one file cannot mask another", async () => {
    const run = await runRules(SENSITIVE);
    const dotenv = resultOf(run, SECURITY_RULE_IDS.DOTENV);
    assert.equal(dotenv.findings.length, 2);
    assert.notDeepEqual(dotenv.findings[0].evidence, dotenv.findings[1].evidence);
  });
});

// ─── Container build context ─────────────────────────────────────────────────

describe("security pack: container build context", () => {
  it("reports a Dockerfile with no ignore file beside it", async () => {
    const run = await runRules(DOCKER_UNPROTECTED);
    const entry = resultOf(run, SECURITY_RULE_IDS.CONTAINER_IGNORE);
    assert.equal(entry.status, RULE_OUTCOME_STATUSES.VIOLATION);
    assert.deepEqual(entry.findings.map((finding) => finding.metadata.path), ["Dockerfile"]);
    assert.ok(entry.findings[0].evidence.includes("evidence:inventory:Dockerfile"));
  });

  it("passes when the ignore file sits beside the Dockerfile", async () => {
    const run = await runRules(DOCKER_PROTECTED);
    const entry = resultOf(run, SECURITY_RULE_IDS.CONTAINER_IGNORE);
    assert.equal(entry.status, RULE_OUTCOME_STATUSES.PASS);
    assert.equal(entry.metadata.dockerfiles, 1);
    assert.equal(entry.metadata.dockerignores, 1);
  });

  it("still reports when the ignore file exists in a different directory", async () => {
    const run = await runRules(DOCKER_ELSEWHERE);
    const entry = resultOf(run, SECURITY_RULE_IDS.CONTAINER_IGNORE);
    assert.equal(entry.status, RULE_OUTCOME_STATUSES.VIOLATION);
    assert.deepEqual(entry.findings.map((finding) => finding.metadata.path), ["Dockerfile"]);
  });

  it("passes with no container build at all, and declines when coverage is unknown", async () => {
    const complete = await runRules(CLEAN);
    assert.equal(statusOf(complete, SECURITY_RULE_IDS.CONTAINER_IGNORE), RULE_OUTCOME_STATUSES.PASS);
    assert.equal(resultOf(complete, SECURITY_RULE_IDS.CONTAINER_IGNORE).metadata.dockerfiles, 0);

    const partial = await runRules(CLEAN_PARTIAL);
    assert.equal(
      statusOf(partial, SECURITY_RULE_IDS.CONTAINER_IGNORE),
      RULE_OUTCOME_STATUSES.UNKNOWN,
    );
  });
});

// ─── Coverage semantics ──────────────────────────────────────────────────────

describe("security pack: coverage semantics", () => {
  it("turns an absence claim over an incomplete inventory into unknown, never pass", async () => {
    const run = await runRules(CLEAN_PARTIAL);

    assert.deepEqual(run.findings, []);
    assert.equal(run.complete, false);
    for (const entry of run.rules) {
      assert.equal(entry.status, RULE_OUTCOME_STATUSES.UNKNOWN, entry.rule.id);
      assert.equal(entry.applicability.coverage, APPLICABILITY_COVERAGE.UNKNOWN);
      assert.ok(entry.applicability.reason.length > 0);
      assert.notEqual(entry.status, RULE_OUTCOME_STATUSES.NOT_APPLICABLE);
    }
  });

  it("treats an unreadable path as unknown, because something there was never seen", async () => {
    const run = await runRules(CLEAN_UNREADABLE);
    for (const entry of run.rules) {
      assert.equal(entry.status, RULE_OUTCOME_STATUSES.UNKNOWN, entry.rule.id);
      assert.ok(entry.applicability.reason.includes("could not be read"));
    }
  });

  it("still reports what it did observe in an incomplete scan", async () => {
    const run = await runRules(SENSITIVE_PARTIAL);
    // Coverage limits the *absence* claim; it must never suppress an observation.
    assert.equal(run.findings.length, 11);
    assert.equal(statusOf(run, SECURITY_RULE_IDS.DOTENV), RULE_OUTCOME_STATUSES.VIOLATION);
    assert.equal(statusOf(run, SECURITY_RULE_IDS.KEYSTORE), RULE_OUTCOME_STATUSES.VIOLATION);
    assert.equal(statusOf(run, SECURITY_RULE_IDS.TERRAFORM_STATE), RULE_OUTCOME_STATUSES.VIOLATION);
    // The one rule whose claim needs the absence half still declines, even though it
    // observed a Dockerfile: "no .dockerignore beside it" is not established here.
    assert.equal(
      statusOf(run, SECURITY_RULE_IDS.CONTAINER_IGNORE),
      RULE_OUTCOME_STATUSES.UNKNOWN,
    );
    assert.equal(run.metadata.repositoryCoverage, "partial");
  });

  it("keeps every rule's outcome coherent enough to validate", async () => {
    for (const model of [CLEAN, SENSITIVE, CLEAN_PARTIAL, CLEAN_UNREADABLE, DOCKER_ELSEWHERE]) {
      const run = await runRules(model);
      assert.equal(run.rules.length, EXPECTED_RULE_IDS.length);
      assert.equal(run.complete, run.rules.every((entry) => entry.status === "pass" || entry.status === "violation"));
    }
  });
});

// ─── Evidence ────────────────────────────────────────────────────────────────

describe("security pack: evidence", () => {
  it("cites only evidence the repository model already holds", async () => {
    const run = await runRules(SENSITIVE);
    const model = SENSITIVE;
    for (const entry of run.rules) {
      for (const finding of entry.findings) {
        for (const id of finding.evidence) {
          const record = getEvidence(model, id);
          assert.ok(record, `${id} must exist in the model`);
          assert.ok(record.location.path.length > 0);
          assert.equal(record.location.path.startsWith("/"), false);
        }
      }
    }
  });

  it("re-emits no evidence of its own: the run's evidence is the model's", async () => {
    const run = await runRules(SENSITIVE);
    const modelEvidenceIds = new Set(Object.keys(SENSITIVE.indexes.evidenceById));
    // Every record the run carries is either the model's own or absent; the pack
    // fabricates nothing, so nothing new can appear.
    for (const record of run.evidence) {
      assert.ok(modelEvidenceIds.has(record.id), `${record.id} must be a model record`);
    }
  });

  it("resolves the observed artifact rather than a derived substitute", async () => {
    const record = getEvidence(SENSITIVE, "evidence:inventory:id_rsa");
    assert.ok(record);
    assert.equal(record.location.path, "id_rsa");
    const run = await runRules(SENSITIVE);
    const finding = resultOf(run, SECURITY_RULE_IDS.PRIVATE_KEY).findings[0];
    assert.deepEqual(finding.evidence, ["evidence:inventory:id_rsa"]);
  });

  it("leaves an inventory gap visible: a partial scan produces no evidence at all", async () => {
    const run = await runRules(CLEAN_PARTIAL);
    assert.deepEqual(run.evidence, []);
    assert.deepEqual(run.findings, []);
  });
});

// ─── Findings and fingerprints ───────────────────────────────────────────────

describe("security pack: canonical findings", () => {
  it("reaches the Phase 9 Finding Engine and comes back canonical", async () => {
    const result = await runAnalyzer(SENSITIVE);
    assert.equal(result.findings.length, 12);
    for (const finding of result.findings) {
      assert.match(finding.fingerprint, /^cg-fp1-[0-9a-f]{32}$/);
      assert.equal(finding.id, `finding:${finding.fingerprint}`);
      assert.equal(finding.metadata.analyzer.id, SECURITY_ANALYZER_ID);
      assert.equal(finding.metadata.analyzer.scope, "security");
      assert.equal(finding.status, "open");
      assert.ok(finding.evidence.length > 0);
    }
    assert.deepEqual(
      [...new Set(result.findings.map((finding) => finding.ruleId))].sort(),
      EXPECTED_RULE_IDS,
    );
  });

  it("gives two artifacts of the same rule two different fingerprints", async () => {
    const result = await runAnalyzer(SENSITIVE);
    const dotenv = result.findings.filter((finding) => finding.ruleId === SECURITY_RULE_IDS.DOTENV);
    assert.equal(dotenv.length, 2);
    assert.notEqual(dotenv[0].fingerprint, dotenv[1].fingerprint);
  });

  it("keeps fingerprints stable across runs of the same model", async () => {
    const first = await runAnalyzer(SENSITIVE);
    const second = await runAnalyzer(SENSITIVE);
    assert.deepEqual(
      first.findings.map((finding) => finding.fingerprint),
      second.findings.map((finding) => finding.fingerprint),
    );
  });

  it("changes a fingerprint when the observation set changes", async () => {
    const withKey = await runAnalyzer(
      modelOf({ paths: [...BASE_PATHS, "id_rsa"] }),
    );
    const withOtherKey = await runAnalyzer(
      modelOf({ paths: [...BASE_PATHS, "keys/deploy.ppk"] }),
    );
    const keyFinding = (result) =>
      result.findings.find((finding) => finding.ruleId === SECURITY_RULE_IDS.PRIVATE_KEY);
    assert.ok(keyFinding(withKey));
    assert.ok(keyFinding(withOtherKey));
    assert.notEqual(keyFinding(withKey).fingerprint, keyFinding(withOtherKey).fingerprint);
  });
});

// ─── Isolation ───────────────────────────────────────────────────────────────

const FIXTURE_EVIDENCE = createEvidence({
  id: "evidence:security:fixture",
  type: "configuration",
  location: { path: "package.json" },
  source: { analyzer: "security.fixture-rule", method: "fixture" },
  data: {},
  provenance: { deterministic: true, collector: "security.fixture-rule" },
});

function fixtureRule(overrides = {}) {
  return createRule({
    id: "security.fixture-rule",
    version: "1.0.0",
    category: SECURITY_CATEGORY,
    title: "Fixture rule",
    description: "a fixture rule",
    severity: "low",
    applicability: {},
    detect: () => [],
    remediation: {},
    metadata: {},
    ...overrides,
  });
}

describe("security pack: isolation", () => {
  it("keeps the remaining rules running when one throws", async () => {
    const rules = [
      ...securityRules,
      fixtureRule({
        detect: () => {
          throw new Error("boom");
        },
      }),
    ];
    const run = await runRules(SENSITIVE, { rules });
    assert.equal(statusOf(run, "security.fixture-rule"), RULE_OUTCOME_STATUSES.FAILED);
    assert.equal(run.rules.filter((entry) => entry.status === RULE_OUTCOME_STATUSES.VIOLATION).length, 11);
    assert.equal(run.complete, false);
  });

  it("isolates malformed output and records the kind", async () => {
    const rules = [...securityRules, fixtureRule({ detect: () => ({ findings: "nope" }) })];
    const run = await runRules(CLEAN, { rules });
    const entry = resultOf(run, "security.fixture-rule");
    assert.equal(entry.status, RULE_OUTCOME_STATUSES.FAILED);
    assert.equal(entry.errors[0].kind, RULE_FAILURE_KINDS.INVALID_RULE_RESULT);
  });

  it("isolates an emitted record that is not valid Evidence", async () => {
    const rules = [
      ...securityRules,
      fixtureRule({
        id: "security.bad-evidence",
        detect: () => ({ evidence: [{ id: "evidence:security:bad" }], findings: [] }),
      }),
    ];
    const run = await runRules(CLEAN, { rules });
    const entry = resultOf(run, "security.bad-evidence");
    assert.equal(entry.status, RULE_OUTCOME_STATUSES.FAILED);
    assert.equal(entry.errors[0].kind, RULE_FAILURE_KINDS.INVALID_EVIDENCE);
  });

  it("isolates a missing confidence, which is the rule's claim to make", async () => {
    const rules = [
      ...securityRules,
      fixtureRule({ detect: () => [{ evidence: ["evidence:inventory:package.json"] }] }),
    ];
    const run = await runRules(CLEAN, { rules });
    const entry = resultOf(run, "security.fixture-rule");
    assert.equal(entry.status, RULE_OUTCOME_STATUSES.FAILED);
    assert.equal(entry.errors[0].kind, RULE_FAILURE_KINDS.INVALID_FINDING);
  });

  it("skips later rules only when fail-fast is asked for", async () => {
    const rules = [
      fixtureRule({ id: "security.a-breaks", detect: () => { throw new Error("boom"); } }),
      ...securityRules,
    ];
    const run = await runRules(CLEAN, { rules, failFast: true });
    assert.equal(statusOf(run, "security.a-breaks"), RULE_OUTCOME_STATUSES.FAILED);
    const skipped = run.rules.filter((entry) => entry.status === RULE_OUTCOME_STATUSES.SKIPPED);
    assert.equal(skipped.length, securityRules.length);
    assert.equal(run.findings.length, 0);
  });

  it("stops one rule from citing another rule's evidence", async () => {
    const emitter = fixtureRule({
      id: "security.emitter",
      detect: () => ({
        findings: [{ confidence: 1, evidence: [FIXTURE_EVIDENCE.id] }],
        evidence: [FIXTURE_EVIDENCE],
      }),
    });
    const citer = fixtureRule({
      id: "security.citer",
      detect: () => ({ findings: [{ confidence: 1, evidence: [FIXTURE_EVIDENCE.id] }] }),
    });
    const run = await runRules(CLEAN, { rules: [...securityRules, emitter, citer] });
    assert.equal(statusOf(run, "security.emitter"), RULE_OUTCOME_STATUSES.VIOLATION);
    assert.equal(statusOf(run, "security.citer"), RULE_OUTCOME_STATUSES.FAILED);
    assert.equal(resultOf(run, "security.citer").errors[0].kind, RULE_FAILURE_KINDS.INVALID_FINDING);
  });

  it("refuses a second copy of the same evidence id in one run", async () => {
    const a = fixtureRule({
      id: "security.emits-a",
      detect: () => ({ evidence: [FIXTURE_EVIDENCE], findings: [{ confidence: 1, evidence: [FIXTURE_EVIDENCE.id] }] }),
    });
    const b = fixtureRule({
      id: "security.emits-b",
      detect: () => ({ evidence: [FIXTURE_EVIDENCE], findings: [{ confidence: 1, evidence: [FIXTURE_EVIDENCE.id] }] }),
    });
    const run = await runRules(CLEAN, { rules: [...securityRules, a, b] });
    assert.equal(statusOf(run, "security.emits-a"), RULE_OUTCOME_STATUSES.VIOLATION);
    assert.equal(statusOf(run, "security.emits-b"), RULE_OUTCOME_STATUSES.FAILED);
    assert.equal(
      resultOf(run, "security.emits-b").errors[0].kind,
      RULE_FAILURE_KINDS.DUPLICATE_EVIDENCE_ID,
    );
  });

  it("keeps a running rule set independent of the caller's own rule objects", async () => {
    // A rule cannot reach another rule's state: the registry runs frozen structural
    // copies, so mutating the objects a caller handed over changes nothing.
    const callerRules = securityRules.map((rule) => ({ ...rule }));
    const registry = createSecurityRuleRegistry({ rules: callerRules });
    const registered = registry.get(SECURITY_RULE_IDS.DOTENV);
    assert.ok(Object.isFrozen(registered));
    assert.throws(() => {
      "use strict";
      registered.severity = "info";
    }, TypeError);

    callerRules.find((rule) => rule.id === SECURITY_RULE_IDS.DOTENV).severity = "info";
    // The registry built before the mutation is unaffected: it owns a frozen copy.
    assert.equal(registry.get(SECURITY_RULE_IDS.DOTENV).severity, "high");
    // A registry built *after* it registers exactly what it was given, which is why
    // the shipped pack is a module constant and not something a caller can edit.
    const rebuilt = createSecurityRuleRegistry({ rules: callerRules });
    assert.equal(rebuilt.get(SECURITY_RULE_IDS.DOTENV).severity, "info");
  });
});

// ─── Determinism ─────────────────────────────────────────────────────────────

describe("security pack: determinism", () => {
  it("produces identical results for identical inputs", async () => {
    const first = await runRules(SENSITIVE);
    const second = await runRules(SENSITIVE);
    assert.deepEqual(stableAnalysisView(first), stableAnalysisView(second));

    const third = await runAnalyzer(SENSITIVE);
    const fourth = await runAnalyzer(SENSITIVE);
    assert.deepEqual(stableAnalysisView(third), stableAnalysisView(fourth));
  });

  it("orders rules, findings and evidence deterministically", async () => {
    const run = await runRules(SENSITIVE);
    assert.deepEqual(ruleIdsOf(run), EXPECTED_RULE_IDS);
    assert.deepEqual(
      run.evidence.map((record) => record.id),
      [...run.evidence.map((record) => record.id)].sort(),
    );
    const result = await runAnalyzer(SENSITIVE);
    assert.deepEqual(
      result.findings.map((finding) => finding.fingerprint),
      [...result.findings.map((finding) => finding.fingerprint)].sort(),
    );
  });

  it("reports the rule set through the analyzer metadata, sorted", async () => {
    const result = await runAnalyzer(SENSITIVE);
    const analyzer = result.analyzers.find((entry) => entry.analyzer.id === SECURITY_ANALYZER_ID);
    assert.deepEqual(analyzer.metadata.ruleSet, EXPECTED_RULE_IDS);
    assert.equal(analyzer.metrics.rulesSelected, EXPECTED_RULE_IDS.length);
    assert.equal(analyzer.metrics.rulesViolated, EXPECTED_RULE_IDS.length);
    assert.deepEqual(analyzer.metadata.ruleFailures, []);
  });

  it("surfaces a coverage-limited rule as unavailable, with the reason", async () => {
    const result = await runAnalyzer(CLEAN_PARTIAL);
    const analyzer = result.analyzers.find((entry) => entry.analyzer.id === SECURITY_ANALYZER_ID);
    assert.equal(analyzer.metadata.unavailableRules.length, EXPECTED_RULE_IDS.length);
    for (const unavailable of analyzer.metadata.unavailableRules) {
      assert.ok(unavailable.reason.length > 0);
      assert.ok(EXPECTED_RULE_IDS.includes(unavailable.ruleId));
    }
    assert.equal(analyzer.metrics.rulesUnknown, EXPECTED_RULE_IDS.length);
    assert.deepEqual(result.findings, []);
  });
});

// ─── Architectural boundary ──────────────────────────────────────────────────

describe("security pack: architectural boundary", () => {
  const SECURITY_DIR = join(dirname(fileURLToPath(import.meta.url)), "..", "src", "rules", "security");

  function sourceFiles(dir) {
    const files = [];
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const full = join(dir, entry.name);
      if (entry.isDirectory()) files.push(...sourceFiles(full));
      else if (entry.name.endsWith(".js")) files.push(full);
    }
    return files;
  }

  const files = sourceFiles(SECURITY_DIR);

  it("covers every security source file", () => {
    assert.ok(files.length >= 7, `expected the pack's modules, found ${files.length}`);
  });

  it("imports nothing but sibling modules inside the rules layer", () => {
    for (const file of files) {
      const source = readFileSync(file, "utf8");
      const specifiers = [...source.matchAll(/from\s+"([^"]+)"/g)].map((match) => match[1]);
      for (const specifier of specifiers) {
        assert.ok(specifier.startsWith("."), `${file} imports disallowed module "${specifier}"`);
      }
    }
  });

  it("has no filesystem, path, process, network, transport or worker access", () => {
    const forbidden = [
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
      "stdio-server",
      "http-server",
    ];
    for (const file of files) {
      const source = readFileSync(file, "utf8");
      for (const needle of forbidden) {
        assert.ok(!source.includes(`"${needle}"`), `${file} must not reference "${needle}"`);
      }
    }
  });

  it("reads no file content and consults no clock, random source or environment", () => {
    const forbidden = [
      "readFile",
      "readdir",
      "createReadStream",
      "execSync",
      "spawnSync",
      "process.env",
      "Math.random",
      "Date.now",
      "new Date(",
    ];
    for (const file of files) {
      const source = readFileSync(file, "utf8");
      for (const needle of forbidden) {
        assert.ok(!source.includes(needle), `${file} must not use "${needle}"`);
      }
    }
  });

  it("gives rules no execution capability through the context", async () => {
    let received = null;
    const probe = fixtureRule({
      id: "security.probe",
      detect: (context) => {
        received = context;
        return [];
      },
    });
    await runRules(CLEAN, { rules: [...securityRules, probe] });
    for (const capability of ["filesystem", "fs", "spawn", "exec", "fetch", "http", "mcp", "tools"]) {
      assert.equal(capability in received, false, `context must not expose "${capability}"`);
    }
    assert.equal(typeof received.repository, "object");
  });

  it("keeps the pack's configuration signals equal to the scanner's", () => {
    // Drift guard: the constants the rules match against must be the signals the
    // scanner writes and the model preserves, or the container rule silently stops
    // firing without any test of the remaining rules noticing.
    assert.equal(CONFIGURATION_SIGNALS.DOCKERFILE, SCAN_SIGNALS.DOCKERFILE);
    assert.equal(CONFIGURATION_SIGNALS.CONTAINER_IGNORE, SCAN_SIGNALS.CONTAINER_IGNORE);

    const observed = Object.values(DOCKER_PROTECTED.indexes.entitiesById)
      .filter((entity) => entity.kind === "configuration")
      .map((entity) => entity.signal)
      .sort();
    assert.deepEqual(observed, [CONFIGURATION_SIGNALS.CONTAINER_IGNORE, CONFIGURATION_SIGNALS.DOCKERFILE]);
  });
});
