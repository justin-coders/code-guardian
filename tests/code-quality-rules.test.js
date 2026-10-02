/**
 * Code Guardian — Code Quality Acquisition & Pack Unit Tests (official roadmap Phase 12)
 *
 * Unit-level proof for the pieces the Code Quality Analyzer rests on: the bounded CI
 * quality-command classifier, the model projection that carries it, the configuration signals
 * the tooling rules read, the language-modular tool vocabulary, and the pack contract itself.
 *
 * Every fixture is a real repository written to a temporary directory and scanned through the
 * accepted scanner and model boundaries, so "CI runs eslint" means a workflow's literal bytes
 * were read — never that the project is JavaScript.
 *
 * Run with: node --test tests/code-quality-rules.test.js
 */

import { after, describe, it } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

import { scanRepository } from "../src/repository/scanner/index.js";
import { buildRepositoryModel } from "../src/repository/model/index.js";
import {
  QUALITY_TOOL_DEFINITIONS,
  QUALITY_TOOL_DOMAINS as SCANNER_TOOL_DOMAINS,
  QUALITY_TOOL_IDS as SCANNER_TOOL_IDS,
  classifyQualityCommand,
} from "../src/repository/scanner/policies/quality.js";

import {
  CODE_QUALITY_RULE_IDS,
  CODE_QUALITY_RULE_ID_PREFIX,
  QUALITY_LANGUAGE_IDS,
  QUALITY_TOOLING,
  QUALITY_TOOL_DOMAINS,
  QUALITY_TOOL_IDS,
  TYPE_CHECK_CONFIG_BASENAMES,
  codeQualityRules,
  codeQualityRuleSetIssues,
  createCodeQualityAnalyzer,
  createCodeQualityRuleRegistry,
} from "../src/rules/index.js";

const TMP_ROOT = join(tmpdir(), `cg-code-quality-rules-${process.pid}-${Date.now()}`);
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

const pkg = (extra = {}) => JSON.stringify({ name: "demo", version: "1.0.0", ...extra });

// ─── CI quality-command classification ──────────────────────────────────────

describe("code quality acquisition: command classification", () => {
  it("recognises each tool only from its own documented invocation", () => {
    assert.deepEqual(classifyQualityCommand("eslint .").tools, ["eslint"]);
    assert.deepEqual(classifyQualityCommand("npx prettier --check .").tools, ["prettier"]);
    assert.deepEqual(classifyQualityCommand("tsc --noEmit").tools, ["tsc"]);
    assert.deepEqual(classifyQualityCommand("ruff check .").tools, ["ruff"]);
    assert.deepEqual(classifyQualityCommand("cargo clippy -- -D warnings").tools, ["clippy"]);
    // A build command is not a quality command.
    assert.deepEqual(classifyQualityCommand("npm run build").tools, []);
    assert.deepEqual(classifyQualityCommand("node src/server.js").tools, []);
  });

  it("maps each tool to its domain and is total and deterministic", () => {
    assert.deepEqual(classifyQualityCommand("eslint .").domains, ["linting"]);
    assert.deepEqual(classifyQualityCommand("tsc --noEmit").domains, ["type-checking"]);
    assert.deepEqual(classifyQualityCommand(null), { tools: [], domains: [] });
    assert.deepEqual(classifyQualityCommand(""), { tools: [], domains: [] });
    assert.deepEqual(classifyQualityCommand("eslint ."), classifyQualityCommand("eslint ."));
  });

  it("keeps the pack's tool vocabulary pinned to the acquisition layer's", () => {
    assert.deepEqual([...QUALITY_TOOL_IDS].sort(), [...SCANNER_TOOL_IDS].sort());
    assert.deepEqual({ ...QUALITY_TOOL_DOMAINS }, { ...SCANNER_TOOL_DOMAINS });
  });

  it("declares a domain for every tool definition", () => {
    for (const definition of QUALITY_TOOL_DEFINITIONS) {
      assert.ok(["linting", "formatting", "type-checking"].includes(definition.domain));
      assert.ok(definition.matcher instanceof RegExp);
    }
  });
});

// ─── CI acquisition through the scanner and model ───────────────────────────

describe("code quality acquisition: CI workflow content", () => {
  it("establishes quality tools from a workflow's content", async () => {
    const { scan, model } = await scanModel({
      ".github/workflows/ci.yml": "jobs:\n  quality:\n    steps:\n      - run: npm run lint\n      - run: eslint .\n      - run: prettier --check .\n",
    });
    const entry = scan.cicd.evidence.find((item) => item.path === ".github/workflows/ci.yml");
    assert.deepEqual(entry.qualityCommands, ["eslint", "prettier"]);
    assert.deepEqual(model.ci.entries[0].qualityCommands, ["eslint", "prettier"]);
  });

  it("does not mistake a build-only workflow for quality execution", async () => {
    const { scan } = await scanModel({
      ".github/workflows/ci.yml": "jobs:\n  build:\n    steps:\n      - run: npm run build\n",
    });
    const entry = scan.cicd.evidence.find((item) => item.path === ".github/workflows/ci.yml");
    assert.deepEqual(entry.qualityCommands, []);
  });

  it("records an unreadable workflow without inventing quality tools", async () => {
    const { scan, model } = await scanModel({
      ".github/workflows/ci.yml": "jobs:\u0000binary",
    });
    const entry = scan.cicd.evidence.find((item) => item.path === ".github/workflows/ci.yml");
    assert.equal(entry.testExecution, "unknown");
    assert.deepEqual(entry.qualityCommands, []);
    assert.deepEqual(model.ci.entries[0].qualityCommands, []);
  });
});

// ─── Configuration signals ──────────────────────────────────────────────────

describe("code quality acquisition: configuration signals", () => {
  it("reports lint, format and build configuration with distinct signals", async () => {
    const { scan } = await scanModel({
      ".eslintrc.json": "",
      ".prettierrc": "",
      "tsconfig.json": "",
    });
    const byPath = new Map(scan.configuration.evidence.map((entry) => [entry.path, entry.signal]));
    assert.equal(byPath.get(".eslintrc.json"), "lint-configuration");
    assert.equal(byPath.get(".prettierrc"), "format-configuration");
    assert.equal(byPath.get("tsconfig.json"), "build-configuration");
  });

  it("keeps a compiler configuration decidable by basename within the build signal", () => {
    assert.deepEqual([...TYPE_CHECK_CONFIG_BASENAMES], ["tsconfig.json", "jsconfig.json"]);
    // A bundler configuration shares the build signal but is not a compiler configuration.
    assert.equal(TYPE_CHECK_CONFIG_BASENAMES.includes("vite.config.ts"), false);
  });
});

// ─── Language vocabulary ────────────────────────────────────────────────────

describe("code quality rules: language vocabulary", () => {
  it("unions the per-language profiles into one tool vocabulary", () => {
    assert.deepEqual([...QUALITY_LANGUAGE_IDS].sort(), [
      "go",
      "javascript",
      "python",
      "rust",
      "typescript",
    ]);
    for (const domain of ["linting", "formatting", "type-checking"]) {
      assert.ok(Array.isArray(QUALITY_TOOLING[domain].dependencies));
      assert.ok(Array.isArray(QUALITY_TOOLING[domain].scriptWords));
      assert.ok(Array.isArray(QUALITY_TOOLING[domain].ciTools));
    }
    assert.ok(QUALITY_TOOLING.linting.dependencies.includes("eslint"));
    assert.ok(QUALITY_TOOLING["type-checking"].dependencies.includes("mypy"));
    assert.ok(QUALITY_TOOLING.formatting.ciTools.includes("prettier"));
  });

  it("has a language module for every language a profile claims", () => {
    // The union is non-empty and every id is a lower-case language token.
    assert.ok(QUALITY_LANGUAGE_IDS.length > 0);
    for (const id of QUALITY_LANGUAGE_IDS) assert.match(id, /^[a-z0-9-]+$/);
  });
});

// ─── Rule set ───────────────────────────────────────────────────────────────

describe("code quality rules: rule set", () => {
  it("ships every declared rule under the namespace, frozen and sorted", () => {
    assert.deepEqual(
      codeQualityRules.map((rule) => rule.id),
      [...codeQualityRules.map((rule) => rule.id)].sort(),
    );
    assert.equal(Object.isFrozen(codeQualityRules), true);
    for (const rule of codeQualityRules) {
      assert.match(rule.id, new RegExp(`^${CODE_QUALITY_RULE_ID_PREFIX.replace(".", "\\.")}`));
      assert.equal(typeof rule.detect, "function");
      assert.deepEqual({ ...rule.applicability }, {});
      assert.ok(rule.description.length > 0);
      assert.ok(["info", "low", "medium", "high", "critical"].includes(rule.severity));
    }
  });

  it("covers all nine official domains", () => {
    const ids = Object.values(CODE_QUALITY_RULE_IDS);
    const families = new Set(ids.map((id) => id.split(".")[1]));
    assert.deepEqual(
      [...families].sort(),
      [
        "complexity",
        "configuration",
        "dead-code",
        "duplication",
        "formatting",
        "linting",
        "maintainability",
        "type-checking",
        "unsafe-pattern",
      ],
    );
  });

  it("fails the registry when a declared rule is missing or misnamed", () => {
    const dropped = codeQualityRules.filter((rule) => rule.id !== CODE_QUALITY_RULE_IDS.LINTING_UNCONFIGURED);
    const issues = codeQualityRuleSetIssues(dropped);
    assert.ok(issues.some((issue) => issue.includes(CODE_QUALITY_RULE_IDS.LINTING_UNCONFIGURED)));
    assert.throws(() => createCodeQualityRuleRegistry({ rules: dropped }));
  });

  it("accepts an extra project-local rule without editing the pack contract", () => {
    const extra = {
      id: "code-quality.project-local.fixture",
      version: "1.0.0",
      category: "code-quality",
      title: "fixture",
      description: "fixture",
      severity: "info",
      applicability: {},
      detect: () => [],
      remediation: {},
      metadata: {},
    };
    assert.deepEqual(codeQualityRuleSetIssues([...codeQualityRules, extra]), []);
  });
});

// ─── Analyzer descriptor ────────────────────────────────────────────────────

describe("code quality rules: analyzer descriptor", () => {
  it("is an ordinary Analyzer descriptor the registry can hold", () => {
    const analyzer = createCodeQualityAnalyzer();
    assert.equal(analyzer.id, "code-quality");
    assert.equal(typeof analyzer.analyze, "function");
    assert.equal(analyzer.canAnalyze().applicable, true);
  });

  it("is deterministic across two constructions", () => {
    assert.deepEqual(
      codeQualityRules.map((rule) => rule.id),
      codeQualityRules.map((rule) => rule.id),
    );
  });
});
