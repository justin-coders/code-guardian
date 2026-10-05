/**
 * Code Guardian — Rule Registry Tests (Phase 18)
 *
 * The framework contract for the Phase 18 Rule Registry: registration, lookup,
 * version discovery, filtering, applicability delegation, enable/disable,
 * category selection, configuration and metadata discovery — each deterministic,
 * each derived from the canonical registered entries, and each preserving the
 * Phase 10 backward-compatible surface.
 *
 * Like `tests/rule-engine.test.js`, every rule here is a **test fixture**, and the
 * repository model is a real Phase 8D model built from a hand-built ScanResult, so
 * applicability is exercised against the contract it will actually receive.
 *
 * Run with: node --test tests/rule-registry.test.js
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";

import { createRule } from "../src/core/index.js";

import { createScanResult } from "../src/repository/scanner/index.js";
import { buildRepositoryModel } from "../src/repository/model/index.js";

import { buildAnalysisContext } from "../src/analysis/index.js";

import {
  APPLICABILITY_COVERAGE,
  RULE_CONFIGURATION_KEYS,
  RULE_FAILURE_KINDS,
  RULE_FILTER_KEYS,
  RuleConfigurationError,
  RuleRegistrationError,
  createRuleRegistry,
  evaluateRuleApplicability,
  // Existing packs (Phase 10–17) for the compatibility proof.
  architectureRules,
  apiAnalysisRules,
  cicdRules,
  codeQualityRules,
  createApiAnalysisRuleRegistry,
  createArchitectureRuleRegistry,
  createCicdRuleRegistry,
  createCodeQualityRuleRegistry,
  createDependencyAnalysisRuleRegistry,
  createReliabilityAnalysisRuleRegistry,
  createSecurityRuleRegistry,
  createTestingRuleRegistry,
  dependencyAnalysisRules,
  reliabilityAnalysisRules,
  securityRules,
  testingRules,
} from "../src/rules/index.js";

// ─── Fixtures: a real RepositoryModel ────────────────────────────────────────

const ISO = "2026-01-01T00:00:00.000Z";
const byPath = (a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0);

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

const filesOf = (...paths) => paths.map((path) => toEntry(path)).sort(byPath);
const dirsOf = (...paths) => paths.map((path) => toEntry(path, true)).sort(byPath);
const signal = (path, signalId, extra = {}) => ({ path, signal: signalId, ...extra });

function buildModel(overrides = {}) {
  return buildRepositoryModel(
    createScanResult({
      root: "/scan-root",
      scannedAt: ISO,
      files: filesOf("package.json", "src/app.js", "src/util.js", "tests/app.test.js"),
      directories: dirsOf("src", "tests"),
      languages: [
        {
          id: "javascript",
          fileCount: 3,
          extensions: [".js"],
          evidence: [
            signal("src/app.js", "source-extension"),
            signal("src/util.js", "source-extension"),
          ],
          evidenceTruncated: false,
        },
      ],
      manifests: [
        {
          path: "package.json",
          name: "package.json",
          directory: ".",
          ecosystem: "node",
          kind: "manifest",
          languages: ["javascript"],
          parse: { status: "parsed", format: "json", bytes: 12 },
        },
      ],
      tests: {
        detected: true,
        frameworks: ["node-test"],
        evidence: [
          signal("tests", "test-directory", { kind: "directory", framework: null }),
          signal("tests/app.test.js", "test-file", { kind: "file", framework: "node-test" }),
        ],
        evidenceTruncated: false,
      },
      statistics: {
        filesScanned: 4,
        directoriesScanned: 2,
        symlinksScanned: 0,
        ignored: 0,
        unreadable: 0,
        truncatedBy: [],
      },
      scan: { complete: true, truncated: false, limits: { maxFiles: 10000, maxDepth: 20 }, errors: [] },
      ...overrides,
    }),
  );
}

const MODEL = buildModel();
const TRUNCATED_MODEL = buildModel({
  scan: { complete: false, truncated: true, limits: { maxFiles: 2, maxDepth: 20 }, errors: [] },
});
const context = (model = MODEL) => buildAnalysisContext({ repository: model });

// ─── Fixtures: rules ─────────────────────────────────────────────────────────

function ruleOf(overrides = {}) {
  return createRule({
    id: "testing.fixture-rule",
    version: "1.0.0",
    category: "testing",
    title: "Fixture rule",
    description: "a fixture rule",
    severity: "medium",
    applicability: {},
    detect: () => [],
    remediation: { summary: "fix it" },
    metadata: {},
    ...overrides,
  });
}

const CATALOG = [
  ruleOf({
    id: "security.a",
    category: "security",
    version: "1.0.0",
    metadata: { tags: ["network", "auth"] },
  }),
  ruleOf({
    id: "security.b",
    category: "security",
    version: "2.0.0",
    metadata: { tags: ["network"], deprecated: true },
  }),
  ruleOf({ id: "reliability.a", category: "reliability", version: "1.0.0", metadata: { tags: ["io"] } }),
  ruleOf({ id: "testing.a", category: "testing", version: "1.0.0" }),
];

const idsOf = (rules) => rules.map((rule) => rule.id);

// ─── Registration / lookup ───────────────────────────────────────────────────

describe("rule registry: registration and lookup", () => {
  it("registers, then looks up and lists in deterministic id order", () => {
    const registry = createRuleRegistry();
    registry.register(CATALOG[3]).register(CATALOG[1]);
    registry.registerAll([CATALOG[2], CATALOG[0]]);
    assert.equal(registry.size, 4);
    assert.deepEqual(registry.ids(), ["reliability.a", "security.a", "security.b", "testing.a"]);
    assert.deepEqual(idsOf(registry.list()), registry.ids());
    assert.equal(registry.lookup("security.a"), registry.get("security.a"));
    assert.equal(registry.has("security.a"), true);
    assert.equal(registry.lookup("security.zzz"), null);
    assert.equal(registry.has("security.zzz"), false);
  });

  it("rejects a duplicate id deterministically", () => {
    const registry = createRuleRegistry([CATALOG[0]]);
    assert.throws(() => registry.register(CATALOG[0]), RuleConfigurationError);
    assert.equal(registry.size, 1);
  });

  it("rejects an invalid descriptor", () => {
    assert.throws(() => createRuleRegistry([{ id: "security.bad" }]), RuleRegistrationError);
  });

  it("exposes the declared version and never substitutes one", () => {
    const registry = createRuleRegistry(CATALOG);
    assert.equal(registry.version("security.b"), "2.0.0");
    assert.equal(registry.version("security.b"), registry.lookup("security.b").version);
    assert.equal(registry.version("security.missing"), null);
  });

  it("accepts an initial configuration object", () => {
    const registry = createRuleRegistry(CATALOG, { disabled: ["security.b"] });
    assert.equal(registry.isEnabled("security.b"), false);
    assert.equal(registry.isEnabled("security.a"), true);
  });
});

// ─── Filter ──────────────────────────────────────────────────────────────────

describe("rule registry: filter", () => {
  it("filters by category, tag, namespace, version and deprecation deterministically", () => {
    const registry = createRuleRegistry(CATALOG);
    assert.deepEqual(idsOf(registry.filter({ category: "security" })), ["security.a", "security.b"]);
    assert.deepEqual(idsOf(registry.filter({ tags: ["network"] })), ["security.a", "security.b"]);
    assert.deepEqual(idsOf(registry.filter({ tags: ["io"] })), ["reliability.a"]);
    assert.deepEqual(idsOf(registry.filter({ namespace: "security" })), ["security.a", "security.b"]);
    assert.deepEqual(idsOf(registry.filter({ version: "2.0.0" })), ["security.b"]);
    assert.deepEqual(idsOf(registry.filter({ deprecated: true })), ["security.b"]);
    assert.deepEqual(idsOf(registry.filter({ deprecated: false })), [
      "reliability.a",
      "security.a",
      "testing.a",
    ]);
  });

  it("combines keys with AND and multi-values with OR", () => {
    const registry = createRuleRegistry(CATALOG);
    // (category security OR reliability) AND (tags include network)
    assert.deepEqual(
      idsOf(registry.filter({ category: ["security", "reliability"], tags: ["network"] })),
      ["security.a", "security.b"],
    );
  });

  it("returns an empty list for unknown values and never mutates state", () => {
    const registry = createRuleRegistry(CATALOG);
    const before = registry.ids();
    assert.deepEqual(registry.filter({ category: "nope" }), []);
    assert.deepEqual(registry.filter({ id: ["security.a", "security.a"] }).map((r) => r.id), ["security.a"]);
    assert.deepEqual(registry.ids(), before);
  });

  it("rejects an unknown selector key rather than ignoring it", () => {
    const registry = createRuleRegistry(CATALOG);
    assert.throws(() => registry.filter({ colur: "security" }), RuleConfigurationError);
    assert.throws(() => registry.filter({ deprecated: "yes" }), RuleConfigurationError);
    assert.deepEqual(RULE_FILTER_KEYS.includes("category"), true);
  });

  it("returns disabled rules as catalog entries", () => {
    const registry = createRuleRegistry(CATALOG, { disabled: ["security.b"] });
    assert.deepEqual(idsOf(registry.filter({ category: "security" })), ["security.a", "security.b"]);
    assert.deepEqual(idsOf(registry.filter({ enabled: true })), [
      "reliability.a",
      "security.a",
      "testing.a",
    ]);
    assert.deepEqual(idsOf(registry.filter({ enabled: false })), ["security.b"]);
  });
});

// ─── Enable / disable ────────────────────────────────────────────────────────

describe("rule registry: enable and disable", () => {
  it("disables a rule but leaves it discoverable", () => {
    const registry = createRuleRegistry(CATALOG);
    registry.disable("security.b");
    assert.equal(registry.isEnabled("security.b"), false);
    assert.equal(registry.has("security.b"), true);
    assert.equal(registry.lookup("security.b").id, "security.b");
    assert.equal(registry.version("security.b"), "2.0.0");
    assert.equal(registry.ids().includes("security.b"), true);
    assert.equal(registry.describe("security.b").enabled, false);
    assert.equal(registry.filter({ id: "security.b" }).length, 1);
    assert.equal(registry.configuration().disabled.includes("security.b"), true);
  });

  it("excludes disabled rules from execution selection and restores them on enable", () => {
    const registry = createRuleRegistry(CATALOG);
    registry.disable("security.b");
    assert.deepEqual(registry.enabledIds().includes("security.b"), false);
    assert.deepEqual(idsOf(registry.selectCategories(["security"])), ["security.a"]);
    assert.throws(() => registry.select(["security.b"]), RuleConfigurationError);
    registry.enable("security.b");
    assert.equal(registry.isEnabled("security.b"), true);
    assert.deepEqual(idsOf(registry.select(["security.b"])), ["security.b"]);
  });

  it("keeps explicit disable winning over enable, deterministically", () => {
    const registry = createRuleRegistry(CATALOG, { enabled: ["security.a"], disabled: ["security.a"] });
    assert.equal(registry.isEnabled("security.a"), false);
  });

  it("fails explicitly for unknown ids", () => {
    const registry = createRuleRegistry(CATALOG);
    assert.throws(() => registry.enable("nope.a"), (error) => {
      assert.equal(error.kind, RULE_FAILURE_KINDS.UNKNOWN_RULE);
      return true;
    });
    assert.throws(() => registry.disable("nope.a"), RuleConfigurationError);
    assert.throws(() => registry.isEnabled("nope.a"), RuleConfigurationError);
  });
});

// ─── Category selection ──────────────────────────────────────────────────────

describe("rule registry: category selection", () => {
  it("selects enabled rules in the requested categories, id-sorted and deduped", () => {
    const registry = createRuleRegistry(CATALOG);
    assert.deepEqual(idsOf(registry.selectCategories(["security", "reliability"])), [
      "reliability.a",
      "security.a",
      "security.b",
    ]);
    assert.deepEqual(idsOf(registry.selectCategories(["security", "security"])), [
      "security.a",
      "security.b",
    ]);
  });

  it("rejects an unknown category", () => {
    const registry = createRuleRegistry(CATALOG);
    assert.throws(() => registry.selectCategories(["nope"]), (error) => {
      assert.equal(error.kind, RULE_FAILURE_KINDS.UNKNOWN_CATEGORY);
      return true;
    });
  });
});

// ─── Configuration ───────────────────────────────────────────────────────────

describe("rule registry: configuration", () => {
  it("applies the closed configuration schema and reports it deterministically", () => {
    const registry = createRuleRegistry(CATALOG).configure({
      disabled: ["security.b"],
      categories: ["security", "reliability"],
      ruleOptions: { "security.a": { strict: true } },
    });
    assert.deepEqual(idsOf(registry.selectCategories(["security", "reliability"])), ["reliability.a", "security.a"]);
    // testing.a is outside the allowed categories.
    assert.equal(registry.isEnabled("testing.a"), false);
    const config = registry.configuration();
    assert.deepEqual(config.disabled, ["security.b"]);
    assert.deepEqual(config.categories, ["reliability", "security"]);
    assert.deepEqual(config.ruleOptions, { "security.a": { strict: true } });
    assert.equal(Object.isFrozen(config), true);
    assert.equal(Object.isFrozen(config.ruleOptions["security.a"]), true);
    assert.deepEqual(RULE_CONFIGURATION_KEYS, [
      "enabled",
      "disabled",
      "includeRules",
      "excludeRules",
      "categories",
      "ruleOptions",
    ]);
  });

  it("rejects unknown keys, unknown ids, unknown categories and malformed values", () => {
    const registry = createRuleRegistry(CATALOG);
    assert.throws(() => registry.configure({ colour: "red" }), RuleConfigurationError);
    assert.throws(() => registry.configure({ disabled: ["nope.a"] }), RuleConfigurationError);
    assert.throws(() => registry.configure({ categories: ["nope"] }), RuleConfigurationError);
    assert.throws(() => registry.configure({ disabled: [42] }), RuleConfigurationError);
    assert.throws(() => registry.configure({ ruleOptions: [] }), RuleConfigurationError);
    assert.throws(() => registry.configure({ ruleOptions: { "nope.a": {} } }), RuleConfigurationError);
  });

  it("rejects hostile configuration shapes", () => {
    const registry = createRuleRegistry(CATALOG);
    const withProto = { ["__proto__"]: { polluted: true } };
    assert.throws(() => registry.configure({ ruleOptions: { "security.a": withProto } }), RuleConfigurationError);
    assert.throws(
      () => registry.configure({ ruleOptions: { "security.a": { constructor: {} } } }),
      RuleConfigurationError,
    );
    assert.throws(
      () => registry.configure({ ruleOptions: { "security.a": { fn: () => 1 } } }),
      RuleConfigurationError,
    );
    const cyclic = {};
    cyclic.self = cyclic;
    assert.throws(() => registry.configure({ ruleOptions: { "security.a": cyclic } }), RuleConfigurationError);

    let deep = 1;
    let nested = { value: deep };
    for (let i = 0; i < 10; i += 1) nested = { nested };
    assert.throws(() => registry.configure({ ruleOptions: { "security.a": nested } }), RuleConfigurationError);
    assert.throws(
      () => registry.configure({ ruleOptions: { "security.a": { list: new Array(500).fill(1) } } }),
      RuleConfigurationError,
    );
    assert.equal(({}).polluted, undefined);
  });

  it("accepts legitimate shared (non-cyclic) references in ruleOptions", () => {
    const registry = createRuleRegistry(CATALOG);
    const shared = { level: 1 };
    registry.configure({ ruleOptions: { "security.a": { left: shared, right: shared } } });
    const stored = registry.configuration().ruleOptions["security.a"];
    assert.deepEqual(stored.left, { level: 1 });
    assert.deepEqual(stored.right, { level: 1 });
  });

  it("overlays state without mutating Rule descriptors, the caller's object or registry entries", () => {
    const registry = createRuleRegistry(CATALOG);
    const before = registry.lookup("security.a");
    const config = { disabled: ["security.a"], ruleOptions: { "security.b": { n: 1 } } };
    const configSnapshot = JSON.parse(JSON.stringify(config));
    registry.configure(config);
    registry.configure(config); // idempotent
    assert.equal(registry.lookup("security.a"), before);
    assert.equal(Object.isFrozen(before), true);
    assert.equal(before.version, "1.0.0");
    assert.equal(before.detect instanceof Function, true);
    // The caller's own configuration object was not mutated.
    assert.deepEqual(JSON.parse(JSON.stringify(config)), configSnapshot);
    // Mutating the caller's object afterwards cannot reach the registry.
    config.ruleOptions["security.b"].n = 999;
    assert.equal(registry.configuration().ruleOptions["security.b"].n, 1);
  });
});

// ─── Metadata discovery ──────────────────────────────────────────────────────

describe("rule registry: metadata discovery", () => {
  it("describes a rule as safe declarative data with no executable internals", () => {
    const registry = createRuleRegistry(CATALOG);
    const described = registry.describe("security.a");
    assert.equal(described.id, "security.a");
    assert.equal(described.version, "1.0.0");
    assert.equal(described.category, "security");
    assert.equal(described.severity, "medium");
    assert.equal(described.title, "Fixture rule");
    assert.equal(typeof described.description, "string");
    assert.deepEqual(described.applicability, {});
    assert.deepEqual(described.metadata, { tags: ["network", "auth"] });
    assert.equal(described.deprecated, false);
    assert.equal(described.enabled, true);
    assert.equal("detect" in described, false);
    // Deeply frozen and no functions anywhere in the record.
    const walk = (value, path) => {
      if (typeof value === "function") assert.fail(`function leaked at ${path}`);
      if (value !== null && typeof value === "object") {
        assert.equal(Object.isFrozen(value), true, `${path} is frozen`);
        for (const key of Object.keys(value)) walk(value[key], `${path}.${key}`);
      }
    };
    walk(described, "describe");
    assert.equal(registry.describe("nope.a"), null);
  });

  it("describes all rules id-sorted", () => {
    const registry = createRuleRegistry(CATALOG);
    assert.deepEqual(registry.describeAll().map((entry) => entry.id), registry.ids());
    assert.equal(Object.isFrozen(registry.describeAll()), true);
  });

  it("does not let returned metadata mutate the registry", () => {
    const registry = createRuleRegistry(CATALOG);
    const described = registry.describe("security.a");
    assert.throws(() => {
      described.metadata.tags.push("mutated");
    });
    assert.throws(() => {
      described.id = "changed";
    });
    assert.deepEqual(registry.describe("security.a").metadata.tags, ["network", "auth"]);
  });
});

// ─── Applicability delegation ────────────────────────────────────────────────

describe("rule registry: applicability", () => {
  it("delegates to the single applicability evaluator", () => {
    const rule = ruleOf({ id: "testing.ts", applicability: { languages: ["typescript"] } });
    const registry = createRuleRegistry([rule]);
    const decision = registry.evaluateApplicability("testing.ts", context());
    const evaluated = evaluateRuleApplicability(registry.lookup("testing.ts"), context());
    assert.equal(decision.id, "testing.ts");
    assert.equal(decision.applicable, evaluated.applicable);
    assert.equal(decision.reason, evaluated.reason);
    assert.equal(decision.coverage, evaluated.coverage);
    assert.equal(decision.applicable, false);
    assert.equal(decision.coverage, APPLICABILITY_COVERAGE.COMPLETE);
    assert.equal(Object.isFrozen(decision), true);
  });

  it("preserves unknown when coverage is incomplete", () => {
    const rule = ruleOf({ id: "testing.ts", applicability: { languages: ["typescript"] } });
    const registry = createRuleRegistry([rule]);
    const decision = registry.evaluateApplicability("testing.ts", context(TRUNCATED_MODEL));
    assert.equal(decision.applicable, false);
    assert.equal(decision.coverage, APPLICABILITY_COVERAGE.UNKNOWN);
    assert.notEqual(decision.coverage, APPLICABILITY_COVERAGE.COMPLETE);
  });

  it("fails explicitly for an unknown rule id", () => {
    const registry = createRuleRegistry(CATALOG);
    assert.throws(() => registry.evaluateApplicability("nope.a", context()), RuleConfigurationError);
  });
});

// ─── Determinism & immutability ──────────────────────────────────────────────

describe("rule registry: determinism and immutability", () => {
  it("produces identical answers regardless of registration order", () => {
    const forward = createRuleRegistry(CATALOG);
    const backward = createRuleRegistry([...CATALOG].reverse());
    assert.deepEqual(forward.ids(), backward.ids());
    assert.deepEqual(forward.describeAll(), backward.describeAll());
    assert.deepEqual(
      idsOf(forward.filter({ tags: ["network"] })),
      idsOf(backward.filter({ tags: ["network"] })),
    );
  });

  it("produces byte-identical configuration and metadata snapshots across runs", () => {
    const build = () =>
      createRuleRegistry(CATALOG, { disabled: ["security.b"], ruleOptions: { "security.a": { z: 1, a: 2 } } });
    assert.equal(JSON.stringify(build().configuration()), JSON.stringify(build().configuration()));
    assert.equal(JSON.stringify(build().describeAll()), JSON.stringify(build().describeAll()));
  });

  it("does not let a caller mutate the registry through its own rule object", () => {
    const source = ruleOf({ id: "testing.frozen", metadata: { tags: ["a"] } });
    const registry = createRuleRegistry([source]);
    const stored = registry.lookup("testing.frozen");
    // Reassigning the caller's own fields must not reach the registry's frozen copy.
    source.id = "testing.changed";
    source.metadata = { tags: ["b"] };
    source.version = "9.9.9";
    assert.equal(registry.ids()[0], "testing.frozen");
    assert.equal(stored.version, "1.0.0");
    assert.deepEqual(stored.metadata.tags, ["a"]);
    assert.equal(Object.isFrozen(stored), true);
  });

  it("keeps the registry handle frozen", () => {
    const registry = createRuleRegistry(CATALOG);
    assert.equal(Object.isFrozen(registry), true);
    assert.throws(() => {
      registry.extra = 1;
    });
  });

  it("preserves the Phase 10 backward-compatible surface", () => {
    const registry = createRuleRegistry(CATALOG);
    assert.equal(registry.size, 4);
    assert.deepEqual(registry.get("security.a").id, "security.a");
    assert.equal(registry.has("security.a"), true);
    assert.deepEqual(registry.ids(), idsOf(registry.list()));
    assert.deepEqual(idsOf(registry.select(["security.b", "security.a"])), ["security.a", "security.b"]);
    assert.throws(() => registry.select(["does.not.exist"]), RuleConfigurationError);
  });
});

// ─── Existing pack compatibility ─────────────────────────────────────────────

describe("rule registry: existing pack compatibility", () => {
  const packs = [
    ["security", createSecurityRuleRegistry, securityRules],
    ["testing", createTestingRuleRegistry, testingRules],
    ["code-quality", createCodeQualityRuleRegistry, codeQualityRules],
    ["cicd", createCicdRuleRegistry, cicdRules],
    ["architecture", createArchitectureRuleRegistry, architectureRules],
    ["dependency-analysis", createDependencyAnalysisRuleRegistry, dependencyAnalysisRules],
    ["api-analysis", createApiAnalysisRuleRegistry, apiAnalysisRules],
    ["reliability-analysis", createReliabilityAnalysisRuleRegistry, reliabilityAnalysisRules],
  ];

  for (const [name, create, rules] of packs) {
    it(`keeps the ${name} pack registry valid on the formalized registry`, () => {
      const registry = create({ rules });
      assert.ok(registry.size > 0, `${name} registers rules`);
      assert.ok(registry.size === rules.length, `${name} registers every declared rule`);
      assert.deepEqual(registry.ids(), [...registry.ids()].sort(), `${name} ids are sorted`);
      // The new Phase 18 surface is available and coherent on every pack.
      const described = registry.describeAll();
      assert.equal(described.length, rules.length);
      assert.equal(registry.enabledIds().length, rules.length);
      for (const rule of rules) {
        assert.equal(registry.version(rule.id), rule.version);
        assert.equal(registry.describe(rule.id).category, rule.category);
      }
      assert.deepEqual(
        idsOf(registry.filter({ category: rules[0].category })).length > 0,
        true,
      );
    });
  }
});
