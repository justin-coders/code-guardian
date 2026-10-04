/**
 * Code Guardian — Dependency Analysis Rule Pack Tests (official roadmap Phase 15)
 *
 * The rule-layer proof for the Dependency Analysis pack: the pack contract (eight namespaced,
 * domain-mapped ids present), the version semantics, the external-intelligence normalization,
 * and the usage-evidence helpers. These are unit-level checks, complementing the end-to-end
 * suite in `dependency-analysis-analyzer.test.js`.
 *
 * Run with: node --test tests/dependency-analysis-rules.test.js
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";

import {
  DEPENDENCY_ANALYSIS_RULE_ID_PREFIX,
  DEPENDENCY_ANALYSIS_RULE_IDS,
  DEPENDENCY_INTELLIGENCE_STATES,
  compareVersions,
  dependencyAnalysisRuleSetIssues,
  dependencyAnalysisRules,
  createDependencyAnalysisRuleRegistry,
  exactDeclaredVersion,
  isComparableEcosystem,
  normalizeDependencyIntelligence,
  packageRootOf,
  readDependencyIntelligence,
  parseVersion,
  satisfiesRange,
  wordTokens,
} from "../src/rules/index.js";

describe("dependency analysis rules: pack contract", () => {
  it("declares one rule per official domain, all in the dependency namespace", () => {
    assert.deepEqual(dependencyAnalysisRuleSetIssues(dependencyAnalysisRules), []);
    assert.equal(Object.keys(DEPENDENCY_ANALYSIS_RULE_IDS).length, 8);
    for (const id of Object.values(DEPENDENCY_ANALYSIS_RULE_IDS)) {
      assert.equal(id.startsWith(DEPENDENCY_ANALYSIS_RULE_ID_PREFIX), true, id);
    }
    const shipped = dependencyAnalysisRules.map((rule) => rule.id);
    assert.deepEqual(shipped, [...shipped].sort());
    assert.equal(new Set(shipped).size, 8);
  });

  it("registers exactly the shipped pack and rejects a foreign or missing rule", () => {
    assert.equal(createDependencyAnalysisRuleRegistry({ rules: dependencyAnalysisRules }).size, 8);
    assert.throws(
      () =>
        createDependencyAnalysisRuleRegistry({
          rules: [{ ...dependencyAnalysisRules[0], id: "security.x" }],
        }),
      (error) => (error.details?.issues ?? []).join(" ").includes("namespace"),
    );
    assert.throws(
      () => createDependencyAnalysisRuleRegistry({ rules: [] }),
      (error) => (error.details?.issues ?? []).join(" ").includes("missing from the pack"),
    );
  });

  it("does not disturb the existing dependency inventory rule ids", () => {
    const shipped = new Set(dependencyAnalysisRules.map((rule) => rule.id));
    assert.equal(shipped.has("dependency.inventory.declarations"), false);
    assert.equal(shipped.has("dependency.graph.inventory"), false);
  });
});

describe("dependency analysis: version semantics", () => {
  it("compares numerically, never lexically", () => {
    assert.equal(compareVersions("node", "10.0.0", "9.0.0"), 1);
    assert.equal(compareVersions("node", "1.2.0", "1.10.0"), -1);
    assert.equal(compareVersions("node", "v1.2.3", "1.2.3"), 0);
  });

  it("refuses to compare an ecosystem whose semantics it cannot establish", () => {
    assert.equal(isComparableEcosystem("python"), false);
    assert.equal(compareVersions("python", "1.0.0", "2.0.0"), null);
    assert.equal(compareVersions("node", "not-a-version", "2.0.0"), null);
  });

  it("evaluates the npm range forms this build documents", () => {
    assert.equal(satisfiesRange("node", "1.5.0", "^1.2.0"), true);
    assert.equal(satisfiesRange("node", "2.0.0", "^1.2.0"), false);
    assert.equal(satisfiesRange("node", "1.9.0", "~1.4.0"), false);
    assert.equal(satisfiesRange("node", "1.4.9", "~1.4.0"), true);
    assert.equal(satisfiesRange("node", "1.0.0", ">=1.0.0 <2.0.0"), true);
    assert.equal(satisfiesRange("node", "2.1.0", ">=1.0.0 <2.0.0"), false);
    assert.equal(satisfiesRange("node", "1.2.3", "<2.0.0 || >=3.0.0"), true);
    assert.equal(satisfiesRange("node", "1.0.0", "1.x"), true);
  });

  it("returns null (unknown) for an unparseable range or version", () => {
    assert.equal(satisfiesRange("node", "1.0.0", "workspace:*"), null);
    assert.equal(satisfiesRange("node", "latest", "<2.0.0"), null);
    assert.equal(parseVersion("nonsense"), null);
  });

  it("treats only an operator-free spec as an exact declared version", () => {
    assert.equal(exactDeclaredVersion("1.2.3"), "1.2.3");
    assert.equal(exactDeclaredVersion("^1.2.3"), null);
    assert.equal(exactDeclaredVersion("~1.2.3"), null);
    assert.equal(exactDeclaredVersion("1.x"), null);
    assert.equal(exactDeclaredVersion("workspace:*"), null);
  });
});

describe("dependency analysis: external intelligence", () => {
  const valid = {
    sources: [{ id: "s1", revision: "2026-10-01" }],
    advisories: [
      { id: "A-1", sourceId: "s1", ecosystem: "node", package: "Lodash", affectedRange: "<2.0.0" },
    ],
    releases: [{ sourceId: "s1", ecosystem: "node", package: "lodash", latest: "4.0.0" }],
  };

  it("normalizes package identity and preserves the source revision", () => {
    const normalized = normalizeDependencyIntelligence(valid);
    assert.equal(normalized.state, DEPENDENCY_INTELLIGENCE_STATES.VALID);
    assert.equal(normalized.advisories[0].package, "lodash");
    assert.equal(normalized.sources[0].revision, "2026-10-01");
  });

  it("refuses a dataset missing provenance instead of guessing", () => {
    const noRevision = normalizeDependencyIntelligence({
      sources: [{ id: "s1" }],
      advisories: [],
      releases: [],
    });
    assert.equal(noRevision.state, DEPENDENCY_INTELLIGENCE_STATES.INVALID);

    const unknownSource = normalizeDependencyIntelligence({
      sources: [{ id: "s1", revision: "r" }],
      advisories: [
        { id: "A", sourceId: "other", ecosystem: "node", package: "x", affectedRange: "<1.0.0" },
      ],
      releases: [],
    });
    assert.equal(unknownSource.state, DEPENDENCY_INTELLIGENCE_STATES.INVALID);
    assert.deepEqual(unknownSource.advisories, []);
  });

  it("reports absent when no dataset is supplied, and refuses a non-object one", () => {
    assert.equal(readDependencyIntelligence({ options: {} }).state, DEPENDENCY_INTELLIGENCE_STATES.ABSENT);
    assert.equal(readDependencyIntelligence({}).state, DEPENDENCY_INTELLIGENCE_STATES.ABSENT);
    assert.equal(
      normalizeDependencyIntelligence({ sources: [], advisories: [], releases: [] }).state,
      DEPENDENCY_INTELLIGENCE_STATES.VALID,
    );
    assert.equal(normalizeDependencyIntelligence("nope").state, DEPENDENCY_INTELLIGENCE_STATES.INVALID);
  });
});

describe("dependency analysis: usage helpers", () => {
  it("extracts the package root from a bare or scoped specifier, and nothing from a path", () => {
    assert.equal(packageRootOf("lodash/fp"), "lodash");
    assert.equal(packageRootOf("@scope/pkg/sub"), "@scope/pkg");
    assert.equal(packageRootOf("./local"), null);
    assert.equal(packageRootOf("/abs"), null);
    assert.equal(packageRootOf("node:fs"), null);
  });

  it("splits a path or command into lower-case word tokens", () => {
    assert.deepEqual(wordTokens("eslint.config.js"), ["eslint.config.js", "eslint", "config", "js"]);
    assert.ok(wordTokens("run: eslint .").includes("eslint"));
  });
});
