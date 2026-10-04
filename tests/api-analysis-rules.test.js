/**
 * Code Guardian — API Analysis Rule Pack Tests (official roadmap Phase 16)
 *
 * The rule-layer proof for the API Analysis pack: the pack contract (thirteen namespaced ids,
 * one per official domain, in roadmap order), the vocabulary it borrows from the model, the
 * closed artifact set, and the registry's refusal to shrink silently. These are unit-level
 * checks, complementing the end-to-end suite in `api-analysis-analyzer.test.js`.
 *
 * Run with: node --test tests/api-analysis-rules.test.js
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";

import { MIDDLEWARE_CLASSIFICATIONS } from "../src/repository/model/index.js";

import {
  API_ANALYSIS_BODY_METHODS,
  API_ANALYSIS_CATEGORY,
  API_ANALYSIS_CONFIDENCE,
  API_ANALYSIS_DOMAIN_CLASSIFICATION,
  API_ANALYSIS_DOMAINS,
  API_ANALYSIS_LIMITS,
  API_ANALYSIS_OPENAPI_BASENAMES,
  API_ANALYSIS_RULE_ID_PREFIX,
  API_ANALYSIS_RULE_IDS,
  API_ANALYSIS_STATES,
  API_ANALYSIS_SUBJECTS,
  apiAnalysisRuleSetIssues,
  apiAnalysisRules,
  createApiAnalysisRuleRegistry,
} from "../src/rules/index.js";

describe("api analysis rules: pack contract", () => {
  it("declares one rule per official domain, all in the api namespace", () => {
    assert.deepEqual(apiAnalysisRuleSetIssues(apiAnalysisRules), []);
    assert.equal(Object.keys(API_ANALYSIS_RULE_IDS).length, 13);
    for (const id of Object.values(API_ANALYSIS_RULE_IDS)) {
      assert.equal(id.startsWith(API_ANALYSIS_RULE_ID_PREFIX), true, id);
    }
    const shipped = apiAnalysisRules.map((rule) => rule.id);
    assert.deepEqual(shipped, [...shipped].sort());
    assert.equal(new Set(shipped).size, 13);
  });

  it("maps the thirteen domains to their rule ids in the roadmap's own order", () => {
    assert.equal(API_ANALYSIS_DOMAINS.length, 13);
    assert.deepEqual(
      API_ANALYSIS_DOMAINS.map((entry) => entry.domain),
      [
        "input-validation",
        "schema-validation",
        "authentication",
        "authorization",
        "error-handling",
        "status-codes",
        "pagination",
        "rate-limiting",
        "cors",
        "openapi",
        "request-limits",
        "logging",
        "correlation-ids",
      ],
    );
    const shipped = new Set(apiAnalysisRules.map((rule) => rule.id));
    for (const entry of API_ANALYSIS_DOMAINS) {
      assert.equal(shipped.has(entry.ruleId), true, entry.ruleId);
    }
  });

  it("registers exactly the shipped pack and rejects a foreign or missing rule", () => {
    assert.equal(createApiAnalysisRuleRegistry({ rules: apiAnalysisRules }).size, 13);
    assert.throws(
      () =>
        createApiAnalysisRuleRegistry({
          rules: [{ ...apiAnalysisRules[0], id: "security.x" }],
        }),
      (error) => (error.details?.issues ?? []).join(" ").includes("namespace"),
    );
    assert.throws(
      () => createApiAnalysisRuleRegistry({ rules: [] }),
      (error) => (error.details?.issues ?? []).join(" ").includes("missing from the pack"),
    );
  });

  it("does not disturb the existing API inventory rule id", () => {
    const shipped = new Set(apiAnalysisRules.map((rule) => rule.id));
    assert.equal(shipped.has("api.graph.inventory"), false);
  });
});

describe("api analysis rules: vocabulary", () => {
  it("reads classifications the middleware graph actually assigns", () => {
    const assigned = new Set(Object.values(MIDDLEWARE_CLASSIFICATIONS));
    for (const value of Object.values(API_ANALYSIS_DOMAIN_CLASSIFICATION)) {
      assert.equal(assigned.has(value), true, value);
    }
  });

  it("marks the six structural rules with the classification each reads", () => {
    const structural = apiAnalysisRules.filter((rule) => rule.metadata.mode === "gap" || rule.metadata.mode === "positive");
    assert.equal(structural.length, 6);
    for (const rule of structural) {
      const expected = API_ANALYSIS_DOMAIN_CLASSIFICATION[rule.metadata.domain];
      assert.equal(expected, rule.metadata.classification, rule.id);
    }
  });

  it("records the three non-structural domains as body/artifact/unestablished", () => {
    const modes = Object.fromEntries(apiAnalysisRules.map((rule) => [rule.metadata.domain, rule.metadata.mode]));
    assert.equal(modes["input-validation"], "gap");
    assert.equal(modes.authentication, "gap");
    assert.equal(modes.authorization, "gap");
    assert.equal(modes.logging, "gap");
    assert.equal(modes["rate-limiting"], "positive");
    assert.equal(modes.cors, "positive");
    assert.equal(modes.openapi, "artifact");
    for (const domain of ["schema-validation", "error-handling", "status-codes", "pagination", "request-limits", "correlation-ids"]) {
      assert.equal(modes[domain], "unestablished", domain);
    }
  });

  it("keeps the OpenAPI artifact set closed and searchable by basename", () => {
    assert.ok(API_ANALYSIS_OPENAPI_BASENAMES.includes("openapi.yaml"));
    assert.ok(API_ANALYSIS_OPENAPI_BASENAMES.includes("swagger.json"));
    assert.equal(API_ANALYSIS_OPENAPI_BASENAMES.includes("readme.md"), false);
  });

  it("declares bounded limits, a body-method set and a complete state vocabulary", () => {
    assert.ok(API_ANALYSIS_LIMITS.MAX_FINDINGS > 0);
    assert.deepEqual([...API_ANALYSIS_BODY_METHODS], ["POST", "PUT", "PATCH"]);
    assert.deepEqual(Object.values(API_ANALYSIS_STATES).sort(), [
      "detected",
      "established",
      "not_applicable",
      "unknown",
    ]);
    assert.deepEqual(Object.values(API_ANALYSIS_SUBJECTS).sort(), [
      "applicable",
      "not_applicable",
      "unknown",
    ]);
    assert.equal(API_ANALYSIS_CATEGORY, "architecture");
    for (const value of Object.values(API_ANALYSIS_CONFIDENCE)) {
      assert.equal(typeof value, "number");
      assert.ok(value > 0 && value <= 1);
    }
  });
});
