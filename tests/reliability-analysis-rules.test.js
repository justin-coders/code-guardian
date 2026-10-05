/**
 * Code Guardian — Reliability Analysis Rule Pack Tests (official roadmap Phase 17)
 *
 * The rule-layer proof for the Reliability Analysis pack: the pack contract (ten namespaced ids,
 * one per official domain, in roadmap order), the closed vocabularies it reads, and the registry's
 * refusal to shrink silently. These are unit-level checks, complementing the end-to-end suite in
 * `reliability-analysis-analyzer.test.js`.
 *
 * Run with: node --test tests/reliability-analysis-rules.test.js
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";

import {
  RELIABILITY_ANALYSIS_CATEGORY,
  RELIABILITY_ANALYSIS_CONFIDENCE,
  RELIABILITY_ANALYSIS_DOMAINS,
  RELIABILITY_ANALYSIS_LIMITS,
  RELIABILITY_ANALYSIS_RULE_ID_PREFIX,
  RELIABILITY_ANALYSIS_RULE_IDS,
  RELIABILITY_ANALYSIS_STATES,
  RELIABILITY_ANALYSIS_SUBJECTS,
  RELIABILITY_LOCAL_VOCABULARY,
  RELIABILITY_OBSERVABILITY_DIMENSIONS,
  RELIABILITY_PACKAGE_VOCABULARY,
  RELIABILITY_SERVICE_RUNTIME_PACKAGES,
  createReliabilityAnalysisRuleRegistry,
  reliabilityAnalysisRuleSetIssues,
  reliabilityAnalysisRules,
} from "../src/rules/index.js";

const OFFICIAL_DOMAINS = [
  "timeouts",
  "retry-behavior",
  "circuit-breaking",
  "graceful-shutdown",
  "health-checks",
  "failure-handling",
  "resource-cleanup",
  "transaction-handling",
  "queue-behavior",
  "observability",
];

describe("reliability analysis rules: pack contract", () => {
  it("declares one rule per official domain, all in the reliability namespace", () => {
    assert.deepEqual(reliabilityAnalysisRuleSetIssues(reliabilityAnalysisRules), []);
    assert.equal(Object.keys(RELIABILITY_ANALYSIS_RULE_IDS).length, 10);
    for (const id of Object.values(RELIABILITY_ANALYSIS_RULE_IDS)) {
      assert.equal(id.startsWith(RELIABILITY_ANALYSIS_RULE_ID_PREFIX), true, id);
    }
    const shipped = reliabilityAnalysisRules.map((rule) => rule.id);
    assert.deepEqual(shipped, [...shipped].sort());
    assert.equal(new Set(shipped).size, 10);
  });

  it("maps the ten official domains to their rule ids in the roadmap's own order", () => {
    assert.equal(RELIABILITY_ANALYSIS_DOMAINS.length, 10);
    assert.deepEqual(
      RELIABILITY_ANALYSIS_DOMAINS.map((entry) => entry.domain),
      OFFICIAL_DOMAINS,
    );
    const shipped = new Set(reliabilityAnalysisRules.map((rule) => rule.id));
    for (const entry of RELIABILITY_ANALYSIS_DOMAINS) {
      assert.equal(shipped.has(entry.ruleId), true, entry.ruleId);
      assert.equal(entry.ruleId, `reliability.${entry.domain}`, entry.domain);
    }
  });

  it("registers exactly the shipped pack and rejects a foreign or missing rule", () => {
    assert.equal(createReliabilityAnalysisRuleRegistry({ rules: reliabilityAnalysisRules }).size, 10);
    assert.throws(
      () => createReliabilityAnalysisRuleRegistry({ rules: [{ ...reliabilityAnalysisRules[0], id: "api.logging" }] }),
      (error) => (error.details?.issues ?? []).join(" ").includes("namespace"),
    );
    assert.throws(
      () => createReliabilityAnalysisRuleRegistry({ rules: [] }),
      (error) => (error.details?.issues ?? []).join(" ").includes("missing from the pack"),
    );
  });

  it("does not disturb any existing rule id", () => {
    const shipped = new Set(reliabilityAnalysisRules.map((rule) => rule.id));
    for (const foreign of ["api.graph.inventory", "api.logging", "api.authentication", "middleware.graph.inventory", "security.x"]) {
      assert.equal(shipped.has(foreign), false, foreign);
    }
  });
});

describe("reliability analysis rules: vocabulary and modes", () => {
  it("records each domain's mode", () => {
    const modes = Object.fromEntries(reliabilityAnalysisRules.map((rule) => [rule.metadata.domain, rule.metadata.mode]));
    for (const domain of [
      "timeouts",
      "retry-behavior",
      "circuit-breaking",
      "graceful-shutdown",
      "failure-handling",
      "resource-cleanup",
      "transaction-handling",
      "queue-behavior",
    ]) {
      assert.equal(modes[domain], "usage", domain);
    }
    assert.equal(modes["health-checks"], "structural");
    assert.equal(modes.observability, "dimensional");
  });

  it("keeps the package vocabulary closed: string specifiers, no database client under transactions", () => {
    for (const [domain, packages] of Object.entries(RELIABILITY_PACKAGE_VOCABULARY)) {
      assert.ok(Array.isArray(packages) && packages.length > 0, domain);
      for (const name of packages) assert.equal(typeof name, "string");
    }
    // Using a database is not using a transaction.
    for (const client of ["knex", "pg", "sequelize", "typeorm", "prisma", "mongoose"]) {
      assert.equal(
        Object.values(RELIABILITY_PACKAGE_VOCABULARY).some((packages) => packages.includes(client)),
        false,
        client,
      );
    }
  });

  it("keeps observability multi-dimensional and the local vocabulary domain-scoped", () => {
    assert.deepEqual(
      Object.keys(RELIABILITY_OBSERVABILITY_DIMENSIONS).sort(),
      ["error-reporting", "logging", "metrics", "tracing"],
    );
    for (const domain of Object.keys(RELIABILITY_LOCAL_VOCABULARY)) {
      assert.equal(OFFICIAL_DOMAINS.includes(domain), true, domain);
    }
    // The logging dimension does not fall back to a generic `logger` name.
    assert.equal(Object.values(RELIABILITY_LOCAL_VOCABULARY).flat().includes("logger"), false);
    // The service-runtime set is closed and includes the queue/server packages.
    for (const name of ["express", "fastify", "koa", "@nestjs/core", "bullmq"]) {
      assert.equal(RELIABILITY_SERVICE_RUNTIME_PACKAGES.includes(name), true, name);
    }
  });

  it("declares bounded limits, a complete state vocabulary and a confidence policy", () => {
    assert.ok(RELIABILITY_ANALYSIS_LIMITS.MAX_FINDINGS > 0);
    assert.ok(RELIABILITY_ANALYSIS_LIMITS.MAX_USAGES > 0);
    assert.deepEqual(Object.values(RELIABILITY_ANALYSIS_STATES).sort(), [
      "detected",
      "established",
      "not_applicable",
      "unknown",
    ]);
    assert.deepEqual(Object.values(RELIABILITY_ANALYSIS_SUBJECTS).sort(), [
      "applicable",
      "not_applicable",
      "unknown",
    ]);
    assert.equal(RELIABILITY_ANALYSIS_CATEGORY, "architecture");
    for (const value of Object.values(RELIABILITY_ANALYSIS_CONFIDENCE)) {
      assert.equal(typeof value, "number");
      assert.ok(value > 0 && value <= 1);
    }
  });

  it("gives every rule a stable id, version, category, severity and description", () => {
    for (const rule of reliabilityAnalysisRules) {
      assert.equal(typeof rule.version, "string");
      assert.equal(rule.category, RELIABILITY_ANALYSIS_CATEGORY);
      assert.equal(["info", "low", "medium", "high"].includes(rule.severity), true, rule.id);
      assert.equal(typeof rule.detect, "function");
      assert.ok(rule.description.length > 40, rule.id);
      assert.equal(typeof rule.metadata.domain, "string");
    }
  });
});
