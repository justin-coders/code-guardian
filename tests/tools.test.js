/**
 * Code Guardian — Unit Tests for tools.js
 *
 * Tests individual tool functions in isolation.
 */

import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { writeFileSync, rmSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const PLUGIN_DIR = fileURLToPath(new URL("..", import.meta.url));

// ─── Tool imports ────────────────────────────────────────────────────────────

const tools = await import("file:///" + PLUGIN_DIR.replace(/\\/g, "/") + "/src/tools.js");

// ─── Helpers ─────────────────────────────────────────────────────────────────

/** Create a temp fixture directory with given files. */
async function createFixture(files) {
  const dir = join(PLUGIN_DIR, ".test-tmp", "test-fixture-" + Date.now());
  mkdirSync(dir, { recursive: true });
  for (const [path, content] of Object.entries(files)) {
    const fullPath = join(dir, path);
    mkdirSync(join(fullPath, ".."), { recursive: true });
    writeFileSync(fullPath, content);
  }
  return dir;
}

async function cleanup(dir) {
  try {
    rmSync(dir, { recursive: true, force: true });
  } catch {}
}

// ─── Tests ──────────────────────────────────────────────────────────────────

describe("tools.js", () => {
  describe("tryRead", () => {
    it("should read a file that exists", async () => {
      const dir = await createFixture({ "test.txt": "hello" });
      try {
        const result = await tools.tryRead(join(dir, "test.txt"));
        assert.equal(result, "hello");
      } finally {
        await cleanup(dir);
      }
    });

    it("should return null for non-existent file", async () => {
      const result = await tools.tryRead("/nonexistent/path/file.txt");
      assert.equal(result, null);
    });
  });

  describe("listFiles", () => {
    it("should list files in a directory", async () => {
      const dir = await createFixture({ "a.js": "", "b.ts": "", "c.json": "{}" });
      try {
        const files = await tools.listFiles(dir);
        assert.deepEqual(files.sort(), ["a.js", "b.ts", "c.json"]);
      } finally {
        await cleanup(dir);
      }
    });

    it("should return empty array for non-existent directory", async () => {
      const files = await tools.listFiles("/nonexistent");
      assert.deepEqual(files, []);
    });
  });

  describe("run", () => {
    it("should execute a simple command", async () => {
      const result = await tools.run("echo", ["hello"]);
      assert.ok(result.stdout.includes("hello"));
      assert.equal(result.code, 0);
    });

    it("should capture stderr", async () => {
      const result = await tools.run("node", ["-e", "console.error('err')"]);
      assert.ok(result.stderr.includes("err"));
    });
  });

  describe("toolProductionReadiness", () => {
    it("should score F for empty directory", async () => {
      const dir = await createFixture({});
      try {
        const result = await tools.toolProductionReadiness({ cwd: dir });
        assert.equal(result.version, "2.0.0");
        assert.equal(result.score.grade, "F");
        assert.equal(result.score.total, 10);
        // Empty dir passes only "No .env at root", so passed should be 1
        assert.equal(result.score.passed, 1, "Should pass .env check on empty dir");
        assert(result.score.percentage < 20, "Should score below 20% on empty dir");
      } finally {
        await cleanup(dir);
      }
    });

    it("should include guidance for failed items", async () => {
      const dir = await createFixture({});
      try {
        const result = await tools.toolProductionReadiness({ cwd: dir });
        const failed = result.items.filter((i) => !i.passed);
        assert.ok(failed.length > 0);
        assert.ok(failed.every((i) => i.guidance), "All failed items should have guidance");
      } finally {
        await cleanup(dir);
      }
    });

    it("should score higher for a well-configured project", async () => {
      const dir = await createFixture({
        "package.json": JSON.stringify({ name: "test", version: "1.0.0", scripts: { build: "tsc", test: "jest", lint: "eslint ." } }),
        "package-lock.json": "{}",
        "README.md": "# Test",
        ".gitignore": "node_modules/",
        "eslint.config.js": "export default [];",
        "tsconfig.json": JSON.stringify({ compilerOptions: { strict: true } }),
        "app.test.ts": "test('ok', () => {})",
      });
      try {
        const result = await tools.toolProductionReadiness({ cwd: dir });
        assert.ok(result.score.percentage > 50, "Should score above 50% with good config, got: " + result.score.percentage);
        assert.ok(result.score.grade !== "F", "Should not be F grade with good config");
      } finally {
        await cleanup(dir);
      }
    });

    it("should handle empty args", async () => {
      const result = await tools.toolProductionReadiness({});
      assert.ok(result.score, "Should return score even with no cwd arg");
    });
  });

  describe("toolAuditCodebase", () => {
    it("should return reports and summary", async () => {
      const dir = await createFixture({ "package.json": "{}" });
      try {
        const result = await tools.toolAuditCodebase({ cwd: dir });
        assert.equal(result.tool, "audit_codebase");
        assert.equal(result.version, "2.0.0");
        assert(Array.isArray(result.reports));
        assert(result.summary);
        assert(typeof result.summary.totalChecks === "number");
      } finally {
        await cleanup(dir);
      }
    });

    it("should include guidance for warnings", async () => {
      const dir = await createFixture({});
      try {
        const result = await tools.toolAuditCodebase({ cwd: dir });
        assert(Array.isArray(result.guidance));
      } finally {
        await cleanup(dir);
      }
    });
  });

  describe("toolGenerateProductionCode", () => {
    it("should generate NestJS API template", async () => {
      const result = await tools.toolGenerateProductionCode({ feature: "api", stack: "nestjs" });
      assert.equal(result.tool, "generate_production_code");
      assert.equal(result.feature, "api");
      assert(Array.isArray(result.template));
      assert(result.template.length > 0);
      assert(Array.isArray(result.checklist));
    });

    it("should generate Express API template", async () => {
      const result = await tools.toolGenerateProductionCode({ feature: "api", stack: "express" });
      assert(Array.isArray(result.template));
      assert(result.template.length > 0);
    });

    it("should generate auth template", async () => {
      const result = await tools.toolGenerateProductionCode({ feature: "auth", stack: "nestjs" });
      assert(result.template.length > 0);
      assert(result.checklist.length > 0);
    });

    it("should return error for unknown feature", async () => {
      const result = await tools.toolGenerateProductionCode({ feature: "nonexistent" });
      assert(result.error, "Should return error for unknown feature");
    });

    it("should handle empty args", async () => {
      const result = await tools.toolGenerateProductionCode({});
      // Should not crash
      assert(result.tool === "generate_production_code" || result.error);
    });
  });

  describe("toolGetIndustryPatterns", () => {
    it("should return all patterns", async () => {
      const result = await tools.toolGetIndustryPatterns({});
      assert(Array.isArray(result.patterns));
      assert(result.patterns.length >= 10);
    });

    it("should return specific category", async () => {
      const result = await tools.toolGetIndustryPatterns({ category: "security" });
      assert.equal(result.category, "security");
      assert(result.pattern.checklist.length > 0);
    });
  });

  describe("toolGenerateGitHubWorkflow", () => {
    it("should generate a workflow YAML string", async () => {
      const result = await tools.toolGenerateGitHubWorkflow({ stack: "nestjs", deployTarget: "docker" });
      assert(result.workflow.includes("name: ci"));
      assert(result.workflow.includes("actions/checkout"));
      assert.equal(result.filename, ".github/workflows/ci.yml");
    });

    it("should handle empty args", async () => {
      const result = await tools.toolGenerateGitHubWorkflow({});
      assert(result.workflow.length > 0);
    });
  });

  describe("toolDetectAgent", () => {
    it("should return all supported agents", async () => {
      const result = await tools.toolDetectAgent({});
      assert(Array.isArray(result.allSupportedAgents));
      const names = result.allSupportedAgents.map((a) => a.name);
      assert(names.includes("Claude Code"));
      assert(names.includes("Google Gemini"), "Should include Google Gemini, not Emni");
      assert(names.includes("Cursor"));
      assert(names.includes("Windsurf (Codeium)"));
      assert(names.includes("Devin"));
      assert(names.includes("OpenAI Codex"));
      assert(names.includes("Antigravity"));
    });
  });

  describe("toolGetAgentGuidance", () => {
    it("should return guidance for each supported agent", async () => {
      const agents = ["claude-code", "cursor", "windsurf", "devin", "codex", "gemini", "antigravity"];
      for (const agent of agents) {
        const result = await tools.toolGetAgentGuidance({ agent });
        assert.equal(result.agent, agent, "Failed for agent: " + agent);
        assert(result.config, "Should have config for " + agent);
      }
    });

    it("should return error for unknown agent", async () => {
      const result = await tools.toolGetAgentGuidance({ agent: "unknown" });
      assert(result.error, "Should return error for unknown agent");
    });
  });

  describe("toolGenerateStarterRepo", () => {
    it("should generate NestJS starter config", async () => {
      const result = await tools.toolGenerateStarterRepo({ framework: "nestjs" });
      assert.equal(result.framework, "nestjs");
      assert(result.recommendedStructure);
      assert(result.essentialPackages);
      assert(result.productionConfig);
    });

    it("should generate Express starter config", async () => {
      const result = await tools.toolGenerateStarterRepo({ framework: "express" });
      assert.equal(result.framework, "express");
    });

    it("should handle empty args", async () => {
      const result = await tools.toolGenerateStarterRepo({});
      assert.equal(result.framework, "nestjs", "Should default to nestjs");
    });
  });

  describe("toolCheckBranch", () => {
    it("should return branch info and patterns", async () => {
      const dir = await createFixture({ "package.json": "{}" });
      try {
        const result = await tools.toolCheckBranch({ cwd: dir });
        assert(result.patterns, "Should return patterns array");
        assert(result.patterns.length > 0, "Should have branch patterns");
        assert("compliant" in result, "Should have compliant boolean");
        assert(Array.isArray(result.violations), "Should have violations array");
      } finally {
        await cleanup(dir);
      }
    });
  });

  describe("toolCheckTests", () => {
    it("should detect test files in a fixture", async () => {
      const dir = await createFixture({
        "src/app.test.ts": "test('ok', () => {})",
        "src/utils.spec.ts": "test('ok', () => {})",
        "src/app.js": "console.log('hello')",
      });
      try {
        const result = await tools.toolCheckTests({ cwd: dir });
        assert.equal(result.tool, "check_tests");
        assert.equal(result.version, "2.0.0");
        const testReport = result.reports.find((r) => r.area === "test-files");
        assert(testReport, "Should have test-files report");
        assert.equal(testReport.count, 2, "Should find 2 test files");
      } finally {
        await cleanup(dir);
      }
    });

    it("should handle empty args", async () => {
      const result = await tools.toolCheckTests({});
      assert.equal(result.tool, "check_tests");
      assert(Array.isArray(result.reports));
    });
  });

  describe("toolCheckCICD", () => {
    it("should detect package scripts", async () => {
      const dir = await createFixture({
        "package.json": JSON.stringify({
          scripts: { build: "tsc", test: "jest", lint: "eslint ." },
        }),
      });
      try {
        const result = await tools.toolCheckCICD({ cwd: dir });
        assert.equal(result.tool, "check_cicd");
        const scriptsReport = result.reports.find((r) => r.name === "package-scripts");
        assert(scriptsReport, "Should have package-scripts report");
        assert.equal(scriptsReport.build, true);
        assert.equal(scriptsReport.test, true);
        assert.equal(scriptsReport.lint, true);
      } finally {
        await cleanup(dir);
      }
    });

    it("should handle empty args", async () => {
      const result = await tools.toolCheckCICD({});
      assert.equal(result.tool, "check_cicd");
      assert(Array.isArray(result.reports));
    });
  });

  describe("toolCheckLinting", () => {
    it("should return lint results with or without installed tools", async () => {
      const result = await tools.toolCheckLinting({ cwd: PLUGIN_DIR });
      assert.equal(result.tool, "check_linting");
      assert.equal(result.version, "2.0.0");
      // The function returns linterVersions as an array
      assert(Array.isArray(result.linterVersions));
      // Each entry should have tool name and installed flag
      result.linterVersions.forEach((l) => {
        assert(l.tool, "Should have tool property");
        assert(typeof l.installed === "boolean", "Should have installed boolean");
      });
    });
  });

  describe("toolCheckSecurity", () => {
    it("should return security report for a fixture", async () => {
      const dir = await createFixture({
        "package.json": JSON.stringify({ name: "test", version: "1.0.0" }),
      });
      try {
        const result = await tools.toolCheckSecurity({ cwd: dir });
        assert.equal(result.tool, "check_security");
        assert.equal(result.version, "2.0.0");
        assert(Array.isArray(result.reports));
      } finally {
        await cleanup(dir);
      }
    });

    it("should handle empty args", async () => {
      const result = await tools.toolCheckSecurity({});
      assert.equal(result.tool, "check_security");
      assert(Array.isArray(result.reports));
    });
  });

  describe("toolGenerateSecurityChecklist", () => {
    it("should return a security checklist", async () => {
      const result = await tools.toolGenerateSecurityChecklist({});
      assert.equal(result.tool, "generate_security_checklist");
      assert.equal(result.version, "2.0.0");
      assert(Array.isArray(result.checklist));
      assert(result.checklist.length > 0, "Should have checklist items");
    });

    it("should accept stack parameter", async () => {
      const result = await tools.toolGenerateSecurityChecklist({ stack: "nestjs" });
      assert(Array.isArray(result.checklist));
    });
  });
});
