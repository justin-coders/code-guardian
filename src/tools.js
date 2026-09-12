/**
 * Shared tool implementations for code-guardian.
 * Imported by both stdio-server.js and http-server.js.
 */

import { spawn } from "node:child_process";
import { readdir, readFile } from "node:fs/promises";

// ─── IO helpers ─────────────────────────────────────────────────────────────

export function run(cmd, args = [], cwd = process.cwd()) {
  return new Promise((resolve) => {
    const proc = spawn(cmd, args, { cwd, stdio: ["ignore", "pipe", "pipe"], shell: true });
    let out = "",
      err = "";
    proc.stdout.on("data", (d) => (out += d.toString()));
    proc.stderr.on("data", (d) => (err += d.toString()));
    proc.on("close", (code) => resolve({ stdout: out, stderr: err, code: code ?? 1 }));
  });
}

export async function tryRead(path) {
  try {
    return await readFile(path, "utf8");
  } catch {
    return null;
  }
}

export async function listFiles(dir, max = 200) {
  try {
    const entries = await readdir(dir, { withFileTypes: true });
    return entries.filter((e) => e.isFile()).map((e) => e.name).slice(0, max);
  } catch {
    return [];
  }
}

// ─── Tool: audit_codebase ───────────────────────────────────────────────────

export async function toolAuditCodebase(args) {
  const cwd = (args.cwd || process.cwd()).toString();
  const depth = Number(args.depth || 3);
  const reports = [];

  const pkg = await tryRead(cwd + "/package.json");
  const pkgData = pkg ? JSON.parse(pkg) : null;
  reports.push({
    area: "package.json",
    severity: pkgData ? "info" : "warn",
    message: pkgData
      ? `Found package.json — scripts: ${Object.keys(pkgData.scripts || {}).join(", ") || "none"}`
      : "No package.json found at project root.",
  });

  const readme = await tryRead(cwd + "/README.md");
  reports.push({
    area: "documentation",
    severity: readme ? "info" : "warn",
    message: readme ? "README.md present." : "No README.md found. Recommended for any production project.",
  });

  const gitignore = await tryRead(cwd + "/.gitignore");
  reports.push({
    area: "source-control",
    severity: gitignore ? "info" : "warn",
    message: gitignore ? ".gitignore present." : "No .gitignore found.",
  });

  const eslintFiles = await listFiles(cwd);
  const hasEslint = eslintFiles.some(
    (f) => f.startsWith(".eslintrc") || f === "eslint.config.js" || f === "eslint.config.mjs" || f === "eslint.config.ts",
  );
  reports.push({
    area: "linting",
    severity: hasEslint ? "info" : "warn",
    message: hasEslint ? "ESLint config detected." : "No ESLint config found. Consider adding one.",
  });

  const tsconfig = await tryRead(cwd + "/tsconfig.json");
  reports.push({
    area: "typescript",
    severity: tsconfig ? "info" : "warn",
    message: tsconfig
      ? "tsconfig.json present."
      : "No tsconfig.json found. TypeScript projects should have strict mode enabled.",
  });

  const testFiles = await listFiles(cwd);
  const hasTestConfig =
    (await tryRead(cwd + "/jest.config.js")) !== null ||
    (await tryRead(cwd + "/jest.config.ts")) !== null ||
    (await tryRead(cwd + "/vitest.config.ts")) !== null;
  const hasTests = testFiles.some((f) => f.endsWith(".test.ts") || f.endsWith(".test.tsx") || f.endsWith(".spec.ts"));
  reports.push({
    area: "testing",
    severity: hasTestConfig || hasTests ? "info" : "warn",
    message: hasTestConfig
      ? "Test config (Jest/Vitest) detected."
      : hasTests
        ? "Test files found but no config detected."
        : "No test files or config found. Production projects need tests.",
  });

  const hasCI = (await tryRead(cwd + "/.github/workflows/ci.yml")) !== null;
  reports.push({ area: "ci-cd", severity: hasCI ? "info" : "warn", message: hasCI ? "GitHub Actions CI workflow detected." : "No .github/workflows/ci.yml found." });

  const lockfile =
    (await tryRead(cwd + "/package-lock.json")) !== null ||
    (await tryRead(cwd + "/yarn.lock")) !== null ||
    (await tryRead(cwd + "/bun.lockb")) !== null;
  reports.push({
    area: "dependencies",
    severity: lockfile ? "info" : "warn",
    message: lockfile ? "Lock file present." : "No lock file found. Pinning dependencies is recommended.",
  });

  let lintResult = null;
  if (hasEslint) {
    const lint = await run("npx", ["eslint", "--max-warnings=0", "."], cwd);
    lintResult = lint.code === 0 ? { ok: true, message: "ESLint passed with no errors." } : { ok: false, message: lint.stdout || lint.stderr };
  }

  let typeResult = null;
  if (tsconfig) {
    const tsc = await run("npx", ["tsc", "--noEmit"], cwd);
    typeResult = tsc.code === 0 ? { ok: true, message: "TypeScript type-check passed." } : { ok: false, message: tsc.stdout || tsc.stderr };
  }

  return {
    tool: "audit_codebase",
    reports,
    lint: lintResult,
    typescript: typeResult,
    summary: {
      totalChecks: reports.length,
      warnings: reports.filter((r) => r.severity === "warn").length,
      info: reports.filter((r) => r.severity === "info").length,
      lintPassed: lintResult?.ok,
      typescriptPassed: typeResult?.ok,
    },
  };
}

// ─── Tool: check_branch ─────────────────────────────────────────────────────

export async function toolCheckBranch(args) {
  const cwd = (args.cwd || process.cwd()).toString();
  try {
    const { stdout } = await run("git", ["branch", "--list", "--format=%(refname:short)"], cwd);
    const branches = stdout.trim().split("\n").filter(Boolean);
    const current = branches.find((b) => b.startsWith("*"));
    const currentBranch = current ? current.replace("* ", "").trim() : null;

    const patterns = [
      { name: "feature", regex: /^feature\// },
      { name: "bugfix", regex: /^bugfix\// },
      { name: "hotfix", regex: /^hotfix\// },
      { name: "release", regex: /^release\// },
      { name: "main/master", regex: /^(main|master)$/ },
      { name: "develop", regex: /^develop$/ },
    ];

    const violations = [];
    if (currentBranch && currentBranch !== "main" && currentBranch !== "master" && currentBranch !== "develop") {
      const matched = patterns.some((p) => p.regex.test(currentBranch));
      if (!matched) {
        violations.push(`Current branch "${currentBranch}" does not match conventional patterns (feature/, bugfix/, hotfix/, release/, main, master, develop).`);
      }
    }

    return { tool: "check_branch", currentBranch, allBranches: branches, patterns, violations, compliant: violations.length === 0 };
  } catch (err) {
    return { tool: "check_branch", error: err.message };
  }
}

// ─── Tool: check_tests ──────────────────────────────────────────────────────

export async function toolCheckTests(args) {
  const cwd = (args.cwd || process.cwd()).toString();
  const reports = [];

  const { execSync } = await import("node:child_process");
  try {
    const testFiles = execSync(
      'find . -type f \\( -name "*.test.ts" -o -name "*.test.tsx" -o -name "*.spec.ts" -o -name "*.spec.tsx" \\) 2>/dev/null | head -50',
      { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] },
    );
    const files = testFiles.trim().split("\n").filter(Boolean);
    reports.push({ area: "test-files", count: files.length, message: `Found ${files.length} test/spec file(s).` });

    const hasJest = (await tryRead(cwd + "/jest.config.js")) !== null || (await tryRead(cwd + "/jest.config.ts")) !== null;
    const hasVitest = (await tryRead(cwd + "/vitest.config.ts")) !== null || (await tryRead(cwd + "/vitest.config.tsx")) !== null;
    reports.push({
      area: "test-config",
      message: hasJest ? "Jest config found." : hasVitest ? "Vitest config found." : "No test framework config detected.",
    });

    let testRun = null;
    if (hasJest) {
      const r = await run("npx", ["jest", "--listTests", "--passWithNoTests"], cwd);
      testRun = { ok: r.code === 0, output: (r.stdout || r.stderr).slice(0, 500) };
    } else if (hasVitest) {
      const r = await run("npx", ["vitest", "run", "--reporter=verbose"], cwd);
      testRun = { ok: r.code === 0, output: (r.stdout || r.stderr).slice(0, 500) };
    }

    if (testRun) reports.push({ area: "test-execution", passed: testRun.ok, output: testRun.output });

    return { tool: "check_tests", reports, passed: !reports.some((r) => r.area === "test-execution" && !r.passed) };
  } catch (err) {
    return { tool: "check_tests", error: err.message, reports };
  }
}

// ─── Tool: check_cicd ───────────────────────────────────────────────────────

export async function toolCheckCICD(args) {
  const cwd = (args.cwd || process.cwd()).toString();
  const reports = [];

  const checks = [
    { path: ".github/workflows/ci.yml", name: "GitHub Actions CI" },
    { path: ".github/workflows/cd.yml", name: "GitHub Actions CD" },
    { path: ".github/workflows/deploy.yml", name: "GitHub Actions Deploy" },
    { path: ".gitlab-ci.yml", name: "GitLab CI" },
    { path: "Jenkinsfile", name: "Jenkinsfile" },
    { path: ".circleci/config.yml", name: "CircleCI" },
    { path: "Dockerfile", name: "Dockerfile" },
    { path: "docker-compose.yml", name: "docker-compose.yml" },
    { path: ".pre-commit-config.yaml", name: "Pre-commit hooks" },
  ];

  for (const { path: p, name } of checks) {
    const exists = (await tryRead(cwd + "/" + p)) !== null;
    reports.push({ name, present: exists, severity: exists ? "info" : "warn" });
  }

  const pkg = JSON.parse((await tryRead(cwd + "/package.json")) || "{}");
  const hasBuild = !!pkg.scripts?.build;
  const hasTest = !!pkg.scripts?.test;
  const hasLint = !!pkg.scripts?.lint;
  reports.push({
    name: "package-scripts",
    build: hasBuild,
    test: hasTest,
    lint: hasLint,
    severity: hasBuild && hasTest && hasLint ? "info" : "warn",
  });

  return { tool: "check_cicd", reports };
}

// ─── Tool: check_linting ────────────────────────────────────────────────────

export async function toolCheckLinting(args) {
  const cwd = (args.cwd || process.cwd()).toString();
  const { execSync } = await import("node:child_process");

  const lintCmds = [
    { name: "eslint", cmd: ["npx", "eslint", "--version"] },
    { name: "prettier", cmd: ["npx", "prettier", "--version"] },
    { name: "biome", cmd: ["npx", "@biomejs/biome", "--version"] },
    { name: "oxlint", cmd: ["npx", "oxlint", "--version"] },
    { name: "stylelint", cmd: ["npx", "stylelint", "--version"] },
  ];

  const results = [];
  for (const { name, cmd } of lintCmds) {
    try {
      const ver = execSync(cmd.join(" "), { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim();
      results.push({ tool: name, installed: true, version: ver });
    } catch {
      results.push({ tool: name, installed: false });
    }
  }

  let eslintResults = null;
  const eslintInstalled = results.find((r) => r.tool === "eslint" && r.installed);
  if (eslintInstalled) {
    const r = await run("npx", ["eslint", ".", "--format", "compact"], cwd);
    eslintResults = { passed: r.code === 0, output: (r.stdout || r.stderr).slice(0, 2000) };
  }

  return { tool: "check_linting", linterVersions: results, eslint: eslintResults };
}

// ─── Tool: check_security ───────────────────────────────────────────────────

export async function toolCheckSecurity(args) {
  const cwd = (args.cwd || process.cwd()).toString();
  const reports = [];

  const envFiles = await listFiles(cwd);
  const hasEnv = envFiles.some((f) => f === ".env" || f.startsWith(".env."));
  reports.push({
    area: "secret-management",
    severity: hasEnv ? "warn" : "info",
    message: hasEnv ? ".env file(s) found at project root. Ensure they are in .gitignore." : "No .env files at project root.",
  });

  const gitLog = await run("git", ["log", "--oneline", "-20"], cwd);
  reports.push({
    area: "git-history",
    recentCommits: gitLog.stdout.trim().split("\n").filter(Boolean).length,
    message: `${gitLog.stdout.trim().split("\n").filter(Boolean).length} recent commit(s) found.`,
  });

  const pkg = await tryRead(cwd + "/package.json");
  if (pkg) {
    const audit = await run("npm", ["audit", "--production"], cwd);
    const parsed = (() => {
      try {
        return JSON.parse(audit.stdout);
      } catch {
        return null;
      }
    })();
    if (parsed) {
      reports.push({
        area: "dependency-security",
        vulnerabilities: parsed.vulnerabilities || 0,
        fine: (parsed.fine || 0) > 0,
        low: (parsed.low || 0) > 0,
        moderate: (parsed.moderate || 0) > 0,
        high: (parsed.high || 0) > 0,
        critical: (parsed.critical || 0) > 0,
      });
    } else {
      reports.push({ area: "dependency-security", rawOutput: audit.stdout.slice(0, 500) });
    }
  }

  return { tool: "check_security", reports };
}

// ─── Tool: check_architecture ───────────────────────────────────────────────

export async function toolCheckArchitecture(args) {
  const cwd = (args.cwd || process.cwd()).toString();
  const depth = Number(args.depth || 2);
  const reports = [];

  try {
    const { execSync } = await import("node:child_process");
    const tree = execSync(
      `find . -maxdepth ${depth} -type d | grep -v node_modules | grep -v '.git' | sort`,
      { cwd, encoding: "utf8" },
    );
    const dirs = tree.trim().split("\n").filter(Boolean);
    reports.push({ area: "directory-structure", directories: dirs.slice(0, 30) });

    const hasSrc = dirs.some((d) => d.includes("/src") || d === "./src");
    const hasTests = dirs.some((d) => d.includes("test") || d.includes("spec") || d.includes("__tests__"));
    const hasDist = dirs.some((d) => d.includes("dist") || d.includes("build"));
    const hasDocs = dirs.some((d) => d.includes("docs") || d === "./docs");

    const structureReport = {
      area: "structure-convention",
      hasSrc,
      hasTests,
      hasDist,
      hasDocs,
      warnings: [],
    };
    if (!hasSrc) structureReport.warnings.push("No src/ directory found — consider organizing source code.");
    if (!hasTests) structureReport.warnings.push("No test directory found.");
    if (!hasDocs) structureReport.warnings.push("No docs/ directory found.");
    reports.push(structureReport);
  } catch (err) {
    reports.push({ area: "architecture", error: err.message });
  }

  const workspacePkg = await tryRead(cwd + "/package.json");
  const hasWorkspaces = workspacePkg ? JSON.parse(workspacePkg).workspaces !== undefined : false;
  const hasNx = (await tryRead(cwd + "/nx.json")) !== null;
  const hasLerna = (await tryRead(cwd + "/lerna.json")) !== null;
  reports.push({
    area: "monorepo",
    workspacePackageJson: hasWorkspaces,
    nxConfigured: hasNx,
    lernaConfigured: hasLerna,
  });

  return { tool: "check_architecture", reports };
}

// ─── Tool: production_readiness ─────────────────────────────────────────────

export async function toolProductionReadiness(args) {
  const cwd = (args.cwd || process.cwd()).toString();
  const items = [];
  const add = (check, passed, detail) => items.push({ check, passed, detail });

  const pkg = await tryRead(cwd + "/package.json");
  add("package.json exists", !!pkg, pkg ? `name: ${JSON.parse(pkg).name}` : "missing");

  const hasLock =
    (await tryRead(cwd + "/package-lock.json")) !== null ||
    (await tryRead(cwd + "/yarn.lock")) !== null ||
    (await tryRead(cwd + "/bun.lockb")) !== null;
  add("Lock file present", hasLock, hasLock ? "dependency versions pinned" : "dependencies not pinned");

  const readme = await tryRead(cwd + "/README.md");
  add("README.md present", !!readme, readme ? "project documented" : "no documentation");

  const gitignore = await tryRead(cwd + "/.gitignore");
  add(".gitignore present", !!gitignore, gitignore ? "build artifacts excluded" : "risk of committing sensitive files");

  const eslintFiles = await listFiles(cwd);
  const hasEslint = eslintFiles.some((f) => f.startsWith(".eslintrc") || f === "eslint.config.js" || f === "eslint.config.mjs");
  add("ESLint configured", hasEslint, hasEslint ? "code quality enforced" : "no linter");

  const tsconfig = await tryRead(cwd + "/tsconfig.json");
  const strict = tsconfig ? JSON.parse(tsconfig).compilerOptions?.strict : false;
  add("TypeScript strict mode", !!strict, strict ? "strict type checking enabled" : "strict mode not enabled");

  const hasTests = eslintFiles.some((f) => f.endsWith(".test.ts") || f.endsWith(".spec.ts"));
  add("Test files present", hasTests, hasTests ? "tests exist" : "no tests found");

  const hasCI = (await tryRead(cwd + "/.github/workflows/ci.yml")) !== null;
  add("CI/CD pipeline", hasCI, hasCI ? "GitHub Actions CI detected" : "no CI pipeline");

  const hasEnv = eslintFiles.some((f) => f === ".env" || f.startsWith(".env."));
  add("No .env at root", !hasEnv, hasEnv ? "WARNING: .env files should not be committed" : "clean");

  const pkgData = pkg ? JSON.parse(pkg) : {};
  add("Build script defined", !!pkgData.scripts?.build, pkgData.scripts?.build ? pkgData.scripts.build : "missing");

  const total = items.length;
  const passed = items.filter((i) => i.passed).length;
  const pct = total > 0 ? Math.round((passed / total) * 100) : 0;
  const grade = pct >= 90 ? "A" : pct >= 75 ? "B" : pct >= 60 ? "C" : pct >= 40 ? "D" : "F";

  return { tool: "production_readiness", score: { total, passed, percentage: pct, grade }, items };
}
