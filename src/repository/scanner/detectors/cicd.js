/**
 * Code Guardian — CI/CD Signal Detection (Phase 8C, extended by Official Roadmap
 * Phase 11)
 *
 * Recognises continuous-integration configuration by its documented location, so
 * "a pipeline is configured" is reported as an observed fact. Whether the
 * pipeline is complete, correct or enforced is not a scanner question.
 *
 * Rules are matched by path shape rather than by a glob engine:
 * `directoryPath` + `extension` for workflow directories, exact `basename` for
 * the single-file providers.
 *
 * ### Phase 11: a workflow file is not a test run
 *
 * The mere presence of `.github/workflows` does not prove tests execute in CI.
 * Phase 11 therefore adds one bounded content pass over the observed workflow
 * files: each file's text is classified into the closed runner vocabulary, and the
 * record states whether a *test invocation* was established, whether the file was
 * read and established none, or whether it could not be interpreted. This is the
 * narrow testing-related CI fact Phase 11 needs — the full content-aware CI/CD
 * analyzer is a later roadmap phase and is deliberately not implemented here.
 *
 * Reading is bounded and deterministic: a per-file byte cap, a global file and
 * byte budget, files consumed in sorted order, and anything beyond a budget
 * recorded as `unknown` — never as "this workflow runs no tests".
 */

import { capEvidence, compareEvidence, SCAN_SIGNALS } from "../contracts.js";
import { classifyQualityCommand } from "../policies/quality.js";
import { classifyTestCommand, looksBinary } from "../policies/testing.js";
import { matchEntries } from "./match.js";

/** Ordered CI/CD rules (most specific first). */
export const CICD_RULES = Object.freeze([
  {
    directoryPath: ".github/workflows",
    extension: [".yml", ".yaml"],
    provider: "github-actions",
  },
  { basename: ".gitlab-ci.yml", provider: "gitlab-ci" },
  { path: ".circleci/config.yml", provider: "circleci" },
  { path: ".circleci/config.yaml", provider: "circleci" },
  { basename: "azure-pipelines.yml", provider: "azure-pipelines" },
  { basename: "azure-pipelines.yaml", provider: "azure-pipelines" },
  {
    directoryPath: "azure-pipelines",
    extension: [".yml", ".yaml"],
    provider: "azure-pipelines",
  },
  {
    directoryPath: ".buildkite",
    extension: [".yml", ".yaml"],
    provider: "buildkite",
  },
  { basename: "Jenkinsfile", caseInsensitive: true, provider: "jenkins" },
  { basename: ".travis.yml", provider: "travis-ci" },
  { basename: "bitbucket-pipelines.yml", provider: "bitbucket-pipelines" },
  { basename: "appveyor.yml", provider: "appveyor" },
  { basename: ".drone.yml", provider: "drone" },
  { basename: "codefresh.yml", provider: "codefresh" },
  { basename: "cloudbuild.yaml", provider: "google-cloud-build" },
  { basename: "buildspec.yml", provider: "aws-codebuild" },
]);

/** Byte and file bounds on the Phase 11 content pass over CI files. */
export const CICD_ACQUISITION_LIMITS = Object.freeze({
  maxFiles: 50,
  maxFileBytes: 131072,
  maxTotalBytes: 4 * 1024 * 1024,
});

/** How a CI file's test-execution evidence was established. */
export const CI_TEST_EXECUTION = Object.freeze({
  DETECTED: "detected",
  NONE: "none",
  UNKNOWN: "unknown",
});

/** Why a CI file's test execution could not be established. */
export const CI_TEST_EXECUTION_REASONS = Object.freeze([
  "unreadable",
  "too-large",
  "not-text",
  "budget-exhausted",
]);

/** The extensions whose CI text is read for commands. */
const READABLE_CI_EXTENSIONS = Object.freeze([".yml", ".yaml", "Jenkinsfile"]);

function extensionOf(path) {
  const name = String(path).split("/").pop() ?? "";
  const dot = name.lastIndexOf(".");
  return dot <= 0 ? "" : name.slice(dot).toLowerCase();
}

function isReadableCiFile(entry) {
  const extension = extensionOf(entry.path);
  if (READABLE_CI_EXTENSIONS.includes(extension)) return true;
  return (String(entry.path).split("/").pop() ?? "") === "Jenkinsfile";
}

/**
 * Detect CI/CD providers and, for the readable ones, whether a test invocation is
 * established.
 *
 * @param {object} view Repository view.
 * @returns {Promise<{ detected: boolean, providers: string[], evidence: object[],
 *   evidenceTruncated: boolean }>}
 */
export async function detectCicd(view) {
  const matches = matchEntries(CICD_RULES, view.files);

  const providers = new Set();
  const evidence = matches.map(({ rule, entry }) => {
    providers.add(rule.provider);
    return {
      path: entry.path,
      signal: SCAN_SIGNALS.CI_CONFIGURATION,
      provider: rule.provider,
      testExecution: CI_TEST_EXECUTION.UNKNOWN,
      testRunners: [],
      testLevels: [],
      coverageCommands: [],
      // Phase 12 — the code-quality tools this workflow's content invokes. Kept
      // separate from the test vocabulary so a consumer never reads a linter as a
      // test runner.
      qualityCommands: [],
      reason: null,
    };
  });

  const ordered = evidence.sort(compareEvidence);
  const capped = capEvidence(ordered);

  let filesRead = 0;
  let totalBytes = 0;

  for (const entry of capped.evidence) {
    if (!isReadableCiFile(entry)) {
      entry.reason = "not-text";
      continue;
    }

    const fileBudgetLeft = CICD_ACQUISITION_LIMITS.maxFiles - filesRead;
    const byteBudgetLeft = CICD_ACQUISITION_LIMITS.maxTotalBytes - totalBytes;
    if (fileBudgetLeft <= 0 || byteBudgetLeft <= 0) {
      entry.reason = "budget-exhausted";
      continue;
    }

    const maxBytes = Math.min(CICD_ACQUISITION_LIMITS.maxFileBytes, byteBudgetLeft);
    const read = await view.read(entry.path, { maxBytes });
    if (!read.ok) {
      entry.reason = "unreadable";
      continue;
    }

    const content = typeof read.content === "string" ? read.content : "";
    if (looksBinary(content)) {
      entry.reason = "not-text";
      continue;
    }

    filesRead += 1;
    totalBytes += Number.isInteger(read.bytesRead) ? read.bytesRead : 0;

    const classification = classifyTestCommand(content);
    entry.testRunners = [...classification.runners];
    entry.testLevels = [...classification.levels];
    entry.coverageCommands = [...classification.coverage];
    entry.testExecution =
      classification.runners.length > 0 ? CI_TEST_EXECUTION.DETECTED : CI_TEST_EXECUTION.NONE;
    entry.qualityCommands = [...classifyQualityCommand(content).tools];
    entry.reason = read.truncated === true ? "too-large" : null;
  }

  return {
    detected: capped.evidence.length > 0,
    providers: [...providers].sort(),
    evidence: capped.evidence,
    evidenceTruncated: capped.evidenceTruncated,
  };
}
