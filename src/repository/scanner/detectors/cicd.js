/**
 * Code Guardian — CI/CD Signal Detection (Phase 8C)
 *
 * Recognises continuous-integration configuration by its documented location, so
 * "a pipeline is configured" is reported as an observed fact. Whether the
 * pipeline is complete, correct or enforced is not a scanner question.
 *
 * Rules are matched by path shape rather than by a glob engine:
 * `directoryPath` + `extension` for workflow directories, exact `basename` for
 * the single-file providers.
 */

import { capEvidence, compareEvidence, SCAN_SIGNALS } from "../contracts.js";
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

/**
 * Detect CI/CD providers.
 *
 * @param {object} view Repository view.
 * @returns {{ detected: boolean, providers: string[], evidence: object[], evidenceTruncated: boolean }}
 */
export function detectCicd(view) {
  const matches = matchEntries(CICD_RULES, view.files);

  const providers = new Set();
  const evidence = matches.map(({ rule, entry }) => {
    providers.add(rule.provider);
    return {
      path: entry.path,
      signal: SCAN_SIGNALS.CI_CONFIGURATION,
      provider: rule.provider,
    };
  });

  const ordered = evidence.sort(compareEvidence);
  const capped = capEvidence(ordered);

  return {
    detected: ordered.length > 0,
    providers: [...providers].sort(),
    evidence: capped.evidence,
    evidenceTruncated: capped.evidenceTruncated,
  };
}
