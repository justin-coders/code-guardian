/**
 * Code Guardian — Pipeline Rules: dependencies, tests, builds (Official Roadmap Phase 13)
 *
 * The three "does the pipeline actually do the work" domains. All three are absence-shaped — a
 * workflow read in full that establishes none of the behavior — and all three read a **closed,
 * language-aware command vocabulary** from the acquisition layer rather than a bare word, so a
 * job named `build` establishes nothing about building and a step that echoes `"test"` is not a
 * test run.
 *
 * `test-execution` consumes Official Phase 11's own evidence: the model already records whether
 * a workflow's content established a *test invocation*, with the runner ids and the
 * `detected`/`none`/`unknown` vocabulary Phase 11 defined. The rule reads that fact rather than
 * re-classifying commands, so the two phases can never disagree about what a workflow runs, and
 * it does not restate Phase 11's conclusions about the repository's *test configuration*.
 */

import { CICD_RULE_IDS } from "../contracts.js";

import { createAbsenceRule } from "./factories.js";

export const pipelineRules = Object.freeze([
  createAbsenceRule({
    id: CICD_RULE_IDS.DEPENDENCIES_NOT_ESTABLISHED,
    domain: "dependency-installation",
    title: "A workflow establishes no dependency installation",
    description:
      "The workflow's content was read in full and establishes no dependency-installation command from the acquisition layer's closed, cross-ecosystem vocabulary (`npm ci`, `pip install`, `cargo build`, `go mod download`, `bundle install`, and the other documented invocations). A build tool that resolves dependencies implicitly, or an installation command this vocabulary does not document, looks identical to the absence of one — which is why the finding names the observation and not the repository's dependency health.",
    behavior: (workflow) => workflow.dependencyInstallation,
    absenceReason: "the workflow was read in full and establishes no dependency-installation command",
    severity: "low",
    tags: ["dependency-installation"],
    falsePositives: [
      "an ecosystem whose install command this build's vocabulary does not document",
      "a pipeline that relies on an image with dependencies pre-installed",
    ],
  }),

  createAbsenceRule({
    id: CICD_RULE_IDS.TESTS_NOT_ESTABLISHED,
    domain: "test-execution",
    title: "A workflow establishes no test execution",
    description:
      "The workflow's content was read in full and Official Phase 11's closed runner vocabulary established no test invocation in it — the workflow's own test-execution evidence reads `none`, not `unknown`. The finding reports that observation alone: it does not say the repository has no tests, and it does not restate Phase 11's conclusions about the repository's test configuration or CI coverage of it.",
    behavior: (workflow) =>
      workflow.testExecution === "detected"
        ? workflow.testRunners.length > 0
          ? [...workflow.testRunners]
          : ["detected"]
        : [],
    absenceReason: "the workflow was read in full and establishes no test invocation",
    severity: "low",
    tags: ["test-execution"],
    falsePositives: [
      "a test runner this build's vocabulary does not document",
      "tests invoked only through a wrapper script the workflow's command text does not name",
    ],
  }),

  createAbsenceRule({
    id: CICD_RULE_IDS.BUILD_NOT_ESTABLISHED,
    domain: "build-execution",
    title: "A workflow establishes no build execution",
    description:
      "The workflow's content was read in full and establishes no build command from the acquisition layer's closed, cross-ecosystem vocabulary (`npm run build`, `cargo build`, `go build`, `dotnet build`, `mvn package`, `gradle build`, `cmake`, and the other documented invocations). A build performed by an action, or an invocation this vocabulary does not document, looks identical to the absence of one.",
    behavior: (workflow) => workflow.builds,
    absenceReason: "the workflow was read in full and establishes no build command",
    severity: "low",
    tags: ["build-execution"],
    falsePositives: [
      "a build performed inside a container action rather than a `run:` command",
      "a toolchain whose build command this build's vocabulary does not document",
    ],
  }),
]);
