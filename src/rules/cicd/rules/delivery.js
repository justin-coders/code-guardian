/**
 * Code Guardian — Artifact & Cache Rules (Official Roadmap Phase 13)
 *
 * The roadmap's "artifact handling" and "caching" domains, both absence-shaped over a complete
 * read and both reading a **documented structural** vocabulary rather than the bare word:
 *
 *   artifacts  an upload/download *action or command*, a retention declaration, a release asset
 *   caching    a cache action, a setup action's `cache:` input, an explicit cache key step, a
 *              Docker layer cache
 *
 * The word "artifact" in a description and the word "cache" in an unrelated configuration
 * establish nothing, which is what keeps these rules from firing on prose.
 */

import { CICD_RULE_IDS } from "../contracts.js";

import { createAbsenceRule } from "./factories.js";

export const deliveryRules = Object.freeze([
  createAbsenceRule({
    id: CICD_RULE_IDS.ARTIFACTS_NOT_HANDLED,
    domain: "artifact-handling",
    title: "A workflow establishes no artifact handling",
    description:
      "The workflow's content was read in full and establishes no artifact upload, artifact download, retention declaration or release asset. Many correct pipelines publish no artifacts — a repository whose build output is consumed only by a later step in the same job legitimately handles none — so the finding reports the observation and nothing more: it is not a defect claim, and it says nothing about how a build output is stored or whether it should be.",
    behavior: (workflow) => workflow.artifacts,
    absenceReason:
      "the workflow was read in full and establishes no artifact upload, download, retention or release asset",
    severity: "info",
    tags: ["artifact-handling"],
    falsePositives: [
      "an artifact mechanism this build's vocabulary does not document for the provider",
      "a pipeline that legitimately passes data between jobs by another means",
    ],
  }),

  createAbsenceRule({
    id: CICD_RULE_IDS.CACHING_NOT_CONFIGURED,
    domain: "caching",
    title: "A workflow establishes no cache configuration",
    description:
      "The workflow's content was read in full and establishes no cache action, no setup action's `cache:` input, no explicit cache key and no Docker layer cache. The finding reports that observation: it does not say caching is impossible in this pipeline, and it makes no claim about cache correctness, cache-key hygiene or whether a cache should exist at all — a workflow whose work is dominated by a fast build has no reason to have one.",
    behavior: (workflow) => workflow.caches,
    absenceReason: "the workflow was read in full and establishes no cache configuration",
    severity: "info",
    tags: ["caching"],
    falsePositives: [
      "a provider-native cache mechanism this build's vocabulary does not document",
      "a cache configured at the provider/runner level rather than in the workflow file",
    ],
  }),
]);
