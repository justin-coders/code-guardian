/**
 * Code Guardian — Deployment & Environment-Separation Rules (Official Roadmap Phase 13)
 *
 * The roadmap's "deployment" and "environment separation" domains.
 *
 *   deployment             a **presence** rule. A workflow that pushes an image, applies a
 *                          manifest, upgrades a chart or publishes a package is an observation
 *                          worth reporting, and the finding lists the deployment invocations it
 *                          saw. It never claims the deployment succeeded, is safe, or is
 *                          reversible — this build runs nothing.
 *   environment separation a **relation** rule. Environment separation is not inferred from the
 *                          string `NODE_ENV=production` (the roadmap forbids exactly that): the
 *                          rule compares two facts — the workflow deploys, and no environment
 *                          class is declared — and even then only states that no separation was
 *                          *established* from this read.
 */

import { CICD_RULE_IDS } from "../contracts.js";

import { createPresenceRule, createRelationRule } from "./factories.js";

export const deploymentRules = Object.freeze([
  createPresenceRule({
    id: CICD_RULE_IDS.DEPLOYMENT_OBSERVED,
    domain: "deployment",
    title: "A workflow publishes or deploys",
    description:
      "The workflow's content establishes a deployment invocation from the acquisition layer's bounded vocabulary (a `kubectl apply`, a `helm upgrade`, a `terraform apply`, a registry push, a provider deploy command, a package publish). The finding lists the invocations observed. It is an observation about configuration text: it does not mean a deployment ran, succeeded, targeted the intended environment, or is safe to repeat.",
    behavior: (workflow) => workflow.deployments,
    severity: "info",
    tags: ["deployment"],
    falsePositives: [
      "a deploy command documented in a comment or echoed in a string (both are excluded by the acquisition layer's comment/quote handling)",
      "a deployment performed by a provider action this vocabulary does not document",
    ],
  }),

  createRelationRule({
    id: CICD_RULE_IDS.ENVIRONMENT_NOT_SEPARATED,
    domain: "environment-separation",
    title: "A deploying workflow establishes no environment separation",
    description:
      "The workflow deploys and no environment class is declared in it, over a complete read of the file. The finding reports the relation between those two observations — it does not infer environment separation from an application's own configuration (a `NODE_ENV=production` variable is not CI/CD environment separation, as the roadmap states), and it does not claim the deployment targets production, or any environment at all.",
    premise: (workflow) => workflow.deployments,
    conclusion: (workflow) => workflow.environments,
    severity: "low",
    tags: ["environment-separation"],
    falsePositives: [
      "environment separation expressed through a matrix, a reusable workflow or provider settings this read does not evaluate",
      "a single-environment repository where separation genuinely does not apply",
    ],
  }),
]);
