/**
 * Code Guardian — CI/CD Rule Set (Official Roadmap Phase 13)
 *
 * The twelve rules this pack ships, in one frozen, id-sorted list. Every rule id maps to exactly
 * one of the twelve official-roadmap domains, and the id order is the registry's order, so a
 * rule run's output is deterministic without any sorting at the call site.
 *
 * Providers are **not** a rule dimension: the acquisition layer owns provider knowledge (its
 * profile table turns each provider's documented syntax into the same closed vocabulary), so the
 * rules read one union of facts and never branch on a provider. Adding a provider is adding a
 * profile there, not editing a rule here.
 */

import { deliveryRules } from "./delivery.js";
import { deploymentRules } from "./deployment.js";
import { permissionRules } from "./permissions.js";
import { pipelineRules } from "./pipeline.js";
import { safetyRules } from "./safety.js";
import { triggerRules } from "./triggers.js";

/** Every CI/CD rule, frozen and sorted by id. */
export const cicdRules = Object.freeze(
  [
    ...triggerRules,
    ...permissionRules,
    ...pipelineRules,
    ...deploymentRules,
    ...deliveryRules,
    ...safetyRules,
  ].sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0)),
);
