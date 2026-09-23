/**
 * Code Guardian — Dependency Rule Set (Phase 13, extended by Phase 14)
 *
 * The pack's rules, sorted by id so the exported order never depends on the order
 * they happen to be listed in. The registry validates and sorts again; this exists so
 * a consumer importing the rules directly still gets a deterministic set.
 */

import { dependencyDeclarationRules } from "./declarations.js";
import { dependencyGraphRules } from "./graph.js";

export { dependencyDeclarationRules, dependencyGraphRules };

export const dependencyRules = Object.freeze(
  [...dependencyDeclarationRules, ...dependencyGraphRules].sort((a, b) =>
    a.id < b.id ? -1 : a.id > b.id ? 1 : 0,
  ),
);
