/**
 * Code Guardian — API Analysis Unestablished-Domain Rules (Official Roadmap Phase 16)
 *
 * The shared engine behind the domains the repository model holds **no fact** for. Six of the
 * thirteen official domains — schema validation, error handling, status codes, pagination,
 * request limits and correlation IDs — need evidence the model does not carry: handler bodies,
 * framework reply configuration, query-parameter declarations, body-parser options,
 * request-context propagation. This build reads none of those, so the honest answer for an
 * API subject is `unknown`, never a clean pass and never an invented failure.
 *
 * The distinction the roadmap insists on is the whole point of this module:
 *
 *   CLI / no API subject   `not_applicable` — no finding, and the summary says why
 *   API subject exists     `unknown` — the repository does not establish the fact this build
 *                          would need, so the domain is deliberately left unresolved
 *
 * A rule built from here never produces a finding and never declares a conclusion. It exists so
 * each official domain is *addressed* (and its abstention is attributable) rather than silently
 * omitted, which is exactly what the roadmap asks an honest analyzer to do.
 */

import { createRule } from "../../../core/index.js";

import { API_ANALYSIS_BASES, API_ANALYSIS_STATES } from "../contracts.js";
import { queryFor } from "../signals.js";

import { gateOnApiSubject, unknownDetection } from "./shared.js";

const BASIS = API_ANALYSIS_BASES.API_GRAPH;

function detectUnestablished(context, spec) {
  const query = queryFor(context);

  const gated = gateOnApiSubject(query, BASIS);
  if (gated !== null) return gated;

  return unknownDetection(typeof spec.reason === "function" ? spec.reason(query) : spec.reason);
}

/**
 * Build a rule for a domain the model cannot establish.
 *
 * @param {object} spec
 * @param {string} spec.id Rule id (already namespaced).
 * @param {string} spec.domain The official domain name.
 * @param {string} spec.version Rule version.
 * @param {string} spec.category Finding category.
 * @param {string} spec.severity Finding severity.
 * @param {string} spec.ruleTitle Rule-level title.
 * @param {string} spec.ruleDescription Rule-level description.
 * @param {string|Function} spec.reason Why the model cannot establish the domain.
 * @param {string[]} [spec.tags]
 * @param {string[]} [spec.falsePositives]
 * @returns {object} A Core rule descriptor.
 */
export function createUnestablishedRule(spec) {
  return createRule({
    id: spec.id,
    version: spec.version,
    category: spec.category,
    title: spec.ruleTitle,
    description: spec.ruleDescription,
    severity: spec.severity,
    applicability: {},
    detect: (context) => detectUnestablished(context, spec),
    remediation: {},
    metadata: {
      basis: BASIS,
      domain: spec.domain,
      mode: "unestablished",
      state: API_ANALYSIS_STATES.UNKNOWN,
      tags: spec.tags ?? ["api", spec.domain],
      falsePositives: spec.falsePositives ?? [],
    },
  });
}
