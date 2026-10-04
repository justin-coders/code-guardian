/**
 * Code Guardian — API OpenAPI Rule (Official Roadmap Phase 16)
 *
 * The "OpenAPI" domain, and the pack's one **artifact** rule. The model establishes no
 * relationship between an API document and the API graph, so the rule distinguishes exactly two
 * facts and never merges them:
 *
 *   an OpenAPI artifact is observed   a file whose basename is a recognised OpenAPI/Swagger
 *                                     document exists in the inventory (`openapi.yaml`,
 *                                     `swagger.json`, …). Reported as an informational finding.
 *   its relation to the API           not established. A document existing does not mean the API
 *                                     is documented accurately or that the document is in sync
 *                                     with the route set, so the finding says so and the domain
 *                                     makes no synchronisation claim.
 *
 * The absence side is gated on the file inventory's completeness: "no OpenAPI artifact exists"
 * is only claimed when the scan covered the repository.
 */

import { createRule } from "../../../core/index.js";

import { COVERAGE_GUARANTEES } from "../../../repository/model/index.js";

import {
  API_ANALYSIS_BASES,
  API_ANALYSIS_CATEGORY,
  API_ANALYSIS_CONFIDENCE,
  API_ANALYSIS_RULE_IDS,
  API_ANALYSIS_RULE_VERSION,
  API_ANALYSIS_STATES,
} from "../contracts.js";
import { fileInventoryCoverage, openapiArtifacts, queryFor } from "../signals.js";

import { capFindings, gateOnApiSubject, unknownDetection } from "./shared.js";

const BASIS = API_ANALYSIS_BASES.FILE_INVENTORY;
const IDS = API_ANALYSIS_RULE_IDS;

function detect(context) {
  const query = queryFor(context);

  const gated = gateOnApiSubject(query, BASIS);
  if (gated !== null) return gated;

  const artifacts = openapiArtifacts(query);
  const inventory = fileInventoryCoverage(query);

  if (artifacts.length > 0) {
    const candidates = artifacts.map((artifact) => ({
      confidence: API_ANALYSIS_CONFIDENCE.OBSERVED_ARTIFACT,
      title: "An OpenAPI artifact is observed in the repository",
      description: `The repository contains \`${artifact.path}\`, whose basename names an OpenAPI/Swagger document. This states that the artifact is observed; it does not establish that the API is described accurately by it, that it is synchronised with the routes the API graph declares, or that it is served or maintained.`,
      evidence: [...artifact.evidenceIds],
      metadata: {
        basis: BASIS,
        state: API_ANALYSIS_STATES.ESTABLISHED,
        fingerprintKey: artifact.fingerprintKey,
        domain: "openapi",
        artifact: artifact.path,
        basename: artifact.basename,
      },
    }));
    const { entries, truncated } = capFindings(candidates);
    return {
      findings: entries,
      evidence: [],
      metadata: {
        basis: BASIS,
        state: API_ANALYSIS_STATES.ESTABLISHED,
        domain: "openapi",
        artifacts: artifacts.length,
        reported: entries.length,
        capped: truncated,
        files: inventory.files,
      },
    };
  }

  if (inventory.coverage !== COVERAGE_GUARANTEES.COMPLETE || inventory.truncated) {
    return unknownDetection(
      "no OpenAPI artifact was observed, but the file inventory is not complete",
    );
  }

  return {
    findings: [],
    evidence: [],
    metadata: {
      basis: BASIS,
      state: API_ANALYSIS_STATES.ESTABLISHED,
      domain: "openapi",
      artifacts: 0,
      reported: 0,
      capped: false,
      files: inventory.files,
    },
  };
}

export const openapiRules = Object.freeze([
  createRule({
    id: IDS.OPENAPI,
    version: API_ANALYSIS_RULE_VERSION,
    category: API_ANALYSIS_CATEGORY,
    title: "An OpenAPI artifact is observed in the repository",
    description:
      "A file whose basename is a recognised OpenAPI/Swagger document was observed, and the finding states only that the artifact exists, citing the inventory observation behind it. It makes no claim that the API is documented accurately, that the document is synchronised with the routes the API graph declares, that it is served, or that it is maintained — the model establishes no relationship between a document and the API, and a filename is not a synchronisation proof. When no artifact is observed the rule reports the fact only over a complete file inventory, and abstains otherwise.",
    severity: "info",
    applicability: {},
    detect,
    remediation: {},
    metadata: {
      basis: BASIS,
      domain: "openapi",
      mode: "artifact",
      tags: ["api", "openapi", "documentation"],
      falsePositives: [
        "a document describing an API other than this repository's",
        "a stale document that no longer matches the declared routes",
        "an artifact under a basename this build does not recognise",
      ],
    },
  }),
]);
