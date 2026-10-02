/**
 * Code Guardian — Test Script Rules (Official Roadmap Phase 11)
 *
 * Two rules for the roadmap's "test scripts" domain, both reading the *manifest*
 * evidence the acquisition layer already classified:
 *
 *   testing.script.missing            an observed Node manifest declares no
 *                                     test-related script at all
 *   testing.script.unrecognized-runner a declared test script exists, but its
 *                                     command invokes no runner this build recognises
 *
 * A `package.json` whose parse *failed* is neither: its scripts cannot be read at
 * all, so the rule abstains with `unknown` rather than reporting a missing script.
 * A script declaration is evidence of intent, never proof the script succeeds, so
 * neither rule reports `verified` — only the summary's CI cross-check can.
 */

import { createRule } from "../../../core/index.js";

import {
  TESTING_BASES,
  TESTING_CATEGORY,
  TESTING_CONFIDENCE,
  TESTING_RULE_IDS,
  TESTING_RULE_VERSION,
} from "../contracts.js";
import { nodeManifestFacts, queryFor } from "../signals.js";

const PARSED = "parsed";
const FAILED = "failed";

export const scriptRules = Object.freeze([
  createRule({
    id: TESTING_RULE_IDS.SCRIPT_MISSING,
    version: TESTING_RULE_VERSION,
    category: TESTING_CATEGORY,
    title: "An observed Node manifest declares no test script",
    description:
      "An observed `package.json` was parsed and declares no script whose name is test-related (`test`, `test:unit`, `test:coverage`, `e2e`, `integration`, `spec`). Whether tests can be run through the package manager is therefore not established by the manifest. The finding reports the declaration, not the absence of tests.",
    severity: "info",
    applicability: {},
    detect: (context) => {
      const query = queryFor(context);
      const manifests = nodeManifestFacts(query);

      if (manifests.length === 0) {
        return {
          findings: [],
          evidence: [],
          metadata: { basis: TESTING_BASES.MANIFEST_SCRIPT, state: "not_applicable" },
        };
      }

      const unparsed = manifests.filter((record) => record.parseStatus !== PARSED);
      const findings = [];
      for (const record of manifests) {
        if (!record.parsed) continue;
        if (record.testScripts.length > 0) continue;
        findings.push({
          confidence: TESTING_CONFIDENCE.DECLARED_COMMAND,
          evidence: [...record.entity.evidenceIds],
          metadata: { basis: TESTING_BASES.MANIFEST_SCRIPT, state: "detected", path: record.path },
        });
      }

      // A manifest whose parse failed is `unknown`, not "declares no script": the
      // failure means its scripts could not be read, which the summary records as a
      // `failed` state for the scripts domain.
      if (findings.length === 0 && unparsed.some((record) => record.parseStatus === FAILED)) {
        return {
          findings: [],
          evidence: [],
          coverage: "unknown",
          reason: "an observed package.json could not be parsed, so its declared scripts are not established",
        };
      }

      return { findings, evidence: [], metadata: { basis: TESTING_BASES.MANIFEST_SCRIPT } };
    },
    remediation: {},
    metadata: { tags: ["testing", "scripts"], falsePositives: ["a repository whose tests are run by a task runner rather than npm"] },
  }),

  createRule({
    id: TESTING_RULE_IDS.SCRIPT_UNRECOGNIZED,
    version: TESTING_RULE_VERSION,
    category: TESTING_CATEGORY,
    title: "A declared test script invokes no recognised runner",
    description:
      "A test-related script in an observed `package.json` declares a command, but the command invokes no test runner this build recognises (Jest, Vitest, Mocha, the Node built-in runner, pytest, `go test`, …). The command may delegate to a runner through another tool, so this finding reports that the runner could not be identified from the command text, not that the script is broken.",
    severity: "info",
    applicability: {},
    detect: (context) => {
      const query = queryFor(context);
      const findings = [];

      for (const record of nodeManifestFacts(query)) {
        if (!record.parsed) continue;
        for (const script of record.testScripts) {
          if (script.command === null) continue;
          if (script.runners.length > 0) continue;
          findings.push({
            confidence: TESTING_CONFIDENCE.DECLARED_COMMAND,
            evidence: [...record.entity.evidenceIds],
            metadata: {
              basis: TESTING_BASES.MANIFEST_SCRIPT,
              state: "detected",
              path: record.path,
              script: script.name,
            },
          });
        }
      }

      return { findings, evidence: [], metadata: { basis: TESTING_BASES.MANIFEST_SCRIPT } };
    },
    remediation: {},
    metadata: { tags: ["testing", "scripts"], falsePositives: ["a script that shells out to a wrapper this build does not recognise"] },
  }),
]);
