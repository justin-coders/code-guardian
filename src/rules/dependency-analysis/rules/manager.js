/**
 * Code Guardian — Dependency Package Manager Consistency Rule (Official Roadmap Phase 15)
 *
 * The "package manager consistency" domain. It identifies the package-manager evidence the
 * repository actually contains — from lockfile basenames through a closed map — and reports an
 * inconsistency only where one is established: **two competing package managers lock the same
 * ecosystem**.
 *
 * It imposes no preferred manager (the roadmap prescribes none) and reports `not_applicable`
 * when the repository records no lockfile at all, because then there is no manager evidence to be
 * consistent or inconsistent about.
 */

import { createRule } from "../../../core/index.js";

import {
  DEPENDENCY_ANALYSIS_BASES,
  DEPENDENCY_ANALYSIS_CATEGORY,
  DEPENDENCY_ANALYSIS_CONFIDENCE,
  DEPENDENCY_ANALYSIS_RULE_IDS,
  DEPENDENCY_ANALYSIS_RULE_VERSION,
  DEPENDENCY_ANALYSIS_STATES,
} from "../contracts.js";
import { lockfileFacts, queryFor } from "../signals.js";

import { capFindings, keyFragment } from "./shared.js";

const CATEGORY = DEPENDENCY_ANALYSIS_CATEGORY;
const VERSION = DEPENDENCY_ANALYSIS_RULE_VERSION;
const IDS = DEPENDENCY_ANALYSIS_RULE_IDS;
const BASES = DEPENDENCY_ANALYSIS_BASES;
const STATES = DEPENDENCY_ANALYSIS_STATES;

export const dependencyManagerRules = Object.freeze([
  createRule({
    id: IDS.MANAGER_CONSISTENCY,
    version: VERSION,
    category: CATEGORY,
    title: "An ecosystem records competing package managers",
    description:
      "An ecosystem in this repository records lockfiles belonging to two or more distinct package managers, established from the observed lockfile names. The finding names the ecosystem, the managers and their lockfiles. It is an observation about the evidence present, not a preference for one manager over another.",
    severity: "low",
    applicability: {},
    detect: (context) => {
      const query = queryFor(context);
      const lockfiles = lockfileFacts(query);

      if (lockfiles.length === 0) {
        return {
          findings: [],
          evidence: [],
          metadata: { basis: BASES.PACKAGE_MANAGER, state: STATES.NOT_APPLICABLE, lockfiles: 0 },
        };
      }

      const byEcosystem = new Map();
      for (const lockfile of lockfiles) {
        if (lockfile.manager === null || lockfile.ecosystem === null) continue;
        const managers = byEcosystem.get(lockfile.ecosystem);
        if (managers === undefined) byEcosystem.set(lockfile.ecosystem, new Map([[lockfile.manager, [lockfile]]]));
        else {
          const list = managers.get(lockfile.manager);
          if (list === undefined) managers.set(lockfile.manager, [lockfile]);
          else list.push(lockfile);
        }
      }

      const candidates = [];
      for (const [ecosystem, managers] of byEcosystem) {
        if (managers.size < 2) continue;
        const entries = [...managers.entries()].sort((a, b) => (a[0] < b[0] ? -1 : 1));
        const evidence = [
          ...new Set(entries.flatMap(([, list]) => list.flatMap((lockfile) => lockfile.evidenceIds))),
        ].sort();
        if (evidence.length === 0) continue;
        candidates.push({
          ecosystem,
          managers: entries.map(([manager]) => manager),
          paths: entries.flatMap(([, list]) => list.map((lockfile) => lockfile.path)).sort(),
          evidence,
        });
      }

      if (candidates.length === 0) {
        return {
          findings: [],
          evidence: [],
          metadata: {
            basis: BASES.PACKAGE_MANAGER,
            state: STATES.ESTABLISHED,
            lockfiles: lockfiles.length,
            reported: 0,
          },
        };
      }

      candidates.sort((a, b) => (a.ecosystem < b.ecosystem ? -1 : 1));
      const { entries, truncated } = capFindings(candidates);
      const findings = entries.map((entry) => ({
        confidence: DEPENDENCY_ANALYSIS_CONFIDENCE.OBSERVED_FACT,
        description: `The \`${entry.ecosystem}\` ecosystem records lockfiles for ${entry.managers.length} distinct package managers — ${entry.managers.map((manager) => `\`${manager}\``).join(", ")} — in ${entry.paths.map((path) => `\`${path}\``).join(", ")}. Competing managers for one ecosystem leave no single record of the installed tree. This states the evidence present; it expresses no preference among managers.`,
        evidence: [...entry.evidence],
        metadata: {
          basis: BASES.PACKAGE_MANAGER,
          state: STATES.DETECTED,
          fingerprintKey: `manager:${keyFragment(entry.ecosystem)}`,
          ecosystem: entry.ecosystem,
          managers: [...entry.managers],
          lockfiles: [...entry.paths],
        },
      }));

      return {
        findings,
        evidence: [],
        metadata: {
          basis: BASES.PACKAGE_MANAGER,
          state: STATES.DETECTED,
          lockfiles: lockfiles.length,
          reported: findings.length,
          truncated,
        },
      };
    },
    remediation: {},
    metadata: {
      tags: ["dependency", "package-manager"],
      falsePositives: ["a repository deliberately migrating from one manager to another"],
    },
  }),
]);
