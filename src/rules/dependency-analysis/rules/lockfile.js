/**
 * Code Guardian — Dependency Lockfile Integrity Rule (Official Roadmap Phase 15)
 *
 * The "lockfile integrity" domain. It analyses the relationship between manifest declarations and
 * lockfile evidence, and reports only conditions the repository actually establishes:
 *
 *   lockfile-missing        a manifest declares runtime dependencies and no lockfile for its
 *                           ecosystem was observed
 *   declaration-unresolved  a lockfile exists, yet a directly declared dependency has no
 *                           resolution record at all
 *   conflicting-lockfiles   two lockfiles of the same package manager are present
 *
 * Applicability is ecosystem-aware: a missing lockfile is only reported for an ecosystem whose
 * convention establishes one (today `node`), never as a universal defect. Over incomplete
 * acquisition the rule answers `unknown`.
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
import {
  dependencyCoverageEstablished,
  dependencyDeclarations,
  dependencyEntities,
  lockfileFacts,
  manifestEntities,
  queryFor,
} from "../signals.js";

import { capFindings, keyFragment, unknownDetection } from "./shared.js";

const CATEGORY = DEPENDENCY_ANALYSIS_CATEGORY;
const VERSION = DEPENDENCY_ANALYSIS_RULE_VERSION;
const IDS = DEPENDENCY_ANALYSIS_RULE_IDS;
const BASES = DEPENDENCY_ANALYSIS_BASES;
const STATES = DEPENDENCY_ANALYSIS_STATES;

/** The ecosystem whose convention establishes a lockfile for this build. */
const LOCKFILE_ECOSYSTEM = "node";

export const dependencyLockfileRules = Object.freeze([
  createRule({
    id: IDS.LOCKFILE_INTEGRITY,
    version: VERSION,
    category: CATEGORY,
    title: "Manifest and lockfile evidence disagree",
    description:
      "The relationship between manifest declarations and lockfile evidence establishes one of the documented integrity conditions: a manifest declares runtime dependencies with no lockfile observed for its ecosystem; a lockfile exists yet a directly declared dependency has no resolution; or two lockfiles of the same package manager are present. Each condition is reported from real evidence, never assumed from a file being present, and a missing lockfile is reported only for an ecosystem whose convention establishes one.",
    severity: "low",
    applicability: {},
    detect: (context) => {
      const query = queryFor(context);
      // Every condition below is an *absence* claim about resolution ("no lockfile was observed",
      // "no resolution records this declaration"). Over an acquisition that did not interpret
      // every dependency source — a lockfile that exists but could not be parsed, say — that
      // absence is not established, so the rule answers `unknown` instead of inventing a gap.
      const coverage = dependencyCoverageEstablished(query);
      const manifests = manifestEntities(query);
      const lockfiles = lockfileFacts(query);
      const ecosystemLockfiles = lockfiles.filter((lockfile) => lockfile.ecosystem === LOCKFILE_ECOSYSTEM);
      const declarations = dependencyDeclarations(query);

      const runtimeByManifest = new Map();
      for (const declaration of declarations) {
        if (declaration.ecosystem !== LOCKFILE_ECOSYSTEM) continue;
        if (declaration.scope !== "runtime") continue;
        const list = runtimeByManifest.get(declaration.manifestPath);
        if (list === undefined) runtimeByManifest.set(declaration.manifestPath, [declaration]);
        else list.push(declaration);
      }

      const resolvedKeys = new Set();
      for (const dependency of dependencyEntities(query)) {
        if ((dependency.resolutions ?? []).length > 0) {
          resolvedKeys.add(`${dependency.ecosystem}\u0000${dependency.name}`);
        }
      }

      const candidates = [];

      if (coverage.established && ecosystemLockfiles.length === 0) {
        for (const manifest of manifests) {
          if (manifest.manifestKind !== "manifest") continue;
          if (manifest.ecosystemId !== `ecosystem:${LOCKFILE_ECOSYSTEM}`) continue;
          const runtime = runtimeByManifest.get(manifest.path) ?? [];
          if (runtime.length === 0) continue;
          if ((manifest.evidenceIds ?? []).length === 0) continue;
          candidates.push({
            kind: "lockfile-missing",
            description: `\`${manifest.path}\` declares ${runtime.length} runtime dependenc${runtime.length === 1 ? "y" : "ies"} but no \`${LOCKFILE_ECOSYSTEM}\` lockfile was observed, so the declared tree has no recorded resolution in this repository. This is an observation about the files the scan saw; it does not assume a lockfile is required in every workflow.`,
            evidence: [...manifest.evidenceIds],
            fingerprintKey: `lockfile-missing:${keyFragment(manifest.path)}`,
            metadata: { manifestPath: manifest.path, runtimeDependencies: runtime.length },
          });
        }
      }

      if (coverage.established && ecosystemLockfiles.length > 0) {
        const seen = new Set();
        for (const declaration of declarations) {
          if (declaration.ecosystem !== LOCKFILE_ECOSYSTEM || declaration.direct !== true) continue;
          const key = `${declaration.ecosystem}\u0000${declaration.name}`;
          if (resolvedKeys.has(key) || seen.has(key)) continue;
          seen.add(key);
          if (declaration.evidenceIds.length === 0) continue;
          candidates.push({
            kind: "declaration-unresolved",
            description: `\`${declaration.name}\` is declared directly in \`${declaration.manifestPath}\`, but the observed \`${LOCKFILE_ECOSYSTEM}\` lockfile(s) record no resolution for it. A declared dependency with no resolved version is a gap between declaration and resolution.`,
            evidence: [...declaration.evidenceIds],
            fingerprintKey: `declaration-unresolved:${keyFragment(declaration.ecosystem)}:${keyFragment(declaration.name)}`,
            metadata: {
              manifestPath: declaration.manifestPath,
              package: declaration.name,
              ecosystem: declaration.ecosystem,
            },
          });
        }
      }

      const byManager = new Map();
      for (const lockfile of ecosystemLockfiles) {
        if (lockfile.manager === null) continue;
        const list = byManager.get(lockfile.manager);
        if (list === undefined) byManager.set(lockfile.manager, [lockfile]);
        else list.push(lockfile);
      }
      for (const [manager, list] of byManager) {
        if (list.length < 2) continue;
        const evidence = [...new Set(list.flatMap((lockfile) => lockfile.evidenceIds))].sort();
        if (evidence.length === 0) continue;
        candidates.push({
          kind: "conflicting-lockfiles",
          description: `The \`${LOCKFILE_ECOSYSTEM}\` ecosystem records ${list.length} lockfiles for the \`${manager}\` package manager — ${list.map((lockfile) => `\`${lockfile.path}\``).join(", ")}. Two lockfiles of one manager state the resolution twice, which leaves no single record of the installed tree.`,
          evidence,
          fingerprintKey: `conflicting-lockfiles:${keyFragment(manager)}`,
          metadata: { manager, paths: list.map((lockfile) => lockfile.path) },
        });
      }

      if (candidates.length === 0) {
        const absence = coverage;
        if (!absence.established) {
          return unknownDetection(`no integrity condition was observed, but ${absence.reason}`);
        }
        if (declarations.length === 0) {
          return {
            findings: [],
            evidence: [],
            metadata: { basis: BASES.LOCKFILE_RESOLUTION, state: STATES.NOT_APPLICABLE, declarations: 0 },
          };
        }
        return {
          findings: [],
          evidence: [],
          metadata: {
            basis: BASES.LOCKFILE_RESOLUTION,
            state: STATES.ESTABLISHED,
            declarations: declarations.length,
            lockfiles: lockfiles.length,
            reported: 0,
          },
        };
      }

      candidates.sort((a, b) =>
        a.fingerprintKey < b.fingerprintKey ? -1 : a.fingerprintKey > b.fingerprintKey ? 1 : 0,
      );
      const { entries, truncated } = capFindings(candidates);
      const findings = entries.map((entry) => ({
        confidence: DEPENDENCY_ANALYSIS_CONFIDENCE.OBSERVED_FACT,
        description: entry.description,
        evidence: entry.evidence,
        metadata: {
          basis: BASES.LOCKFILE_RESOLUTION,
          state: STATES.DETECTED,
          fingerprintKey: entry.fingerprintKey,
          condition: entry.kind,
          ...entry.metadata,
        },
      }));

      return {
        findings,
        evidence: [],
        metadata: {
          basis: BASES.LOCKFILE_RESOLUTION,
          state: STATES.DETECTED,
          declarations: declarations.length,
          lockfiles: lockfiles.length,
          reported: findings.length,
          truncated,
        },
      };
    },
    remediation: {},
    metadata: {
      tags: ["dependency", "lockfile", "integrity"],
      falsePositives: ["a monorepo whose lockfile lives at a root the scan did not treat as a source"],
    },
  }),
]);
