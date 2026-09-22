/**
 * Code Guardian — Configuration Signal Detection (Phase 8C)
 *
 * Records tooling and project configuration artifacts: containers, environment
 * templates, lint/format/build configuration, version pinning, VCS metadata and
 * licences.
 *
 * These are facts about *what is configured*. Whether the configuration is
 * correct, safe or actually exercised is decided by analyzers, never here.
 *
 * Licence files are reported in this section rather than under documentation:
 * a licence is a legal/policy artifact whose presence is configuration, even
 * though its text is prose.
 *
 * Overlap with other detectors is avoided on purpose — test runners
 * (`pytest.ini`, `jest.config.*`) live in the testing section, CI files in the
 * CI/CD section, and manifests (`setup.cfg`, `build.gradle`) in the manifests
 * section, so a path is never reported under two competing signal ids.
 */

import { capEvidence, compareEvidence, SCAN_SIGNALS } from "../contracts.js";
import { COMPOSE_FILENAMES } from "../policies/containers.js";
import { matchEntries } from "./match.js";

/** Ordered configuration rules (most specific first). */
export const CONFIGURATION_RULES = Object.freeze([
  // Containers.
  { basenamePattern: "Dockerfile*", caseInsensitive: true, signal: SCAN_SIGNALS.DOCKERFILE },
  { basenamePattern: "*.dockerfile", caseInsensitive: true, signal: SCAN_SIGNALS.DOCKERFILE },
  { basename: [".dockerignore"], signal: SCAN_SIGNALS.CONTAINER_IGNORE },
  // Shared with the container detector, so the file it reads for build declarations
  // is exactly the file this table reports as a Compose file.
  { basename: [...COMPOSE_FILENAMES], signal: SCAN_SIGNALS.COMPOSE_FILE },

  // Environment templates (a committed example, not a live secret file).
  {
    basename: [".env.example", ".env.sample", ".env.template", ".env.dist"],
    signal: SCAN_SIGNALS.ENVIRONMENT_EXAMPLE,
  },
  { basenamePattern: "*.env.example", signal: SCAN_SIGNALS.ENVIRONMENT_EXAMPLE },

  // Quality tooling.
  {
    basenamePattern: [".eslintrc*", "eslint.config.*", ".stylelintrc*", "biome.json"],
    signal: SCAN_SIGNALS.LINT_CONFIGURATION,
  },
  {
    basename: [".flake8", "ruff.toml", ".ruff.toml", "mypy.ini", ".golangci.yml", ".golangci.yaml", "clippy.toml"],
    signal: SCAN_SIGNALS.LINT_CONFIGURATION,
  },
  {
    basenamePattern: [".prettierrc*", "prettier.config.*"],
    signal: SCAN_SIGNALS.FORMAT_CONFIGURATION,
  },
  {
    basename: [".editorconfig", "rustfmt.toml", ".rustfmt.toml", ".clang-format"],
    signal: SCAN_SIGNALS.FORMAT_CONFIGURATION,
  },

  // Build/compile configuration.
  {
    basename: ["tsconfig.json", "jsconfig.json"],
    signal: SCAN_SIGNALS.BUILD_CONFIGURATION,
  },
  {
    basenamePattern: [
      "babel.config.*",
      ".babelrc*",
      "vite.config.*",
      "webpack.config.*",
      "rollup.config.*",
      "esbuild.config.*",
    ],
    signal: SCAN_SIGNALS.BUILD_CONFIGURATION,
  },

  // Runtime version pinning.
  {
    basename: [
      ".nvmrc",
      ".node-version",
      ".python-version",
      ".ruby-version",
      "rust-toolchain",
      "rust-toolchain.toml",
      ".tool-versions",
    ],
    signal: SCAN_SIGNALS.VERSION_PINNING,
  },

  // Version control metadata.
  {
    basename: [".gitignore", ".gitattributes", ".gitmodules"],
    signal: SCAN_SIGNALS.VCS_CONFIGURATION,
  },

  // Legal/policy artifact.
  {
    basenamePattern: ["LICENSE*", "LICENCE*", "COPYING*", "NOTICE*"],
    caseInsensitive: true,
    signal: SCAN_SIGNALS.LICENSE,
  },
]);

/**
 * Detect configuration signals.
 *
 * @param {object} view Repository view.
 * @returns {{ detected: boolean, evidence: object[], evidenceTruncated: boolean }}
 */
export function detectConfiguration(view) {
  const matches = matchEntries(CONFIGURATION_RULES, view.files);

  const evidence = matches.map(({ rule, entry }) => ({
    path: entry.path,
    signal: rule.signal,
  }));

  const ordered = evidence.sort(compareEvidence);
  const capped = capEvidence(ordered);

  return {
    detected: ordered.length > 0,
    evidence: capped.evidence,
    evidenceTruncated: capped.evidenceTruncated,
  };
}
