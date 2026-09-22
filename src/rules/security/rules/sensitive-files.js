/**
 * Code Guardian — Sensitive-File Security Rules (Phase 12)
 *
 * Seven rules that report a *named* security-relevant artifact observed in the
 * repository inventory. They share one detection shape, so the only thing that
 * differs between them is the filename spec and the wording:
 *
 *   observed match   → one finding per matching file, citing that file's own
 *                      repository evidence (never fabricated, never re-provenanced)
 *   no match, and the inventory supports an absence claim
 *                    → `pass`, with the audit basis in the result metadata
 *   no match, and it does not
 *                    → `unknown`, so "not observed" never reads as "not there"
 *
 * ### Wording is part of the contract
 *
 * Every description states exactly what the model proved — a file with this name was
 * observed — and says plainly that contents were not read. A `.pem` may be a public
 * certificate; a committed `.env` may hold nothing sensitive. The rules therefore
 * never claim a secret *was found*, only that an artifact whose name conventionally
 * carries one is present. That distinction is enforced by review, not by code, which
 * is why it is written down here.
 *
 * ### There is no remediation field, on purpose
 *
 * Phase 12 detects and evidences; generating fixes, patches or PRs is a later
 * phase's job (and Phase 10 already treats `remediation` as an optional contract
 * field). The rules therefore declare an explicitly empty `remediation` rather than
 * inventing guidance text that nothing consumes yet.
 */

import { createRule } from "../../../core/index.js";

import { APPLICABILITY_COVERAGE } from "../../contracts.js";
import { createRuleDetection } from "../../evaluation.js";

import {
  FINDING_BASIS,
  SECURITY_CATEGORY,
  SECURITY_CONFIDENCE,
  SECURITY_RULE_IDS,
  SECURITY_RULE_VERSION,
  SENSITIVE_FILE_SPECS,
} from "../contracts.js";
import { defineFileSpec } from "../matching.js";
import { filesMatching, inventoryAbsence, queryFor } from "../signals.js";

/** A spec every rule shares, validated and frozen once at load. */
const SPECS = Object.freeze({
  dotenv: defineFileSpec(SENSITIVE_FILE_SPECS.dotenv, { name: "dotenvSpec" }),
  privateKey: defineFileSpec(SENSITIVE_FILE_SPECS.privateKey, { name: "privateKeySpec" }),
  keyMaterial: defineFileSpec(SENSITIVE_FILE_SPECS.keyMaterial, { name: "keyMaterialSpec" }),
  keystore: defineFileSpec(SENSITIVE_FILE_SPECS.keystore, { name: "keystoreSpec" }),
  credentials: defineFileSpec(SENSITIVE_FILE_SPECS.credentials, { name: "credentialsSpec" }),
  serviceAccount: defineFileSpec(SENSITIVE_FILE_SPECS.serviceAccount, {
    name: "serviceAccountSpec",
  }),
  terraformState: defineFileSpec(SENSITIVE_FILE_SPECS.terraformState, {
    name: "terraformStateSpec",
  }),
});

/**
 * Detect named sensitive files.
 *
 * Beyond the spec, detection has no inputs: no clock, no environment, no random
 * source, no external state. Two runs over the same model therefore produce
 * byte-identical findings, which is what makes the fingerprints stable.
 */
function detectSensitiveFile(context, spec) {
  const query = queryFor(context);
  const matches = filesMatching(query, spec);

  if (matches.length > 0) {
    return {
      findings: matches.map((file) => ({
        confidence: SECURITY_CONFIDENCE.OBSERVED_ARTIFACT,
        // The observation the model already recorded for this file: real
        // provenance, referenced rather than rebuilt.
        evidence: [...file.evidenceIds],
        metadata: { path: file.path, basis: FINDING_BASIS },
      })),
      evidence: [],
    };
  }

  const absence = inventoryAbsence(query);
  if (!absence.established) {
    return createRuleDetection({
      findings: [],
      coverage: APPLICABILITY_COVERAGE.UNKNOWN,
      reason: `no matching file was observed, but ${absence.reason}`,
    });
  }

  // A clean pass states the basis it rests on, so an absence claim is auditable
  // rather than a bare "nothing".
  return {
    findings: [],
    evidence: [],
    metadata: { basis: FINDING_BASIS, observedFiles: absence.observedFiles, ignoredPaths: absence.ignoredPaths },
  };
}

/** Build one sensitive-file rule from its identity and its spec. */
function sensitiveFileRule({ id, title, description, severity, spec, metadata = {} }) {
  return createRule({
    id,
    version: SECURITY_RULE_VERSION,
    category: SECURITY_CATEGORY,
    title,
    description,
    severity,
    // Universally applicable: every repository is worth checking for committed
    // credentials, and a selector here would only skip the check on repositories
    // that happen to look unusual.
    applicability: {},
    detect: (context) => detectSensitiveFile(context, spec),
    remediation: {},
    metadata: { basis: FINDING_BASIS, ...metadata },
  });
}

export const sensitiveFileRules = Object.freeze([
  sensitiveFileRule({
    id: SECURITY_RULE_IDS.DOTENV,
    title: "Dotenv environment file is present in the repository",
    description:
      "A file named `.env` or an `.env.*` variant (excluding the committed `.env.example` template family) was observed in the repository inventory. Dotenv files conventionally hold environment secrets and are meant to stay out of version control. Only the file's name was observed: its contents were not read, so whether it holds live credentials is not established by this finding.",
    severity: "high",
    spec: SPECS.dotenv,
    metadata: { tags: ["secrets"], falsePositives: ["a committed dotenv file that holds no secret"] },
  }),
  sensitiveFileRule({
    id: SECURITY_RULE_IDS.PRIVATE_KEY,
    title: "SSH private key file is present in the repository",
    description:
      "A file named after an SSH private key (`id_rsa`, `id_ed25519`, an `ssh_host_*_key`, or a PuTTY `.ppk`) was observed in the repository inventory. Public halves (`.pub`) are excluded. Only the file's name was observed: its contents were not read.",
    severity: "high",
    spec: SPECS.privateKey,
    metadata: { tags: ["secrets", "keys"] },
  }),
  sensitiveFileRule({
    id: SECURITY_RULE_IDS.KEY_MATERIAL,
    title: "PEM or key file is present in the repository",
    description:
      "A `.pem` or `.key` file was observed in the repository inventory. These formats carry private keys and public certificates alike, and the contents were not read, so this finding reports the artifact's presence and does not assert which it is.",
    severity: "medium",
    spec: SPECS.keyMaterial,
    metadata: {
      tags: ["keys"],
      falsePositives: ["a public certificate chain or a non-credential key file"],
    },
  }),
  sensitiveFileRule({
    id: SECURITY_RULE_IDS.KEYSTORE,
    title: "Key store or certificate container is present in the repository",
    description:
      "A `.jks`, `.keystore`, `.p12`, `.pfx`, `.pkcs12` or `.bcfks` file was observed in the repository inventory. These container formats exist to hold key material, almost always including a private key. Only the file's name was observed: its contents were not read.",
    severity: "high",
    spec: SPECS.keystore,
    metadata: { tags: ["keys"] },
  }),
  sensitiveFileRule({
    id: SECURITY_RULE_IDS.CREDENTIALS,
    title: "Credential store file is present in the repository",
    description:
      "A credential-store file (`.netrc`, `.git-credentials`, `.htpasswd`, `.pgpass`, `.pypirc`, `.s3cfg`, `credentials.json`, `auth.json`, or any file inside an `.aws` directory) was observed in the repository inventory. Only the file's name was observed: its contents were not read.",
    severity: "high",
    spec: SPECS.credentials,
    metadata: { tags: ["secrets", "credentials"] },
  }),
  sensitiveFileRule({
    id: SECURITY_RULE_IDS.SERVICE_ACCOUNT,
    title: "Service-account key file is present in the repository",
    description:
      "A cloud service-account key file (for example `service-account.json` or `firebase-adminsdk-*.json`) was observed in the repository inventory. These filenames exist to hold a long-lived credential. Only the file's name was observed: its contents were not read.",
    severity: "high",
    spec: SPECS.serviceAccount,
    metadata: { tags: ["secrets", "cloud"] },
  }),
  sensitiveFileRule({
    id: SECURITY_RULE_IDS.TERRAFORM_STATE,
    title: "Terraform state file is present in the repository",
    description:
      "A Terraform state file (`.tfstate`, or its `.backup`) was observed in the repository inventory. State records every managed resource attribute, including generated passwords and keys, in plaintext and outside the resource's own access control. Only the file's name was observed: its contents were not read.",
    severity: "high",
    spec: SPECS.terraformState,
    metadata: { tags: ["secrets", "infrastructure"] },
  }),
]);
