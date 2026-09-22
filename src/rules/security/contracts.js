/**
 * Code Guardian — Security Rule Pack Contracts (Phase 12)
 *
 * The security domain's vocabulary: which rules exist, what filenames count as
 * security-relevant, which model signals the pack consumes, and the confidence
 * policy its rules assert. Nothing here redefines a framework concept — rule
 * identity comes from the Core Rule contract, severities from the Core Finding
 * contract, and outcome vocabulary from the Phase 10 Rule Engine.
 *
 * ### Rule identity is a long-term contract
 *
 * A rule id is namespace-shaped (`security.sensitive-file.dotenv`) and appears in
 * every finding fingerprint the rule will ever produce. Renaming a rule id is
 * therefore a **breaking identity change**: it retires every existing fingerprint,
 * so a baseline built yesterday no longer matches the same condition today.
 * `SECURITY_RULE_IDS` is the single place the shipped ids are declared, and
 * `securityRuleSetIssues()` fails the registry if a declared rule is missing or an
 * id leaves the `security.` namespace.
 *
 * ### Filename matching, never content
 *
 * Phase 12 reads no file contents: the RepositoryModel records paths, names and
 * extensions, and that is all these rules use. A spec therefore matches *names*,
 * and the findings are worded to say exactly that — "a file whose name indicates
 * X was observed", never "a secret was found". A `.pem` may be a public
 * certificate, so the pack says so rather than guessing.
 *
 * Matching is case-insensitive on purpose: on a case-preserving filesystem
 * `ID_RSA` is a private key, and a matcher that missed it would be a false
 * negative in a security rule. Extensions arrive already lower-cased from the
 * model.
 *
 * ### Signals are the model's, not the pack's
 *
 * The two configuration signal ids below are the ModelEntity `signal` values the
 * Phase 8C scanner writes and the Phase 8D model preserves. They are re-declared
 * here rather than imported from the scanner layer, because the rules layer must
 * not depend on the acquisition side of the architecture; a test in
 * `tests/security-rules.test.js` builds a real model from real scanner signals and
 * fails if these constants ever drift from it.
 */

/** Version of the pack as a whole (analyzer version, rule set revision). */
export const SECURITY_RULE_PACK_VERSION = "1.0.0";

/** Initial version of every rule in the pack. */
export const SECURITY_RULE_VERSION = "1.0.0";

/** Analyzer identity. `security` is the domain namespace, not a rule. */
export const SECURITY_ANALYZER_ID = "security";
export const SECURITY_ANALYZER_NAME = "Security";
export const SECURITY_ANALYZER_SCOPE = "security";

/** Category recorded on every security finding (Core Finding contract). */
export const SECURITY_CATEGORY = "security";

/** Every security rule id must live in this namespace. */
export const SECURITY_RULE_ID_PREFIX = "security.";

/**
 * The rules this pack ships.
 *
 * Ordered by id here for readability; `securityRules` is sorted by id at
 * definition time, and the registry sorts again, so no consumer depends on this
 * literal order.
 */
export const SECURITY_RULE_IDS = Object.freeze({
  DOTENV: "security.sensitive-file.dotenv",
  PRIVATE_KEY: "security.sensitive-file.private-key",
  KEY_MATERIAL: "security.sensitive-file.key-material",
  KEYSTORE: "security.sensitive-file.keystore",
  CREDENTIALS: "security.sensitive-file.credentials",
  SERVICE_ACCOUNT: "security.sensitive-file.service-account",
  TERRAFORM_STATE: "security.sensitive-file.terraform-state",
  CONTAINER_IGNORE: "security.configuration.container-ignore",
  CREDENTIAL_CONTENT: "security.sensitive-content.credential-assignment",
  PRIVATE_KEY_CONTENT: "security.sensitive-content.private-key-material",
  SYMLINK_ESCAPE: "security.exposure.symlink-escape",
});

/**
 * Confidence policy.
 *
 * Confidence is *the rule's* assertion, never a framework default (Phase 10 refuses
 * to invent it). Two honest levels are used in this phase:
 *
 *   OBSERVED_ARTIFACT  the model directly observed the artifact the finding names,
 *                      so the named condition is a fact about the inventory. The
 *                      claim stops short of certainty because what the file
 *                      *contains* is not read in this phase.
 *   DERIVED_CONDITION  the finding compares two observations (a Dockerfile with no
 *                      `.dockerignore` at a plausible build-context root) rather
 *                      than naming one artifact.
 *   OBSERVED_CONTENT   the bounded content inspection read the bytes and matched a
 *                      pattern, so the condition is directly established. It is the
 *                      strongest claim this pack can make and is still not "a secret
 *                      was stolen": the pattern proves a credential-shaped string is
 *                      present, nothing about its validity or reach.
 *   OBSERVED_LINK      the model classified a symlink's target as escaping the
 *                      repository, which is a recorded fact about the link rather
 *                      than an inference from its name.
 */
export const SECURITY_CONFIDENCE = Object.freeze({
  OBSERVED_ARTIFACT: 0.9,
  DERIVED_CONDITION: 0.6,
  OBSERVED_CONTENT: 0.95,
  OBSERVED_LINK: 0.9,
});

/**
 * Model `signal` values this pack consumes from configuration entities.
 *
 * A `configuration` entity carries the scanner signal that produced it, so a rule
 * can distinguish a Dockerfile from a `.dockerignore` without re-deriving either.
 */
export const CONFIGURATION_SIGNALS = Object.freeze({
  DOCKERFILE: "dockerfile",
  CONTAINER_IGNORE: "container-ignore",
});

/**
 * The filename specs that decide which observed files a rule reports.
 *
 * Each spec is validated and frozen by `defineFileSpec` (see `matching.js`), which
 * enforces the documented shape: at least one positive criterion, and criteria
 * drawn only from `basenames` / `extensions` / `namePrefixes` / `nameSuffixes` /
 * `pathSegments`, with an optional `exclude` of the same shape.
 *
 * Sensitive names are listed explicitly rather than pattern-matched loosely,
 * because a security rule that reports everything reports nothing. Names that
 * cannot be decided by name alone — `.npmrc`, `*.tfvars`, generic `*.sql` dumps —
 * are absent from this table because they are decided by the **content** rules
 * instead (see `CONTENT_CANDIDATE_FILES`): a `.npmrc` with no credential in it is
 * not a finding, and only reading it can tell the two apart.
 */
export const SENSITIVE_FILE_SPECS = Object.freeze({
  /** Live dotenv files, excluding the committed `.env.example` template family. */
  dotenv: {
    basenames: [".env"],
    namePrefixes: [".env."],
    exclude: {
      nameSuffixes: [".example", ".sample", ".template", ".dist", ".md", ".txt"],
    },
  },
  /** SSH/OpenSSH private keys and PuTTY key files, excluding public halves. */
  privateKey: {
    basenames: [
      "id_rsa",
      "id_dsa",
      "id_ecdsa",
      "id_ed25519",
      "id_xmss",
      "ssh_host_rsa_key",
      "ssh_host_dsa_key",
      "ssh_host_ecdsa_key",
      "ssh_host_ed25519_key",
    ],
    extensions: [".ppk"],
    exclude: { nameSuffixes: [".pub"] },
  },
  /** PEM/DER key material: possibly a private key, possibly a public certificate. */
  keyMaterial: {
    extensions: [".pem", ".key"],
    exclude: { nameSuffixes: [".pub", ".example", ".sample"] },
  },
  /** Archive formats that exist to hold private key material. */
  keystore: {
    extensions: [".jks", ".keystore", ".p12", ".pfx", ".pkcs12", ".bcfks"],
  },
  /** Credential stores, including anything inside an `.aws` directory. */
  credentials: {
    basenames: [
      ".netrc",
      "_netrc",
      ".git-credentials",
      ".htpasswd",
      ".pgpass",
      ".pypirc",
      ".s3cfg",
      "credentials.json",
      "auth.json",
    ],
    pathSegments: [".aws"],
    exclude: { basenames: ["config", "config.json", "cli", "cli.json"] },
  },
  /** Cloud service-account keys: filenames that exist only to hold a secret. */
  serviceAccount: {
    basenames: [
      "service-account.json",
      "serviceaccount.json",
      "service_account.json",
      "gcp-credentials.json",
      "application_default_credentials.json",
    ],
    namePrefixes: [
      "service-account-",
      "serviceaccount-",
      "service_account_",
      "firebase-adminsdk-",
    ],
    nameSuffixes: ["-service-account.json", "-adminsdk.json", "_service_account.json"],
  },
  /** Terraform state: resource attributes, including secrets, in plaintext. */
  terraformState: {
    nameSuffixes: [".tfstate", ".tfstate.backup"],
  },
});

/**
 * `metadata.basis` recorded on every finding this pack produces.
 *
 * The basis names *what was observed*, so a consumer can tell a finding that rests
 * on a path from one that rests on bytes:
 *
 *   filename  a name was observed in the inventory (Phase 12)
 *   content   bounded content inspection matched a pattern (correction 2)
 *   link      a symlink target was classified (correction 1)
 *   build-context  the container rule compared observed paths (correction 3)
 */
export const FINDING_BASIS = "filename";

export const FINDING_BASES = Object.freeze({
  FILENAME: "filename",
  CONTENT: "content",
  LINK: "link",
  BUILD_CONTEXT: "build-context",
});

/**
 * The content patterns this pack reports, and which rule owns each.
 *
 * The ids are the scanner's closed vocabulary, re-declared here for the same reason
 * `CONFIGURATION_SIGNALS` is: the rules layer must not depend on the acquisition
 * layer. `tests/security-rules.test.js` asserts this list against a real scan, so a
 * rename on either side fails the suite instead of silently retiring a rule.
 */
export const CONTENT_PATTERNS = Object.freeze({
  PRIVATE_KEY_BLOCK: "private-key-block",
  CREDENTIAL_ASSIGNMENT: "credential-assignment",
  AWS_CREDENTIAL_ASSIGNMENT: "aws-credential-assignment",
  BASIC_AUTH_URL: "basic-auth-url",
  SQL_PASSWORD_STATEMENT: "sql-password-statement",
});

/**
 * Which files the content rules consider.
 *
 * The spec mirrors the scanner's candidate table (`.npmrc`, `.pypirc`, `.envrc`,
 * dotenv files, Terraform variable files, SQL dumps). It exists so a rule can find
 * the files that *should* carry a content observation; whether one actually does is
 * read from the model, never assumed. A candidate with no observation is `unknown`,
 * not `pass`, so an older scan that inspected nothing cannot produce a clean bill of
 * health.
 */
export const CONTENT_CANDIDATE_FILES = Object.freeze({
  basenames: [".npmrc", ".pypirc", ".envrc", ".env"],
  namePrefixes: [".env."],
  nameSuffixes: [".tfvars", ".tfvars.json", ".sql"],
});
