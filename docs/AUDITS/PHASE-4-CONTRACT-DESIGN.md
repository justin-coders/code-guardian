
# Phase 4 — Internal Contract Design

## 4.1 The target execution flow

The future Code Guardian engine should work approximately like this:

```text
                    MCP / CLI / CI / API
                           │
                           ▼
                  ┌─────────────────┐
                  │ Interface Layer │
                  └────────┬────────┘
                           │
                           ▼
                  ┌─────────────────┐
                  │ Guardian Engine │
                  └────────┬────────┘
                           │
             ┌─────────────┼─────────────┐
             ▼             ▼             ▼
      Repository       Rule Engine   Execution Engine
       Intelligence
             │             │             │
             └─────────────┼─────────────┘
                           ▼
                     Analyzer Engine
                           │
                           ▼
                    Evidence Collection
                           │
                           ▼
                     Finding Creation
                           │
                           ▼
                     Risk Aggregation
                           │
             ┌─────────────┴─────────────┐
             ▼                           ▼
       Report / MCP result         Remediation
                                         │
                                         ▼
                                  Verification
```

The contracts below are the backbone of this.

---

# 4.2 Contract #1 — RepositoryModel

This is the most important contract.

Today, different functions in `tools.js` independently inspect the repository.

That must stop.

Instead:

> **The repository is scanned once into a shared `RepositoryModel`, and analyzers consume that model.**

### Conceptual structure

```js
RepositoryModel {
  identity
  root
  files
  directories
  manifests
  languages
  frameworks
  dependencies
  scripts
  configuration
  git
  ci
  tests
  source
  architecture
  metadata
}
```

A more concrete shape:

```js
{
  version: "1",

  identity: {
    root: "/repo",
    name: "my-project",
    packageManager: "npm"
  },

  files: {
    entries: [],
    count: 0,
    truncated: false
  },

  languages: [],

  frameworks: [],

  manifests: {
    packageJson: {},
    lockfiles: [],
    workspaceConfig: {}
  },

  dependencies: {
    production: [],
    development: [],
    graph: null
  },

  scripts: {},

  configuration: {
    typescript: null,
    eslint: null,
    prettier: null,
    envFiles: [],
    docker: [],
    editor: []
  },

  git: {
    branch: null,
    repository: null,
    status: null
  },

  ci: {
    providers: [],
    workflows: []
  },

  tests: {
    frameworks: [],
    files: [],
    configuration: []
  },

  architecture: {
    sourceDirectories: [],
    modules: [],
    imports: null
  },

  metadata: {
    generatedAt: "...",
    scannerVersion: "..."
  }
}
```

## Critical rule

`RepositoryModel` should contain **observed facts**, not judgments.

Bad:

```js
security: {
  secure: false
}
```

Good:

```js
configuration: {
  envFiles: [
    {
      path: ".env"
    }
  ]
}
```

The security analyzer decides whether that fact constitutes a finding.

This separation is crucial.

---

# 4.3 RepositoryModel must support incomplete scans

This directly addresses one of the current codebase's problems.

Currently recursive scanning can silently stop because of:

* maximum depth
* maximum file count
* permissions
* filesystem errors

That is dangerous because:

```text
"we didn't find a vulnerability"
```

could actually mean:

```text
"we didn't inspect that part of the repository."
```

Therefore:

```js
scan: {
  complete: true,
  truncated: false,
  limits: {
    maxFiles: 10000,
    maxDepth: 20
  },
  errors: []
}
```

Example:

```js
{
  scan: {
    complete: false,
    truncated: true,
    limits: {
      maxFiles: 5000,
      maxDepth: 20
    },
    errors: [
      {
        path: "vendor/private",
        code: "EACCES"
      }
    ]
  }
}
```

Analyzers can then downgrade confidence when their evidence is incomplete.

---

# 4.4 Contract #2 — Evidence

This is what makes Code Guardian fundamentally different from a checklist tool.

Every meaningful finding should be explainable through evidence.

### Evidence model

```js
{
  id: "evidence_123",

  type: "file",

  location: {
    path: "src/auth/login.js",
    line: 42,
    column: 17
  },

  source: {
    analyzer: "security",
    method: "ast"
  },

  data: {
    ...
  }
}
```

Evidence types should eventually include:

```text
file
directory
line
symbol
ast
dependency
configuration
git
command
workflow
test
http
runtime
graph
documentation
```

---

# 4.5 Evidence should not always contain source snippets

We should avoid automatically storing large chunks of source code.

Instead:

```js
{
  type: "file",
  location: {
    path: "src/auth.js",
    line: 91
  },

  data: {
    symbol: "authenticateUser"
  }
}
```

A renderer can retrieve the relevant source when necessary.

For some reports, we can optionally include:

```js
snippet: {
  text: "...",
  startLine: 89,
  endLine: 94
}
```

This keeps the core model smaller.

---

# 4.6 Evidence provenance

Every piece of evidence needs provenance.

```js
provenance: {
  collector: "typescript-parser",
  collectorVersion: "5.x",
  timestamp: "...",
  deterministic: true
}
```

This becomes very important later when Code Guardian supports:

* deterministic analysis
* LLM-assisted reasoning
* cached analysis
* incremental analysis
* reproducible CI results

We need to know:

> **Where did this conclusion come from?**

---

# 4.7 Contract #3 — Finding

A `Finding` is not the same thing as evidence.

Evidence says:

> "This exists."

Finding says:

> "This observed condition represents a problem or noteworthy condition."

### Proposed structure

```js
{
  id: "CG-SEC-001",

  ruleId: "security.hardcoded-secret",

  category: "security",

  severity: "high",

  confidence: 0.96,

  title: "Potential hardcoded credential",

  description: "...",

  evidence: [
    "evidence_123"
  ],

  impact: {
    type: "security",
    description: "..."
  },

  remediation: {
    summary: "...",
    steps: []
  },

  metadata: {
    analyzer: "security",
    ruleVersion: "1.2.0"
  }
}
```

---

# 4.8 Severity and confidence must be separate

This is extremely important.

Suppose Code Guardian detects:

```text
Potential hardcoded AWS secret
```

Confidence:

```text
0.98
```

Severity:

```text
critical
```

Those represent different dimensions.

Another finding could be:

```text
Potential insecure configuration
```

Confidence:

```text
0.55
```

Severity:

```text
high
```

So:

```text
Severity = how bad if true

Confidence = how certain we are that the finding is true
```

Never collapse those into one number.

---

# 4.9 Finding lifecycle

We should also support future states:

```text
open
acknowledged
suppressed
resolved
regressed
```

But **do not implement all of these immediately**.

The initial engine only needs:

```js
status: "open"
```

The architecture should leave room for lifecycle management later.

---

# 4.10 Finding fingerprint

This becomes essential for CI.

Suppose:

```text
Run 1:
CG-SEC-001 at src/auth.js:42

Run 2:
CG-SEC-001 at src/auth.js:44
```

Line number changed because code moved.

We don't want Code Guardian to report this as a completely new issue.

Therefore each finding should eventually have:

```js
fingerprint: "sha256(...)"
```

derived from stable information such as:

```text
rule ID
file path
symbol
normalized AST location
finding identity
```

rather than simply:

```text
file + line number
```

This enables:

* baseline files
* regression detection
* historical tracking
* PR diff analysis
* suppression
* "new vs existing" findings

---

# 4.11 Contract #4 — Rule

A Rule is the executable definition of a quality/security/architecture expectation.

Current `INDUSTRY_PATTERNS` is essentially static knowledge.

That needs to evolve.

### Proposed Rule

```js
{
  id: "security.hardcoded-secret",

  version: "1.0.0",

  category: "security",

  title: "Hardcoded secret detection",

  description: "...",

  severity: "critical",

  applicability: {},

  detect: {},

  remediation: {},

  metadata: {}
}
```

But there is an important distinction:

## Rule ≠ Analyzer

A rule defines **what to detect**.

An analyzer defines **how to inspect the repository**.

For example:

```text
Security Analyzer
       │
       ├── secret rule
       ├── insecure cookie rule
       ├── weak crypto rule
       ├── unsafe CORS rule
       └── exposed debug endpoint rule
```

This allows many rules to reuse the same repository intelligence.

---

# 4.12 Rule applicability

Rules must first determine whether they apply.

For example:

```text
React-specific rule
```

should not run against:

```text
Python CLI project
```

So:

```js
applicability: {
  languages: ["javascript", "typescript"],
  frameworks: ["react"]
}
```

Another:

```js
applicability: {
  files: ["Dockerfile"]
}
```

Another:

```js
applicability: {
  capabilities: ["http-server"]
}
```

This eventually gives us much better precision than simply running every checklist item everywhere.

---

# 4.13 Rule detection

Conceptually:

```js
detect(context) -> Finding[]
```

Example:

```js
const findings = rule.detect({
  repository,
  evidence,
  execution
});
```

The rule must **not** independently perform uncontrolled filesystem crawling.

It consumes the shared context.

---

# 4.14 Rule remediation

A rule can optionally provide remediation metadata:

```js
remediation: {
  strategy: "manual",

  explanation: "...",

  steps: [
    "...",
    "..."
  ]
}
```

Later:

```js
remediation: {
  strategy: "patch",
  patchGenerator: "..."
}
```

Eventually:

```text
Finding
   ↓
Remediation Plan
   ↓
Patch
   ↓
Tests
   ↓
Verification
```

But automatic patching should come much later.

---

# 4.15 Rule metadata

We should support:

```js
metadata: {
  references: [],
  tags: [],
  frameworks: [],
  introducedIn: "1.0.0",
  deprecated: false
}
```

This lets the project eventually maintain a proper rule catalog.

---

# 4.16 Contract #5 — Analyzer

An analyzer is a domain-specific analysis module.

Examples:

```text
SecurityAnalyzer
ArchitectureAnalyzer
TestingAnalyzer
DependencyAnalyzer
CICDAnalyzer
CodeQualityAnalyzer
APIAnalyzer
ReliabilityAnalyzer
ProductionAnalyzer
```

### Proposed interface

```js
{
  id: "security",

  version: "1.0.0",

  analyze(context): Promise<AnalysisResult>
}
```

Where:

```js
AnalysisResult {
  findings: Finding[],
  evidence: Evidence[],
  metrics: {},
  metadata: {}
}
```

---

# 4.17 Analyzer responsibilities

An analyzer should:

1. consume `RepositoryModel`
2. select applicable rules
3. collect specialized evidence if necessary
4. execute rules
5. return findings
6. return metrics
7. never own transport concerns
8. never format MCP responses
9. never directly manipulate the user's repository unless explicitly operating in a remediation mode

For example:

```text
SecurityAnalyzer
       │
       ▼
RepositoryModel
       │
       ├── dependencies
       ├── env files
       ├── source AST
       ├── CI workflows
       └── configuration
       │
       ▼
Applicable security rules
       │
       ▼
Findings
```

---

# 4.18 Analyzer contract

I would make the contract conceptually:

```js
class Analyzer {
  id;
  version;

  async canAnalyze(context) {}

  async analyze(context) {}
}
```

Where:

```js
canAnalyze()
```

answers:

> Does this analyzer have enough information to operate?

For example:

```text
API analyzer
```

may determine that the repository doesn't contain an HTTP application.

It can return:

```js
{
  applicable: false,
  reason: "No HTTP application detected"
}
```

That is much better than manufacturing a bunch of irrelevant findings.

---

# 4.19 The central AnalysisContext

These five contracts naturally produce another contract:

```text
AnalysisContext
```

It becomes the common input to analyzers/rules.

```js
{
  repository,
  configuration,
  execution,
  rules,
  evidence,
  options
}
```

Conceptually:

```text
                    AnalysisContext
                         │
        ┌────────────────┼────────────────┐
        ▼                ▼                ▼
 Repository         Execution          Rules
   Model             Policy           Registry
        │                │                │
        └────────────────┼────────────────┘
                         │
                         ▼
                     Analyzers
```

---

# 4.20 ExecutionEngine

Because current Code Guardian runs commands, this deserves its own contract.

Current:

```js
run(command, args, cwd)
```

is too primitive for a future remote/agent-accessible system.

Instead:

```js
ExecutionRequest {
  command,
  args,
  cwd,
  environment,
  timeout,
  limits,
  policy
}
```

Result:

```js
ExecutionResult {
  exitCode,
  stdout,
  stderr,
  duration,
  timedOut,
  killed,
  truncated
}
```

This directly fixes the current lack of output-size limits and execution-policy separation.

---

# 4.21 Execution policy

Eventually:

```js
ExecutionPolicy {
  allowCommands: [],
  denyCommands: [],
  allowedRoots: [],
  network: "disabled",
  maxDurationMs: 30000,
  maxOutputBytes: 1048576,
  maxProcesses: 1
}
```

This becomes especially important because Code Guardian is not merely reading files—it currently executes commands.

The architecture must treat command execution as a **trust boundary**.

---

# 4.22 Risk model

Once Findings exist, `production_readiness` should stop being:

```text
8 / 10 checks passed = 80%
```

Instead:

```text
Repository
    ↓
Findings
    ↓
Severity × Confidence × Impact
    ↓
Risk aggregation
    ↓
Readiness assessment
```

For example:

```js
RiskSummary {
  critical: 1,
  high: 3,
  medium: 7,
  low: 12,

  confidenceAdjustedRisk: ...,

  categories: {
    security: ...,
    architecture: ...,
    reliability: ...
  }
}
```

Then production readiness becomes an **interpretation of evidence**, rather than an independent checklist.

---

# 4.23 The final core contract relationship

We now have:

```text
RepositoryModel
       │
       ▼
AnalysisContext
       │
       ├───────────────┐
       ▼               ▼
   Analyzer         RuleRegistry
       │               │
       └───────┬───────┘
               ▼
            Evidence
               │
               ▼
            Findings
               │
               ▼
          Risk Engine
               │
       ┌───────┴────────┐
       ▼                ▼
    Reports        Remediation
```

This is the foundation.

---

# 4.24 How the existing 15 tools map onto it

This is where the architecture starts becoming practical.

| Current tool                  | Future implementation                |
| ----------------------------- | ------------------------------------ |
| `audit_codebase`              | Guardian Engine / Audit Orchestrator |
| `check_branch`                | Git Analyzer                         |
| `check_tests`                 | Testing Analyzer                     |
| `check_cicd`                  | CI/CD Analyzer                       |
| `check_linting`               | Code Quality Analyzer                |
| `check_security`              | Security Analyzer                    |
| `check_architecture`          | Architecture Analyzer                |
| `production_readiness`        | Risk + Production Analyzer           |
| `generate_production_code`    | Remediation Engine                   |
| `get_industry_patterns`       | Rule Registry                        |
| `generate_security_checklist` | Security Remediation Planner         |
| `generate_github_workflow`    | CI/CD Generator                      |
| `detect_agent`                | Agent Integration                    |
| `get_agent_guidance`          | Agent Integration Metadata           |
| `generate_starter_repo`       | Scaffold Generator                   |

Notice something important:

**We aren't losing any existing functionality.**

We're moving it underneath a better architecture.

---

# 4.25 Compatibility layer

For v2 compatibility, the existing MCP tool names should remain.

So instead of:

```text
MCP
 ↓
tools.js
```

we eventually have:

```text
MCP
 ↓
Tool Adapter
 ↓
Guardian Engine
 ↓
Analyzer / Rule / Repository Model
```

For example:

```js
async function checkSecurity(args) {
  const result = await guardian.audit({
    cwd: args.cwd,
    analyzers: ["security"]
  });

  return legacySecurityResponse(result);
}
```

Thus existing clients don't immediately break.

---

# 4.26 What happens to `tools.js`

This is now clear.

We **do not simply split 1,400 lines into 15 files**.

Instead:

```text
OLD

tools.js
 ├── scanning
 ├── execution
 ├── security
 ├── architecture
 ├── testing
 ├── CI
 ├── generation
 ├── agent detection
 └── formatting
```

becomes:

```text
NEW

core/
repository/
execution/
analyzers/
rules/
remediation/
generators/
integrations/
mcp/
transports/
cli/
```

And `tools.js` eventually becomes either:

```text
deprecated compatibility layer
```

or disappears after migration.

---

# 4.27 Migration sequence

This is important because a large rewrite would be unnecessarily risky.

### Stage A — Contracts

Create and test:

```text
RepositoryModel
Evidence
Finding
Rule
Analyzer
AnalysisContext
ExecutionRequest
ExecutionResult
```

No behavior change yet.

### Stage B — Infrastructure extraction

Move:

```text
filesystem
JSON/config parsing
command execution
git operations
```

out of `tools.js`.

Existing tools continue calling them.

### Stage C — Repository intelligence

Build:

```text
RepositoryScanner
ProjectDetector
DependencyAnalyzer/Graph
ConfigurationScanner
GitScanner
TestScanner
CI scanner
```

and produce `RepositoryModel`.

### Stage D — First real analyzer

Start with:

```text
SecurityAnalyzer
```

because it demonstrates the full pipeline:

```text
Repository
→ evidence
→ rules
→ findings
→ remediation
```

### Stage E — Migrate existing analyzers

```text
Testing
Code Quality
CI/CD
Architecture
Git
Dependencies
API
Reliability
```

### Stage F — Production readiness

Replace the current 10-item percentage model with risk aggregation.

### Stage G — Remediation

Make generators repository-aware.

### Stage H — Interface modernization

Only now:

```text
MCP SDK / current MCP transport
CLI
CI integration
HTTP
```

This order prevents transport work from hiding architectural problems.

---

# 4.28 What we should NOT build yet

At this stage, these should explicitly be deferred:

```text
❌ 20 new MCP tools
❌ autonomous coding agent
❌ automatic patching
❌ LLM-first analysis
❌ huge rule database
❌ dashboard
❌ cloud service
❌ multi-user server
❌ distributed execution
```

The core engine must become reliable first.

---

# 4.29 The resulting Code Guardian identity

The architecture now points toward something substantially more capable than the current package.

The current product is roughly:

```text
MCP tools
+
engineering checklists
+
generators
```

The target becomes:

```text
Code Guardian
│
├── Repository Intelligence
│
├── Deterministic Analysis
│
├── Executable Engineering Rules
│
├── Evidence-backed Findings
│
├── Risk & Readiness Analysis
│
├── Repository-aware Remediation
│
├── Verification
│
└── Multiple Interfaces
     ├── MCP
     ├── CLI
     ├── CI
     └── HTTP/API
```

The key differentiator is not simply **"more checks."**

It is:

> **Code Guardian understands a repository as a system, produces evidence-backed engineering findings, and can eventually connect those findings to verified remediation.**

---

# Phase 4 conclusion

The five mandatory contracts are now defined:

```text
RepositoryModel
      ↓
Evidence
      ↓
Finding
      ↓
Rule
      ↓
Analyzer
```

with these supporting contracts:

```text
AnalysisContext
ExecutionRequest
ExecutionResult
RiskSummary
RemediationPlan
```

That gives us enough architectural certainty to move to the next stage.

## Phase 5 — Master Architecture Specification

The next document should formally define:

1. **Current architecture**
2. **Target architecture**
3. **Core contracts**
4. **Module boundaries**
5. **Dependency direction**
6. **Repository intelligence pipeline**
7. **Analyzer architecture**
8. **Rule engine**
9. **Evidence model**
10. **Finding/risk model**
11. **Execution security model**
12. **Remediation architecture**
13. **MCP/CLI/CI/API interfaces**
14. **Compatibility strategy**
15. **Testing architecture**
16. **Versioning strategy**
17. **Security boundaries**
18. **Performance/scalability model**
19. **Migration architecture**
20. **Explicit non-goals**

Then the **Long-Term Development Roadmap** can be derived from that architecture rather than being a disconnected feature list.

**Phase 4 is therefore complete.**
