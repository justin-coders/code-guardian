# Code Guardian
## Architecture & Evolution Specification

**Repository:** `justin-coders/code-guardian`  
**Package:** `@justin-coders/code-guardian`  
**Current baseline:** v2.0.4  
**Document status:** Architecture specification  
**Purpose:** Define the target architecture and controlled migration path for Code Guardian.

---

# 1. Executive Architecture Decision

Code Guardian should evolve from a collection of MCP tools containing independent checks and generators into a **repository intelligence and engineering analysis platform**.

The primary architectural principle is:

> **Interfaces invoke a common Guardian Core. The Core builds shared repository intelligence, runs applicable analyzers and rules, produces evidence-backed findings, aggregates risk, and optionally produces verified remediation.**

The architecture must not grow by adding independent logic to individual MCP tools.

The existing tools become compatibility-facing interfaces over the new engine.

---

# 2. Current Architecture

The current system is approximately:

```text
MCP Client
    |
    +--> stdio-server.js
    |
    +--> http-server.js
             |
             v
       tool-registry.js
             |
             v
          tools.js
             |
      +------+------+----------------+
      |      |      |                |
    audit  tests security       generators
      |      |      |                |
      +------+------+----------------+
             |
          filesystem
          git
          commands
```

The architecture has several strengths:

- centralized tool registry
- clear MCP tool boundary
- no runtime dependencies
- working stdio transport
- HTTP/SSE transport
- automated tests
- npm/GitHub Packages publication
- release automation
- useful initial industry-pattern knowledge

However, most domain intelligence remains concentrated inside `tools.js`.

This produces coupling between:

- filesystem access
- command execution
- detection
- policy
- analysis
- report formatting
- generation
- MCP behavior

The primary architectural problem is therefore **responsibility concentration**, not absence of functionality.

---

# 3. Target Architecture

The target architecture is:

```text
                         ┌──────────────────────┐
                         │      MCP Clients      │
                         │ Claude / Cursor / ... │
                         └──────────┬───────────┘
                                    │
                         ┌──────────▼───────────┐
                         │   Interface Layer    │
                         │ MCP / CLI / CI / API │
                         └──────────┬───────────┘
                                    │
                         ┌──────────▼───────────┐
                         │    Guardian Core     │
                         │ orchestration        │
                         │ configuration        │
                         │ policies             │
                         └──────────┬───────────┘
                                    │
             ┌──────────────────────┼──────────────────────┐
             │                      │                      │
     ┌───────▼────────┐     ┌──────▼───────┐     ┌──────▼───────┐
     │ Repository     │     │ Rule Engine  │     │ Execution     │
     │ Intelligence   │     │              │     │ Engine        │
     └───────┬────────┘     └──────┬───────┘     └───────────────┘
             │                     │
             └──────────┬──────────┘
                        │
                 ┌──────▼──────┐
                 │  Analyzers   │
                 └──────┬──────┘
                        │
                 ┌──────▼──────┐
                 │   Evidence  │
                 └──────┬──────┘
                        │
                 ┌──────▼──────┐
                 │   Findings  │
                 └──────┬──────┘
                        │
                 ┌──────▼──────┐
                 │ Risk Engine │
                 └──────┬──────┘
                        │
               ┌────────┴────────┐
               │                 │
        ┌──────▼──────┐   ┌──────▼─────────┐
        │   Reports   │   │ Remediation    │
        └─────────────┘   └──────┬─────────┘
                                 │
                          ┌──────▼──────┐
                          │ Verification│
                          └─────────────┘
```

---

# 4. Architectural Layers

## 4.1 Interface Layer

The interface layer is responsible for communication with external consumers.

Initial interfaces:

```text
MCP
CLI
CI
HTTP/API
```

The interface layer must not contain analysis logic.

For example:

```text
MCP tools/call
      ↓
Tool adapter
      ↓
Guardian Core
```

not:

```text
MCP tools/call
      ↓
security implementation
      ↓
filesystem
      ↓
npm audit
```

---

# 5. Guardian Core

The Guardian Core is the application's orchestration layer.

Responsibilities:

- initialize analysis
- load configuration
- create analysis context
- obtain repository model
- select analyzers
- execute analyzers
- aggregate findings
- calculate risk
- construct output
- coordinate remediation when requested

Conceptually:

```js
guardian.audit({
  cwd,
  analyzers,
  rules,
  options
})
```

The Core should remain independent of MCP.

This allows:

```text
MCP ─────┐
CLI ─────┤
CI ──────┼──> Guardian Core
HTTP ────┘
```

---

# 6. Repository Intelligence

Repository intelligence is the foundation of the system.

The repository should be analyzed into a reusable `RepositoryModel`.

```text
Repository
    |
    v
Scanner
    |
    +-- filesystem
    +-- manifests
    +-- languages
    +-- frameworks
    +-- dependencies
    +-- configuration
    +-- Git
    +-- tests
    +-- CI/CD
    +-- source structure
    +-- dependency graph
    |
    v
RepositoryModel
```

The key principle is:

> **Analyzers should consume shared repository intelligence instead of repeatedly rediscovering the same facts.**

---

# 7. RepositoryModel

The RepositoryModel represents observed repository state.

It must not contain subjective judgments.

Example:

```js
{
  version: "1",

  identity: {
    root: "...",
    name: "...",
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
    workspaces: []
  },

  dependencies: {
    production: [],
    development: [],
    graph: null
  },

  scripts: {},

  configuration: {},

  git: {},

  tests: {},

  ci: {},

  architecture: {},

  scan: {
    complete: true,
    errors: [],
    truncation: []
  }
}
```

The model should be versioned.

---

# 8. Incomplete Repository Intelligence

A partial scan must never masquerade as a complete scan.

Every scanner should report:

```text
complete
truncated
errors
limits
```

Example:

```js
{
  complete: false,
  truncated: true,
  limits: {
    maxFiles: 5000,
    maxDepth: 20
  }
}
```

This allows downstream analyzers to account for incomplete evidence.

This is particularly important for security analysis.

---

# 9. Evidence Architecture

Evidence is a first-class object.

A finding without explainable evidence should be treated as lower-quality analysis.

Supported evidence categories should eventually include:

```text
file
line
symbol
AST
dependency
configuration
Git
command
workflow
test
runtime
graph
documentation
```

Example:

```js
{
  id: "evidence-123",

  type: "file",

  location: {
    path: "src/auth/login.js",
    line: 42,
    column: 17
  },

  source: {
    analyzer: "security",
    method: "ast"
  }
}
```

Evidence must contain provenance.

---

# 10. Finding Architecture

A finding represents an interpretation of observed evidence.

```js
{
  id: "...",
  ruleId: "security.hardcoded-secret",
  category: "security",

  severity: "high",
  confidence: 0.94,

  title: "...",
  description: "...",

  evidence: [],

  impact: {},
  remediation: {},

  status: "open",

  fingerprint: "...",

  metadata: {
    analyzer: "security",
    ruleVersion: "1.0.0"
  }
}
```

---

# 11. Severity vs Confidence

These must remain independent.

```text
Severity
= consequence if the finding is true

Confidence
= probability/strength of evidence supporting the finding
```

A high-confidence low-severity issue and a low-confidence critical issue are fundamentally different cases.

No single score should replace these dimensions.

---

# 12. Finding Fingerprints

Findings need stable fingerprints.

The fingerprint should use stable characteristics such as:

```text
rule ID
repository-relative path
symbol
normalized location
finding identity
```

It should not depend exclusively on line numbers.

This enables future:

- baselines
- regression detection
- PR analysis
- suppression
- historical tracking
- "new vs existing" findings

---

# 13. Rule Engine

The rule engine transforms static industry knowledge into executable engineering rules.

The existing `INDUSTRY_PATTERNS` data becomes seed knowledge for this system.

A rule should contain:

```text
identity
version
category
description
applicability
detection
severity
remediation
metadata
```

Example:

```js
{
  id: "security.hardcoded-secret",
  version: "1.0.0",

  category: "security",

  applicability: {
    capabilities: ["source-code"]
  },

  severity: "critical",

  detect: ...
}
```

---

# 14. Rule Applicability

Rules must be selectively applicable.

Examples:

```text
React rule
→ only React projects

Docker rule
→ only repositories containing container configuration

HTTP security rule
→ only repositories implementing an HTTP service

Database transaction rule
→ only repositories with relevant database behavior
```

Applicability prevents irrelevant findings and reduces unnecessary computation.

---

# 15. Analyzer Architecture

Analyzers are domain-level intelligence modules.

Initial analyzer families:

```text
Security
Architecture
Testing
Code Quality
Dependencies
CI/CD
API
Reliability
Git
Production
```

Each analyzer follows a common contract.

Conceptually:

```js
{
  id: "security",
  version: "1.0.0",

  canAnalyze(context) {},

  analyze(context) {}
}
```

An analyzer returns:

```js
{
  findings: [],
  evidence: [],
  metrics: {},
  metadata: {}
}
```

---

# 16. Analyzer vs Rule

This distinction is mandatory.

```text
Analyzer
= how a domain is analyzed

Rule
= what condition constitutes a finding
```

Example:

```text
SecurityAnalyzer
    |
    +-- hardcoded secret rule
    +-- insecure CORS rule
    +-- weak cookie rule
    +-- dangerous crypto rule
    +-- exposed debug endpoint rule
```

This enables reusable infrastructure.

---

# 17. AnalysisContext

All analyzers and rules should receive a common context.

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

This creates a consistent extension model.

---

# 18. Execution Engine

Code Guardian currently executes external commands.

This must become an explicit subsystem.

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

---

# 19. Execution Security

Command execution is a trust boundary.

The engine should eventually enforce:

```text
allowed commands
denied commands
allowed roots
environment policy
network policy
timeout
output limits
process limits
```

For example:

```js
{
  allowCommands: ["npm", "node", "git"],
  denyCommands: [],
  allowedRoots: [],
  network: "disabled",
  maxDurationMs: 30000,
  maxOutputBytes: 1048576
}
```

The exact policy will vary by execution mode.

---

# 20. Execution Modes

The architecture should distinguish:

### Local trusted mode

Typical developer usage.

```text
local machine
→ repository
→ commands
```

### CI mode

Restricted non-interactive execution.

```text
CI runner
→ repository
→ controlled commands
```

### Remote mode

Potentially untrusted network client.

This requires stronger controls:

```text
authentication
authorization
allowed roots
command policy
network restrictions
resource limits
```

### Multi-user/service mode

This should not be treated as equivalent to local mode.

---

# 21. Production Readiness

The current production-readiness percentage should not remain the long-term architecture.

Current conceptual model:

```text
10 checks
→ percentage
→ grade
```

Target:

```text
Repository
    ↓
Analyzers
    ↓
Findings
    ↓
Risk model
    ↓
Production assessment
```

Production readiness becomes a derived assessment.

It should identify:

```text
critical blockers
high-risk areas
medium-risk concerns
operational gaps
unknowns
evidence limitations
```

rather than simply saying:

```text
8/10 = 80%
```

---

# 22. Risk Model

Risk should consider at least:

```text
severity
confidence
impact
scope
exploitability where relevant
evidence completeness
```

The architecture should avoid pretending that these can always be reduced to a single mathematically objective number.

The system may provide aggregate metrics, but the underlying dimensions must remain visible.

---

# 23. Remediation Architecture

Remediation follows findings.

```text
Finding
   ↓
Remediation Planner
   ↓
Remediation Plan
   ↓
Patch / Change
   ↓
Tests
   ↓
Verification
```

A remediation plan may initially be informational:

```js
{
  strategy: "manual",
  steps: []
}
```

Later it may become:

```js
{
  strategy: "patch",
  changes: []
}
```

Automatic modification should require explicit user authorization.

---

# 24. Verification

A remediation is not complete merely because a file changed.

Verification should eventually include:

```text
syntax check
type check
unit tests
integration tests
targeted analyzer rerun
original finding verification
regression analysis
```

The eventual objective is:

> **Code Guardian should be able to demonstrate that a proposed remediation actually addressed the finding without introducing a known regression.**

---

# 25. Repository-Aware Generators

Current generators are mostly static templates.

Future generators should consume:

```text
RepositoryModel
+
Finding
+
Project configuration
+
Target environment
```

For example, Docker generation should not assume:

```text
Node
npm
TypeScript
```

unless repository evidence supports those choices.

This applies to:

- Docker
- GitHub Actions
- deployment workflows
- configuration
- security fixes
- scaffolding

---

# 26. MCP Architecture

The MCP layer becomes an adapter.

```text
MCP request
    ↓
schema validation
    ↓
tool adapter
    ↓
Guardian Core
    ↓
analysis
    ↓
structured result
    ↓
MCP response
```

The Core must not depend on MCP.

This allows the same engine to be used from:

```text
MCP
CLI
CI
HTTP
future SDK/API
```

---

# 27. MCP Tool Strategy

The current 15 tools should remain during migration.

However, new capabilities should generally be implemented in the Core first.

The existing tools become compatibility adapters.

Example:

```text
check_security
      ↓
Guardian Core
      ↓
Security Analyzer
      ↓
Rules
```

rather than maintaining a separate security implementation.

---

# 28. Structured MCP Results

The current tool responses primarily serialize results into text.

The future interface should support structured outputs where appropriate.

Conceptually:

```text
Tool
├── input schema
├── output schema
├── annotations
└── structured result
```

This is especially important for machine consumers such as coding agents.

The MCP implementation should be modernized after the Core contracts stabilize.

---

# 29. Transport Architecture

Transport should remain separate from application logic.

Target:

```text
transports/
    stdio/
    http/
```

The transport layer handles:

- protocol connection
- HTTP/session behavior
- authentication
- transport errors
- serialization
- lifecycle

It does not implement analysis.

The existing legacy stdio and HTTP/SSE implementations should therefore be migrated incrementally rather than rewritten before the Core exists.

---

# 30. HTTP Security

The current HTTP implementation has several architectural concerns that must be addressed during transport modernization:

- path validation based on string prefixes
- optional authentication
- reflected CORS origin
- remote binding potentially exposing command execution
- filesystem inspection through HTTP

The future HTTP server should have explicit deployment modes.

A remote server should not behave like an unrestricted local developer process.

---

# 31. Dependency Direction

The target dependency direction should be:

```text
interfaces
    ↓
core
    ↓
analyzers
    ↓
repository / execution abstractions
```

More precisely, domain logic should depend on abstractions rather than concrete transport implementations.

Forbidden direction:

```text
Analyzer
   ↓
MCP server
```

or:

```text
Core
   ↓
HTTP server
```

The dependency graph must point inward toward stable domain contracts.

---

# 32. Proposed Source Structure

The architecture maps to:

```text
src/
  core/
    engine/
    findings/
    evidence/
    rules/
    risk/
    configuration/
    version/

  repository/
    scanner/
    filesystem/
    parsers/
    git/
    project-model/
    dependency-graph/

  execution/
    command-runner/
    policies/
    limits/

  analyzers/
    audit/
    security/
    architecture/
    testing/
    code-quality/
    dependencies/
    cicd/
    api/
    reliability/
    production/

  rules/
    builtin/

  remediation/
    planner/
    generator/
    verification/

  generators/
    cicd/
    scaffold/

  integrations/
    agents/

  mcp/
    tools/
    schemas/
    adapters/

  transports/
    stdio/
    http/

  cli/
```

This is the **target structure**, not an instruction to create all directories immediately.

---

# 33. Agent Integrations

Agent-specific behavior remains outside the core.

Current:

```text
detect_agent
get_agent_guidance
```

should eventually live under:

```text
integrations/agents/
```

The core should not know whether the consumer is:

```text
Claude
Cursor
Windsurf
Codex
other agent
```

The agent integration layer translates Core capabilities into agent-specific metadata or workflows.

---

# 34. Testing Architecture

The current 83-test suite is valuable but insufficient for the target platform.

Testing should evolve into four layers.

## Layer 1 — Unit tests

Test:

- parsers
- rules
- contracts
- utility functions
- risk calculations

## Layer 2 — Analyzer integration

Test complete analyzer behavior against fixtures.

## Layer 3 — Golden repositories

Maintain representative repositories containing known conditions.

Example:

```text
fixtures/
  javascript-secure/
  javascript-insecure/
  typescript-monorepo/
  python-api/
  docker-project/
  react-app/
  malformed-project/
  large-project/
```

Expected findings become regression fixtures.

## Layer 4 — Benchmarks

Measure:

```text
precision
recall
false positives
false negatives
runtime
memory
scan completeness
```

This is necessary if Code Guardian is going to make claims about engineering intelligence.

---

# 35. Security Testing

Security boundaries require dedicated tests.

At minimum:

```text
path traversal
root escape
command injection
malicious repository content
oversized output
timeout behavior
symlink traversal
environment leakage
secret leakage
remote HTTP authorization
CORS policy
```

These tests should be treated as first-class regression tests.

---

# 36. Configuration Architecture

Configuration should eventually be centralized.

Possible sources:

```text
CLI arguments
environment
guardian configuration file
repository configuration
defaults
```

Priority must be deterministic.

Conceptually:

```text
defaults
   ↓
global config
   ↓
repository config
   ↓
environment
   ↓
CLI
```

The final precedence order should be formally specified before implementation.

---

# 37. Rule Versioning

Rules need independent versions.

Example:

```text
security.hardcoded-secret@1.2.0
```

This matters because findings generated under one rule definition should remain explainable later.

Rule metadata should record:

```text
rule ID
rule version
analyzer version
Guardian version
```

---

# 38. Engine Versioning

RepositoryModel and result contracts should also be versioned.

Example:

```text
RepositoryModel v1
Finding v1
AnalysisResult v1
```

This makes future changes safer for:

- MCP clients
- CI integrations
- stored reports
- baseline files
- third-party integrations

---

# 39. Caching

Caching should be introduced only after repository intelligence is stable.

Potential cache targets:

```text
file hashes
ASTs
dependency graph
repository model
rule results
command results
```

The cache key should include relevant versions/configuration.

Never allow stale analysis to appear indistinguishable from fresh analysis.

---

# 40. Incremental Analysis

The architecture should eventually support:

```text
full repository audit
```

and:

```text
changed files only
```

For example:

```text
Git diff
   ↓
affected files
   ↓
affected modules
   ↓
affected rules
   ↓
targeted analysis
```

This becomes particularly useful for pull requests and CI.

---

# 41. CI Architecture

The CI interface should eventually expose concepts such as:

```text
audit
baseline
diff
fail-on
report
```

For example:

```text
new critical findings → fail
existing accepted findings → report
```

The exact policy should be configurable rather than hardcoded.

---

# 42. Baseline Architecture

A baseline allows existing technical debt to be distinguished from regressions.

Conceptually:

```text
Current findings
      +
Baseline
      ↓
New findings
Resolved findings
Existing findings
```

This is essential for adoption in imperfect real-world repositories.

Code Guardian should not force teams to fix every historical issue before receiving value.

---

# 43. Output Architecture

The Core should produce a canonical result.

Example:

```js
{
  schemaVersion: "1",

  repository: {},

  analysis: {
    startedAt: "...",
    completedAt: "...",
    durationMs: 1234
  },

  analyzers: [],

  findings: [],

  evidence: [],

  metrics: {},

  risk: {},

  scan: {}
}
```

Different interfaces can render this differently.

```text
Canonical Result
   |
   +--> MCP
   +--> CLI
   +--> JSON
   +--> CI annotations
   +--> future dashboard
```

---

# 44. Reporting

Reports should distinguish:

```text
Facts
Findings
Risk interpretation
Recommendations
Unknowns
```

An incomplete scan should be visible.

For example:

```text
Analysis coverage: partial

Reason:
2 directories could not be inspected.
```

This is better than presenting false certainty.

---

# 45. LLM Integration

LLMs should not become the primary source of truth.

Preferred architecture:

```text
Deterministic evidence
       ↓
Structured findings
       ↓
Optional semantic reasoning
       ↓
Contextual explanation/remediation
```

Not:

```text
Repository
   ↓
LLM
   ↓
"Your architecture looks bad"
```

Deterministic analysis should establish the factual foundation.

LLMs may later help with:

- contextual explanations
- prioritization assistance
- remediation planning
- code transformation
- natural-language reporting

Their conclusions should remain distinguishable from deterministic evidence.

---

# 46. Performance Architecture

Performance must be designed around shared repository intelligence.

Bad:

```text
Security scans files
Testing scans files
Architecture scans files
CI scans files
Audit scans files
```

Better:

```text
Repository Scanner
      ↓
RepositoryModel
      ↓
multiple analyzers
```

Common data should be computed once and reused.

Parallel analyzer execution may be introduced after correctness is established.

---

# 47. Resource Limits

The system should have explicit limits for:

```text
files
directories
AST size
repository size
command duration
command output
memory
process count
network access
```

The limits should be observable in results.

---

# 48. Error Handling

Errors must distinguish:

```text
analysis finding
tool failure
repository error
execution failure
configuration error
unsupported project
incomplete scan
internal error
```

These should never all become generic:

```text
something went wrong
```

---

# 49. Unsupported Technologies

Code Guardian must explicitly distinguish:

```text
not detected
not applicable
unsupported
not analyzed
analysis failed
```

For example:

```text
Python API detected
→ API analyzer applicable

Rust project detected
→ JavaScript-specific rule not applicable
```

This prevents absence of evidence from becoming evidence of quality.

---

# 50. Compatibility Strategy

The migration must preserve current public functionality.

Current MCP tools remain available.

Internally:

```text
Legacy Tool
    ↓
Adapter
    ↓
Guardian Core
```

This permits incremental migration.

No requirement exists to rewrite the entire package in one release.

---

# 51. Migration Strategy

The recommended migration order is:

```text
Phase A
Contracts

Phase B
Infrastructure extraction

Phase C
Repository intelligence

Phase D
Security analyzer

Phase E
Remaining analyzers

Phase F
Risk / production readiness

Phase G
Remediation

Phase H
MCP / transport modernization

Phase I
CLI / CI expansion

Phase J
Advanced intelligence
```

Each phase should preserve the previous test suite.

---

# 52. What Must Not Happen

The following architectural shortcuts are explicitly rejected:

### 52.1 More independent logic in `tools.js`

Rejected.

### 52.2 One-file-per-tool refactor

Rejected as the primary architecture.

It would reproduce the same coupling in smaller files.

### 52.3 LLM-first auditing

Rejected.

### 52.4 Checklist percentage as production readiness

Rejected.

### 52.5 Static generators as the long-term remediation architecture

Rejected.

### 52.6 Transport-driven architecture

Rejected.

### 52.7 Silent scan truncation

Rejected.

### 52.8 Treating branch naming as universal engineering quality

Rejected.

### 52.9 Automatic repository mutation without explicit authorization

Rejected.

---

# 53. Priority Order

The architecture establishes this priority hierarchy:

```text
1. Correctness
2. Evidence quality
3. Security
4. Contract stability
5. Analyzer quality
6. Performance
7. Remediation
8. Interface expansion
9. Advanced intelligence
```

Feature count is not a priority metric.

---

# 54. Definition of Architectural Success

The architecture is successful when:

```text
A new analyzer
```

can be added without modifying:

```text
MCP transport
HTTP transport
CLI
existing analyzers
filesystem implementation
report renderer
```

and can simply implement the analyzer contract.

Similarly:

```text
A new rule
```

should not require modifying every analyzer.

And:

```text
A new interface
```

should not require rewriting analysis logic.

These are the practical tests of architectural modularity.

---

# 55. End-State Vision

The mature Code Guardian architecture should look like:

```text
                    CODE GUARDIAN
                          │
                ┌─────────┴─────────┐
                │                   │
          Interfaces            Integrations
                │                   │
       MCP / CLI / CI / API      Agents
                │
                ▼
          Guardian Core
                │
       ┌────────┼────────┐
       │        │        │
 Repository   Rules   Execution
 Intelligence Engine    Engine
       │        │        │
       └────────┼────────┘
                ▼
             Analyzers
                │
                ▼
             Evidence
                │
                ▼
             Findings
                │
                ▼
           Risk / Policy
                │
        ┌───────┴────────┐
        ▼                ▼
     Reports        Remediation
                         │
                         ▼
                    Verification
```

The central asset is therefore not the MCP interface.

It is the **Guardian Intelligence Engine** underneath it.

---

# 56. Final Architectural Principle

Code Guardian should evolve according to one fundamental rule:

> **Do not build more surface area until the underlying intelligence becomes reusable.**

The existing 15 tools are sufficient as the public compatibility surface while the underlying architecture is rebuilt.

Once the Core is mature, additional capabilities become comparatively inexpensive because they reuse:

```text
RepositoryModel
+
Evidence
+
Findings
+
Rules
+
Analyzers
+
Execution
+
Risk
+
Remediation
```

That is the architectural foundation for the next generation of Code Guardian.