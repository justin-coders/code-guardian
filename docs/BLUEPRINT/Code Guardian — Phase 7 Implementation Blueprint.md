# Code Guardian
## Phase 7 — Implementation Blueprint

**Repository:** `justin-coders/code-guardian`  
**Current baseline:** v2.0.4  
**Implementation objective:** Introduce the new Core contracts safely without destabilizing existing behavior.

---

# 1. Phase Objective

Phase 7 establishes the first production foundation for the new Code Guardian architecture.

The goal is:

```text
Current Code Guardian
        │
        │ existing behavior remains intact
        ▼
New Core Contracts
        │
        ▼
Future Repository Intelligence
        │
        ▼
Future Analyzers
```

This phase does **not** attempt to implement the complete target architecture.

It creates the stable interfaces upon which later phases depend.

---

# 2. Scope

Phase 7 includes:

```text
Core contract definitions
Contract validation
Contract tests
Common enums/constants
Execution result model
Basic Core result model
Initial module boundaries
```

Phase 7 does not include:

```text
MCP rewrite
HTTP rewrite
Repository scanner
Security analyzer
Rule database
Automatic remediation
LLM integration
CLI redesign
Cloud architecture
```

---

# 3. Golden Rule

The current application must continue working while the new architecture is introduced.

Therefore:

```text
OLD IMPLEMENTATION
       │
       ├── remains operational
       │
       ▼
NEW CONTRACTS
       │
       ▼
future migration
```

Do not delete working functionality merely to make the new structure look cleaner.

---

# 4. Initial Directory Structure

Create only the minimum required structure.

```text
src/
  core/
    contracts/
      repository-model.js
      evidence.js
      finding.js
      rule.js
      analyzer.js
      analysis-context.js
      execution.js

    errors/
      core-error.js

    validation/
      contract-validation.js

    index.js
```

Do **not** create all future directories yet.

For example, do not prematurely create:

```text
src/analyzers/
src/rules/
src/remediation/
src/repository/
src/execution/
```

until their implementation phases begin.

This keeps the first migration clean.

---

# 5. Contract 1 — RepositoryModel

Create:

```text
src/core/contracts/repository-model.js
```

The module should define the conceptual repository model.

Required top-level areas:

```text
identity
files
languages
frameworks
manifests
dependencies
scripts
configuration
git
tests
ci
architecture
scan
metadata
```

The contract must not contain analysis judgments.

Correct:

```js
configuration.envFiles = [
  { path: ".env" }
];
```

Incorrect:

```js
configuration.security = "bad";
```

---

# 6. Repository Scan State

The RepositoryModel must explicitly represent incomplete scanning.

Required concepts:

```text
complete
truncated
limits
errors
```

Example:

```js
scan: {
  complete: false,
  truncated: true,
  limits: {
    maxFiles: 5000,
    maxDepth: 20
  },
  errors: []
}
```

A scanner must never silently transform:

```text
"not inspected"
```

into:

```text
"not found"
```

---

# 7. Contract 2 — Evidence

Create:

```text
src/core/contracts/evidence.js
```

Required concepts:

```text
id
type
location
source
data
provenance
```

Location should support:

```text
path
line
column
```

without requiring every evidence type to have all three.

For example:

```js
{
  id: "evidence-123",

  type: "file",

  location: {
    path: "src/auth/login.js"
  },

  source: {
    analyzer: "security",
    method: "filesystem"
  },

  data: {},

  provenance: {
    deterministic: true
  }
}
```

---

# 8. Evidence Types

Initially define a controlled vocabulary.

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
runtime
graph
documentation
```

Do not build specialized implementations for all of these yet.

The contract simply allows them.

---

# 9. Contract 3 — Finding

Create:

```text
src/core/contracts/finding.js
```

Required:

```text
id
ruleId
category
severity
confidence
title
description
evidence
status
fingerprint
metadata
```

Recommended initial severity values:

```text
info
low
medium
high
critical
```

Recommended initial status:

```text
open
```

Do not implement full suppression/resolution workflows yet.

---

# 10. Confidence

Confidence must be normalized.

Initial contract:

```text
0 <= confidence <= 1
```

Examples:

```text
0.25
0.70
0.95
1.00
```

Reject:

```text
-1
1.4
"high"
```

---

# 11. Finding Evidence References

A finding should reference evidence rather than duplicating evidence objects everywhere.

Conceptually:

```js
finding.evidence = [
  "evidence-123",
  "evidence-456"
];
```

This provides:

```text
Finding
   │
   ├── Evidence A
   └── Evidence B
```

rather than embedding large source snippets repeatedly.

---

# 12. Finding Fingerprints

The contract should permit:

```js
fingerprint: "..."
```

but fingerprint generation itself should be implemented later.

Do not build a sophisticated fingerprinting engine during this phase.

---

# 13. Contract 4 — Rule

Create:

```text
src/core/contracts/rule.js
```

A Rule should define:

```text
id
version
category
title
description
severity
applicability
detection
remediation
metadata
```

The rule contract must distinguish metadata from executable behavior.

---

# 14. Rule Contract

Conceptually:

```js
{
  id: "security.example",
  version: "1.0.0",

  category: "security",

  title: "...",
  description: "...",

  severity: "high",

  applicability: {},

  detect: async context => [],

  remediation: {},

  metadata: {}
}
```

Rules must not know about:

```text
MCP
HTTP
CLI
```

---

# 15. Contract 5 — Analyzer

Create:

```text
src/core/contracts/analyzer.js
```

Required:

```text
id
version
canAnalyze()
analyze()
```

Conceptual contract:

```js
{
  id: "security",
  version: "1.0.0",

  canAnalyze: async context => ({
    applicable: true
  }),

  analyze: async context => ({
    findings: [],
    evidence: [],
    metrics: {},
    metadata: {}
  })
}
```

---

# 16. Analyzer Result

Define a standard result.

```js
{
  findings: [],
  evidence: [],
  metrics: {},
  metadata: {}
}
```

The result must be validated.

An analyzer returning:

```js
null
```

should fail contract validation rather than causing a mysterious downstream error.

---

# 17. Contract 6 — AnalysisContext

Create:

```text
src/core/contracts/analysis-context.js
```

Conceptual structure:

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

The context is the shared boundary between Core and analyzers.

---

# 18. Context Ownership

The context should be constructed by the Core.

Analyzers should consume it.

Do not allow every analyzer to construct its own repository scanner.

Bad:

```text
SecurityAnalyzer
 → scan repository

TestingAnalyzer
 → scan repository

ArchitectureAnalyzer
 → scan repository
```

Correct:

```text
Guardian Core
 → RepositoryModel

SecurityAnalyzer
TestingAnalyzer
ArchitectureAnalyzer
 → consume RepositoryModel
```

---

# 19. Contract 7 — Execution

Create:

```text
src/core/contracts/execution.js
```

Define:

```text
ExecutionRequest
ExecutionResult
```

Request:

```js
{
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
{
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

# 20. Execution Contract Principle

The contract describes execution.

It does not execute anything.

Do not put:

```js
child_process.spawn(...)
```

inside the contract module.

Later:

```text
Execution Contract
       ↑
Command Runner
       ↑
Guardian Core
```

---

# 21. Core Error Contract

Create:

```text
src/core/errors/core-error.js
```

Define a small structured error hierarchy.

Initial categories:

```text
ValidationError
ConfigurationError
RepositoryError
ExecutionError
AnalysisError
```

Each error should contain enough information for interfaces to present useful errors.

Do not expose internal stack traces automatically to remote clients.

---

# 22. Contract Validation

Create:

```text
src/core/validation/contract-validation.js
```

The validation layer should verify:

```text
RepositoryModel shape
Evidence shape
Finding shape
Rule shape
Analyzer result shape
Execution result shape
```

Keep validation lightweight initially.

Do not introduce a large validation dependency unless the architecture genuinely requires one.

---

# 23. Core Index

Create:

```text
src/core/index.js
```

It should expose the stable public Core contracts.

Conceptually:

```js
export {
  ...
};
```

This gives future modules one stable import boundary.

For example:

```text
future analyzer
      ↓
src/core
```

instead of importing random internal files.

---

# 24. Contract Tests

Create a dedicated test file:

```text
tests/core-contracts.test.js
```

Test every contract independently.

---

# 25. RepositoryModel Tests

Test:

```text
valid model
missing identity
invalid scan state
invalid file collection
truncated scan
scan errors
```

Also verify that analysis judgments are not required.

---

# 26. Evidence Tests

Test:

```text
valid file evidence
line evidence
AST evidence
missing ID
invalid type
invalid location
provenance
```

---

# 27. Finding Tests

Test:

```text
valid finding
invalid severity
confidence < 0
confidence > 1
missing rule ID
missing title
invalid evidence reference
fingerprint
```

---

# 28. Rule Tests

Test:

```text
valid rule
version
severity
detect function
invalid rule
missing ID
missing detect behavior
```

---

# 29. Analyzer Tests

Test:

```text
valid analyzer
canAnalyze()
analyze()
invalid result
missing findings
invalid evidence
```

---

# 30. Execution Tests

Test:

```text
valid request
valid result
timeout
killed process
truncated output
non-zero exit code
```

The contract should not assume that non-zero exit code itself is a Guardian error.

A command may legitimately return non-zero and still produce useful analysis evidence.

---

# 31. Existing Test Suite Must Remain Green

Run:

```text
npm test
```

Then:

```text
npm run test:unit
npm run test:integration
```

The new contract tests are additive.

Do not replace the existing suite.

---

# 32. Lint and Formatting

After implementation:

```text
npm run lint
```

and:

```text
npx prettier --check src tests
```

If the repository's current formatting conventions require adjustment, follow the existing configuration rather than inventing a new style.

---

# 33. No Behavior Migration Yet

This is critical.

After Phase 7, this should still exist:

```text
MCP
 ↓
tool-registry.js
 ↓
tools.js
```

The new contracts simply exist beside it.

That means:

```text
v2 behavior
     +
new architectural foundation
```

---

# 34. First Migration Target

After Phase 7, the first actual migrated subsystem should be:

```text
filesystem/path infrastructure
```

not an MCP tool.

Reason:

Every future analyzer depends on reliable repository access.

---

# 35. Second Migration Target

Then:

```text
command execution
```

Move the current `run()` behavior behind the new execution contract.

This directly addresses:

- output limits
- timeout semantics
- process termination
- environment control
- cwd validation

---

# 36. Third Migration Target

Then:

```text
Repository Scanner
```

which produces:

```text
RepositoryModel
```

Only after that should the first analyzer be migrated.

---

# 37. First Analyzer Target

The first complete analyzer should be:

```text
SecurityAnalyzer
```

because it exercises the architecture across:

```text
filesystem
configuration
dependencies
source
commands
evidence
rules
findings
```

It therefore provides a meaningful architecture proof.

---

# 38. Commit Strategy

Do not create one enormous migration commit.

Use small logical commits.

Recommended sequence:

```text
1. core: introduce repository model contract

2. core: introduce evidence contract

3. core: introduce finding contract

4. core: introduce rule contract

5. core: introduce analyzer contract

6. core: introduce analysis context

7. core: introduce execution contracts

8. core: add contract validation

9. test: add core contract coverage
```

Then separately:

```text
10. refactor: extract filesystem infrastructure

11. refactor: extract command execution

12. feature: introduce repository scanner

13. feature: introduce security analyzer
```

This gives easy rollback points.

---

# 39. Branching Strategy

The architectural migration should happen on a dedicated feature branch.

Recommended conceptual branch:

```text
feature/core-architecture
```

Do not assume that is the user's current branch; verify Git state before executing commands.

The coding agent must inspect:

```text
current branch
working tree
uncommitted changes
```

before modifying anything.

---

# 40. Agent Execution Rules

When handing this phase to a coding agent, the agent should be instructed:

```text
DO:
- inspect the current repository first
- preserve existing behavior
- implement contracts incrementally
- add tests
- run existing tests
- report exact files changed
- report exact test results

DO NOT:
- rewrite tools.js
- redesign MCP transport
- add new MCP tools
- introduce an LLM
- add cloud infrastructure
- remove existing tests
- change public tool names
- silently alter existing behavior
```

---

# 41. Phase 7 Exit Gate

Phase 7 is complete only when all are true:

```text
[ ] Core contracts exist
[ ] Contracts are validated
[ ] Contract tests exist
[ ] Existing tests pass
[ ] Existing MCP behavior is preserved
[ ] No transport rewrite occurred
[ ] No analyzer migration occurred
[ ] No public tool was removed
[ ] Lint passes
[ ] Formatting passes
[ ] Changes are documented
```

---

# 42. Phase 8 Preview

Once Phase 7 passes, Phase 8 begins:

```text
Infrastructure Extraction
```

Its sequence will be:

```text
tools.js
   │
   ├── filesystem → repository/filesystem
   │
   ├── path handling → repository/filesystem
   │
   ├── JSON/config → repository/parsers
   │
   ├── run() → execution/command-runner
   │
   └── Git operations → repository/git
```

The important rule is:

```text
Extract first.
Improve behavior second.
Migrate consumers third.
Delete legacy code last.
```

This prevents a refactor from becoming an accidental rewrite.

---

# 43. Overall Implementation Dependency Graph

```text
Phase 7
Core Contracts
     │
     ▼
Phase 8
Infrastructure
     │
     ▼
Phase 9
Repository Intelligence
     │
     ▼
Phase 10
Security Analyzer
     │
     ├──────────────┐
     ▼              ▼
Evidence        Findings
     │              │
     └──────┬───────┘
            ▼
      Guardian Engine
            │
            ▼
       Other Analyzers
            │
            ▼
       Risk / Readiness
            │
            ▼
       Remediation
            │
            ▼
       Verification
            │
            ▼
    MCP / CLI / CI modernization
```

---

# 44. The Immediate Coding Boundary

The exact boundary for the next coding task is therefore:

```text
START
src/core/contracts/
src/core/errors/
src/core/validation/
src/core/index.js
tests/core-contracts.test.js

STOP
before touching:
src/tools.js
src/tool-registry.js
src/stdio-server.js
src/http-server.js
```

This is intentional.

We first establish the **new architectural spine** before moving the existing organs onto it.

---

# 45. Final Decision

The first implementation task is **not "refactor Code Guardian."**

It is:

> **Introduce and test the Core contracts while preserving the current system unchanged.**

Once that succeeds, we can safely begin extracting the actual implementation behind those contracts.