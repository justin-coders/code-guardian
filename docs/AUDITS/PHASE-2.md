
# Phase 2 — Deep Tool & Contract Audit

## 1. Actual current architecture

The real execution path is:

```text
MCP Client
   │
   ├── stdio-server.js
   │
   └── http-server.js
          │
          ▼
   tool-registry.js
          │
          ▼
       tools.js
          │
          ├── filesystem
          ├── git
          ├── npm/npx
          ├── pattern database
          ├── agent configs
          ├── generators
          └── scoring
```

The centralized registry is already implemented.

So **“create a centralized tool registry” must be removed from the future roadmap**. It is already done.

The actual architectural bottleneck is:

```text
tool-registry.js
       ↓
   1 giant tools.js
       ↓
many unrelated responsibilities
```

That is the major refactoring target.

---

# 2. The 15-tool capability matrix

Here is the important part.

| Tool                          | Current role               | Actual depth | Main problem                           | Future role                  |
| ----------------------------- | -------------------------- | -----------: | -------------------------------------- | ---------------------------- |
| `audit_codebase`              | General audit              |   Low–Medium | Checklist-based                        | **Core audit orchestrator**  |
| `check_branch`                | Git branch convention      |          Low | Opinionated/static rules               | Git/repository analyzer      |
| `check_tests`                 | Test discovery/execution   |       Medium | Framework-specific + partial execution | Testing analyzer             |
| `check_cicd`                  | CI/CD presence             |          Low | Presence ≠ quality                     | CI/CD analyzer               |
| `check_linting`               | Linter detection/execution |       Medium | JS-centric, sequential commands        | Code-quality analyzer        |
| `check_security`              | Env + npm audit            |          Low | Very shallow security coverage         | Security analyzer            |
| `check_architecture`          | Directory structure        |          Low | No dependency graph                    | Architecture analyzer        |
| `production_readiness`        | 10-item score              |          Low | Binary checklist score                 | Risk/readiness aggregation   |
| `generate_production_code`    | Static templates           |          Low | Doesn't understand target repo         | Remediation/patch generator  |
| `get_industry_patterns`       | Static pattern database    |          Low | Not executable/versioned rules         | Rule registry                |
| `generate_security_checklist` | Security recommendations   |          Low | Mostly static advice                   | Security remediation planner |
| `generate_github_workflow`    | YAML generator             |          Low | Hardcoded assumptions                  | CI/CD generator              |
| `detect_agent`                | Agent config detection     |          Low | Very shallow detection                 | Agent/workspace analyzer     |
| `get_agent_guidance`          | Static agent advice        |          Low | Knowledge blob                         | Agent integration metadata   |
| `generate_starter_repo`       | Starter recommendations    |          Low | Doesn't generate repository            | Project scaffolding engine   |

This gives us an important conclusion:

> **We should not build 15 new tools. We should turn the existing 15 tools into interfaces over a common intelligence engine.**

That is a much stronger architecture.

---

# 3. `audit_codebase` — currently the central tool, but not actually a deep auditor

The implementation currently checks things such as:

```text
package.json
README
.gitignore
ESLint
tsconfig strict
test files/config
GitHub CI
lockfile
ESLint execution
TypeScript execution
```

It produces:

```json
{
  "reports": [],
  "lint": {},
  "typescript": {},
  "summary": {},
  "guidance": []
}
```

This is useful, but it is fundamentally:

```text
repository checklist
+
command execution
```

rather than:

```text
codebase intelligence
```

### Missing

It doesn't currently understand:

* module relationships
* import graph
* dependency direction
* circular dependencies
* architectural boundaries
* authentication flows
* authorization flows
* data flow
* sensitive-data flow
* API contracts
* dangerous sinks
* dead code
* duplicated logic
* configuration relationships
* dependency risk
* deployment topology
* infrastructure relationships

Therefore the future `audit_codebase` should **not itself contain all audit logic**.

It should become:

```text
audit_codebase
      │
      ▼
Audit Engine
      │
      ├── repository analyzer
      ├── architecture analyzer
      ├── security analyzer
      ├── dependency analyzer
      ├── testing analyzer
      ├── API analyzer
      ├── reliability analyzer
      └── production analyzer
```

---

# 4. `check_branch`

Current implementation actually executes:

```text
git rev-parse --abbrev-ref HEAD
git branch --list
```

and checks:

```text
feature/*
bugfix/*
hotfix/*
release/*
main
master
develop
```

### Problem

This is not really a codebase-quality signal.

Branch naming is a **repository policy**, not an inherent engineering-quality property.

Therefore this shouldn't disappear, but it should become:

```text
Repository Policy Analyzer
    └── Branch Policy Rule
```

That allows future users to configure their own policy.

For example:

```json
{
  "rule": "repository.branch-naming",
  "policy": {
    "allowed": [
      "feature/*",
      "fix/*",
      "chore/*"
    ]
  }
}
```

Instead of Code Guardian deciding globally that `bugfix/` is correct.

---

# 5. `check_tests`

This one is more valuable than it initially appeared.

It actually:

* recursively discovers test files
* detects Jest
* detects Vitest
* detects Node's test runner
* executes Jest discovery
* executes Vitest
* reports test execution

But there is an important flaw:

### Node's test runner isn't actually executed.

The implementation detects:

```text
node --test
```

but execution only happens for:

```text
Jest
Vitest
```

So:

```text
detected ≠ verified
```

This distinction will become extremely important in the new engine.

We should introduce evidence states:

```text
detected
verified
failed
unknown
not_applicable
```

rather than simply:

```text
true / false
```

---

# 6. `check_cicd`

This currently checks fixed paths:

```text
.github/workflows/ci.yml
.github/workflows/cd.yml
.github/workflows/deploy.yml
.gitlab-ci.yml
Jenkinsfile
.circleci/config.yml
Dockerfile
docker-compose.yml
.pre-commit-config.yaml
```

Then checks:

```text
package.json build
package.json test
package.json lint
```

### Major conceptual problem

This:

```text
ci.yml exists
```

doesn't mean:

```text
CI is good
```

For example, a CI pipeline could exist but:

* never run tests
* expose secrets
* use mutable action versions
* have excessive permissions
* deploy directly from untrusted PRs
* lack dependency caching
* lack artifact integrity
* lack environment protection
* lack rollback
* fail silently

Therefore future architecture should distinguish:

```text
CI detected
CI parsed
CI behavior analyzed
CI security analyzed
CI reliability analyzed
```

---

# 7. `check_linting`

This tool sequentially checks:

```text
ESLint
Prettier
Biome
oxlint
stylelint
```

and then executes ESLint.

Useful, but it is heavily Node/JS-centric.

Future architecture should be language-neutral:

```text
Code Quality Analyzer
       │
       ├── JavaScript/TypeScript
       ├── Python
       ├── Go
       ├── Rust
       ├── Java
       └── ...
```

The analyzer should first detect the project ecosystem and then select applicable rules.

---

# 8. `check_security` is currently the biggest capability gap

Current security analysis essentially does:

```text
root .env detection
        +
git log -20
        +
npm audit
```

That is nowhere near a complete security audit.

It doesn't currently inspect:

```text
hard-coded secrets
API keys
JWT configuration
authentication
authorization
SQL injection
command injection
path traversal
SSRF
XSS
CSRF
unsafe deserialization
crypto misuse
TLS configuration
CORS
security headers
dependency provenance
CI/CD permissions
Docker security
Kubernetes security
secret history
sensitive data exposure
```

This should become a **major analyzer subsystem**, not a bigger `check_security()` function.

---

# 9. `check_architecture`

Current architecture analysis is:

```text
directory tree
src/
tests/
dist/
docs/
workspace
Nx
Lerna
```

That means:

```text
folder structure ≠ architecture
```

A project can have:

```text
src/
  controllers/
  services/
  repositories/
```

and still have terrible architecture.

The future analyzer needs:

```text
Source Files
    ↓
AST / imports
    ↓
Dependency Graph
    ↓
Module Graph
    ↓
Architectural Boundaries
    ↓
Violations
```

For example:

```text
Controller
   ↓
Service
   ↓
Repository
```

is structurally different from:

```text
Controller
   ↓
Database
```

and:

```text
Repository
   ↓
Controller
```

may represent dependency inversion problems.

That is the level Code Guardian eventually needs to reach.

---

# 10. `production_readiness`

This is currently:

```text
10 checks
   ↓
passed / total
   ↓
percentage
   ↓
A-F
```

Example:

```text
README          ✓
.gitignore      ✓
ESLint          ✓
tests           ✓
CI              ✓
...
```

This is easy to understand, but architecturally we should **not keep this scoring model**.

Consider:

```text
Project A:
9/10 checklist items
but has critical auth vulnerability

Project B:
7/10 checklist items
but has no known critical vulnerability
```

A percentage cannot meaningfully represent that.

Future model:

```text
Evidence
   ↓
Findings
   ↓
Severity
   ↓
Confidence
   ↓
Impact
   ↓
Risk aggregation
```

Then readiness becomes a **derived report**, not a primary analyzer.

---

# 11. `generate_production_code`

This is currently template generation.

For example:

```text
feature = api
stack = nestjs
```

returns a static template.

The generator doesn't inspect the target repository.

That means it cannot know:

```text
existing architecture
existing conventions
existing dependencies
existing naming
existing auth system
existing database layer
existing error handling
existing testing strategy
```

Future architecture should be:

```text
Repository Intelligence
        ↓
Detected Project Model
        ↓
Findings
        ↓
Remediation Plan
        ↓
Patch Generator
        ↓
Human/Agent approval
        ↓
Patch
```

This is a much more powerful direction.

---

# 12. `get_industry_patterns`

This is actually the seed of what could become one of Code Guardian's most important systems.

Current structure is roughly:

```text
security
api
auth
database
testing
logging
...
```

with:

```text
description
checklist
stack guidance
```

We should transform that into a proper **Rule Engine**.

For example:

```yaml
id: CG-SEC-AUTH-001
version: 1
category: security
name: JWT secret configuration
severity: high

applies_when:
  - jwt_used

detect:
  ...

evidence:
  ...

false_positive_conditions:
  ...

remediation:
  ...

references:
  ...

fixtures:
  ...
```

Then community contributors could add rules without modifying the core engine.

That could become one of Code Guardian's strongest long-term differentiators.

---

# 13. `generate_security_checklist`

Currently:

```text
check_security()
       +
static OWASP-style checklist
       +
static recommendations
```

This should become:

```text
Security Findings
      ↓
Security Remediation Plan
      ↓
prioritized fixes
      ↓
optional patches
```

In other words, move from:

> “Here are security things you should consider.”

toward:

> “Here is the evidence showing exactly which security controls are missing or violated.”

---

# 14. `generate_github_workflow`

This is more problematic than just being a simple generator.

The workflow templates contain hardcoded assumptions.

For example:

```text
node 20
npm
main/master/develop
docker
specific deployment commands
```

And the Kubernetes template contains:

```text
kubectl config set-context --current ${{ }}
```

which is effectively a placeholder rather than a deployable configuration.

So this should eventually become:

```text
Project Model
    ↓
CI requirements
    ↓
Deployment model
    ↓
Security constraints
    ↓
Workflow IR
    ↓
Validated YAML
```

rather than string templates.

---

# 15. `detect_agent`

The actual detection is extremely narrow.

It checks:

```text
.cursorrules
.windsurfrules
CLAUDE.md
AGENTS.md
```

It does not actually deeply determine:

```text
which agent is connected
which MCP client is calling
agent-specific configuration hierarchy
agent capabilities
agent-specific tool behavior
```

Therefore I would rename the conceptual capability to:

```text
Agent Environment Intelligence
```

rather than merely `detect_agent`.

---

# 16. `get_agent_guidance`

This is currently essentially a static database:

```text
agent → configuration → best practices
```

That is fine as metadata.

It should probably **not be a major core capability**.

Instead it becomes an integration layer:

```text
integrations/
    agents/
        claude-code
        cursor
        windsurf
        codex
        ...
```

---

# 17. `generate_starter_repo`

This does not currently generate a repository.

It returns:

```text
recommended structure
essential packages
production config
```

So the current name overstates the capability.

Eventually this could become a true scaffolding engine:

```text
project specification
        ↓
architecture plan
        ↓
files
        ↓
configs
        ↓
tests
        ↓
CI
        ↓
security baseline
```

But I would **not prioritize this early**.

The audit/intelligence engine should come first.

---

# 18. Contract audit: MCP layer

This is one of the most important findings.

The current server implements MCP manually.

It currently performs:

```text
initialize
ping
tools/list
tools/call
```

and returns tool results as:

```json
{
  "content": [
    {
      "type": "text",
      "text": "{...JSON...}"
    }
  ]
}
```

So the model has to parse JSON embedded inside text.

That is an unnecessary contract weakness.

---

## Current tool contract

Currently:

```json
{
  "name": "audit_codebase",
  "description": "...",
  "inputSchema": {
    "type": "object",
    "properties": {}
  }
}
```

There are no meaningful:

```text
required
additionalProperties
outputSchema
annotations
structuredContent
```

Modern MCP's 2026-07-28 specification supports full JSON Schema 2020-12 for tool input/output schemas and structured tool output. ([Model Context Protocol Blog][1])

So future Code Guardian tools should have machine-readable contracts like:

```text
inputSchema
outputSchema
annotations
```

rather than:

```text
text containing serialized JSON
```

---

# 19. MCP protocol version is now a major modernization item

The current stdio implementation hardcodes/echoes:

```text
2024-11-05
```

and performs:

```text
initialize
initialized-style lifecycle
```

The current MCP specification is **2026-07-28**, which changed the protocol substantially: protocol-level sessions and the initialize/initialized exchange were retired in favor of a stateless request model. ([Model Context Protocol Blog][2])

The current TypeScript SDK v2 is explicitly built around the 2026-07-28 specification. ([MCP TypeScript SDK][3])

This means:

> We should **not simply continue expanding the current hand-written MCP protocol implementation**.

We need an explicit MCP compatibility/upgrade layer.

---

# 20. HTTP transport has an even larger modernization requirement

Current implementation describes itself as:

```text
HTTP/SSE
```

with:

```text
POST /mcp
GET /sse
```

The current MCP specification considers legacy HTTP+SSE deprecated and uses the modern Streamable HTTP architecture. ([Model Context Protocol Blog][2])

Therefore the old roadmap item:

```text
"Add Streamable HTTP"
```

is stale.

The correct architectural item is:

```text
Modern MCP transport compatibility
```

with:

```text
stdio
Streamable HTTP
legacy compatibility where necessary
```

rather than building another custom SSE implementation.

---

# 21. HTTP security finding

This is a serious issue.

Current authentication:

```js
const token = process.env.CODE_GUARDIAN_TOKEN;

if (!token) return true;
```

Therefore:

```text
CODE_GUARDIAN_TOKEN absent
        ↓
authentication disabled
```

The server defaults to localhost, which reduces the immediate risk.

But:

```text
CODE_GUARDIAN_HOST=0.0.0.0
```

plus no token can turn this into:

```text
remote unauthenticated filesystem/codebase inspection
```

And the server executes:

```text
git
npm
npx
```

against a user-selected `cwd`.

That makes the trust boundary extremely important.

---

# 22. Windows path validation bug

Current validation:

```js
cwd.startsWith(root + "/")
```

is not a robust Windows path containment check.

The correct conceptual operation is:

```text
canonicalRoot
canonicalTarget
       ↓
relative(canonicalRoot, canonicalTarget)
       ↓
reject if outside root
```

This should move into a centralized:

```text
PathPolicy
```

component.

---

# 23. CORS issue

Current behavior when token auth is enabled:

```text
Access-Control-Allow-Origin:
    request Origin
```

That effectively reflects the origin.

Future configuration should instead be:

```text
CODE_GUARDIAN_ALLOWED_ORIGINS
```

with exact matching.

---

# 24. Another real implementation defect: ESM `require`

Earlier we identified:

```js
const _require = createRequire(import.meta.url);
```

but a later helper uses:

```js
require("node:fs")
```

instead of:

```js
_require("node:fs")
```

Because this is an ESM project, that bare `require` is undefined.

The exception is swallowed.

This is a good example of why the new architecture needs centralized infrastructure utilities instead of each tool doing its own filesystem logic.

---

# 25. `safeParseJSON` is also misleading

The helper claims to handle malformed JSON/config variations, but ultimately uses:

```text
JSON.parse(...)
```

which does not support:

```text
comments
trailing commas
```

and silently falls back.

That creates a dangerous audit behavior:

```text
invalid configuration
        ↓
parse failure
        ↓
fallback {}
        ↓
"configuration absent"
```

That can produce false negatives.

Future repository parsing should distinguish:

```text
missing
valid
invalid
unsupported
```

rather than collapsing all four into:

```text
{}
```

---

# 26. Command execution needs to become infrastructure

Current `run()` is used for:

```text
git
npm
npx
eslint
tsc
jest
vitest
```

This is currently just a generic subprocess helper.

But once Code Guardian becomes remote/agent-accessible, command execution is a security boundary.

We eventually need something like:

```text
ExecutionPolicy
    │
    ├── allowed commands
    ├── arguments policy
    ├── cwd policy
    ├── environment policy
    ├── timeout
    ├── output limit
    ├── network policy
    └── resource limits
```

Then:

```text
CommandRunner
```

becomes a controlled subsystem.

---

# 27. Output size is another infrastructure issue

Current subprocess execution accumulates stdout/stderr.

There is no robust global output cap.

A malicious or simply noisy command can produce huge output.

Future runner should have:

```text
maxStdoutBytes
maxStderrBytes
timeout
killGracePeriod
exitCode
signal
truncated
```

as structured execution evidence.

---

# 28. Test architecture: surprisingly important finding

The existing test suite is better than the production architecture in one respect:

It already has:

```text
unit tests
integration tests
fixtures
Windows-path regression coverage
workflow-generation regression coverage
```

And the integration suite exercises the MCP server itself.

That's good.

But the tests are mostly checking:

```text
does this function return the expected shape?
```

rather than:

```text
does Code Guardian correctly identify real engineering problems?
```

That distinction becomes critical.

---

# 29. The future testing strategy should be very different

We need four layers:

### Layer 1 — Unit

```text
parser
rule
analyzer
scoring
path policy
command runner
```

### Layer 2 — Integration

```text
repository → analyzer → finding
```

### Layer 3 — Golden repositories

Example:

```text
fixtures/
  secure-node-api/
  insecure-node-api/
  clean-python-api/
  cyclic-architecture/
  broken-ci/
  leaked-secret/
  vulnerable-dependencies/
```

Expected findings become version-controlled.

### Layer 4 — Benchmark

Measure:

```text
precision
recall
false positives
false negatives
runtime
memory
large-repository performance
```

This is essential if Code Guardian is going to claim serious auditing capability.

---

# 30. Most important architectural conclusion

After inspecting the actual implementation, I would now define Code Guardian as:

> **A repository intelligence and engineering assurance engine exposed through MCP, CLI, CI, and eventually other interfaces.**

Not:

> “an MCP server containing 15 production-readiness tools.”

That distinction matters enormously.

---

# 31. The new conceptual architecture

I would now use this as the working architecture:

```text
                         ┌──────────────────────┐
                         │      MCP Clients      │
                         │ Claude / Cursor / ... │
                         └──────────┬───────────┘
                                    │
                         ┌──────────▼───────────┐
                         │   Interface Layer    │
                         │                      │
                         │ MCP / CLI / CI / API │
                         └──────────┬───────────┘
                                    │
                         ┌──────────▼───────────┐
                         │   Guardian Core      │
                         │                      │
                         │ Audit orchestration  │
                         │ Policies             │
                         │ Configuration        │
                         └──────────┬───────────┘
                                    │
              ┌─────────────────────┼─────────────────────┐
              │                     │                     │
      ┌───────▼───────┐     ┌──────▼──────┐     ┌──────▼──────┐
      │ Repository    │     │ Rule Engine  │     │ Execution   │
      │ Intelligence  │     │              │     │ Engine      │
      │               │     │ rules        │     │ commands    │
      │ files         │     │ applicability│     │ sandbox     │
      │ AST           │     │ evidence     │     │ limits      │
      │ dependencies  │     │ remediation  │     │             │
      │ project model │     └──────┬───────┘     └─────────────┘
      └───────┬───────┘            │
              │                    │
              └──────────┬─────────┘
                         │
                ┌────────▼────────┐
                │ Analyzer Engine │
                │                 │
                │ Security        │
                │ Architecture    │
                │ Dependencies    │
                │ Testing         │
                │ CI/CD           │
                │ API             │
                │ Reliability     │
                │ Production      │
                └────────┬────────┘
                         │
                ┌────────▼────────┐
                │ Evidence Engine │
                │                 │
                │ files           │
                │ lines           │
                │ AST             │
                │ graph           │
                │ command output  │
                └────────┬────────┘
                         │
                ┌────────▼────────┐
                │ Finding Engine  │
                │                 │
                │ severity        │
                │ confidence      │
                │ impact          │
                │ fingerprint     │
                └────────┬────────┘
                         │
                ┌────────▼────────┐
                │ Remediation     │
                │ Engine          │
                │                 │
                │ explanation     │
                │ patch           │
                │ tests           │
                │ verification    │
                └─────────────────┘
```

This is substantially stronger than the current:

```text
15 tools → tools.js
```

---

# 32. What happens to the existing 15 tools?

This is important: **we should not throw them away.**

They become compatibility/interface tools.

For example:

```text
audit_codebase
    → Audit Engine

check_security
    → Security Analyzer

check_architecture
    → Architecture Analyzer

check_tests
    → Testing Analyzer

check_cicd
    → CI/CD Analyzer

check_linting
    → Code Quality Analyzer

production_readiness
    → Finding/Risk aggregation

get_industry_patterns
    → Rule Registry

generate_security_checklist
    → Remediation Planner

generate_production_code
    → Remediation Generator

generate_github_workflow
    → CI/CD Generator
```

And:

```text
check_branch
detect_agent
get_agent_guidance
generate_starter_repo
```

become specialized supporting capabilities.

This preserves backward compatibility while allowing the internals to evolve.

---

# 33. One more important MCP decision

Because the current MCP implementation is hand-written and the MCP protocol has moved significantly since the version this repository implements, I recommend we **do not refactor `stdio-server.js` and `http-server.js` yet**.

First define:

```text
Core Engine API
```

Then put MCP on top of it.

Otherwise we'd risk doing:

```text
old MCP server
    ↓
refactor
    ↓
new MCP server
    ↓
discover new core architecture
    ↓
refactor again
```

Instead:

```text
Core architecture
       ↓
stable internal contracts
       ↓
MCP adapter
       ↓
CLI adapter
       ↓
CI adapter
```

The current MCP 2026-07-28 design is explicitly moving toward stateless, routable HTTP and richer tool contracts, so this separation is particularly valuable now. ([Model Context Protocol Blog][2])

---

# 34. Phase 2 result

We can now mark Phase 2 as:

**Deep behavior + contract audit — COMPLETE**

### Confirmed:

* [x] All 15 tools mapped
* [x] Registry inspected
* [x] stdio contract inspected
* [x] HTTP contract inspected
* [x] CLI inspected
* [x] package scripts inspected
* [x] unit-test architecture inspected
* [x] integration-test architecture inspected
* [x] filesystem behavior inspected
* [x] command execution inspected
* [x] security boundaries inspected
* [x] MCP contract assessed against current specification
* [x] generator architecture assessed
* [x] rule/pattern architecture assessed
* [x] testing gaps identified
* [x] migration direction established

### Most important finding:

**The project does not need “more tools” first. It needs a reusable repository-intelligence core underneath the existing tools.**

That is the architectural pivot I would lock in before writing the master roadmap.

---

## Next: Phase 3

The next step should be **not documentation yet**.

We should perform a **dependency and responsibility decomposition of `tools.js`**:

```text
tools.js
   │
   ├── filesystem responsibilities
   ├── process execution
   ├── repository discovery
   ├── project detection
   ├── rule/pattern knowledge
   ├── security analysis
   ├── architecture analysis
   ├── testing analysis
   ├── CI analysis
   ├── scoring
   ├── agent integrations
   ├── code generation
   └── repository generation
```

Then map every function to:

```text
KEEP
MOVE
REWRITE
DEPRECATE
REPLACE
```

That will give us the **actual migration map from Code Guardian v2 → Code Guardian's next architecture**, rather than designing a greenfield architecture disconnected from the code that already exists.

[1]: https://blog.modelcontextprotocol.io/posts/2026-07-28-release-candidate/?utm_source=chatgpt.com "The 2026-07-28 MCP Specification Release Candidate | Model Context Protocol Blog"
[2]: https://blog.modelcontextprotocol.io/posts/2026-07-28/?utm_source=chatgpt.com "The 2026-07-28 Specification | Model Context Protocol Blog"
[3]: https://ts.sdk.modelcontextprotocol.io/v2/?utm_source=chatgpt.com "MCP TypeScript SDK"
