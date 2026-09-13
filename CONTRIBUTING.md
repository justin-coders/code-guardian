# Contributing to Code Guardian

Thanks for your interest in contributing! This document covers everything you need to know.

## Getting Started

### Prerequisites

- Node.js >= 18.0.0
- Git

### Setup

```bash
# Fork and clone
git clone https://github.com/justin-coders/code-guardian.git
cd code-guardian

# No npm install needed — zero dependencies
# Just verify Node version
node --version  # should be >= 18.0.0
```

### Running Tests

```bash
# Unit tests
node --test tests/tools.test.js

# Integration tests
node --test tests/integration.test.js

# All tests with coverage
node --test --experimental-test-coverage tests/**/*.test.js
```

---

## How to Add a New Tool

### 1. Implement the tool in `src/tools.js`

```javascript
export async function toolMyNewTool(args = {}) {
  const { cwd = process.cwd() } = args;
  // ... implementation ...
  return {
    tool: "my_new_tool",
    version: "2.0.0",
    result: { ... },
  };
}
```

### 2. Register in `src/stdio-server.js`

Add to the `TOOLS` array:
```javascript
{
  name: "my_new_tool",
  description: "Description of what the tool does.",
  inputSchema: {
    type: "object",
    properties: {
      cwd: { type: "string", description: "Project root" },
    },
  },
},
```

Add to the `handleRequest` switch:
```javascript
case "my_new_tool":
  result = await toolMyNewTool(args);
  break;
```

### 3. Register in `src/http-server.js`

Same changes as step 2 — duplicate the TOOLS entry and switch case.

### 4. Add tests

Add unit tests to `tests/tools.test.js` and integration tests to `tests/integration.test.js`.

### 5. Update documentation

Update `README.md` with the new tool in the tools table.

---

## How to Add a New Industry Pattern

### 1. Add to `INDUSTRY_PATTERNS` in `src/tools.js`

```javascript
my_pattern: {
  name: "My Pattern",
  description: "Description of the pattern.",
  checklist: [
    "First requirement",
    "Second requirement",
  ],
  stack: {
    nestjs: "NestJS-specific guidance",
    express: "Express-specific guidance",
  },
},
```

### 2. Add template to `getProductionTemplate()`

```javascript
const snippets = {
  my_pattern_nestjs: [...],
  my_pattern_express: [...],
};
```

### 3. Update `README.md` to list the new pattern

---

## How to Add Support for a New Agent

### 1. Add to `AGENT_CONFIGS` in `src/tools.js`

```javascript
new_agent: {
  name: "New Agent",
  pluginSystem: false,
  mcpSupport: true,
  pluginDir: null,
  skillFormat: ".newagentrules file",
  bestPractices: [
    "Best practice 1",
    "Best practice 2",
  ],
},
```

### 2. Update all references in stdio-server.js and http-server.js

Search for `emni` (or `gemini`) and add the new agent name to descriptions.

### 3. Add tests for the new agent in `tests/tools.test.js`

---

## Code Style

This project uses:
- **ES Modules** (`"type": "module"` in package.json)
- **No external dependencies** — pure Node.js built-ins only
- **Consistent naming**: `tool<Name>` for tool functions
- **Defensive args**: Always use `args = {}` default and destructuring with defaults
- **Version marker**: Every tool response includes `version: "2.0.0"`

### File Structure

```
src/
  tools.js          # All tool logic + patterns + templates
  stdio-server.js   # stdio MCP server (Claude Code)
  http-server.js    # HTTP/SSE MCP server
tests/
  tools.test.js     # Unit tests for individual tools
  integration.test.js  # End-to-end MCP protocol tests
```

---

## Commit Convention

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add new tool for X
fix: handle empty args in tool Y
docs: update README with new patterns
test: add coverage for security checks
chore: bump version to 2.1.2
```

### Types
- `feat` — new feature
- `fix` — bug fix
- `docs` — documentation changes
- `test` — adding or updating tests
- `chore` — maintenance, version bumps, config changes

---

## Pull Request Process

1. Create a feature branch: `git checkout -b feat/my-feature`
2. Make your changes
3. Run tests: `node --test tests/**/*.test.js`
4. Commit with conventional commit message
5. Push and open a Pull Request
6. Update CHANGELOG.md with your changes
7. Ping `@justin-coders` for review

---

## Reporting Bugs

Open an issue at https://github.com/justin-coders/code-guardian/issues with:
- Clear description of the bug
- Steps to reproduce
- Expected vs actual behavior
- Your environment (Node version, OS, agent being used)

---

## Asking Questions

Open a GitHub Discussion or issue with the `question` label.

---

## License

By contributing, you agree that your contributions are licensed under the MIT License.
