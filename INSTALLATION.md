# Installation Guide

## Prerequisites

- **Node.js** >= 18.0.0
- No other dependencies required (pure ESM, zero external packages)

## Method 1: Claude Code Plugin (Recommended)

The plugin is auto-discovered when placed in the correct directory.

### Step 1 — Clone or copy the plugin

```bash
# Option A: Clone the repo and copy
git clone https://github.com/justin-coders/code-guardian.git
cp -r code-guardian/v1 ~/.claude/plugins/cache/claude-plugins-official/code-guardian/v1

# Option B: Copy from local path
cp -r /path/to/code-guardian/v1 ~/.claude/plugins/cache/claude-plugins-official/code-guardian/v1
```

### Step 2 — Verify installation

The plugin manifest at `~/.claude/plugins/installed_plugins.json` should include:

```json
{
  "code-guardian": [
    {
      "scope": "user",
      "installPath": "~/.claude/plugins/cache/claude-plugins-official/code-guardian/v1",
      "version": "2.0.0",
      "installedAt": "..."
    }
  ]
}
```

### Step 3 — Restart Claude Code

Close and reopen Claude Code. The plugin will be auto-loaded.

### Step 4 — Verify tools are available

In Claude Code, type:
```
/tools
```
You should see all 15 code-guardian tools listed.

---

## Method 2: Standalone MCP Server

### Step 1 — Clone the repo

```bash
git clone https://github.com/justin-coders/code-guardian.git
cd code-guardian
```

### Step 2 — Test the server

```bash
# stdio mode (for MCP clients)
node src/stdio-server.js

# HTTP/SSE mode (for direct API access)
node src/http-server.js
# → Server listening on http://localhost:8765
```

### Step 3 — Add to your MCP client config

**Cursor** (`~/.cursor/mcp.json`):
```json
{
  "mcpServers": {
    "code-guardian": {
      "command": "node",
      "args": ["/absolute/path/to/code-guardian/src/stdio-server.js"]
    }
  }
}
```

**Windsurf** (`~/.windsurf/mcp.json`):
```json
{
  "mcpServers": {
    "code-guardian": {
      "command": "node",
      "args": ["/absolute/path/to/code-guardian/src/stdio-server.js"]
    }
  }
}
```

**Custom MCP client**:
```json
{
  "mcpServers": {
    "code-guardian": {
      "command": "node",
      "args": ["<path>/src/stdio-server.js"]
    }
  }
}
```

---

## Method 3: From npm (when published)

```bash
# Install globally
npm install -g code-guardian

# Or as a project dependency
npm install code-guardian --save-dev

# Run
npx code-guardian
```

---

## Verification

After installation, run the test suite:

```bash
node --test tests/**/*.test.js
```

All tests should pass.

---

## Troubleshooting

### Plugin not loading in Claude Code

1. Verify the path exists: `ls ~/.claude/plugins/cache/claude-plugins-official/code-guardian/v1/`
2. Check `installed_plugins.json` has the entry
3. Restart Claude Code completely (close all windows)
4. Check stderr output: `node ~/.claude/plugins/.../code-guardian/v1/src/stdio-server.js`

### Tools not appearing in `/tools`

1. Confirm the plugin is registered in `installed_plugins.json`
2. Check that `.claude-plugin/plugin.json` has the correct name
3. Restart Claude Code

### Server won't start

1. Ensure Node.js >= 18: `node --version`
2. The project uses ESM — ensure `package.json` has `"type": "module"`
3. No external dependencies needed — if `import` fails, check Node version

---

## Uninstall

### Claude Code plugin
Remove from `~/.claude/plugins/installed_plugins.json` and delete the cache directory:

```bash
rm -rf ~/.claude/plugins/cache/claude-plugins-official/code-guardian
```

### Standalone installation
Simply delete the cloned directory.
