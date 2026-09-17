# Installation Guide

## Prerequisites

- **Node.js** >= 18.0.0
- No other dependencies required (pure ESM, zero external packages)

## Method 1: Claude Code Plugin (Recommended)

The plugin is auto-discovered when placed in the correct directory.

### Step 1 — Clone the repo

```bash
git clone https://github.com/justin-coders/code-guardian.git
cd code-guardian
```

### Step 2 — Install via npm link

```bash
npm link
```

This makes `code-guardian` available system-wide so Claude Code can locate it.

### Step 3 — Enable in Claude Code

In Claude Code, run:

```
/plugin marketplace add justin-coders/code-guardian
/plugin install
```

Or manually add the stdio config (see Method 2 below).

### Step 4 — Verify installation

In Claude Code, type:
```
/tools
```
You should see all 15 code-guardian tools listed.

---

## Method 2: Manual MCP Config (Any Agent)

### Step 1 — Clone the repo

```bash
git clone https://github.com/justin-coders/code-guardian.git
cd code-guardian
```

### Step 2 — Add MCP config

**Claude Code** (`~/.claude/settings.json`):
```json
{
  "mcpServers": {
    "code-guardian": {
      "type": "stdio",
      "command": "node",
      "args": ["<absolute-path>/src/stdio-server.js"],
      "cwd": "<absolute-path>"
    }
  }
}
```

**Cursor** (`~/.cursor/mcp.json`):
```json
{
  "mcpServers": {
    "code-guardian": {
      "command": "node",
      "args": ["<absolute-path>/src/stdio-server.js"]
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
      "args": ["<absolute-path>/src/stdio-server.js"]
    }
  }
}
```

Replace `<absolute-path>` with the real path to the cloned repo.

### Step 3 — Restart your agent

Close and reopen Claude Code / Cursor / Windsurf.

---

## Method 3: Standalone Server

### Step 1 — Clone the repo

```bash
git clone https://github.com/justin-coders/code-guardian.git
cd code-guardian
```

### Step 2 — Run the server

```bash
# stdio mode (for MCP clients)
node src/stdio-server.js

# HTTP/SSE mode (for direct API access)
node src/http-server.js
# → Server listening on http://localhost:8765
```

### Step 3 — Use with any JSON-RPC client

Send JSON-RPC 2.0 messages over stdio or HTTP. Example tool call:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "audit_codebase",
    "arguments": { "cwd": "/path/to/your/project" }
  }
}
```

---

## Verification

After installation, run the test suite:

```bash
node --test tests/**/*.test.js
```

All 83 tests should pass.

---

## Updating an Existing Install

```bash
cd /path/to/code-guardian
git pull origin main    # or your branch

# If using npm link:
npm unlink && npm link

# If using manual MCP config: no action needed — path still points to repo

# Restart your agent
# Claude Code: close and reopen
# Cursor/Windsurf: restart the editor
```

---

## Troubleshooting

### Plugin not loading in Claude Code

1. Verify the path in your config points to the actual `src/stdio-server.js`
2. Check `~/.claude/settings.json` has the correct `mcpServers` entry
3. Restart Claude Code completely (close all windows)
4. Check stderr output: `node <path>/src/stdio-server.js`

### Tools not appearing in `/tools`

1. Confirm the MCP config is valid JSON
2. Check that the server starts without errors (run it manually first)
3. Restart Claude Code

### Server won't start

1. Ensure Node.js >= 18: `node --version`
2. The project uses ESM — ensure `package.json` has `"type": "module"`
3. No external dependencies needed — if `import` fails, check Node version
4. Verify `src/stdio-server.js` exists and is the correct entry point

---

## Uninstall

### Claude Code plugin
Remove the `mcpServers` entry from `~/.claude/settings.json`.

### Manual MCP config
Remove the entry from your agent's MCP config file and delete the cloned directory.
