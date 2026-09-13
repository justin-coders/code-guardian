#!/usr/bin/env node
import { spawn } from "child_process";
import { fileURLToPath } from "url";
import { dirname, join } from "path";

const __dirname = dirname(fileURLToPath(import.meta.url));
const serverPath = join(__dirname, "..", "src", "stdio-server.js");

const child = spawn("node", [serverPath, ...process.argv.slice(2)], {
  stdio: "inherit",
  env: { ...process.env, PLUGIN_DIR: process.cwd() },
});

child.on("exit", (code, signal) => {
  if (signal) {
    process.kill(process.pid, signal);
  } else {
    process.exit(code);
  }
});