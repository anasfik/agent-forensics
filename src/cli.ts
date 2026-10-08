#!/usr/bin/env node
import { run } from "./cli-run.js";

// Piping to `head` closes stdout early — don't crash with EPIPE.
process.stdout.on("error", (err) => {
  if (err && typeof err === "object" && "code" in err && err.code === "EPIPE") process.exit(0);
  throw err;
});
run(process.argv.slice(2)).catch((err) => {
  const msg = (err instanceof Error ? err.message : String(err)).replace(/[\u0000-\u0008\u000B-\u001F\u007F-\u009F]/g, "");
  process.stderr.write(`error: ${msg}\n`);
  process.exit(1);
});
