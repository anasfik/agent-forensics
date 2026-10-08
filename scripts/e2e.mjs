// End-to-end smoke: seed -> CLI -> ui server -> HTTP asserts. Stdlib only.
import { spawn, execFile } from "node:child_process";
import { promisify } from "node:util";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import assert from "node:assert";

const run = promisify(execFile);
const ROOT = new URL("..", import.meta.url).pathname;
const CLI = join(ROOT, "dist", "cli.js");
const PORT = 4321;

const cli = (args, env = {}) =>
  run("node", [CLI, ...args], { cwd: ROOT, env: { ...process.env, ...env } });

const dir = await mkdtemp(join(tmpdir(), "af-e2e-"));
const D = ["--data-dir", dir];
try {
  for (const f of ["success", "fail-loop", "diverge-a", "diverge-b"]) {
    await cli(["import", join(ROOT, "fixtures", `${f}.json`), ...D]);
  }
  const target = join(dir, "race.json");
  const race = await Promise.allSettled([
    cli(["export", "ses_fail_loop", "--out", target, ...D]),
    cli(["export", "ses_fail_loop", "--out", target, ...D]),
  ]);
  assert.equal(race.filter((x) => x.status === "fulfilled").length, 1, "exclusive export winner");
  const srv = spawn("node", [CLI, "ui", "--port", String(PORT), ...D], { cwd: ROOT, stdio: "pipe" });
  const ready = await new Promise((resolve) => {
    const t = setTimeout(() => resolve(false), 15000);
    srv.stdout.on("data", (d) => {
      if (String(d).includes(`:${PORT}`)) {
        clearTimeout(t);
        resolve(true);
      }
    });
    srv.on("exit", () => {
      clearTimeout(t);
      resolve(false);
    });
  });
  assert.ok(ready, "ui server did not start");
  try {
    const get = async (p) => {
      const r = await fetch(`http://127.0.0.1:${PORT}${p}`);
      assert.equal(r.status, 200, `${p} -> ${r.status}`);
      return r;
    };
    const sessions = await (await get("/api/sessions")).json();
    assert.equal(sessions.sessions.length, 4, "seeded session count");
    const html = await (await get("/")).text();
    assert.ok(html.includes("Agent Forensics"), "dashboard title");
    const analysis = await (await get("/api/analysis?id=ses_fail_loop")).json();
    assert.ok(analysis.findings.some((f) => f.ruleId === "failure-loop"), "failure-loop via HTTP");
    const cmp = await (await get("/api/compare?a=ses_diverge_a&b=ses_diverge_b")).json();
    assert.ok(cmp.firstDivergence?.aEventId, "two-sided divergence via HTTP");
    assert.equal((await get("/api/session?id=ses_success")).status, 200);
    const trav = await fetch(`http://127.0.0.1:${PORT}/%2e%2e/package.json`);
    assert.ok(trav.status === 403 || trav.status === 404, "traversal blocked");
    console.log("e2e ok: 4 sessions, dashboard, analysis, compare, traversal guard");
  } finally {
    srv.kill("SIGTERM");
  }
} finally {
  await rm(dir, { recursive: true, force: true });
}
