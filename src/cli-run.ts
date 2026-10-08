import { promises as fs } from "node:fs";
import * as path from "node:path";
import { createServer } from "node:http";
import { randomUUID } from "node:crypto";
import { SessionExportSchema } from "./schemas.js";
import { normalizeExport } from "./normalize.js";
import { analyze } from "./detectors.js";
import { compare } from "./compare.js";
import { listSessions, loadSession, saveSession } from "./store.js";

export const CLI_VERSION = "0.1.0";

function opt(args: string[], name: string): string | null {
  const i = args.indexOf(name);
  if (i === -1) return null;
  const v = args[i + 1];
  return v && !v.startsWith("--") ? v : null;
}

function has(args: string[], name: string): boolean {
  return args.includes(name);
}

// Imported strings are untrusted. JSON.stringify already escapes controls;
// this strips live terminal control bytes from every stdout/stderr path.
export function terminalSafe(text: string): string {
  return text.replace(/[\u0000-\u0008\u000B-\u001F\u007F-\u009F]/g, "");
}

function out(text: string): void {
  process.stdout.write(terminalSafe(text));
}

function usage(): string {
  return [
    "agent-forensics <command> [args]",
    "",
    "  sessions [--json]              list imported sessions",
    "  import <file|ses_ID> [--json]  import opencode export JSON (or live ses_ID)",
    "  inspect <session-id> [--json]  show timeline summary + events",
    "  analyze <session-id> [--json]  run deterministic diagnostics",
    "  compare <a> <b> [--json]       differential analysis of two sessions",
    "  export <id> --out <file>       write redacted JSON report (--force to overwrite)",
    "  ui [--port 4311]               serve local dashboard (read-only)",
    "",
  ].join("\n");
}

function fail(msg: string, code: number): never {
  process.stderr.write(terminalSafe(`error: ${msg}\n`));
  process.exit(code);
}

async function readExportInput(input: string): Promise<{ raw: unknown; label: string }> {
  if (input.startsWith("ses_")) {
    const { execFile } = await import("node:child_process");
    const { promisify } = await import("node:util");
    const run = promisify(execFile);
    try {
      const { stdout } = await run("opencode", ["session", "export", input, "--sanitize"], {
        maxBuffer: 32 * 1024 * 1024,
      });
      const parsed = JSON.parse(stdout) as unknown;
      const rec = parsed as Record<string, unknown>;
      const wrapped =
        rec && typeof rec === "object" && !("data" in rec) && "info" in rec ? { data: parsed } : parsed;
      return { raw: wrapped, label: `live:${input}` };
    } catch (err) {
      throw new Error(`live export failed for ${input}: ${err instanceof Error ? err.message : String(err)}`);
    }
  }
  const txt = await fs.readFile(input, "utf8").catch(() => {
    throw new Error(`cannot read file: ${input}`);
  });
  try {
    const parsed = JSON.parse(txt) as unknown;
    const rec = parsed as Record<string, unknown>;
    // `opencode session export` prints SessionTransfer.Data ({info,messages});
    // the HTTP API wraps it as {data:{info,messages}}. Accept both.
    if (rec && typeof rec === "object" && !("data" in rec) && "info" in rec && "messages" in rec) {
      return { raw: { data: parsed }, label: `file:${path.basename(input)}` };
    }
    return { raw: parsed, label: `file:${path.basename(input)}` };
  } catch {
    throw new Error(`invalid JSON in ${input}`);
  }
}

export async function run(argv: string[]): Promise<void> {
  const cmd = argv[0];
  const rest = argv.slice(1);
  const dataDir =
    opt(rest, "--data-dir") ?? process.env["FORENSICS_DATA"] ?? path.join(process.cwd(), "data");
  const json = has(rest, "--json");

  if (!cmd || cmd === "--help" || cmd === "-h" || cmd === "help") {
    out(usage());
    return;
  }
  if (cmd === "--version" || cmd === "-v") {
    out(`${CLI_VERSION}\n`);
    return;
  }

  if (cmd === "sessions") {
    const rows = await listSessions(dataDir);
    if (json) {
      out(JSON.stringify({ sessions: rows }, null, 2) + "\n");
    } else if (!rows.length) {
      out("no sessions imported yet. Run: agent-forensics import <export.json>\n");
    } else {
      for (const r of rows) {
        out(`${r.id}  ${r.status} events=${r.events} tools=${r.tools} errors=${r.errors} tokens=${r.tokens ?? "unknown"} model=${r.model ?? "unknown"}  ${r.title}\n`);
      }
    }
    return;
  }

  if (cmd === "import") {
    const input = rest.find((a) => !a.startsWith("--"));
    if (!input) fail("usage: agent-forensics import <export.json|ses_ID>", 1);
    const { raw, label } = await readExportInput(input as string);
    const parsed = SessionExportSchema.safeParse(raw);
    if (!parsed.success) {
      fail(`schema validation failed: ${parsed.error.issues.slice(0, 3).map((i) => i.message).join("; ")}`, 3);
    }
    const norm = normalizeExport(parsed.data!, { sanitize: label.startsWith("live:") });
    const p = await saveSession(norm, { dataDir, sourceLabel: label });
    const findings = analyze(norm);
    if (json) {
      out(
        JSON.stringify({ session: norm.sessionId, events: norm.eventCount, findings: findings.length, path: p, warnings: norm.warnings }, null, 2) + "\n",
      );
    } else {
      out(`imported ${norm.sessionId} (${norm.eventCount} events, ${findings.length} findings) -> ${p}\n`);
    }
    return;
  }

  if (cmd === "inspect") {
    const id = rest.find((a) => !a.startsWith("--"));
    if (!id) fail("usage: agent-forensics inspect <session-id>", 1);
    const s = await loadSession(id as string, dataDir).catch(() => fail(`session not found: ${id}`, 2));
    if (json) {
      out(JSON.stringify(s, null, 2) + "\n");
      return;
    }
    out(`session ${s.sessionId}\ntitle: ${s.title}\nmodel: ${s.model ?? "unknown"} agent: ${s.agent ?? "unknown"}\n`);
    out(`events=${s.eventCount} tools=${s.toolCount} errors=${s.errorCount} durationMs=${s.durationMs ?? "unknown"}\n`);
    if (s.warnings.length) out(`warnings: ${s.warnings.slice(0, 5).join(" | ")}\n`);
    for (const e of s.events.slice(0, 80)) {
      const when = e.tsMs ? new Date(e.tsMs).toISOString().slice(11, 19) : "--:--:--";
      const what = e.category === "tool" ? `${e.toolName} [${e.status}]` : `${e.category} [${e.status}]`;
      const det = e.files.length ? ` files=${e.files.slice(0, 2).join(",")}` : "";
      out(`#${e.seq} ${when} ${what} id=${e.eventId}${det}\n`);
    }
    if (s.events.length > 80) out(`... (${s.events.length - 80} more, use --json)\n`);
    return;
  }

  if (cmd === "analyze") {
    const id = rest.find((a) => !a.startsWith("--"));
    if (!id) fail("usage: agent-forensics analyze <session-id>", 1);
    const s = await loadSession(id as string, dataDir).catch(() => fail(`session not found: ${id}`, 2));
    const findings = analyze(s);
    if (json) {
      out(JSON.stringify({ session: s.sessionId, findings, warnings: s.warnings }, null, 2) + "\n");
    } else if (!findings.length) {
      out("no findings.\n");
    } else {
      for (const f of findings) {
        out(`[${f.severity}] ${f.ruleId}: ${f.title}\n  evidence: ${f.evidenceEventIds.slice(0, 6).join(", ")}\n  ${f.explanation}\n`);
      }
    }
    return;
  }

  if (cmd === "compare") {
    const ids = rest.filter((a) => !a.startsWith("--"));
    if (ids.length < 2) fail("usage: agent-forensics compare <session-a> <session-b>", 1);
    const a = await loadSession(ids[0] as string, dataDir).catch(() => fail(`session not found: ${ids[0]}`, 2));
    const b = await loadSession(ids[1] as string, dataDir).catch(() => fail(`session not found: ${ids[1]}`, 2));
    const report = compare(a, b);
    if (json) {
      out(JSON.stringify(report, null, 2) + "\n");
    } else {
      out(`A=${report.aId} (${report.aEvents})  B=${report.bId} (${report.bEvents})\n`);
      out(`matches=${report.matches} uniqueA=${report.uniqueA} uniqueB=${report.uniqueB}\n`);
      if (report.firstDivergence) {
        out(
          `first divergence: A#${report.firstDivergence.aSeq ?? "?"} (${report.firstDivergence.aEventId ?? "-"}) vs B#${report.firstDivergence.bSeq ?? "?"} (${report.firstDivergence.bEventId ?? "-"})\n`,
        );
      } else {
        out("no divergence (identical signatures).\n");
      }
      const t = report.tokenDelta;
      out(`tokens: A=${t.a ?? "unknown"} B=${t.b ?? "unknown"} delta=${t.delta ?? "unknown"}\n`);
      out(`errors: A=${report.outcomeDelta.aErrors} B=${report.outcomeDelta.bErrors}\n`);
    }
    return;
  }

  if (cmd === "export") {
    const id = rest.find((a) => !a.startsWith("--") && a !== "export");
    const outputPath = opt(rest, "--out");
    if (!id || !outputPath) fail("usage: agent-forensics export <session-id> --out <file> [--force]", 1);
    const s = await loadSession(id as string, dataDir).catch(() => fail(`session not found: ${id}`, 2));
    const findings = analyze(s);
    const resolved = path.resolve(outputPath as string);
    process.stderr.write("warning: automated redaction is best-effort. Review before sharing.\n");
    const report = { exportedAt: new Date().toISOString(), redacted: true, redactPolicy: s.redactPolicy, session: s, findings };
    await fs.mkdir(path.dirname(resolved), { recursive: true });
    const tmp = `${resolved}.tmp-${randomUUID()}`;
    await fs.writeFile(tmp, JSON.stringify(report, null, 2), { mode: 0o600, flag: "wx" });
    try {
      if (has(rest, "--force")) await fs.rename(tmp, resolved);
      else await fs.link(tmp, resolved).catch((err: NodeJS.ErrnoException) => {
        if (err.code === "EEXIST") throw new Error(`refusing to overwrite ${resolved} without --force`);
        throw err;
      });
    } finally {
      await fs.rm(tmp, { force: true });
    }
    out(`wrote ${resolved}\n`);
    return;
  }

  if (cmd === "ui") {
    const port = Number(opt(rest, "--port") ?? "4311");
    // Portable web root: installed layout (dist/../apps/web) first, repo cwd fallback.
    const candidates = [
      path.join(path.dirname(new URL(import.meta.url).pathname), "..", "apps", "web"),
      path.join(process.cwd(), "apps", "web"),
    ];
    let webRoot = path.normalize(candidates[1]!);
    for (const c of candidates) {
      const idx = path.join(path.normalize(c), "index.html");
      if (await fs.stat(idx).then(() => true).catch(() => false)) {
        webRoot = path.normalize(c);
        break;
      }
    }
    const server = createServer(async (req, res) => {
      try {
        const url = new URL(req.url ?? "/", "http://localhost");
        res.setHeader("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'");
        if (url.pathname === "/api/sessions") {
          res.setHeader("content-type", "application/json");
          res.end(JSON.stringify({ sessions: await listSessions(dataDir) }));
          return;
        }
        if (url.pathname === "/api/session") {
          const s = await loadSession(url.searchParams.get("id") ?? "", dataDir);
          res.setHeader("content-type", "application/json");
          res.end(JSON.stringify(s));
          return;
        }
        if (url.pathname === "/api/analysis") {
          const s = await loadSession(url.searchParams.get("id") ?? "", dataDir);
          res.setHeader("content-type", "application/json");
          res.end(JSON.stringify({ findings: analyze(s) }));
          return;
        }
        if (url.pathname === "/api/compare") {
          const a = await loadSession(url.searchParams.get("a") ?? "", dataDir);
          const b = await loadSession(url.searchParams.get("b") ?? "", dataDir);
          res.setHeader("content-type", "application/json");
          res.end(JSON.stringify(compare(a, b)));
          return;
        }
        const file = url.pathname === "/" ? "/index.html" : url.pathname;
        const full = path.normalize(path.join(webRoot, `.${file}`));
        if (!full.startsWith(path.normalize(webRoot))) {
          res.statusCode = 403;
          res.end("forbidden");
          return;
        }
        const body = await fs.readFile(full).catch(() => null);
        if (!body) {
          res.statusCode = 404;
          res.end("not found");
          return;
        }
        res.setHeader("content-type", file.endsWith(".html") ? "text/html; charset=utf-8" : "text/plain; charset=utf-8");
        res.end(body);
      } catch (err) {
        res.statusCode = 500;
        res.end(`error: ${err instanceof Error ? err.message : String(err)}`);
      }
    });
    await new Promise<void>((resolve) => server.listen(port, "127.0.0.1", resolve));
    out(`agent-forensics ui on http://127.0.0.1:${port} (Ctrl+C to stop)\n`);
    await new Promise(() => undefined);
    return;
  }

  fail(`unknown command: ${cmd}\n${usage()}`, 1);
}
