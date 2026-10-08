import { promises as fs } from "node:fs";
import * as path from "node:path";
import { createHash } from "node:crypto";
import { canonicalize, hashSignature, type NormalizedSession } from "./events.js";
import { isSensitivePath, redactText, redactUnknown, REDACT_POLICY_VERSION } from "./redact.js";

export interface StoredSession extends NormalizedSession {
  importedAt: string;
  redactPolicy: string;
  sourceLabel: string;
}

function dataDir(base?: string): string {
  return base ?? process.env["FORENSICS_DATA"] ?? path.join(process.cwd(), "data");
}

function sessionPath(dir: string, id: string): string {
  const key = createHash("sha256").update(id).digest("hex");
  return path.join(dir, "sessions", `${key}.json`);
}

export async function saveSession(
  s: NormalizedSession,
  opts: { dataDir?: string; sourceLabel?: string } = {},
): Promise<string> {
  const dir = dataDir(opts.dataDir);
  await fs.mkdir(path.join(dir, "sessions"), { recursive: true });
  const configuredPaths = (process.env["FORENSICS_SENSITIVE_PATHS"] ?? "")
    .split(",")
    .map((x) => x.trim())
    .filter(Boolean)
    .map((x) => new RegExp(x.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "i"));
  const redactedEvents = s.events.map((e) => {
    const a = redactUnknown(e.normalizedArgs);
    const r = typeof e.resultExcerpt === "string" ? redactUnknown(e.resultExcerpt) : { value: e.resultExcerpt, hits: [] as string[] };
    const err = typeof e.errorSignature === "string" ? redactText(e.errorSignature) : { text: e.errorSignature, hits: [] };
    const files = e.files.map((file) => isSensitivePath(file, configuredPaths) ? "[REDACTED_PATH]" : redactText(file).text);
    const hits = [...a.hits, ...r.hits, ...err.hits];
    return {
      ...e,
      normalizedArgs: a.value,
      argsSignature: hashSignature(`${e.toolName ?? e.category}:${canonicalize(a.value)}`),
      resultExcerpt: typeof r.value === "string" ? r.value : e.resultExcerpt,
      errorSignature: err.text,
      files,
      redacted: hits.length > 0 || files.some((file, i) => file !== e.files[i]) ? true : e.redacted,
    };
  });
  const stored: StoredSession = {
    ...s,
    title: redactText(s.title).text,
    agent: s.agent ? redactText(s.agent).text : null,
    model: s.model ? redactText(s.model).text : null,
    events: redactedEvents,
    importedAt: new Date().toISOString(),
    redactPolicy: REDACT_POLICY_VERSION,
    sourceLabel: redactText(opts.sourceLabel ?? "local").text,
  };
  const p = sessionPath(dir, s.sessionId);
  const tmp = `${p}.tmp-${process.pid}`;
  await fs.writeFile(tmp, JSON.stringify(stored, null, 2), { mode: 0o600 });
  await fs.rename(tmp, p);
  try {
    await fs.chmod(p, 0o600);
  } catch {
    /* non-posix, ignore */
  }
  return p;
}

export async function loadSession(id: string, dataDirOpt?: string): Promise<StoredSession> {
  const dir = dataDir(dataDirOpt);
  const direct = sessionPath(dir, id);
  const raw = await fs.readFile(direct, "utf8").catch(async () => {
    const entries = await fs.readdir(path.join(dir, "sessions")).catch(() => [] as string[]);
    for (const f of entries.slice(0, 500)) {
      if (!f.endsWith(".json")) continue;
      const full = path.join(dir, "sessions", path.basename(f));
      try {
        const txt = await fs.readFile(full, "utf8");
        const j = JSON.parse(txt) as StoredSession;
        if (j.sessionId === id) return txt;
      } catch {
        /* skip malformed */
      }
    }
    throw new Error(`session not found: ${id}`);
  });
  const parsed = JSON.parse(raw) as StoredSession;
  if (parsed.sessionId !== id) throw new Error(`session identity mismatch: ${id}`);
  return parsed;
}

export interface SessionSummary {
  id: string;
  title: string;
  status: "errors-recorded" | "recorded";
  model: string | null;
  durationMs: number | null;
  tokens: number | null;
  events: number;
  tools: number;
  errors: number;
  importedAt: string;
}

export async function listSessions(dataDirOpt?: string): Promise<SessionSummary[]> {
  const dir = dataDir(dataDirOpt);
  const entries = await fs.readdir(path.join(dir, "sessions")).catch(() => [] as string[]);
  const out: SessionSummary[] = [];
  for (const f of entries) {
    if (!f.endsWith(".json")) continue;
    try {
      const j = JSON.parse(await fs.readFile(path.join(dir, "sessions", f), "utf8")) as StoredSession;
      out.push({
        id: j.sessionId,
        title: j.title,
        status: j.errorCount > 0 ? "errors-recorded" : "recorded",
        model: j.model,
        durationMs: j.durationMs,
        tokens: j.totalTokens ? j.totalTokens.input + j.totalTokens.output + j.totalTokens.reasoning : null,
        events: j.eventCount,
        tools: j.toolCount,
        errors: j.errorCount,
        importedAt: j.importedAt,
      });
    } catch {
      /* skip malformed, never crash listing */
    }
  }
  return out.sort((a, b) => b.importedAt.localeCompare(a.importedAt));
}
