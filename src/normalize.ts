import { canonicalize, hashSignature, modelLabel, toTokens, type ForensicsEvent, type NormalizedSession } from "./events.js";
import type { SessionExport } from "./schemas.js";
import { redactUnknown } from "./redact.js";

const MAX_EXCERPT = 2000;

function excerpt(v: unknown): string | null {
  if (v === null || v === undefined) return null;
  const s = typeof v === "string" ? v : JSON.stringify(v);
  if (!s) return null;
  return s.length > MAX_EXCERPT ? s.slice(0, MAX_EXCERPT) + "…<truncated>" : s;
}

function durationOf(t: { created?: unknown; ran?: unknown; completed?: unknown } | undefined): number | null {
  if (!t) return null;
  const end = typeof t.completed === "number" ? t.completed : null;
  const start = typeof t.ran === "number" ? t.ran : typeof t.created === "number" ? t.created : null;
  if (end === null || start === null) return null;
  const d = end - start;
  return Number.isFinite(d) && d >= 0 && d < 86_400_000 ? Math.round(d) : null;
}

function statusOf(state: { status?: unknown; error?: unknown } | undefined, output: unknown): ForensicsEvent["status"] {
  const s = typeof state?.status === "string" ? state.status.toLowerCase() : "";
  if (s === "error" || s === "failed") return "error";
  if (s === "completed" || s === "success" || s === "ok") return "completed";
  if (s === "running" || s === "pending" || s === "streaming") return s as ForensicsEvent["status"];
  if (state?.error) return "error";
  if (typeof output === "string" && /^\s*(error|failed|failure|exit code [1-9]|command failed|E[A-Z]+:)/i.test(output.slice(0, 200))) return "error";
  if (s) return "unknown";
  return "unknown";
}

function errorSignatureOf(status: string, state: Record<string, unknown>, output: unknown): string | null {
  if (status !== "error") return null;
  const raw = typeof state["error"] === "string" ? state["error"] : typeof output === "string" ? output : JSON.stringify(output ?? "");
  const first = (raw ?? "").split("\n", 3).join("\n").slice(0, 300);
  // Normalize numbers/paths/hashes so identical failures group together.
  const norm = first
    .replace(/\b\d{4,}\b/g, "<N>")
    .replace(/[0-9a-f]{7,40}/gi, "<H>")
    .replace(/\/[^\s:]*:\d+(:\d+)?/g, "<LOC>")
    .trim();
  return norm ? hashSignature(norm) + ":" + norm.slice(0, 120) : null;
}

/** Heuristic file-path extraction from tool args (used by detectors, not proof). */
function filesOf(args: unknown): string[] {
  const out = new Set<string>();
  const visit = (v: unknown, depth: number) => {
    if (depth > 6 || out.size >= 8) return;
    if (typeof v === "string") {
      if (v.length < 500 && (/\/[^/\s]+\.[A-Za-z0-9]{1,6}\b/.test(v) || /^(src|apps?|packages?|tests?|fixtures?)\//.test(v))) {
        out.add(v.length > 160 ? v.slice(0, 160) + "…" : v);
      }
      return;
    }
    if (Array.isArray(v)) { for (const x of v) visit(x, depth + 1); return; }
    if (v && typeof v === "object") {
      const r = v as Record<string, unknown>;
      for (const k of ["file", "path", "filePath", "filename", "target", "uri"]) {
        if (typeof r[k] === "string") visit(r[k], depth + 1);
      }
      // Also scan one level of other keys for nested arg objects.
      for (const k of Object.keys(r)) {
        if (!(k in { file: 1, path: 1, filePath: 1, filename: 1, target: 1, uri: 1 })) visit(r[k], depth + 1);
      }
    }
  };
  visit(args, 0);
  return [...out];
}

export function normalizeExport(
  parsed: SessionExport,
  opts: { opencodeVersion?: string; sanitize?: boolean } = {},
): NormalizedSession {
  const info = parsed.data.info;
  const messages = parsed.data.messages ?? [];
  const warnings: string[] = [];
  const events: ForensicsEvent[] = [];
  const provenance = {
    source: "opencode-export" as const,
    opencodeVersion: opts.opencodeVersion ?? "unknown",
    exportedAt: new Date().toISOString(),
    sanitize: opts.sanitize ?? false,
  };
  let seq = 0;
  const sessionId = info.id;
  const parentSessionId = typeof info.parentID === "string" ? info.parentID : null;

  for (const m of messages) {
    const rec = m as Record<string, unknown>;
    if (rec["type"] === "user") {
      seq += 1;
      const t = rec["time"] as { created?: unknown } | undefined;
      events.push({
        sessionId, eventId: typeof rec["id"] === "string" ? rec["id"] : `msg-${seq}`,
        seq, tsMs: typeof t?.created === "number" ? t.created : null,
        category: "message", status: "completed",
        agent: null, model: null, parentSessionId,
        toolName: null, normalizedArgs: null, argsSignature: hashSignature("user"),
        resultExcerpt: excerpt(rec["text"]), errorSignature: null, durationMs: null,
        tokens: null, costUsd: null, files: [], correlationId: typeof rec["id"] === "string" ? rec["id"] : `msg-${seq}`,
        redacted: false, provenance,
      });
      continue;
    }
    if (rec["type"] === "assistant") {
      const msgId = typeof rec["id"] === "string" ? rec["id"] : `msg-${seq + 1}`;
      const agent = typeof rec["agent"] === "string" ? rec["agent"] : typeof info.agent === "string" ? info.agent : null;
      const model = modelLabel(rec["model"] ?? info.model);
      const tokens = toTokens(rec["tokens"] as never);
      const cost = typeof rec["cost"] === "number" && Number.isFinite(rec["cost"]) ? rec["cost"] : null;
      const mt = rec["time"] as { created?: unknown; completed?: unknown } | undefined;
      const msgTs = typeof mt?.created === "number" ? mt.created : null;
      const content = Array.isArray(rec["content"]) ? rec["content"] as Record<string, unknown>[] : [];
      if (!Array.isArray(rec["content"])) warnings.push(`assistant message ${msgId} has no content array`);
      for (const part of content) {
        seq += 1;
        if (part["type"] === "tool") {
          const state = (part["state"] && typeof part["state"] === "object" ? part["state"] : {}) as Record<string, unknown>;
          const input = state["input"] ?? {};
          const output = redactUnknown(state["output"] ?? state["content"] ?? state["error"] ?? null).value;
          const status = statusOf(state as never, output);
          const sig = hashSignature(`${String(part["name"] ?? "unknown")}:${canonicalize(input)}`);
          const pt = part["time"] as { created?: unknown; ran?: unknown; completed?: unknown } | undefined;
          events.push({
            sessionId, eventId: typeof part["id"] === "string" ? part["id"] : `${msgId}:tool:${seq}`,
            seq, tsMs: typeof pt?.ran === "number" ? pt.ran : typeof pt?.created === "number" ? pt.created : msgTs,
            category: "tool", status, agent, model, parentSessionId,
            toolName: typeof part["name"] === "string" ? part["name"] : "unknown",
            normalizedArgs: input, argsSignature: sig,
            resultExcerpt: excerpt(output), errorSignature: errorSignatureOf(status, state, output),
            durationMs: durationOf(pt), tokens: null, costUsd: null,
            files: filesOf(input), correlationId: msgId, redacted: false, provenance,
          });
        } else if (part["type"] === "reasoning" || part["type"] === "text") {
          const partType = String(part["type"]);
          events.push({
            sessionId, eventId: `${msgId}:${partType}:${seq}`, seq, tsMs: msgTs,
            category: "message", status: "completed", agent, model, parentSessionId,
            toolName: null, normalizedArgs: null, argsSignature: hashSignature(partType),
            resultExcerpt: excerpt(redactUnknown(part["text"]).value)?.slice(0, 500) ?? null,
            errorSignature: null, durationMs: null, tokens: null, costUsd: null,
            files: [], correlationId: msgId, redacted: false, provenance,
          });
        } else {
          warnings.push(`unknown content type ${(part as Record<string, unknown>)["type"]} in ${msgId} (preserved as unknown)`);
          events.push({
            sessionId, eventId: `${msgId}:part:${seq}`, seq, tsMs: msgTs,
            category: "unknown", status: "unknown", agent, model, parentSessionId,
            toolName: null, normalizedArgs: part, argsSignature: hashSignature(canonicalize(part)),
            resultExcerpt: excerpt(part)?.slice(0, 500) ?? null,
            errorSignature: null, durationMs: null, tokens: null, costUsd: null,
            files: [], correlationId: msgId, redacted: false, provenance,
          });
        }
      }
      // Message-level token/cost event (measured totals — never split per tool).
      seq += 1;
      events.push({
        sessionId, eventId: `${msgId}:usage`, seq,
        tsMs: typeof mt?.completed === "number" ? mt.completed : msgTs,
        category: "message", status: "completed", agent, model, parentSessionId,
        toolName: null, normalizedArgs: null, argsSignature: hashSignature(`usage:${msgId}`),
        resultExcerpt: typeof rec["finish"] === "string" ? `finish=${rec["finish"]}` : null,
        errorSignature: null, durationMs: durationOf(mt as never),
        tokens, costUsd: cost, files: [], correlationId: msgId, redacted: false, provenance,
      });
      continue;
    }
    seq += 1;
    const mtype = (rec as Record<string, unknown>)["type"];
    if (mtype === "shell") {
      const t = rec["time"] as { created?: unknown; completed?: unknown } | undefined;
      const exit = typeof rec["exit"] === "number" ? rec["exit"] : null;
      const rawOutput = rec["output"] && typeof rec["output"] === "object"
        ? (rec["output"] as Record<string, unknown>)["output"] : rec["output"];
      const output = redactUnknown(rawOutput).value;
      const failed = exit !== null ? exit !== 0 : rec["status"] === "timeout" || rec["status"] === "killed";
      const args = { command: rec["command"] };
      events.push({
        sessionId, eventId: typeof rec["id"] === "string" ? rec["id"] : `msg-${seq}`, seq,
        tsMs: typeof t?.created === "number" ? t.created : null,
        category: "tool", status: failed ? "error" : rec["status"] === "running" ? "running" : "completed",
        agent: null, model: null, parentSessionId, toolName: "shell", normalizedArgs: args,
        argsSignature: hashSignature(`shell:${canonicalize(args)}`), resultExcerpt: excerpt(output),
        errorSignature: failed ? errorSignatureOf("error", { error: output }, output) : null,
        durationMs: durationOf(t), tokens: null, costUsd: null, files: filesOf(args),
        correlationId: typeof rec["shellID"] === "string" ? rec["shellID"] : `msg-${seq}`,
        redacted: false, provenance,
      });
      continue;
    }
    if (mtype === "synthetic" || mtype === "idle" || mtype === "system" || mtype === "compaction" || mtype === "agent-switched" || mtype === "model-switched" || mtype === "location-switched") {
      const t = (rec as Record<string, unknown>)["time"] as { created?: unknown } | undefined;
      events.push({
        sessionId, eventId: typeof rec["id"] === "string" ? rec["id"] : `msg-${seq}`, seq,
        tsMs: typeof t?.created === "number" ? t.created : null,
        category: "message", status: "completed", agent: null, model: null, parentSessionId,
        toolName: null, normalizedArgs: null, argsSignature: hashSignature(`lifecycle:${String(mtype)}`),
        resultExcerpt: excerpt((rec as Record<string, unknown>)["text"])?.slice(0, 300) ?? `lifecycle:${String(mtype)}`,
        errorSignature: null, durationMs: null,
        tokens: null, costUsd: null, files: [], correlationId: typeof rec["id"] === "string" ? rec["id"] : `msg-${seq}`,
        redacted: false, provenance,
      });
      continue;
    }
    warnings.push(`unknown message type ${mtype} (preserved as unknown)`);
    events.push({
      sessionId, eventId: typeof rec["id"] === "string" ? rec["id"] : `msg-${seq}`, seq, tsMs: null,
      category: "unknown", status: "unknown", agent: null, model: null, parentSessionId,
      toolName: null, normalizedArgs: rec, argsSignature: hashSignature(canonicalize(rec)),
      resultExcerpt: excerpt(rec)?.slice(0, 500) ?? null, errorSignature: null, durationMs: null,
      tokens: null, costUsd: null, files: [], correlationId: typeof rec["id"] === "string" ? rec["id"] : `msg-${seq}`,
      redacted: false, provenance,
    });
  }

  const toolCount = events.filter((e) => e.category === "tool").length;
  const errorCount = events.filter((e) => e.status === "error").length;
  const times = events.map((e) => e.tsMs).filter((t): t is number => typeof t === "number");
  const startedMs = times.length ? Math.min(...times) : null;
  const endedMs = times.length ? Math.max(...times) : null;
  return {
    sessionId, title: info.title ?? "", agent: typeof info.agent === "string" ? info.agent : null,
    model: modelLabel(info.model), parentSessionId, projectId: typeof info.projectID === "string" ? info.projectID : null,
    startedMs, endedMs, durationMs: startedMs !== null && endedMs !== null ? endedMs - startedMs : null,
    totalTokens: toTokens(info.tokens as never), totalCostUsd: typeof info.cost === "number" ? info.cost : null,
    eventCount: events.length, toolCount, errorCount, events, warnings, provenance,
  };
}
