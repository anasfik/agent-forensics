// Normalized forensic event model. Missing data is explicit (null), never invented.
// Provenance lets every diagnostic trace back to source evidence.

export type EventCategory = "tool" | "message" | "compaction" | "system" | "unknown";
export type EventStatus = "pending" | "running" | "completed" | "error" | "unknown";

export interface TokenTotals {
  input: number;
  output: number;
  reasoning: number;
  cacheRead: number;
  cacheWrite: number;
}

export interface ForensicsEvent {
  sessionId: string;
  eventId: string;
  seq: number;
  tsMs: number | null;
  category: EventCategory;
  status: EventStatus;
  agent: string | null;
  model: string | null;
  parentSessionId: string | null;
  toolName: string | null;
  normalizedArgs: unknown;
  argsSignature: string;
  resultExcerpt: string | null;
  errorSignature: string | null;
  durationMs: number | null;
  tokens: TokenTotals | null;
  costUsd: number | null;
  files: string[];
  correlationId: string;
  redacted: boolean;
  provenance: {
    source: "opencode-export";
    opencodeVersion: string;
    exportedAt: string;
    sanitize: boolean;
  };
}

export interface NormalizedSession {
  sessionId: string;
  title: string;
  agent: string | null;
  model: string | null;
  parentSessionId: string | null;
  projectId: string | null;
  startedMs: number | null;
  endedMs: number | null;
  durationMs: number | null;
  totalTokens: TokenTotals | null;
  totalCostUsd: number | null;
  eventCount: number;
  toolCount: number;
  errorCount: number;
  events: ForensicsEvent[];
  warnings: string[];
  provenance: ForensicsEvent["provenance"];
}

export interface Finding {
  id: string;
  ruleId: string;
  severity: "info" | "warning" | "critical";
  title: string;
  description: string;
  evidenceEventIds: string[];
  confidence: "low" | "medium" | "high";
  explanation: string;
  suggestedNextStep?: string;
}

/** Stable canonicalization for argument equivalence (key-order independent). */
export function canonicalize(value: unknown, depth = 0): string {
  if (depth > 12) return '"<max-depth>"';
  if (value === null || value === undefined) return JSON.stringify(value);
  if (typeof value === "string") {
    const s = value.length > 4000 ? value.slice(0, 4000) + "…<truncated>" : value;
    return JSON.stringify(s);
  }
  if (typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map((v) => canonicalize(v, depth + 1)).join(",")}]`;
  const rec = value as Record<string, unknown>;
  const keys = Object.keys(rec).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalize(rec[k], depth + 1)}`).join(",")}}`;
}

export function hashSignature(s: string): string {
  // FNV-1a 32-bit: stdlib-only, deterministic, no crypto dep for signatures.
  let h = 0x811c9dc5;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return (h >>> 0).toString(16).padStart(8, "0");
}

export function toTokens(t: { input?: unknown; output?: unknown; reasoning?: unknown; cache?: unknown } | null | undefined): TokenTotals | null {
  if (!t || typeof t !== "object") return null;
  const num = (v: unknown) => (typeof v === "number" && Number.isFinite(v) ? v : null);
  const cache = (t.cache && typeof t.cache === "object" ? t.cache : {}) as Record<string, unknown>;
  const values = [num(t.input), num(t.output), num(t.reasoning), num(cache["read"]), num(cache["write"])];
  if (values.some((v) => v === null)) return null;
  const out: TokenTotals = {
    input: values[0]!, output: values[1]!, reasoning: values[2]!, cacheRead: values[3]!, cacheWrite: values[4]!,
  };
  return out;
}

export function modelLabel(m: unknown): string | null {
  if (!m) return null;
  if (typeof m === "string") return m;
  if (typeof m === "object") {
    const r = m as Record<string, unknown>;
    const pid = typeof r["providerID"] === "string" ? r["providerID"] : "";
    const id = typeof r["id"] === "string" ? r["id"] : JSON.stringify(m).slice(0, 80);
    return pid ? `${pid}/${id}` : id;
  }
  return null;
}
