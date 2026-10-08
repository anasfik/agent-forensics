import { describe, expect, it } from "vitest";
import { redactText, redactUnknown } from "./redact.js";
import { readFileSync } from "node:fs";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { SessionExportSchema } from "./schemas.js";
import { normalizeExport } from "./normalize.js";
import { saveSession } from "./store.js";
import { toTokens } from "./events.js";
import { terminalSafe } from "./cli-run.js";

describe("redact", () => {
  it("redacts github token and bearer", () => {
    const r = redactText("key ghp_1234567890abcdefghij and Bearer abcdefgh12345678");
    expect(r.text).not.toContain("ghp_");
    expect(r.hits.length).toBeGreaterThan(0);
  });
  it("no canary survives nested redact", () => {
    const raw = JSON.parse(readFileSync("fixtures/secrets.json", "utf8"));
    const s = normalizeExport(SessionExportSchema.parse(raw));
    const red = redactUnknown(s.events);
    expect(JSON.stringify(red.value)).not.toContain("CANARY");
  });
  it("malformed events are quarantined, not thrown", () => {
    const bad = { data: { info: { id: "ses_x" }, messages: [{ type: "weird", id: "m9" }] } };
    const parsed = SessionExportSchema.safeParse(bad);
    expect(parsed.success).toBe(true);
    const s = normalizeExport(parsed.data!);
    expect(s.warnings.length).toBeGreaterThan(0);
  });
  it("redacts every durable session field", async () => {
    const raw = JSON.parse(readFileSync("fixtures/secrets.json", "utf8"));
    const s = normalizeExport(SessionExportSchema.parse(raw));
    s.title = "Bearer CANARYTITLE123456789";
    s.events[1]!.errorSignature = "token=CANARYERROR123456789";
    s.events[1]!.files = [".env.production"];
    const dir = await mkdtemp(join(tmpdir(), "af-redact-"));
    try {
      const file = await saveSession(s, { dataDir: dir, sourceLabel: "token=CANARYSOURCE123456789" });
      const bytes = await readFile(file, "utf8");
      expect(bytes).not.toContain("CANARY");
      expect(bytes).toContain("[REDACTED_PATH]");
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
  it("redacts long private keys and structured tool output", async () => {
    const pem = `-----BEGIN PRIVATE KEY-----\n${"A".repeat(2000)}\n-----END PRIVATE KEY-----`;
    expect(redactText(pem).text).toBe("[REDACTED]");
    const raw = { data: { info: { id: "ses_struct" }, messages: [{ type: "assistant", id: "m", content: [{ type: "tool", id: "t", name: "x", state: { status: "completed", input: {}, output: { authorization: "CANARY-SHORT", cookie: "CANARY-COOKIE" } } }] }] } };
    const s = normalizeExport(SessionExportSchema.parse(raw));
    const dir = await mkdtemp(join(tmpdir(), "af-struct-"));
    try {
      const file = await saveSession(s, { dataDir: dir });
      expect(await readFile(file, "utf8")).not.toContain("CANARY");
    } finally { await rm(dir, { recursive: true, force: true }); }
  });
  it("keeps complete zero tokens but rejects partial totals", () => {
    expect(toTokens({ input: 1 })).toBeNull();
    expect(toTokens({ input: 0, output: 0, reasoning: 0, cache: { read: 0, write: 0 } })).not.toBeNull();
  });
  it("preserves arrays and strips terminal control bytes", () => {
    const values = Array.from({ length: 501 }, (_, i) => i);
    expect((redactUnknown(values).value as unknown[]).length).toBe(501);
    expect(terminalSafe("ok\u001b]52;c;evil\u0007done")).not.toMatch(/[\u001b\u0007]/);
  });
  it("does not alias colliding-looking session IDs", async () => {
    const base = normalizeExport(SessionExportSchema.parse({ data: { info: { id: "ses/target" }, messages: [] } }));
    const other = { ...base, sessionId: "ses?target" };
    const dir = await mkdtemp(join(tmpdir(), "af-ids-"));
    try {
      const a = await saveSession(base, { dataDir: dir });
      const b = await saveSession(other, { dataDir: dir });
      expect(a).not.toBe(b);
      expect(await readFile(a, "utf8")).toContain("ses/target");
      expect(await readFile(b, "utf8")).toContain("ses?target");
    } finally { await rm(dir, { recursive: true, force: true }); }
  });
  it("normalizes current text, shell, and switch variants without warnings", () => {
    const raw = { data: { info: { id: "ses_v2" }, messages: [
      { type: "assistant", id: "m1", content: [{ type: "text", text: "done" }] },
      { type: "shell", id: "m2", shellID: "sh1", command: "npm test", status: "exited", exit: 1, output: { output: "failed", cursor: 0, size: 6, truncated: false }, time: { created: 1, completed: 2 } },
      { type: "agent-switched", id: "m3", agent: "build", time: { created: 3 } },
    ] } };
    const s = normalizeExport(SessionExportSchema.parse(raw));
    expect(s.warnings).toEqual([]);
    expect(s.events.some((e) => e.toolName === "shell" && e.status === "error")).toBe(true);
    expect(s.events.some((e) => e.resultExcerpt === "done")).toBe(true);
  });
});
