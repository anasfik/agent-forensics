import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { SessionExportSchema } from "./schemas.js";
import { normalizeExport } from "./normalize.js";
import { analyze } from "./detectors.js";

function load(name: string) {
  const raw = JSON.parse(readFileSync(`fixtures/${name}`, "utf8"));
  const parsed = SessionExportSchema.parse(raw);
  return normalizeExport(parsed, { opencodeVersion: "test" });
}

describe("detectors", () => {
  it("success fixture has no failure loop", () => {
    const s = load("success.json");
    const rules = analyze(s).map((f) => f.ruleId);
    expect(rules).not.toContain("failure-loop");
  });
  it("fail loop is critical with evidence", () => {
    const s = load("fail-loop.json");
    const f = analyze(s).filter((x) => x.ruleId === "failure-loop");
    expect(f.length).toBe(1);
    expect(f[0]!.severity).toBe("critical");
    expect(f[0]!.evidenceEventIds.length).toBeGreaterThanOrEqual(3);
  });
  it("reread flags, legit retry after edit does not", () => {
    const bad = analyze(load("reread.json")).map((f) => f.ruleId);
    expect(bad).toContain("file-reread");
    const good = analyze(load("legit-retry.json")).map((f) => f.ruleId);
    expect(good).not.toContain("file-reread");
  });
  it("missing tokens stays unknown, never crashes", () => {
    const s = load("missing-tokens.json");
    expect(s.totalTokens).toBeNull();
    expect(() => analyze(s)).not.toThrow();
  });
  it("is deterministic across consecutive analyses", () => {
    const s = load("fail-loop.json");
    expect(analyze(s)).toEqual(analyze(s));
  });
  it("does not merge the same error across different arguments", () => {
    const s = load("fail-loop.json");
    s.events.filter((e) => e.status === "error").forEach((e, i) => { e.argsSignature = `different-${i}`; });
    expect(analyze(s).some((f) => f.ruleId === "failure-loop")).toBe(false);
  });
});
