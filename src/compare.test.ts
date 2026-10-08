import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { SessionExportSchema } from "./schemas.js";
import { normalizeExport } from "./normalize.js";
import { compare } from "./compare.js";

function load(name: string) {
  const raw = JSON.parse(readFileSync(`fixtures/${name}`, "utf8"));
  return normalizeExport(SessionExportSchema.parse(raw), { opencodeVersion: "test" });
}

describe("compare", () => {
  it("finds first divergence after common prefix", () => {
    const a = load("diverge-a.json");
    const b = load("diverge-b.json");
    const r = compare(a, b);
    expect(r.matches).toBeGreaterThanOrEqual(3);
    expect(r.firstDivergence).not.toBeNull();
    expect(r.uniqueA).toBeGreaterThanOrEqual(1);
    expect(r.uniqueB).toBeGreaterThanOrEqual(1);
  });
  it("identical sessions have no divergence", () => {
    const a = load("success.json");
    const r = compare(a, a);
    expect(r.firstDivergence).toBeNull();
    expect(r.uniqueA).toBe(0);
  });
  it("divergence names an event on both sides", () => {
    const r = compare(load("diverge-a.json"), load("diverge-b.json"));
    expect(r.firstDivergence?.aEventId).toBe("t4");
    expect(r.firstDivergence?.bEventId).toBe("t4");
  });
  it("detects changed output for the same operation", () => {
    const a = load("success.json");
    const b = structuredClone(a);
    b.sessionId = "ses_output_b";
    b.events.find((e) => e.eventId === "t4")!.resultExcerpt = "tests failed";
    expect(compare(a, b).firstDivergence).not.toBeNull();
  });
  it("preserves a later exact match instead of consuming it as similar", () => {
    const base = load("success.json");
    const reads = base.events.filter((e) => e.eventId === "t1" || e.eventId === "t2");
    const a = { ...base, sessionId: "a", events: reads, eventCount: 2 };
    const b = { ...base, sessionId: "b", events: [reads[1]!], eventCount: 1 };
    const r = compare(a, b);
    expect(r.matches).toBe(1);
    expect(r.uniqueAEventIds).toEqual(["t1"]);
  });
  it("large fallback remains order-sensitive", () => {
    const base = load("success.json");
    const template = base.events.find((e) => e.category === "tool")!;
    const events = Array.from({ length: 2001 }, (_, i) => ({ ...template, eventId: `e${i}`, seq: i, argsSignature: `a${i}`, resultExcerpt: `r${i}` }));
    const a = { ...base, sessionId: "large-a", events, eventCount: events.length };
    const bEvents = [...events].reverse();
    const b = { ...base, sessionId: "large-b", events: bEvents, eventCount: bEvents.length };
    const r = compare(a, b);
    expect(r.matches).toBeLessThanOrEqual(1);
    expect(r.firstDivergence).not.toBeNull();
  });
});
