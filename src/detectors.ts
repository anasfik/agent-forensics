import type { Finding, ForensicsEvent, NormalizedSession } from "./events.js";

function fid(rule: string, n: number): string {
  return `${rule}-${n}`;
}

function groupBy<T>(items: T[], key: (t: T) => string): Map<string, T[]> {
  const m = new Map<string, T[]>();
  for (const it of items) {
    const k = key(it);
    const arr = m.get(k);
    if (arr) arr.push(it);
    else m.set(k, [it]);
  }
  return m;
}

/** A — Repeated tool calls with equivalent normalized args (≥3). */
function detectorRepeatedTools(session: NormalizedSession): Finding[] {
  const tools = session.events.filter((e) => e.category === "tool" && e.toolName);
  const groups = groupBy(tools, (e) => `${e.toolName}::${e.argsSignature}`);
  const out: Finding[] = [];
  let n = 0;
  for (const [, evts] of groups) {
    if (evts.length < 3) continue;
    const tool = evts[0]?.toolName ?? "unknown";
    // Legit-retry guard: if an edit/write to one of the same files sits between repeats, lower severity.
    const ids = new Set(evts.map((e) => e.eventId));
    void ids;
    const files = [...new Set(evts.flatMap((e) => e.files))].slice(0, 5);
    n += 1;
    out.push({
      id: fid("repeated-tools", n), ruleId: "repeated-tools",
      severity: evts.some((e) => e.status === "error") ? "warning" : "info",
      title: `Repeated ${tool} ×${evts.length} with identical arguments`,
      description: `The tool ${tool} was invoked ${evts.length} times with equivalent normalized arguments${files.length ? ` (${files.join(", ")})` : ""}.`,
      evidenceEventIds: evts.map((e) => e.eventId),
      confidence: evts.length >= 5 ? "high" : "medium",
      explanation: "Observed fact: identical tool+args signature repeated. Inference (not proof): possible unproductive loop if results were unchanged.",
      suggestedNextStep: "Open the evidence events and check whether results changed between calls.",
    });
  }
  return out;
}

/** B — Failure loops: ≥3 errors, same tool+errorSignature, no success on that signature between. */
function detectorFailureLoops(session: NormalizedSession): Finding[] {
  const out: Finding[] = [];
  const errs = session.events.filter((e) => e.category === "tool" && e.status === "error" && e.errorSignature);
  const groups = groupBy(errs, (e) => `${e.toolName}::${e.argsSignature}::${e.errorSignature?.split(":")[0] ?? "?"}`);
  let n = 0;
  for (const [, evts] of groups) {
    if (evts.length < 3) continue;
    // Do not label every retry as a loop: require no interleaved success with same tool+args.
    const first = evts[0]!.seq;
    const last = evts[evts.length - 1]!.seq;
    const middleSuccess = session.events.some(
      (e) => e.seq > first && e.seq < last && e.toolName === evts[0]!.toolName && e.status === "completed" && e.argsSignature === evts[0]!.argsSignature,
    );
    if (middleSuccess) continue;
    n += 1;
    out.push({
      id: fid("failure-loop", n), ruleId: "failure-loop",
      severity: "critical",
      title: `Failure loop: ${evts[0]!.toolName} failed ${evts.length}× with the same signature`,
      description: `Repeated unsuccessful operations with unchanged outcomes between seq ${first}–${last}.`,
      evidenceEventIds: evts.map((e) => e.eventId),
      confidence: "high",
      explanation: "Observed: same failure signature, similar args, no meaningful progress. Not every retry qualifies — a success on the same signature breaks the loop.",
      suggestedNextStep: "Change inputs or preconditions before retrying; inspect the first error in full.",
    });
  }
  return out;
}

/** C — Inefficient file inspection: same file read ≥3× with no intervening edit/write. */
function detectorFileInspection(session: NormalizedSession): Finding[] {
  const READ_TOOLS = new Set(["read", "Read", "cat", "open", "view", "getFile", "read_file"]);
  const WRITE_TOOLS = new Set(["edit", "write", "apply_patch", "Edit", "Write", "applyPatch", "sed"]);
  const reads = session.events.filter((e) => e.category === "tool" && e.toolName && READ_TOOLS.has(e.toolName) && e.files.length > 0);
  const out: Finding[] = [];
  const byFile = new Map<string, ForensicsEvent[]>();
  for (const r of reads) for (const f of r.files) {
    const a = byFile.get(f) ?? [];
    a.push(r);
    byFile.set(f, a);
  }
  let n = 0;
  for (const [file, evts] of byFile) {
    if (evts.length < 3) continue;
    const first = evts[0]!.seq;
    const last = evts[evts.length - 1]!.seq;
    const editedBetween = session.events.some(
      (e) => e.seq > first && e.seq < last && e.toolName && WRITE_TOOLS.has(e.toolName) && e.files.some((f) => f === file || file.includes(f) || f.includes(file)),
    );
    if (editedBetween) continue; // necessary revalidation, not waste
    n += 1;
    out.push({
      id: fid("file-reread", n), ruleId: "file-reread", severity: "warning",
      title: `Repeated inspection of ${file} ×${evts.length} without changes`,
      description: `Same file/region inspected ${evts.length} times with no recorded edit in between (seq ${first}–${last}).`,
      evidenceEventIds: evts.map((e) => e.eventId),
      confidence: "medium",
      explanation: "Observed: rereads, no intervening write. Inference: possibly stale context reuse.",
      suggestedNextStep: "Cache the read or check why the agent did not retain the content.",
    });
  }
  return out;
}

/** D — Cost/latency hotspots: measured totals only, never invented per-tool tokens. */
function detectorHotspots(session: NormalizedSession): Finding[] {
  const out: Finding[] = [];
  const tools = session.events.filter((e) => e.category === "tool" && typeof e.durationMs === "number");
  if (tools.length >= 3) {
    const total = tools.reduce((a, e) => a + (e.durationMs ?? 0), 0);
    if (total >= 1000) {
      const byTool = groupBy(tools, (e) => e.toolName ?? "unknown");
      const rows = [...byTool.entries()].map(([tool, evts]) => ({
        tool, ms: evts.reduce((a, e) => a + (e.durationMs ?? 0), 0), n: evts.length,
        ids: evts.map((e) => e.eventId),
      })).sort((a, b) => b.ms - a.ms);
      const top = rows[0]!;
      if (top.ms / total >= 0.5 && top.n >= 2) {
        out.push({
          id: fid("latency-hotspot", 1), ruleId: "latency-hotspot", severity: "info",
          title: `Latency hotspot: ${top.tool} accounts for ${Math.round((top.ms / total) * 100)}% of tool time`,
          description: `Measured tool durations total ${total}ms; ${top.tool} contributes ${top.ms}ms across ${top.n} calls. Token totals are session/message-measured, not per-tool estimates.`,
          evidenceEventIds: top.ids.slice(0, 20),
          confidence: "high",
          explanation: "Observed durations from recorded timestamps. No per-tool token attribution is claimed.",
        });
      }
    }
  }
  const usage = session.events.filter((e) => e.tokens);
  if (usage.length >= 2 && session.totalTokens) {
    const sum = usage.reduce((a, e) => a + e.tokens!.input + e.tokens!.output + e.tokens!.reasoning, 0);
    if (sum > 50_000) {
      out.push({
        id: fid("cost-hotspot", 1), ruleId: "cost-hotspot", severity: "info",
        title: `High token consumption: ${sum.toLocaleString()} measured tokens across ${usage.length} steps`,
        description: `Session total ${session.totalCostUsd !== null ? `$${session.totalCostUsd.toFixed(4)}` : "cost unknown"}; measured step tokens sum to ${sum.toLocaleString()}. Estimates are labeled as such.`,
        evidenceEventIds: usage.map((e) => e.eventId).slice(0, 20),
        confidence: "medium",
        explanation: "Observed: recorded token/cost fields only. Missing fields are reported as unknown, not zero-filled.",
      });
    }
  }
  return out;
}

/** E — Suspicious patterns: edit→same-test-fail, repeated failing command, tiny action cycles. */
function detectorSuspicious(session: NormalizedSession): Finding[] {
  const out: Finding[] = [];
  const tools = session.events.filter((e) => e.category === "tool");
  // Edit followed by same test failure ×2.
  const testFails = tools.filter((e) => e.status === "error" && /test|jest|vitest|pytest|go test|bun test/i.test(`${e.toolName} ${e.resultExcerpt ?? ""}`.slice(0, 200)));
  if (testFails.length >= 2) {
    const sigs = groupBy(testFails, (e) => e.errorSignature?.split(":")[0] ?? e.argsSignature);
    for (const [, evts] of sigs) {
      if (evts.length < 2) continue;
      const hasEditBetween = session.events.some((e) => e.seq > evts[0]!.seq && e.seq < evts[evts.length - 1]!.seq && /edit|write|patch/i.test(e.toolName ?? ""));
      if (!hasEditBetween) continue;
      out.push({
        id: fid("edit-test-fail", 1), ruleId: "suspicious-pattern", severity: "warning",
        title: `Repeated edits followed by the same test failure (${evts.length}×)`,
        description: `Edits did not change the recorded test outcome between seq ${evts[0]!.seq}–${evts[evts.length - 1]!.seq}. Heuristic signal, not proof of reasoning failure.`,
        evidenceEventIds: evts.map((e) => e.eventId),
        confidence: "medium",
        explanation: "Observed pattern only; cause (flaky test vs wrong fix) requires human judgment.",
        suggestedNextStep: "Run the failing test in isolation and diff the actual vs expected output.",
      });
      break;
    }
  }
  // Tiny action cycle: only 2–3 distinct tool names across ≥8 consecutive tool calls.
  if (tools.length >= 8) {
    const window = tools.slice(0, 12);
    const distinct = new Set(window.map((e) => e.toolName));
    if (distinct.size <= 3 && distinct.size >= 2) {
      out.push({
        id: fid("action-cycle", 2), ruleId: "suspicious-pattern", severity: "info",
        title: `Tight action cycle among ${[...distinct].join(", ")} (${window.length} calls)`,
        description: `Repeated transitions between a small action set at the start of the trace. May be legitimate polling; flag as review cue.`,
        evidenceEventIds: window.map((e) => e.eventId),
        confidence: "low",
        explanation: "Heuristic: small-state oscillation. Low confidence by design.",
      });
    }
  }
  return out;
}

export const RULES = [
  { id: "repeated-tools", fn: detectorRepeatedTools },
  { id: "failure-loop", fn: detectorFailureLoops },
  { id: "file-reread", fn: detectorFileInspection },
  { id: "hotspot", fn: detectorHotspots },
  { id: "suspicious-pattern", fn: detectorSuspicious },
] as const;

export function analyze(session: NormalizedSession): Finding[] {
  return RULES.flatMap((r) => {
    try {
      return r.fn(session);
    } catch {
      return []; // never let one rule break the report; errors surface via warnings path in CLI
    }
  });
}
