import { hashSignature, type ForensicsEvent, type NormalizedSession } from "./events.js";

// Deterministic alignment on signatures (not indices) so similar ops match
// even when event positions differ. O(n*m) DP with a ceiling; long traces
// fall back to hashed-block matching.
// ponytail: O(n*m) DP, Hirschberg/divide-and-conquer if traces >2k routinely matter.

export interface AlignedPair { a: ForensicsEvent | null; b: ForensicsEvent | null; score: number }
export interface CompareReport {
  aId: string; bId: string;
  aEvents: number; bEvents: number;
  matches: number; uniqueA: number; uniqueB: number;
  firstDivergence: { aSeq: number | null; bSeq: number | null; aEventId: string | null; bEventId: string | null } | null;
  uniqueAEventIds: string[]; uniqueBEventIds: string[];
  tokenDelta: { a: number | null; b: number | null; delta: number | null };
  durationDeltaMs: { a: number | null; b: number | null; delta: number | null };
  outcomeDelta: { aErrors: number; bErrors: number };
  alignment: AlignedPair[];
}

export function eventSignature(e: ForensicsEvent): string {
  if (e.category === "tool") return `tool:${e.toolName}:${e.argsSignature}:${e.status}:${e.errorSignature ?? hashSignature(e.resultExcerpt ?? "")}`;
  if (e.category === "message" && e.resultExcerpt?.startsWith("finish=")) return `usage:${e.resultExcerpt}`;
  return `${e.category}:${e.argsSignature}`;
}

function tokenSum(s: NormalizedSession): number | null {
  if (!s.totalTokens) {
    const steps = s.events.filter((e) => e.tokens);
    if (!steps.length) return null;
    return steps.reduce((x, e) => x + e.tokens!.input + e.tokens!.output + e.tokens!.reasoning, 0);
  }
  const t = s.totalTokens;
  return t.input + t.output + t.reasoning;
}

export function compare(a: NormalizedSession, b: NormalizedSession): CompareReport {
  const A = a.events.filter((e) => e.category === "tool" || e.category === "message");
  const B = b.events.filter((e) => e.category === "tool" || e.category === "message");
  const sigA = A.map(eventSignature);
  const sigB = B.map(eventSignature);
  const n = sigA.length;
  const m = sigB.length;

  let alignment: AlignedPair[];
  if (n * m > 4_000_000) {
    // Ceiling fallback: greedy hash join preserves determinism without huge DP.
    const indexB = new Map<string, number[]>();
    sigB.forEach((s, j) => {
      const arr = indexB.get(s) ?? [];
      arr.push(j);
      indexB.set(s, arr);
    });
    const usedB = new Set<number>();
    let after = -1;
    alignment = [];
    for (let i = 0; i < n; i++) {
      const cand = (indexB.get(sigA[i]!) ?? []).find((j) => !usedB.has(j) && j > after);
      if (cand !== undefined) {
        usedB.add(cand);
        after = cand;
        alignment.push({ a: A[i]!, b: B[cand]!, score: 1 });
      } else {
        alignment.push({ a: A[i]!, b: null, score: 0 });
      }
    }
    sigB.forEach((_, j) => {
      if (!usedB.has(j)) alignment.push({ a: null, b: B[j]!, score: 0 });
    });
  } else {
    // LCS DP on exact signature equality.
    const dp: number[][] = Array.from({ length: n + 1 }, () => new Array<number>(m + 1).fill(0));
    for (let i = n - 1; i >= 0; i--) {
      for (let j = m - 1; j >= 0; j--) {
        dp[i]![j] = sigA[i] === sigB[j] ? (dp[i + 1]![j + 1]! + 1) : Math.max(dp[i + 1]![j]!, dp[i]![j + 1]!);
      }
    }
    alignment = [];
    let i = 0;
    let j = 0;
    while (i < n && j < m) {
      if (sigA[i] === sigB[j]) {
        alignment.push({ a: A[i]!, b: B[j]!, score: 1 });
        i++; j++;
      } else if (dp[i + 1]![j]! >= dp[i]![j + 1]!) {
        alignment.push({ a: A[i]!, b: null, score: 0 });
        i++;
      } else {
        alignment.push({ a: null, b: B[j]!, score: 0 });
        j++;
      }
    }
    while (i < n) { alignment.push({ a: A[i]!, b: null, score: 0 }); i++; }
    while (j < m) { alignment.push({ a: null, b: B[j]!, score: 0 }); j++; }
  }

  // First significant divergence: first non-exact point, reported two-sided —
  // the first unmatched event on EACH side at/after that point.
  let firstDivergence: CompareReport["firstDivergence"] = null;
  const divIdx = alignment.findIndex((p) => p.score !== 1);
  if (divIdx !== -1) {
    const tail = alignment.slice(divIdx);
    const aSide = tail.find((p) => p.a && !p.b)?.a ?? tail.find((p) => p.a)?.a ?? null;
    const bSide = tail.find((p) => p.b && !p.a)?.b ?? tail.find((p) => p.b)?.b ?? null;
    firstDivergence = {
      aSeq: aSide?.seq ?? null, bSeq: bSide?.seq ?? null,
      aEventId: aSide?.eventId ?? null, bEventId: bSide?.eventId ?? null,
    };
  }

  const matches = alignment.filter((p) => p.score === 1).length;
  const uniqueAIds = alignment.filter((p) => p.a && !p.b).map((p) => p.a!.eventId);
  const uniqueBIds = alignment.filter((p) => p.b && !p.a).map((p) => p.b!.eventId);
  const ta = tokenSum(a);
  const tb = tokenSum(b);
  return {
    aId: a.sessionId, bId: b.sessionId, aEvents: A.length, bEvents: B.length,
    matches, uniqueA: uniqueAIds.length, uniqueB: uniqueBIds.length,
    firstDivergence, uniqueAEventIds: uniqueAIds.slice(0, 100), uniqueBEventIds: uniqueBIds.slice(0, 100),
    tokenDelta: { a: ta, b: tb, delta: ta !== null && tb !== null ? tb - ta : null },
    durationDeltaMs: {
      a: a.durationMs, b: b.durationMs,
      delta: a.durationMs !== null && b.durationMs !== null ? b.durationMs - a.durationMs : null,
    },
    outcomeDelta: {
      aErrors: a.events.filter((e) => e.status === "error").length,
      bErrors: b.events.filter((e) => e.status === "error").length,
    },
    alignment: alignment.slice(0, 2000),
  };
}
