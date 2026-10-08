# Architecture

```
opencode (local service, read-only)
  |  `session export --sanitize` / GET /experimental/session/{id}/export?sanitize=true
  v
src/schemas.ts (zod boundary, tolerant; both {data:{...}} and {info,...} shapes)
  v
src/normalize.ts -> NormalizedSession + ForensicsEvent[] (seq, provenance; missing=null)
  v
src/redact.ts (in-memory, BEFORE store) -> src/store.ts (data/sessions/*.json, 0600, tmp+rename)
  v
src/detectors.ts (5 rule fns -> Finding[]) | src/compare.ts (signature LCS -> CompareReport)
  v
src/cli-run.ts (sessions/import/inspect/analyze/compare/export/ui) + apps/web/index.html (static, fetch /api/*)
```

Core (`events/normalize/detectors/compare/redact`) has zero OpenCode imports — new agent adapters only replace `schemas+normalize`. No LLM, no exec of imported content, no outbound calls. Limits: JSON file store (SQLite path reserved), O(n*m) compare with hashed-block fallback over 4M cells.
