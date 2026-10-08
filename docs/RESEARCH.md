# RESEARCH — Agent Forensics integration choices (2026-10-08)

Pinned: `opencode v2.0.25` live; npm `@opencode/client@2.0.26`; source HEAD `38840623` (dev, 2026-10-08).

## Decision: read-only export adapter (supported path)
- Use `opencode session export <ses_ID> --sanitize` (CLI) and `GET /api/experimental/session/{id}/export?sanitize=true` via `@opencode/client@2.0.26`.
- List via `GET /api/session` (`{data:[...],cursor}`); detail via export `{data:{info,messages}}`.
- Verified live fields: `info={agent,cost,id,location,model,parentID,projectID,time,title,tokens}`; assistant `content=[reasoning|tool]`; tool `state={status,input,output|content|error,metadata}` + `time={created,ran,completed}`; tokens `{input,output,reasoning,cache}` at message+session level only.
- Isolated behind `src/normalize.ts` + `src/schemas.ts` (zod, tolerant). Direct DB reads explicitly rejected (layout unstable: cf. `ericmjl/opencode-session-viewer` FS layout is stale).

## What existing tools do (sampled 2026-10-08)
- `ericmjl/opencode-session-viewer@5e3ed56`: copies raw message/part JSON to a single-file viewer. No provenance, no rules, no compare, silently skips malformed files.
- `schemaitat/opencode-otel-observability@31760e5`: OTLP→Prom/Loki/Tempo live stack. Rich spans but 24h retention, ref-parsed subagents, floating images — not reproducible forensics.
- `xrmghost-maintainer/opencode-telemetry@864c93d`: plugin→SQLite metrics (sizes only by default). Best history base, but static pricing, no baseline entity, no paired diff.
- Gap addressed: deterministic rules + first-divergence compare + redacted-only local store with provenance.

## Constraints
- No per-tool token attribution in source data — hotspots report measured message/session totals + tool durations only.
- No private chain-of-thought — `reasoning` parts treated as recorded text, not internal reasoning.
- `session.diff` is per-message file diff (`Snapshot.FileDiff`), not used in MVP (export covers evidence).
- GitHub code search was rate-limited during research; source cites are pinned file paths above, not search.
- Node 20 has no `node:sqlite` — MVP uses JSON file store (`data/sessions/*.json`, 0600) with identical interface; SQLite upgrade path kept.
- No Bun locally — Node+npm chosen; no React build — dependency-free static dashboard served by CLI.
