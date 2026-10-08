# Contributing

Keep it lazy: smallest tested diff, reuse stdlib, no new deps without a measured need.

- `npm ci && npm run typecheck && npm test -- --run`
- Add a fixture in `fixtures/` for every new rule/behavior (synthetic, clearly labeled).
- Boundary data validated with zod; missing stays `null`, never invented.
- Findings need `evidenceEventIds` + a test; heuristics stay `low` confidence by default.
- No `any`, no exec of imported content, redact before any sink.
