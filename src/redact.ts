// In-memory redaction applied BEFORE any durable sink (store/log/export).
// Redacted-only by default; no raw vault in MVP.

export const REDACT_POLICY_VERSION = "v1";

interface Pattern { name: string; re: RegExp }

const PATTERNS: Pattern[] = [
  { name: "aws-key", re: /\bAKIA[0-9A-Z]{8,}\b/g },
  { name: "github-token", re: /\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{20,}\b/g },
  { name: "openai-key", re: /\bsk-(proj-)?[A-Za-z0-9_-]{20,}\b/g },
  { name: "anthropic-key", re: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/g },
  { name: "bearer", re: /\bBearer\s+[A-Za-z0-9\-._~+/=]{12,}\b/gi },
  { name: "private-key", re: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]{0,100000}?-----END [A-Z ]*PRIVATE KEY-----/g },
  { name: "password-url", re: /([a-zA-Z][a-zA-Z0-9+.-]*:\/\/[^/\s:@]+:)([^@\s/]{1,200})(@)/g },
  { name: "secret-assign", re: /\b(api[_-]?key|secret|token|password|passwd|pwd|auth)\b\s*[:=]\s*['"]?([^'"\s]{8,200})['"]?/gi },
];

const DEFAULT_SENSITIVE_PATHS = [/\.env(\.|$)/i, /id_rsa/i, /\.pem$/i, /secrets?\//i];

export interface RedactResult { text: string; hits: string[] }

export function redactText(input: string): RedactResult {
  let text = input;
  const hits: string[] = [];
  for (const p of PATTERNS) {
    p.re.lastIndex = 0;
    if (p.re.test(text)) {
      hits.push(p.name);
      p.re.lastIndex = 0;
      text = text.replace(p.re, (m) => {
        // Keep URL structure for password-url so forensics keeps meaning.
        if (p.name === "password-url") return m.replace(/(:)([^@\s/]{1,200})(@)/, "$1[REDACTED]$3");
        if (p.name === "secret-assign") return m.replace(/([:=]\s*['"]?)([^'"\s]{8,200})(['"]?)/, "$1[REDACTED]$3");
        return "[REDACTED]";
      });
    }
  }
  return { text, hits };
}

export function redactUnknown(value: unknown, depth = 0): { value: unknown; hits: string[] } {
  if (depth > 10) return { value: "[DEPTH-LIMIT]", hits: [] };
  if (typeof value === "string") {
    const r = redactText(value);
    return { value: r.text, hits: r.hits };
  }
  if (Array.isArray(value)) {
    const hits: string[] = [];
    const out = value.map((v) => {
      const r = redactUnknown(v, depth + 1);
      hits.push(...r.hits);
      return r.value;
    });
    return { value: out, hits: [...new Set(hits)] };
  }
  if (value && typeof value === "object") {
    const hits: string[] = [];
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      if (/^(authorization|cookie|set-cookie|x-api-key)$/i.test(k)) {
        hits.push(`header:${k}`);
        out[k] = "[REDACTED]";
        continue;
      }
      const r = redactUnknown(v, depth + 1);
      hits.push(...r.hits);
      out[k] = r.value;
    }
    return { value: out, hits: [...new Set(hits)] };
  }
  return { value, hits: [] };
}

export function isSensitivePath(p: string, extra: RegExp[] = []): boolean {
  return [...DEFAULT_SENSITIVE_PATHS, ...extra].some((re) => re.test(p));
}
