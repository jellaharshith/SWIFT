# SWIFT Security Scan Report — Edusphere-update

**Repository:** https://github.com/jellaharshith/Edusphere-update  
**Scan ID:** SCAN-130f4de7  
**Scan Date:** 2026-04-19  
**Scanner:** SWIFT v1.0 (Haiku triage → Sonnet analysis, 95% confidence gate)  
**Duration:** 57.2 seconds  
**Files Scanned:** 4 flagged (from 117 total source files: 100 tsx, 14 ts, 2 js)

---

## Executive Summary

| Metric | Value |
|--------|-------|
| Total vulnerabilities (≥95% confidence) | **1** |
| Critical | 0 |
| High | **1** |
| Medium | 0 |
| Low | 0 |
| Patches generated | 1 |

---

## Confirmed Vulnerabilities

### SWIFT-001 — Cross-Site Scripting (XSS) [HIGH]

| Field | Value |
|-------|-------|
| **ID** | SWIFT-001 |
| **Severity** | HIGH |
| **Confidence** | 95% |
| **File** | `src/components/ai/AIChatMessages.tsx` |
| **Line** | 58 |
| **Type** | XSS via `dangerouslySetInnerHTML` |

**Description:**  
Unsanitized AI/user-controlled content is rendered as raw HTML via `dangerouslySetInnerHTML`. The `formatMarkdown` function transforms `msg.content` (sourced from the AI chat response) into HTML using regex replacements, then injects it directly into the DOM without sanitization. An attacker who can influence the AI output (e.g., via prompt injection) could inject HTML such as `**<img src=x onerror=alert(document.cookie)>**` which passes through the markdown regex and executes as JavaScript in the victim's browser.

**Vulnerable Code:**
```tsx
dangerouslySetInnerHTML={{ __html: formatMarkdown(msg.content) }}
```

**Attack Vector:**
1. Attacker crafts a message to the AI chat endpoint that causes the AI to respond with malicious HTML/JS embedded in markdown.
2. The response is stored/displayed via `AIChatMessages.tsx`.
3. The `dangerouslySetInnerHTML` renders the payload, executing attacker JS in the victim's browser.
4. Attacker can steal session tokens, cookies, or perform actions as the victim.

**Patch (PATCH-001):**
```diff
--- a/src/components/ai/AIChatMessages.tsx
+++ b/src/components/ai/AIChatMessages.tsx
-dangerouslySetInnerHTML={{ __html: formatMarkdown(msg.content) }}
+dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(formatMarkdown(msg.content)) }}
```

**Remediation Steps:**
1. Install DOMPurify: `npm install dompurify @types/dompurify`
2. Import at top of file: `import DOMPurify from 'dompurify';`
3. Apply `DOMPurify.sanitize()` around all `dangerouslySetInnerHTML` usages
4. Consider switching to a proper Markdown renderer like `react-markdown` with `rehype-sanitize`

**References:**
- [CWE-79: Cross-Site Scripting](https://cwe.mitre.org/data/definitions/79.html)
- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [DOMPurify](https://github.com/cure53/DOMPurify)

---

## Suppressed Findings (confidence < 95%)

These findings were detected but suppressed by the 95% confidence gate. Listed for awareness — not confirmed vulnerabilities.

| File | Lines | Pattern Matched | Confidence |
|------|-------|-----------------|------------|
| `supabase/functions/ai-chat/index.ts` | 26, 37, 40, 44, 78 | CORS wildcard + prompt injection context | 85% |
| `src/lib/ai.ts` | 50, 61, 65 | Prompt injection context building | 85% |
| `src/components/ui/chart.tsx` | 79 | Sonnet returned invalid JSON (parse error) | N/A |

**Note on `supabase/functions/ai-chat/index.ts`:** Although below the 95% gate, this file warrants manual review for:
- `Access-Control-Allow-Origin: "*"` on the edge function (allows any origin)
- Raw error messages returned to clients (`{ error: (err as Error).message }`)
- No input validation on `messages`, `userProfile`, `listings` from `req.json()`

---

## SWIFT Pipeline Execution Log

```
Phase 1 — Regex Triage (zero cost):
  4 files flagged from 117 scanned
  Flagged: AIChatMessages.tsx, ai-chat/index.ts, chart.tsx, ai.ts

Phase 2 — Haiku Fast Scan (~$0.05/file):
  4/4 files confirmed suspicious by Haiku
  Model: claude-haiku-4-5-20251001

Phase 3 — Sonnet Deep Analysis (95% gate):
  Analyzed ~12 locations across 4 files
  Suppressed: 8 findings (confidence 0.85 < threshold 0.95)
  Confirmed: 1 finding (SWIFT-001, confidence 0.95)
  Model: claude-sonnet-4-6

Phase 4 — Patch Generation:
  Generated: PATCH-001 for SWIFT-001
  Sandbox: FAILED (Docker not available — patch untested)
```

---

## Recommendations

### Immediate (High Priority)
1. **Fix SWIFT-001**: Add `DOMPurify.sanitize()` in `AIChatMessages.tsx` before merging any AI-rendered content to DOM.

### Short Term (Manual Review Warranted)
2. **CORS policy**: Restrict `Access-Control-Allow-Origin` in `supabase/functions/ai-chat/index.ts` to known origins only.
3. **Error leakage**: Avoid returning raw `err.message`/`err.stack` to clients. Log server-side, return generic messages.
4. **Input validation**: Validate and sanitize `messages`, `userProfile`, `listings` in the edge function before processing.
5. **Rate limiting**: Add rate limiting to the AI chat edge function to prevent abuse.

### Long Term
6. **Markdown rendering**: Replace custom `formatMarkdown` regex with `react-markdown` + `rehype-sanitize` for safe, spec-compliant rendering.
7. **Content Security Policy**: Add a strict CSP header to limit what scripts can execute in the browser.

---

## Scan Artifacts

| File | Description |
|------|-------------|
| `docs/edusphere_scan.json` | Full machine-readable scan results (JSON) |
| `docs/edusphere_scan.md` | SWIFT-generated Markdown report |
| `docs/edusphere_security_report.md` | This document — detailed security analysis |

---

*Generated by SWIFT — AI-powered vulnerability scanner*  
*Pipeline: Regex triage → Claude Haiku (fast scan) → Claude Sonnet (95% confidence gate) → Patch generation*
