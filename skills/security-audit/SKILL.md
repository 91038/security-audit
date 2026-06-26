---
name: security-audit
description: >-
  Perform a full security audit of a web/app development project and produce a
  clean, visual Korean PDF report. Use this skill whenever the user wants to
  check a codebase, website, or web app for security problems, vulnerabilities,
  or weaknesses — including phrases like "보안 점검", "취약점 점검/분석", "보안 검사",
  "security audit/review", "내 코드/사이트 안전한지 봐줘", "취약점 찾아줘", "보안 리포트 만들어줘".
  Especially relevant for "vibe-coded" apps built quickly with AI where auth,
  secrets, input validation, and access control are often weak. The skill does
  three things: (1) static code analysis of the dev folder, (2) dependency &
  config inspection, (3) live browser analysis of the running site (pages,
  network requests, headers, console, cookies), then compiles findings into a
  visual PDF report. Trigger this skill even if the user only mentions one part
  (e.g. "이 폴더 코드 보안 좀 봐줘" or "사이트 네트워크 취약점 분석해줘").
---

# Security Audit (보안 점검)

This skill runs an end-to-end security audit of a web project and produces a
clean, visual **Korean-language PDF report**. The audience is a developer —
often someone who built the app fast ("vibe coding") and wants to know what's
unsafe and how to fix it.

The goal is not to dump a raw scanner log. It is to **find real, prioritized
problems, explain them in plain Korean, and show concrete fixes** — then present
them in a report that is pleasant to read.

## Workflow overview

Run these phases in order. Each phase feeds findings into a single
`findings.json`, which the report generator turns into the final PDF.

1. **Scope & setup** — figure out what to audit and where.
2. **Static code analysis** — read the code, run the bundled scanners.
3. **Dependency & config inspection** — packages, secrets, security headers, infra config.
4. **Live browser analysis** — open the running site, inspect pages/network/console (optional but recommended).
5. **Compile findings** — write `findings.json`.
6. **Generate the PDF report** — run `scripts/build_report.py`.

Do not skip straight to the report. The report is only as good as the findings,
so spend your effort in phases 2–4.

### Runtime environments (Claude Code & Cowork)

This skill runs in both Claude Code and Cowork. Adapt to whatever tools are
actually available rather than assuming a specific environment:

- **Project location.** In Claude Code the project is usually the current
  working directory / repo. In Cowork it's the connected folder. Use whichever
  applies; if it's unclear which folder to audit, ask.
- **Scratch files.** Write `findings.json` and intermediate scanner output to a
  temp/scratch location (e.g. a `.security-audit/` dir in the repo, or the system
  temp dir) — not somewhere that pollutes the user's source tree or git history.
- **Live browser phase (Phase 4).** Use any available browser-automation MCP:
  Claude in Chrome (`mcp__Claude_in_Chrome__*`) in Cowork, or a Playwright /
  Chrome DevTools MCP in Claude Code. If none is connected, skip Phase 4 and tell
  the user how to enable it — static + dependency phases still produce a full report.
- **Delivering the report.** Save the PDF into the project (or an output dir) and
  give the user its path. If a file-presentation tool like `present_files` exists
  (Cowork), also present it; in Claude Code, just report the saved path.

---

## Phase 1 — Scope & setup

Confirm with the user (only if unclear):

- **Which folder** is the project? In Claude Code, default to the current repo /
  working directory. In Cowork, use the connected folder. Ask only if ambiguous.
- **Is there a running dev server** to inspect live (e.g. `http://localhost:3000`)? If yes, get the URL. If the live phase isn't possible (no server, no browser MCP), say so and do static + dependency phases only — the report still works.
- **What kind of app** is it (frontend SPA, full-stack, API, has a backend/DB)? This focuses the checks. If unsure, treat it as a general web app and run everything.

Pick a scratch location for `findings.json` and scanner output (e.g. a
`.security-audit/` dir in the repo or the system temp dir) so it doesn't clutter
the source tree.

---

## Phase 2 — Static code analysis

First run the bundled scanners — they're fast and catch the common, high-signal
issues that vibe-coded apps almost always have:

```bash
python3 scripts/scan_secrets.py <project_dir> --json > secrets.json
python3 scripts/scan_static.py  <project_dir> --json > static.json
```

`scan_secrets.py` finds hardcoded credentials (API keys, tokens, private keys,
DB connection strings, `.env` values committed to source).
`scan_static.py` finds dangerous code patterns (injection, XSS sinks, `eval`,
weak crypto, disabled TLS verification, overly-permissive CORS, etc.).

The scanners give you **leads, not conclusions**. For every hit, open the file
and read the surrounding code to confirm it's a real issue and not a false
positive (e.g. a key in a `.env.example` placeholder, or `dangerouslySetInnerHTML`
on trusted constant content). Only confirmed issues go in the report.

Then do a **manual read** of the security-critical areas that scanners miss.
Read `references/code-vulnerabilities.md` for the full checklist; the high-value
targets are authentication/session handling, authorization/access control
(can user A read user B's data?), server-side input validation, secrets
management, and any place user input reaches a database, shell, filesystem, or
HTML.

---

## Phase 3 — Dependency & config inspection

Read `references/dependency-config.md` for details. Key actions:

- **Dependencies:** if there's a `package.json`, run `npm audit --json` (and
  `pip-audit` / `requirements.txt` review for Python). Note critical/high CVEs.
- **Secrets in config:** check `.env`, `.env.local`, config files, and whether
  `.env` is git-ignored. Check if a `.git` folder exposes secret history.
- **Client-exposed secrets:** in frontend code, any secret not prefixed for
  public use (e.g. a non-`NEXT_PUBLIC_`/`VITE_` server key shipped to the
  browser) is a leak. Service-role / admin keys must never be in client code.
- **Backend/BaaS config:** if Supabase/Firebase, check Row Level Security / rules
  are enabled and not wide-open. If there's a server, check CORS, security
  headers (CSP, HSTS, X-Frame-Options), cookie flags (HttpOnly, Secure, SameSite).

---

## Phase 4 — Live browser analysis (recommended)

This phase inspects the **running** app — the things you can't see from code
alone. It needs a browser-automation MCP: Claude in Chrome
(`mcp__Claude_in_Chrome__*`) in Cowork, or a Playwright / Chrome DevTools MCP in
Claude Code. If no such tool is connected, tell the user how to enable one
(install the Chrome extension in Cowork, or add a browser MCP in Claude Code),
then continue without this phase — the report still works from phases 2–3.

The tool names below are written for Claude in Chrome; if you're using a
different browser MCP, map them to the equivalent calls (navigate, read network
requests, read console, read page).

Read `references/browser-audit.md` for the full procedure. In short, for each
significant page/route:

- `navigate` to it, then `read_network_requests` to inspect API calls — look for
  secrets in URLs/headers, sensitive data over plain HTTP, missing auth on
  endpoints, and responses that leak more data than the UI shows.
- `read_console_messages` for errors, leaked stack traces, mixed-content warnings.
- Check response headers for missing security headers and inspect cookies for
  missing HttpOnly/Secure/SameSite flags.
- Try accessing authenticated routes/objects without/with another user's session
  to probe access control (only do this on the user's own app).

Stay within the user's own application. Do not attack third-party sites.

---

## Phase 5 — Compile findings.json

Collect every confirmed issue into one JSON file. This is the single source of
truth for the report. Schema:

```json
{
  "project_name": "프로젝트 이름",
  "target": "/path/to/project 또는 http://localhost:3000",
  "scan_date": "2026-06-26",
  "auditor": "Claude 보안 점검",
  "summary": "2~4문장으로 전체 보안 상태를 요약. 가장 심각한 문제와 전반적 위험 수준 언급.",
  "findings": [
    {
      "id": "SEC-001",
      "title": "Supabase service_role 키가 프론트엔드 코드에 하드코딩됨",
      "severity": "critical",
      "category": "시크릿 노출",
      "location": "src/lib/supabase.js:8",
      "description": "관리자 권한을 가진 service_role 키가 클라이언트 번들에 포함되어 브라우저에서 누구나 확인 가능. 이 키로 RLS를 우회해 전체 DB 읽기/쓰기가 가능함.",
      "evidence": "const supabase = createClient(url, 'eyJhbGciOi...service_role...')",
      "impact": "공격자가 전체 데이터베이스를 읽고 수정/삭제할 수 있음. 개인정보 유출 및 데이터 파괴 위험.",
      "recommendation": "service_role 키를 코드에서 즉시 제거하고 키를 폐기/재발급. 클라이언트에는 anon 키만 사용하고, 관리자 작업은 서버(엣지 함수 등)에서만 처리. RLS 정책 활성화 확인.",
      "status": "발견"
    }
  ]
}
```

Field rules:

- **severity**: one of `critical`, `high`, `medium`, `low`, `info`. Be honest —
  reserve `critical` for issues that allow full data/account compromise. Rate by
  realistic impact × exploitability, not by how scary the keyword sounds.
- **category**: short Korean label, e.g. `인증/세션`, `접근제어`, `시크릿 노출`,
  `인젝션`, `XSS`, `의존성 취약점`, `보안 헤더/설정`, `정보 노출`.
- **location**: `file:line` for code issues, URL/endpoint for live issues.
- **evidence**: the real snippet, request, or header — short. This makes the
  report credible and actionable.
- **recommendation**: concrete and specific. Show the fix, not "use best
  practices". Where short, include the corrected code/config.
- **status**: `발견` (found, not fixed), `해결됨` (you fixed it during the
  audit), or `미해결` (acknowledged, left for the user). If the user asked you to
  also fix issues, fix the safe ones, set their status to `해결됨`, and briefly
  note what changed in `recommendation`.

Write all findings to `findings.json`, ordered most-severe first.

---

## Phase 6 — Generate the PDF report

```bash
python3 scripts/build_report.py findings.json --out "보안점검_보고서.pdf"
```

The script reads `findings.json` and produces a clean, visual Korean PDF:
a cover page with the overall risk grade, a severity-distribution chart, an
executive summary, a findings-by-severity overview, then a detail card for each
finding