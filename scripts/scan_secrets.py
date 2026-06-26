#!/usr/bin/env python3
"""
scan_secrets.py — 하드코딩된 시크릿/자격증명 스캐너.

소스 폴더를 훑어 API 키, 토큰, 개인키, DB 접속 문자열 등이 코드에 직접 적혀
있는 곳을 찾는다. 결과는 '리드(lead)'다 — 반드시 해당 파일을 열어 진짜
시크릿인지(예: .env.example 의 자리표시자가 아닌지) 확인한 뒤 보고한다.

사용법:
    python3 scan_secrets.py <dir> [--json]
"""
import argparse, json, os, re, sys

SKIP_DIRS = {".git", "node_modules", "dist", "build", ".next", "out",
             "venv", ".venv", "__pycache__", ".cache", "coverage",
             "vendor", ".idea", ".vscode"}
SKIP_EXT = {".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
            ".pdf", ".zip", ".gz", ".lock", ".map", ".woff", ".woff2",
            ".ttf", ".otf", ".mp4", ".mp3", ".min.js", ".min.css"}
MAX_BYTES = 1_500_000

# (이름, 정규식, 심각도, 카테고리)
PATTERNS = [
    ("AWS Access Key", r"AKIA[0-9A-Z]{16}", "critical", "시크릿 노출"),
    ("AWS Secret Key", r"(?i)aws_secret_access_key\s*[:=]\s*['\"][A-Za-z0-9/+=]{40}['\"]", "critical", "시크릿 노출"),
    ("Private Key Block", r"-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----", "critical", "시크릿 노출"),
    ("Google API Key", r"AIza[0-9A-Za-z\-_]{35}", "high", "시크릿 노출"),
    ("Slack Token", r"xox[baprs]-[0-9A-Za-z-]{10,}", "high", "시크릿 노출"),
    ("Stripe Secret Key", r"sk_live_[0-9a-zA-Z]{20,}", "critical", "시크릿 노출"),
    ("Stripe Restricted Key", r"rk_live_[0-9a-zA-Z]{20,}", "high", "시크릿 노출"),
    ("GitHub Token", r"gh[pousr]_[0-9A-Za-z]{30,}", "high", "시크릿 노출"),
    ("OpenAI/Anthropic Key", r"sk-(ant-)?[A-Za-z0-9\-_]{20,}", "high", "시크릿 노출"),
    ("JWT (service_role?)", r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", "high", "시크릿 노출"),
    ("Supabase service_role", r"(?i)service_role", "high", "시크릿 노출"),
    ("Generic API key assign", r"(?i)(api[_-]?key|apikey|secret[_-]?key|access[_-]?token|auth[_-]?token)\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,}['\"]", "medium", "시크릿 노출"),
    ("Password assign", r"(?i)(password|passwd|pwd|db_pass)\s*[:=]\s*['\"][^'\"\s]{6,}['\"]", "medium", "시크릿 노출"),
    ("DB connection URL", r"(?i)(postgres|postgresql|mysql|mongodb(\+srv)?|redis|amqp)://[^\s'\"]*:[^\s'\"]*@", "high", "시크릿 노출"),
    ("Private key file ref", r"(?i)(private[_-]?key|id_rsa)", "low", "시크릿 노출"),
]

# 자리표시자/예시로 보이는 값은 노이즈로 강등
PLACEHOLDER = re.compile(r"(?i)(your[_-]?|example|placeholder|changeme|xxxx|<.*>|\$\{|process\.env|import\.meta\.env|dummy|sample|test[_-]?key|foo|bar|123456)")

def is_text(path):
    try:
        with open(path, "rb") as f:
            chunk = f.read(2048)
        if b"\x00" in chunk:
            return False
        return True
    except Exception:
        return False

def scan_file(path, rel):
    out = []
    try:
        if os.path.getsize(path) > MAX_BYTES:
            return out
    except OSError:
        return out
    if not is_text(path):
        return out
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except Exception:
        return out
    is_example = bool(re.search(r"\.example$|\.sample$|\.template$", rel)) or "example" in os.path.basename(rel).lower()
    for i, line in enumerate(lines, 1):
        if len(line) > 600:
            continue
        for name, pat, sev, cat in PATTERNS:
            if re.search(pat, line):
                snippet = line.strip()
                placeholder = bool(PLACEHOLDER.search(snippet)) or is_example
                eff_sev = "info" if placeholder else sev
                out.append({
                    "type": name, "severity": eff_sev, "category": cat,
                    "file": rel, "line": i,
                    "snippet": (snippet[:200] + ("…" if len(snippet) > 200 else "")),
                    "likely_placeholder": placeholder,
                })
    return out

def walk(root):
    results = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            ext = os.path.splitext(fn)[1].lower()
            if ext in SKIP_EXT:
                continue
            full = os.path.join(dirpath, fn)
            rel = os.path.relpath(full, root)
            results.extend(scan_file(full, rel))
    return results

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("directory")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    if not os.path.isdir(args.directory):
        print(f"오류: 디렉터리를 찾을 수 없음: {args.directory}", file=sys.stderr)
        sys.exit(1)
    res = walk(args.directory)
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    res.sort(key=lambda r: (order.get(r["severity"], 9), r["file"], r["line"]))
    if args.json:
        print(json.dumps({"scanner": "secrets", "count": len(res), "hits": res},
                         ensure_ascii=False, indent=2))
    else:
        if not res:
            print("시크릿 의심 항목 없음.")
        for r in res:
            tag = " (자리표시자 의심)" if r["likely_placeholder"] else ""
            print(f"[{r['severity'].upper()}] {r['type']}{tag} — {r['file']}:{r['line']}")
            print(f"    {r['snippet']}")
        print(f"\n총 {len(res)}건 (확정 전 — 각 항목 직접 확인 필요)")

if __name__ == "__main__":
    main()
