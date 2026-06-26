#!/usr/bin/env python3
"""
scan_static.py — 위험 코드 패턴 정적 스캐너.

인젝션, XSS 싱크, eval, 약한 암호, TLS 검증 비활성화, 과도한 CORS 등
바이브코딩 앱에서 흔한 위험 패턴을 찾는다. 결과는 리드(lead)이며, 각 항목은
파일을 열어 실제 취약점인지(신뢰 입력인지 등) 확인한 뒤 보고한다.

사용법:
    python3 scan_static.py <dir> [--json]
"""
import argparse, json, os, re, sys

SKIP_DIRS = {".git", "node_modules", "dist", "build", ".next", "out",
             "venv", ".venv", "__pycache__", ".cache", "coverage",
             "vendor", ".idea", ".vscode"}
CODE_EXT = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte",
            ".py", ".rb", ".php", ".go", ".java", ".cs", ".html", ".ejs",
            ".hbs", ".pug", ".sql", ".sh", ".json", ".yml", ".yaml", ".env"}
MAX_BYTES = 1_500_000

# (이름, 정규식, 심각도, 카테고리, 설명)
RULES = [
    ("eval() 사용", r"\beval\s*\(", "high", "인젝션",
     "사용자 입력이 들어가면 임의 코드 실행."),
    ("Function 생성자", r"\bnew\s+Function\s*\(", "high", "인젝션",
     "eval과 동일하게 동적 코드 실행 위험."),
    ("child_process exec", r"\b(exec|execSync|spawn|spawnSync)\s*\(", "high", "인젝션",
     "셸 명령에 입력이 들어가면 OS 커맨드 인젝션."),
    ("os.system/subprocess shell", r"(os\.system\s*\(|subprocess\.[a-z]+\([^)]*shell\s*=\s*True)", "high", "인젝션",
     "셸을 통해 명령 실행 — 입력 결합 시 커맨드 인젝션."),
    ("SQL 문자열 결합", r"(?i)(select|insert|update|delete)\b.*\b(from|into|set|where)\b.*(\+|\$\{|%s\s*%|\.format\(|f['\"])", "high", "인젝션",
     "쿼리에 문자열 결합/포맷 — SQL 인젝션 가능. 파라미터라이즈드 쿼리 사용."),
    ("dangerouslySetInnerHTML", r"dangerouslySetInnerHTML", "medium", "XSS",
     "사용자/외부 데이터면 XSS. 신뢰 상수만 허용."),
    ("v-html", r"v-html\s*=", "medium", "XSS",
     "Vue에서 원시 HTML 렌더 — 입력이면 XSS."),
    ("innerHTML 대입", r"\.innerHTML\s*=", "medium", "XSS",
     "DOM에 원시 HTML 주입 — 입력이면 XSS."),
    ("document.write", r"document\.write\s*\(", "medium", "XSS",
     "DOM 기반 XSS 위험."),
    ("React href javascript:", r"href\s*=\s*\{?\s*[`'\"]javascript:", "medium", "XSS",
     "javascript: 스킴 — 스크립트 주입 경로."),
    ("템플릿 자동이스케이프 해제", r"(\|\s*safe\b|\{\{\{|escape\s*=\s*False|autoescape\s*=\s*False)", "medium", "XSS",
     "출력 인코딩 비활성화 — 입력이면 XSS."),
    ("CORS 전체 허용", r"(?i)(access-control-allow-origin['\"]?\s*[:,]\s*['\"]?\*|origin\s*:\s*['\"]\*['\"]|cors\(\s*\))", "medium", "보안 헤더/설정",
     "모든 출처 허용 — credentials 동반 시 특히 위험."),
    ("TLS 검증 비활성화", r"(rejectUnauthorized\s*:\s*false|verify\s*=\s*False|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0|InsecureSkipVerify\s*:\s*true)", "high", "암호화",
     "인증서 검증 끔 — 중간자 공격(MITM) 가능."),
    ("약한 해시(MD5/SHA1)", r"(?i)(md5|sha1)\s*\(", "low", "암호화",
     "비밀번호/무결성에 약한 해시 — bcrypt/argon2 또는 SHA-256+ 사용."),
    ("Math.random 보안용도", r"Math\.random\s*\(", "low", "암호화",
     "토큰/ID에 쓰면 예측 가능 — crypto 난수 사용."),
    ("하드코딩 IV/키 의심", r"(?i)(iv|secret|key)\s*[:=]\s*['\"][0-9a-f]{16,}['\"]", "low", "암호화",
     "고정 IV/키 의심 — 검토 필요."),
    ("디버그 모드 on", r"(?i)(debug\s*[:=]\s*true|DEBUG\s*=\s*True|app\.run\([^)]*debug\s*=\s*True)", "low", "정보 노출",
     "프로덕션 디버그 — 스택트레이스/정보 노출 위험."),
    ("쿠키 보안플래그 누락 의심", r"(?i)set-?cookie", "info", "보안 헤더/설정",
     "쿠키 설정 — HttpOnly/Secure/SameSite 플래그 확인 필요."),
    ("eval 유사 setTimeout 문자열", r"set(Timeout|Interval)\s*\(\s*['\"]", "low", "인젝션",
     "문자열 인자 setTimeout — eval과 유사."),
    ("path traversal 의심", r"(\.\./|os\.path\.join\([^)]*req|__dirname\s*\+\s*req)", "low", "정보 노출",
     "경로 조작 가능성 — 입력 정규화 확인."),
]

def is_text(path):
    try:
        with open(path, "rb") as f:
            return b"\x00" not in f.read(2048)
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
    for i, line in enumerate(lines, 1):
        if len(line) > 800:
            continue
        s = line.strip()
        if s.startswith(("//", "#", "*")):  # 단순 주석은 노이즈 줄이기 (완벽하진 않음)
            pass
        for name, pat, sev, cat, desc in RULES:
            if re.search(pat, line):
                out.append({
                    "type": name, "severity": sev, "category": cat,
                    "description": desc, "file": rel, "line": i,
                    "snippet": (s[:200] + ("…" if len(s) > 200 else "")),
                })
    return out

def walk(root):
    results = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            ext = os.path.splitext(fn)[1].lower()
            if ext not in CODE_EXT and not fn.startswith(".env"):
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
        print(json.dumps({"scanner": "static", "count": len(res), "hits": res},
                         ensure_ascii=False, indent=2))
    else:
        if not res:
            print("위험 패턴 없음.")
        for r in res:
            print(f"[{r['severity'].upper()}] {r['type']} — {r['file']}:{r['line']}")
            print(f"    {r['snippet']}")
        print(f"\n총 {len(res)}건 (확정 전 — 각 항목 직접 확인 필요)")

if __name__ == "__main__":
    main()
