# 의존성 & 설정 점검 가이드

## 1. 의존성 취약점

### Node / npm
```bash
cd <project_dir>
npm audit --json            # 설치된 트리 기준 CVE
```
- `critical`/`high`만 우선 보고. 각 항목의 패키지명·버전·권고 버전을 findings에 기록.
- `npm audit fix`로 자동 해결 가능한지 확인하되, 메이저 업그레이드는 사용자에게 알린다.
- lockfile(`package-lock.json`)이 없으면 버전 고정이 안 돼 공급망 위험이 커진다.

### Python
```bash
pip3 install pip-audit --break-system-packages   # 가능하면
pip-audit -r requirements.txt
```
- pip-audit이 없으면 `requirements.txt`의 핵심 패키지 버전을 알려진 CVE와 대조.
- 버전 핀(`==`)이 없거나 매우 오래된 버전인지 확인.

### 공통
- 사용하지 않는 의존성, 출처 불명/타이포스쿼팅 의심 패키지 확인.

## 2. 시크릿 & 설정 파일
- `.env`, `.env.local`, `.env.production`, `config.*`, `secrets.*` 존재 여부와 내용.
- **`.gitignore`에 `.env`가 포함돼 있는가?** 없으면 시크릿이 커밋될 위험.
- git 히스토리에 시크릿이 남아 있는가:
  ```bash
  git log --all -p -- .env 2>/dev/null | head
  git grep -nE "(api[_-]?key|secret|password|token)" $(git rev-list --all) 2>/dev/null | head
  ```
- 웹 루트에 `.git/`, `.env`, `*.bak`, `*.sql` 덤프가 노출되는지 (배포 시).

## 3. 클라이언트 노출 시크릿 (프론트엔드)
- Next.js: `NEXT_PUBLIC_` 접두사가 붙은 변수만 클라이언트로 나간다. 접두사 없는
  서버 키가 클라이언트 컴포넌트/`use client`에서 쓰이면 번들에 노출됨.
- Vite/CRA: `VITE_`/`REACT_APP_` 접두사 변수는 전부 공개됨 → 여기에 비밀키 금지.
- **service_role / admin / private 키는 절대 클라이언트 코드에 두지 않는다.**
- 빌드 산출물(`dist/`, `.next/`)에서 `grep -r "service_role\|secret\|sk_live"` 로 확인.

## 4. 백엔드 / BaaS 설정

### Supabase
- 모든 테이블에 **RLS 활성화** 여부 (`alter table ... enable row level security`).
- 정책이 `using (true)`처럼 전면 허용이 아닌지. anon 역할 권한 범위.
- Storage 버킷이 public인데 민감 파일을 담고 있지 않은지.
- 가능하면 `get_advisors`(보안 advisor) 결과 확인.

### Firebase
- Firestore/RTDB 규칙이 `allow read, write: if true`로 열려 있지 않은지.
- 인증 기반 규칙(`request.auth != null` + 소유자 체크)이 있는지.

### 일반 서버 (Express/Node 등)
- **CORS**: `origin: '*'` + `credentials: true` 조합은 위험. 화이트리스트로.
- **보안 헤더** (helmet 등):
  - `Content-Security-Policy`
  - `Strict-Transport-Security` (HSTS)
  - `X-Frame-Options` / `frame-ancestors` (클릭재킹)
  - `X-Content-Type-Options: nosniff`
  - `Referrer-Policy`
- **쿠키 플래그**: 세션 쿠키에 `HttpOnly`, `Secure`, `SameSite` 설정 여부.
- 디버그/스택트레이스가 프로덕션에서 노출되지 않는지 (`NODE_ENV=production`).
- 관리자 페이지/디버그 엔드포인트(`/admin`, `/debug`, `/__debug__`)의 보호 여부.

## 5. 인프라 / 배포
- HTTPS 강제 및 HTTP→HTTPS 리다이렉트.
- 기본 자격증명(admin/admin), 기본 포트로 노출된 DB.
- 컨테이너/서버에 불필요한 포트·서비스 노출.

각 확정 항목은 `findings.json`에 적절한 category(`의존성 취약점`,
`시크릿 노출`, `보안 헤더/설정` 등)로 기록한다.
