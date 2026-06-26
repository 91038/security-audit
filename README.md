# security-audit — 웹 프로젝트 보안 점검 스킬

바이브코딩으로 빠르게 만든 웹/앱 프로젝트의 보안 취약점을 점검하고,
**시각적인 한글 PDF 보고서**까지 자동으로 만들어 주는 [Claude Cowork](https://claude.com) 스킬입니다.

> 빠르게 만든 앱일수록 인증·권한, 시크릿 노출, 입력 검증이 취약하기 쉽습니다.
> 이 스킬은 그런 약점을 찾아내고, 무엇이 문제이고 어떻게 고치는지 보고서로 정리해 줍니다.

## 무엇을 하나요

이 스킬은 한 번의 점검에서 네 단계를 수행합니다.

1. **코드 정적 분석** — 개발 폴더를 훑어 하드코딩된 키/시크릿, SQL·OS 커맨드 인젝션,
   XSS, 약한 암호, TLS 검증 비활성화 등을 찾고, 인증/접근제어(IDOR)와 입력 검증은
   직접 코드를 읽어 확인합니다.
2. **의존성 / 설정 점검** — `npm audit`, `.env` 노출, 클라이언트에 새어나간 서버 키,
   Supabase RLS, CORS, 보안 헤더, 쿠키 플래그를 점검합니다.
3. **라이브 브라우저 점검** — 실행 중인 사이트를 브라우저로 직접 열어 페이지·네트워크
   요청·콘솔·응답 헤더·쿠키를 분석하고 접근제어를 실제로 테스트합니다.
   (Claude in Chrome 확장 필요)
4. **시각적 한글 PDF 보고서** — 종합 등급(A~F), 심각도 막대 차트, 항목별 상세 카드
   (위치·증거·영향·해결 방법), 그리고 무엇을 해결했고 무엇이 남았는지까지 정리합니다.

## 설치

### Claude Code

스킬 폴더를 아래 위치에 두면 자동 인식됩니다(`SKILL.md`가 그 안에 있으면 됨).

```bash
# 전역(모든 프로젝트에서 사용)
git clone https://github.com/<your-id>/security-audit.git ~/.claude/skills/security-audit

# 또는 특정 프로젝트에서만
git clone https://github.com/<your-id>/security-audit.git .claude/skills/security-audit
```

### Claude Cowork

`security-audit.skill` 파일을 채팅에 끌어다 놓고 **Save skill**을 누르거나,
**설정 → Capabilities**에서 추가합니다. `.skill` 패키지는 폴더를 zip으로 압축해 만듭니다.

```bash
cd ..
zip -r security-audit.skill security-audit -x "*/__pycache__/*"
```

## 라이브 브라우저 점검 설정 (선택)

실행 중인 사이트의 네트워크·헤더·콘솔·접근제어까지 점검하려면 브라우저 자동화
MCP가 필요합니다. 없어도 코드·의존성 점검만으로 완전한 보고서가 나오므로 선택 사항입니다.

### Claude Code — Playwright MCP

```bash
# 전제: Node.js 18 이상
claude mcp add playwright npx @playwright/mcp@latest

# 모든 프로젝트에서 쓰려면
claude mcp add --scope user playwright npx @playwright/mcp@latest
```

등록 확인은 `claude mcp list` 또는 Claude Code 안에서 `/mcp`. 처음 실행 시
브라우저 바이너리가 자동 설치됩니다. (스킬은 `mcp__playwright__*` 도구를 자동으로 사용)

### Claude Cowork — Claude in Chrome

Cowork에서는 Claude in Chrome 확장을 설치하면 됩니다.

브라우저 MCP가 없으면 해당 단계만 건너뛰고 나머지 점검은 정상 진행됩니다.

## 사용법

설치 후 점검할 프로젝트 폴더를 연결하고 이렇게 말하면 됩니다.

```
내 프로젝트 폴더 보안 점검해줘
```

라이브 브라우저 점검까지 하려면 개발 서버를 띄워둔 뒤 URL을 알려주세요.

```
localhost:3000 띄워놨어. 코드랑 사이트 둘 다 점검하고 PDF로 정리해줘
```

## 구성

```
security-audit/
├── SKILL.md                     # 점검 워크플로우(스킬 본문)
├── references/
│   ├── code-vulnerabilities.md  # 코드 취약점 체크리스트
│   ├── dependency-config.md     # 의존성·설정 점검 가이드
│   └── browser-audit.md         # 라이브 브라우저 점검 가이드
├── scripts/
│   ├── scan_secrets.py          # 하드코딩 시크릿 스캐너
│   ├── scan_static.py           # 위험 코드 패턴 스캐너
│   └── build_report.py          # 한글 PDF 보고서 생성기
└── assets/fonts/                # 나눔고딕(보고서 한글 렌더링용, OFL)
```

## 요구 사항

PDF 생성에는 `reportlab`이 필요합니다(보통 환경에 기본 포함).

```bash
pip3 install reportlab --break-system-packages
```

한글 폰트(나눔고딕 TrueType)는 `assets/fonts/`에 포함되어 있어 별도 설정이 필요 없습니다.

## 라이선스

- 스킬 코드: MIT License (`LICENSE` 참고)
- 번들 폰트(나눔고딕): SIL Open Font License 1.1 (`assets/fonts/LICENSE.txt` 참고)

## 주의

이 스킬은 **사용자 본인 프로젝트**의 약점을 찾아 설명하기 위한 것입니다.
제3자 시스템 공격, 실제 데이터 유출/파괴, 동작하는 익스플로잇 생성에는 사용하지 마세요.
