# security-audit — 웹 프로젝트 보안 점검 플러그인

바이브코딩으로 빠르게 만든 웹/앱 프로젝트의 보안 취약점을 점검하고,
**시각적인 한글 PDF 보고서**까지 자동으로 만들어 주는 Claude Code 플러그인(+ Cowork 스킬)입니다.

> 빠르게 만든 앱일수록 인증·권한, 시크릿 노출, 입력 검증이 취약하기 쉽습니다.
> 이 플러그인은 그런 약점을 찾아내고, 무엇이 문제이고 어떻게 고치는지 보고서로 정리해 줍니다.

## 무엇을 하나요

한 번의 점검에서 네 단계를 수행합니다.

1. **코드 정적 분석** — 하드코딩된 키/시크릿, SQL·OS 커맨드 인젝션, XSS, 약한 암호,
   TLS 검증 비활성화 등을 찾고, 인증/접근제어(IDOR)·입력 검증은 직접 코드를 읽어 확인.
2. **의존성 / 설정 점검** — `npm audit`, `.env` 노출, 클라이언트에 새어나간 서버 키,
   Supabase RLS, CORS, 보안 헤더, 쿠키 플래그.
3. **라이브 브라우저 점검** — 실행 중인 사이트를 직접 열어 페이지·네트워크·콘솔·헤더·쿠키
   분석 및 접근제어 테스트. (브라우저 자동화 MCP 필요 — 아래 설정 참고)
4. **시각적 한글 PDF 보고서** — 종합 등급(A~F), 심각도 차트, 항목별 상세 카드
   (위치·증거·영향·해결 방법), 해결/미해결 현황 요약.

## 설치

### 1) Claude Code — 플러그인 (마켓플레이스, 권장)

```shell
/plugin marketplace add 91038/security-audit
/plugin install security-audit@security-audit
```

설치 후 "내 프로젝트 보안 점검해줘"처럼 말하면 동작합니다.
업데이트는 `/plugin marketplace update security-audit`.

### 2) Claude Code — 스킬만 직접 설치

```bash
git clone https://github.com/91038/security-audit.git /tmp/sa
cp -r /tmp/sa/skills/security-audit ~/.claude/skills/security-audit
```

### 3) Claude Cowork

`security-audit.skill` 파일을 채팅에 끌어다 놓고 **Save skill**, 또는 **설정 → Capabilities**에서 추가.
`.skill`은 `skills/security-audit` 폴더를 zip으로 압축해 만듭니다.

```bash
cd skills && zip -r ../security-audit.skill security-audit -x "*/__pycache__/*"
```

## 라이브 브라우저 점검 설정 (선택)

실행 중인 사이트까지 점검하려면 브라우저 자동화 MCP가 필요합니다. 없어도 코드·의존성
점검만으로 완전한 보고서가 나오므로 선택 사항입니다.

### Claude Code — Playwright MCP

```bash
# 전제: Node.js 18 이상
claude mcp add playwright npx @playwright/mcp@latest
# 모든 프로젝트에서: claude mcp add --scope user playwright npx @playwright/mcp@latest
```

등록 확인은 `claude mcp list` 또는 Claude Code 안에서 `/mcp`. 첫 실행 시 브라우저
바이너리가 자동 설치됩니다. 스킬은 `mcp__playwright__*` 도구를 자동으로 사용합니다.

### Claude Cowork — Claude in Chrome

Cowork에서는 Claude in Chrome 확장을 설치하면 됩니다.

## 저장소 구조

```
security-audit/                      # 마켓플레이스 + 플러그인 루트
├── .claude-plugin/
│   ├── plugin.json                  # 플러그인 매니페스트
│   └── marketplace.json             # 마켓플레이스 카탈로그
├── skills/
│   └── security-audit/              # 실제 스킬
│       ├── SKILL.md                 # 점검 워크플로우
│       ├── references/              # 점검 체크리스트/가이드
│       ├── scripts/                 # 스캐너 + 한글 PDF 생성기
│       └── assets/fonts/            # 나눔고딕 (보고서 한글용, OFL)
├── README.md
└── LICENSE
```

## 요구 사항

PDF 생성에 `reportlab` 필요(`pip3 install reportlab`). 한글 폰트(나눔고딕)는 포함돼 있어
별도 설정이 필요 없습니다.

## 라이선스

- 플러그인/스킬 코드: MIT (`LICENSE`)
- 번들 폰트(나눔고딕): SIL Open Font License 1.1 (`skills/security-audit/assets/fonts/LICENSE.txt`)

## 주의

**본인 소유 프로젝트**의 약점을 찾아 설명하기 위한 도구입니다. 제3자 시스템 공격,
실제 데이터 유출/파괴, 동작하는 익스플로잇 생성에는 사용하지 마세요.
