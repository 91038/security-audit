#!/usr/bin/env python3
"""
build_report.py — findings.json 으로부터 시각적인 한글 보안 점검 PDF 생성.

reportlab + 시스템 Noto Sans CJK KR 폰트만 사용한다(추가 네트워크 불필요).

사용법:
    python3 build_report.py findings.json --out 보안점검_보고서.pdf
"""
import argparse, json, os, sys, datetime

from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.lib.colors import HexColor, white, black
from reportlab.lib.enums import TA_LEFT, TA_CENTER
from reportlab.lib.styles import ParagraphStyle
from reportlab.platypus import (BaseDocTemplate, PageTemplate, Frame, Paragraph,
                                Spacer, Table, TableStyle, KeepTogether,
                                HRFlowable, PageBreak, Flowable, NextPageTemplate)
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont

# ----------------------------------------------------------------------------- 폰트
FONT, FONT_B = "KR", "KRB"

# 번들 폰트(나눔고딕 TrueType) — reportlab은 CFF/OTF를 임베드 못 하므로 TTF 필요.
_HERE = os.path.dirname(os.path.abspath(__file__))
_BUNDLED = [
    (os.path.join(_HERE, "..", "assets", "fonts", "NanumGothic-Regular.ttf"),
     os.path.join(_HERE, "..", "assets", "fonts", "NanumGothic-Bold.ttf")),
]

def _truetype_candidates():
    """시스템에 설치된 TrueType(.ttf) 한글 폰트를 fc-list로 탐색(폴백)."""
    found = []
    try:
        import subprocess
        out = subprocess.run(["fc-list", ":", "file"], capture_output=True,
                             text=True, timeout=10).stdout
        for ln in out.splitlines():
            p = ln.split(":")[0].strip()
            low = p.lower()
            if low.endswith(".ttf") and any(k in low for k in
                    ("nanum", "malgun", "gothic", "gulim", "batang", "spoqa", "pretendard")):
                found.append((p, p))
    except Exception:
        pass
    return found

def register_fonts():
    for reg, bold in _BUNDLED + _truetype_candidates():
        try:
            if not os.path.exists(reg):
                continue
            bold = bold if os.path.exists(bold) else reg
            pdfmetrics.registerFont(TTFont(FONT, reg))
            pdfmetrics.registerFont(TTFont(FONT_B, bold))
            # 패밀리 등록 — <b>/<i> 태그가 올바른 폰트로 매핑되도록(하이픈 없는 이름 사용)
            pdfmetrics.registerFontFamily(FONT, normal=FONT, bold=FONT_B,
                                          italic=FONT, boldItalic=FONT_B)
            pdfmetrics.registerFontFamily(FONT_B, normal=FONT_B, bold=FONT_B,
                                          italic=FONT_B, boldItalic=FONT_B)
            return True
        except Exception:
            continue
    return False

# ----------------------------------------------------------------------------- 색상/심각도
C_INK   = HexColor("#1f2937")
C_MUTE  = HexColor("#6b7280")
C_LINE  = HexColor("#e5e7eb")
C_BG    = HexColor("#f9fafb")
C_BRAND = HexColor("#0f172a")

SEV = {
    "critical": ("치명적", HexColor("#b91c1c"), HexColor("#fee2e2")),
    "high":     ("높음",   HexColor("#ea580c"), HexColor("#ffedd5")),
    "medium":   ("중간",   HexColor("#d97706"), HexColor("#fef3c7")),
    "low":      ("낮음",   HexColor("#2563eb"), HexColor("#dbeafe")),
    "info":     ("정보",   HexColor("#6b7280"), HexColor("#f3f4f6")),
}
SEV_ORDER = ["critical", "high", "medium", "low", "info"]

STATUS_STYLE = {
    "해결됨": (HexColor("#16a34a"), HexColor("#dcfce7")),
    "발견":   (HexColor("#b91c1c"), HexColor("#fee2e2")),
    "미해결": (HexColor("#d97706"), HexColor("#fef3c7")),
}

def grade(counts):
    if counts.get("critical"): return ("F", HexColor("#b91c1c"), "위험")
    if counts.get("high"):     return ("D", HexColor("#ea580c"), "취약")
    if counts.get("medium"):   return ("C", HexColor("#d97706"), "보통")
    if counts.get("low"):      return ("B", HexColor("#2563eb"), "양호")
    return ("A", HexColor("#16a34a"), "안전")

# ----------------------------------------------------------------------------- 스타일
def styles():
    s = {}
    s["h1"]    = ParagraphStyle("h1", fontName=FONT_B, fontSize=20, leading=26, textColor=C_BRAND, spaceAfter=4)
    s["h2"]    = ParagraphStyle("h2", fontName=FONT_B, fontSize=14, leading=19, textColor=C_BRAND, spaceBefore=10, spaceAfter=6)
    s["body"]  = ParagraphStyle("body", fontName=FONT, fontSize=10, leading=16, textColor=C_INK)
    s["muted"] = ParagraphStyle("muted", fontName=FONT, fontSize=9, leading=14, textColor=C_MUTE)
    s["small"] = ParagraphStyle("small", fontName=FONT, fontSize=8.5, leading=13, textColor=C_INK)
    s["label"] = ParagraphStyle("label", fontName=FONT_B, fontSize=8.5, leading=12, textColor=C_MUTE)
    s["card_t"]= ParagraphStyle("card_t", fontName=FONT_B, fontSize=12, leading=16, textColor=C_BRAND)
    s["mono"]  = ParagraphStyle("mono", fontName=FONT, fontSize=8.5, leading=13, textColor=HexColor("#334155"))
    return s

def esc(t):
    return (str(t).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))

def hx(color):
    """reportlab Color -> '#rrggbb' 문자열."""
    return "#%02x%02x%02x" % (int(round(color.red*255)),
                              int(round(color.green*255)),
                              int(round(color.blue*255)))

# ----------------------------------------------------------------------------- 막대 차트 Flowable
class SeverityBars(Flowable):
    def __init__(self, counts, width=170*mm):
        super().__init__()
        self.counts = counts
        self.width = width
        self.row_h = 9*mm
        self.height = self.row_h * len(SEV_ORDER) + 4*mm
    def draw(self):
        c = self.canv
        maxv = max([self.counts.get(k, 0) for k in SEV_ORDER] + [1])
        label_w = 22*mm
        bar_max = self.width - label_w - 16*mm
        y = self.height - self.row_h
        for k in SEV_ORDER:
            name, col, _ = SEV[k]
            v = self.counts.get(k, 0)
            c.setFont(FONT, 9)
            c.setFillColor(C_INK)
            c.drawString(0, y + 2.4*mm, name)
            c.setFillColor(C_BG)
            c.roundRect(label_w, y, bar_max, 5.5*mm, 1.5, stroke=0, fill=1)
            w = (bar_max * v / maxv) if v else 0
            if w > 0:
                c.setFillColor(col)
                c.roundRect(label_w, y, max(w, 3), 5.5*mm, 1.5, stroke=0, fill=1)
            c.setFont(FONT_B, 9)
            c.setFillColor(col if v else C_MUTE)
            c.drawString(label_w + bar_max + 4*mm, y + 1.6*mm, str(v))
            y -= self.row_h

# ----------------------------------------------------------------------------- 표지
def make_cover(canvas, doc, meta, counts):
    canvas.saveState()
    W, H = A4
    canvas.setFillColor(C_BRAND)
    canvas.rect(0, 0, W, H, stroke=0, fill=1)
    g, gc, gtxt = grade(counts)
    canvas.setFillColor(gc)
    canvas.rect(0, H-10*mm, W, 10*mm, stroke=0, fill=1)
    canvas.setFont(FONT, 11)
    canvas.setFillColor(HexColor("#94a3b8"))
    canvas.drawString(20*mm, H-40*mm, "SECURITY AUDIT REPORT · 보안 점검 보고서")
    canvas.setFont(FONT_B, 30)
    canvas.setFillColor(white)
    title = meta.get("project_name", "프로젝트")
    canvas.drawString(20*mm, H-58*mm, title[:24])
    canvas.setFont(FONT, 13)
    canvas.setFillColor(HexColor("#cbd5e1"))
    canvas.drawString(20*mm, H-68*mm, "취약점 점검 결과 보고서")

    bx, by, bs = 20*mm, H-120*mm, 40*mm
    canvas.setFillColor(gc)
    canvas.roundRect(bx, by, bs, bs, 6, stroke=0, fill=1)
    canvas.setFont(FONT_B, 40)
    canvas.setFillColor(white)
    canvas.drawCentredString(bx+bs/2, by+bs/2-4*mm, g)
    canvas.setFont(FONT, 11)
    canvas.drawCentredString(bx+bs/2, by+6*mm, "종합 등급")
    canvas.setFont(FONT_B, 16)
    canvas.setFillColor(white)
    canvas.drawString(bx+bs+10*mm, by+bs-12*mm, f"보안 상태: {gtxt}")
    canvas.setFont(FONT, 10)
    canvas.setFillColor(HexColor("#cbd5e1"))
    total = sum(counts.values())
    canvas.drawString(bx+bs+10*mm, by+bs-20*mm, f"총 {total}건 발견 · 치명적 {counts.get('critical',0)} · 높음 {counts.get('high',0)}")
    canvas.drawString(bx+bs+10*mm, by+bs-27*mm, f"중간 {counts.get('medium',0)} · 낮음 {counts.get('low',0)} · 정보 {counts.get('info',0)}")

    canvas.setFillColor(HexColor("#1e293b"))
    canvas.roundRect(20*mm, 22*mm, W-40*mm, 34*mm, 4, stroke=0, fill=1)
    canvas.setFont(FONT, 9)
    rows = [
        ("점검 대상", str(meta.get("target", "-"))[:70]),
        ("점검 일자", str(meta.get("scan_date", datetime.date.today().isoformat()))),
        ("점검 수행", str(meta.get("auditor", "Claude 보안 점검"))),
    ]
    yy = 48*mm
    for klab, vval in rows:
        canvas.setFillColor(HexColor("#94a3b8"))
        canvas.drawString(26*mm, yy, klab)
        canvas.setFillColor(white)
        canvas.drawString(60*mm, yy, vval)
        yy -= 8*mm
    canvas.restoreState()

# ----------------------------------------------------------------------------- 본문 머리/꼬리
def make_later(canvas, doc, meta):
    canvas.saveState()
    W, H = A4
    canvas.setFillColor(C_MUTE)
    canvas.setFont(FONT, 8)
    canvas.drawString(20*mm, 12*mm, f"보안 점검 보고서 · {meta.get('project_name','')}")
    canvas.drawRightString(W-20*mm, 12*mm, f"{doc.page}")
    canvas.setStrokeColor(C_LINE)
    canvas.line(20*mm, 15*mm, W-20*mm, 15*mm)
    canvas.restoreState()

# ----------------------------------------------------------------------------- 카드
def finding_card(f, st):
    sev = f.get("severity", "info")
    sname, scol, sbg = SEV.get(sev, SEV["info"])
    status = f.get("status", "발견")
    stfg, stbg = STATUS_STYLE.get(status, STATUS_STYLE["발견"])

    fid = esc(f.get("id", ""))
    title = esc(f.get("title", "(제목 없음)"))
    header = Table(
        [[Paragraph(f'<font name="{FONT_B}">{sname}</font>', ParagraphStyle("x", fontName=FONT_B, fontSize=9, textColor=white, alignment=TA_CENTER)),
          Paragraph(f'<b>{fid}</b>  {title}', st["card_t"]),
          Paragraph(f'<font name="{FONT_B}">{esc(status)}</font>', ParagraphStyle("y", fontName=FONT_B, fontSize=8.5, textColor=stfg, alignment=TA_CENTER))]],
        colWidths=[16*mm, None, 18*mm])
    header.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (0,0), scol),
        ("BACKGROUND", (2,0), (2,0), stbg),
        ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
        ("LEFTPADDING",(1,0),(1,0),8), ("RIGHTPADDING",(1,0),(1,0),8),
        ("TOPPADDING",(0,0),(-1,-1),6), ("BOTTOMPADDING",(0,0),(-1,-1),6),
        ("LEFTPADDING",(0,0),(0,0),2), ("RIGHTPADDING",(0,0),(0,0),2),
        ("LEFTPADDING",(2,0),(2,0),2), ("RIGHTPADDING",(2,0),(2,0),2),
    ]))

    def row(label, value, mono=False):
        if not value:
            return None
        vstyle = st["mono"] if mono else st["body"]
        val = Paragraph(esc(value), vstyle)
        if mono:
            val = Table([[val]], style=TableStyle([
                ("BACKGROUND",(0,0),(-1,-1),HexColor("#f1f5f9")),
                ("LEFTPADDING",(0,0),(-1,-1),6),("RIGHTPADDING",(0,0),(-1,-1),6),
                ("TOPPADDING",(0,0),(-1,-1),4),("BOTTOMPADDING",(0,0),(-1,-1),4),
            ]))
        return [Paragraph(label, st["label"]), val]

    rows = []
    cat = f.get("category", "")
    loc = f.get("location", "")
    parts = []
    if cat: parts.append(f"분류: {cat}")
    if loc: parts.append(f"위치: {loc}")
    if parts:
        rows.append([Paragraph("개요", st["label"]), Paragraph(esc(" · ".join(parts)), st["muted"])])
    for label, key in [("설명","description"),("증거","evidence"),("영향","impact"),("권장 조치","recommendation")]:
        r = row(label, f.get(key, ""), mono=(key=="evidence"))
        if r: rows.append(r)

    body = Table(rows, colWidths=[20*mm, None])
    body.setStyle(TableStyle([
        ("VALIGN",(0,0),(-1,-1),"TOP"),
        ("TOPPADDING",(0,0),(-1,-1),4),("BOTTOMPADDING",(0,0),(-1,-1),4),
        ("LEFTPADDING",(0,0),(0,0),8),("LEFTPADDING",(1,0),(1,-1),2),
        ("RIGHTPADDING",(1,0),(1,-1),8),
        ("LINEABOVE",(0,1),(-1,-1),0.4,C_LINE),
    ]))

    card = Table([[header],[body]], colWidths=[None])
    card.setStyle(TableStyle([
        ("BOX",(0,0),(-1,-1),0.8,C_LINE),
        ("TOPPADDING",(0,1),(0,1),6),("BOTTOMPADDING",(0,1),(0,1),8),
        ("LEFTPADDING",(0,0),(-1,-1),0),("RIGHTPADDING",(0,0),(-1,-1),0),
        ("LEFTPADDING",(0,1),(0,1),4),("RIGHTPADDING",(0,1),(0,1),4),
    ]))
    return KeepTogether([card, Spacer(1, 6*mm)])

# ----------------------------------------------------------------------------- 메인 빌드
def build(data, out_path):
    has_font = register_fonts()
    st = styles()
    findings = data.get("findings", [])
    order = {k: i for i, k in enumerate(SEV_ORDER)}
    findings.sort(key=lambda f: order.get(f.get("severity", "info"), 9))
    counts = {k: 0 for k in SEV_ORDER}
    for f in findings:
        counts[f.get("severity", "info")] = counts.get(f.get("severity", "info"), 0) + 1

    meta = {k: data.get(k) for k in ("project_name", "target", "scan_date", "auditor")}
    meta["project_name"] = meta.get("project_name") or "프로젝트"

    W, H = A4
    doc = BaseDocTemplate(out_path, pagesize=A4,
                          leftMargin=20*mm, rightMargin=20*mm,
                          topMargin=22*mm, bottomMargin=20*mm,
                          title=f"보안 점검 보고서 - {meta['project_name']}")
    frame = Frame(doc.leftMargin, doc.bottomMargin,
                  W-doc.leftMargin-doc.rightMargin,
                  H-doc.topMargin-doc.bottomMargin, id="main")
    doc.addPageTemplates([
        PageTemplate(id="cover", frames=[frame],
                     onPage=lambda c, d: make_cover(c, d, meta, counts)),
        PageTemplate(id="body", frames=[frame],
                     onPage=lambda c, d: make_later(c, d, meta)),
    ])

    story = []
    story.append(NextPageTemplate("body"))
    story.append(Spacer(1, 1))
    story.append(PageBreak())

    g, gc, gtxt = grade(counts)
    story.append(Paragraph("점검 요약", st["h1"]))
    story.append(HRFlowable(width="100%", thickness=2, color=gc, spaceAfter=8))
    summary = data.get("summary") or "이 보고서는 대상 프로젝트의 코드, 의존성/설정, 실행 화면을 점검한 결과를 담고 있습니다."
    story.append(Paragraph(esc(summary), st["body"]))
    story.append(Spacer(1, 6*mm))

    story.append(Paragraph("심각도별 발견 현황", st["h2"]))
    story.append(SeverityBars(counts))
    story.append(Spacer(1, 4*mm))

    total = sum(counts.values())
    story.append(Paragraph(
        f'총 <b>{total}</b>건 · 즉시 조치 필요(치명적/높음) <b>{counts.get("critical",0)+counts.get("high",0)}</b>건',
        st["muted"]))
    story.append(Spacer(1, 6*mm))

    story.append(Paragraph("발견 항목 개요", st["h2"]))
    head = [Paragraph(f'<font name="{FONT_B}" color="white">{t}</font>', st["small"])
            for t in ["ID", "심각도", "분류", "제목", "상태"]]
    trows = [head]
    style_cmds = [
        ("BACKGROUND",(0,0),(-1,0),C_BRAND),
        ("VALIGN",(0,0),(-1,-1),"MIDDLE"),
        ("LINEBELOW",(0,0),(-1,-1),0.4,C_LINE),
        ("TOPPADDING",(0,0),(-1,-1),5),("BOTTOMPADDING",(0,0),(-1,-1),5),
        ("LEFTPADDING",(0,0),(-1,-1),6),("RIGHTPADDING",(0,0),(-1,-1),6),
    ]
    for i, f in enumerate(findings, start=1):
        sev = f.get("severity", "info"); sname, scol, sbg = SEV.get(sev, SEV["info"])
        status = f.get("status", "발견"); stfg, stbg = STATUS_STYLE.get(status, STATUS_STYLE["발견"])
        trows.append([
            Paragraph(esc(f.get("id", str(i))), st["small"]),
            Paragraph(f'<font name="{FONT_B}">{sname}</font>', st["small"]),
            Paragraph(esc(f.get("category", "-")), st["small"]),
            Paragraph(esc(f.get("title", "-")), st["small"]),
            Paragraph(esc(status), st["small"]),
        ])
        style_cmds.append(("BACKGROUND",(1,i),(1,i),sbg))
        style_cmds.append(("TEXTCOLOR",(1,i),(1,i),scol))
        style_cmds.append(("BACKGROUND",(4,i),(4,i),stbg))
        if i % 2 == 0:
            style_cmds.append(("BACKGROUND",(0,i),(0,i),C_BG))
            style_cmds.append(("BACKGROUND",(2,i),(3,i),C_BG))
    overview = Table(trows, colWidths=[20*mm, 16*mm, 26*mm, None, 18*mm], repeatRows=1)
    overview.setStyle(TableStyle(style_cmds))
    story.append(overview)
    story.append(Spacer(1, 4*mm))

    story.append(PageBreak())
    story.append(Paragraph("발견 항목 상세", st["h1"]))
    story.append(HRFlowable(width="100%", thickness=2, color=gc, spaceAfter=10))
    if not findings:
        story.append(Paragraph("발견된 취약점이 없습니다. 점검 범위 내에서 양호한 상태입니다.", st["body"]))
    for f in findings:
        story.append(finding_card(f, st))

    fixed = [f for f in findings if f.get("status") == "해결됨"]
    openi = [f for f in findings if f.get("status") != "해결됨"]
    story.append(PageBreak())
    story.append(Paragraph("조치 현황 및 권고", st["h1"]))
    story.append(HRFlowable(width="100%", thickness=2, color=gc, spaceAfter=10))
    summ = Table([[
        Paragraph(f'<font name="{FONT_B}" color="#16a34a" size="22">{len(fixed)}</font><br/><font size="9" color="#6b7280">해결됨</font>', ParagraphStyle("c1", fontName=FONT, alignment=TA_CENTER, leading=26)),
        Paragraph(f'<font name="{FONT_B}" color="#b91c1c" size="22">{len(openi)}</font><br/><font size="9" color="#6b7280">미해결/조치 필요</font>', ParagraphStyle("c2", fontName=FONT, alignment=TA_CENTER, leading=26)),
        Paragraph(f'<font name="{FONT_B}" color="#0f172a" size="22">{total}</font><br/><font size="9" color="#6b7280">전체</font>', ParagraphStyle("c3", fontName=FONT, alignment=TA_CENTER, leading=26)),
    ]], colWidths=[None, None, None])
    summ.setStyle(TableStyle([
        ("BOX",(0,0),(-1,-1),0.8,C_LINE),
        ("INNERGRID",(0,0),(-1,-1),0.8,C_LINE),
        ("TOPPADDING",(0,0),(-1,-1),10),("BOTTOMPADDING",(0,0),(-1,-1),10),
        ("BACKGROUND",(0,0),(-1,-1),C_BG),
    ]))
    story.append(summ)
    story.append(Spacer(1, 6*mm))

    if openi:
        story.append(Paragraph("우선 조치 권고 (심각도 순)", st["h2"]))
        for f in openi[:8]:
            sev = f.get("severity","info"); sname, scol, _ = SEV.get(sev, SEV["info"])
            story.append(Paragraph(
                f'<font name="{FONT_B}" color="{hx(scol)}">[{sname}]</font> '
                f'<b>{esc(f.get("title",""))}</b> — {esc(f.get("recommendation",""))[:200]}',
                st["body"]))
            story.append(Spacer(1, 2*mm))

    story.append(Spacer(1, 8*mm))
    story.append(HRFlowable(width="100%", thickness=0.5, color=C_LINE, spaceAfter=4))
    story.append(Paragraph(
        "본 보고서는 자동 점검과 수동 검토를 결합해 작성되었습니다. 모든 항목을 망라하지는 "
        "않으며, 치명적/높음 항목은 가능한 한 빠르게 조치하시기를 권고합니다.",
        st["muted"]))
    if not has_font:
        story.append(Paragraph("[주의] 한글 폰트를 찾지 못해 일부 글자가 깨질 수 있습니다.", st["muted"]))

    doc.build(story)
    return out_path

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("findings")
    ap.add_argument("--out", default="보안점검_보고서.pdf")
    args = ap.parse_args()
    with open(args.findings, encoding="utf-8") as f:
        data = json.load(f)
    path = build(data, args.out)
    print(f"생성 완료: {path}")

if __name__ == "__main__":
    main()
