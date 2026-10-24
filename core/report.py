"""Remediation-first reports: HTML, PDF, JSON."""
from __future__ import annotations

import html
import json
import os
import textwrap
from collections import OrderedDict
from pathlib import Path
from xml.sax.saxutils import escape as xesc

from .models import SEV_RANK, SEVERITIES, ScanJob
from . import __version__

SEV_COLOR = {"critical": "#b91c1c", "high": "#ea580c", "medium": "#ca8a04",
             "low": "#2563eb", "info": "#6b7280"}
EFFORT = {"critical": "Do now", "high": "This week", "medium": "This sprint",
          "low": "Backlog", "info": "FYI"}


# ---------------------------------------------------------------- plan
def build_plan(job: ScanJob) -> list[dict]:
    """Group findings by rule so one fix covers every affected asset."""
    groups: "OrderedDict[str, dict]" = OrderedDict()
    for f in job.findings:  # already sorted by severity
        g = groups.setdefault(f.rule, {
            "rule": f.rule, "title": f.title, "severity": f.severity, "module": f.module,
            "description": f.description, "remediation": f.remediation,
            "fix_snippet": f.fix_snippet, "references": f.references, "assets": []})
        if SEV_RANK[f.severity] < SEV_RANK[g["severity"]]:
            g["severity"] = f.severity
        g["assets"].append({"asset": f.asset, "evidence": f.evidence, "fingerprint": f.fingerprint})
    plan = sorted(groups.values(), key=lambda g: (SEV_RANK[g["severity"]], -len(g["assets"])))
    for i, g in enumerate(plan, 1):
        g["priority"] = i
        g["when"] = EFFORT[g["severity"]]
    return plan


def to_dict(job: ScanJob) -> dict:
    return {
        "tool": "umbra", "version": __version__, "profile": job.profile,
        "started": job.started, "finished": job.finished, "scope": job.scope,
        "score": job.score(), "grade": job.grade(), "counts": job.counts(),
        "first_run": job.first_run, "diff": job.diff, "modules": job.modules_run,
        "tools": job.tool_status, "plan": build_plan(job),
        "findings": [f.to_dict() for f in job.findings],
        "suppressed": [f.to_dict() for f in job.suppressed],
        "assets": [a.to_dict() for a in job.assets],
    }


# ---------------------------------------------------------------- html
_CSS = """
:root{--bg:#f8fafc;--fg:#0f172a;--mut:#64748b;--card:#fff;--bd:#e2e8f0;--code:#0f172a;--codefg:#e2e8f0}
@media (prefers-color-scheme:dark){:root{--bg:#0b1020;--fg:#e5e7eb;--mut:#94a3b8;--card:#131a2e;--bd:#25304d;--code:#05080f;--codefg:#d1d5db}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.55 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
.wrap{max-width:1080px;margin:0 auto;padding:28px 18px 60px}
h1{margin:0 0 4px;font-size:26px}h2{margin:36px 0 12px;font-size:19px;border-bottom:1px solid var(--bd);padding-bottom:6px}
.mut{color:var(--mut)}.card{background:var(--card);border:1px solid var(--bd);border-radius:10px;padding:14px 16px;margin:10px 0}
.hero{display:flex;gap:18px;flex-wrap:wrap;align-items:center}.grade{font-size:54px;font-weight:800;line-height:1;min-width:84px;text-align:center}
.pill{display:inline-block;color:#fff;border-radius:99px;padding:1px 10px;font-size:12px;font-weight:700;text-transform:uppercase}
.cnt{display:flex;gap:8px;flex-wrap:wrap}.cnt span{padding:4px 12px;border-radius:8px;border:1px solid var(--bd);background:var(--card)}
table{width:100%;border-collapse:collapse;font-size:13.5px}th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--bd);vertical-align:top;word-break:break-word}
.scroll{overflow-x:auto}pre{background:var(--code);color:var(--codefg);padding:12px;border-radius:8px;overflow-x:auto;font-size:12.5px;margin:8px 0}
details summary{cursor:pointer;font-weight:600}code{font-family:ui-monospace,Menlo,Consolas,monospace}
.assets li{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12.5px}footer{margin-top:40px;color:var(--mut);font-size:13px}
"""


def _pill(sev: str) -> str:
    return f'<span class="pill" style="background:{SEV_COLOR[sev]}">{html.escape(sev)}</span>'


def render_html(job: ScanJob, cfg) -> str:
    e = html.escape
    plan, counts = build_plan(job), job.counts()
    scope = ", ".join(job.scope.get("domains", []) + job.scope.get("hosts", [])
                      + job.scope.get("paths", [])) or "-"
    out = [f"<!doctype html><html lang=en><head><meta charset=utf-8>"
           f"<meta name=viewport content='width=device-width,initial-scale=1'>"
           f"<title>{e(cfg.get('report.title', 'Umbra Report'))}</title><style>{_CSS}</style></head>"
           f"<body><div class=wrap><h1>🌑 {e(cfg.get('report.title', 'Umbra Report'))}</h1>"
           f"<div class=mut>Scope: {e(scope)} · profile: {e(job.profile)} · {e(job.finished)}</div>"]
    gcol = {"A": "#16a34a", "B": "#65a30d", "C": "#ca8a04", "D": "#ea580c", "F": "#b91c1c"}[job.grade()]
    out.append(f"<div class='card hero'><div class=grade style='color:{gcol}'>{job.grade()}</div>"
               f"<div><b>Posture score {job.score()}/100</b><div class=cnt style='margin-top:8px'>"
               + "".join(f"<span>{_pill(s)} {counts[s]}</span>" for s in SEVERITIES)
               + "</div></div></div>")

    d = job.diff
    out.append("<h2>Changes since last scan</h2><div class=card>")
    if job.first_run:
        out.append("<span class=mut>First run — this scan established the baseline.</span>")
    else:
        for label, key in (("New assets", "new_assets"), ("Disappeared assets", "gone_assets")):
            items = d.get(key, [])
            out.append(f"<b>{label}: {len(items)}</b>")
            if items:
                out.append("<ul class=assets>" + "".join(f"<li>{e(i)}</li>" for i in items[:60]) + "</ul>")
        out.append(f"<div>New findings: <b>{len(d.get('new_findings', []))}</b> · "
                   f"Resolved: <b>{len(d.get('resolved_findings', []))}</b></div>")
    out.append("</div>")

    out.append(f"<h2>Remediation plan ({len(plan)} actions)</h2>")
    if not plan:
        out.append("<div class=card>✅ Nothing to fix in the scanned scope.</div>")
    for g in plan:
        out.append(f"<div class=card><div>{_pill(g['severity'])} <b>#{g['priority']} {e(g['title'])}</b> "
                   f"<span class=mut>· {e(g['when'])} · {len(g['assets'])} asset(s)</span></div>")
        if g["description"]:
            out.append(f"<p>{e(g['description'])}</p>")
        if g["remediation"]:
            out.append(f"<p><b>How to fix:</b> {e(g['remediation'])}</p>")
        if g["fix_snippet"]:
            out.append(f"<details><summary>Copy-paste fix</summary><pre><code>{e(g['fix_snippet'])}</code></pre></details>")
        out.append("<details><summary>Affected assets</summary><div class=scroll><table><tr><th>Asset</th><th>Evidence</th><th>ID</th></tr>"
                   + "".join(f"<tr><td><code>{e(a['asset'])}</code></td><td>{e(a['evidence'][:300])}</td>"
                             f"<td><code>{e(a['fingerprint'])}</code></td></tr>" for a in g["assets"][:100])
                   + "</table></div></details>")
        if g["references"]:
            out.append("<div class=mut>Refs: " + " · ".join(e(r) for r in g["references"]) + "</div>")
        out.append("</div>")

    out.append(f"<h2>Asset inventory ({len(job.assets)})</h2><div class='card scroll'><table>"
               "<tr><th>Kind</th><th>Value</th><th>Source</th><th>Details</th></tr>")
    for a in job.assets[:400]:
        meta = ", ".join(f"{k}={v}" for k, v in a.meta.items() if k not in ("ip",) and v not in ("", None))
        out.append(f"<tr><td>{e(a.kind)}</td><td><code>{e(a.value)}</code></td>"
                   f"<td>{e(a.source)}</td><td>{e(meta[:200])}</td></tr>")
    out.append("</table></div>")

    out.append("<h2>Modules &amp; tools</h2><div class='card scroll'><table><tr><th>Module</th><th>Status</th><th>Seconds</th><th>Error</th></tr>"
               + "".join(f"<tr><td>{e(m['name'])}</td><td>{e(m['status'])}</td><td>{m['seconds']}</td><td>{e(m['error'])}</td></tr>"
                         for m in job.modules_run) + "</table>")
    out.append("<p class=mut>External tools: " + ", ".join(
        f"{e(t)} {'✔' if ok else '✘'}" for t, ok in job.tool_status.items()) + "</p></div>")
    if job.suppressed:
        out.append(f"<p class=mut>{len(job.suppressed)} finding(s) suppressed by the operator (see JSON).</p>")
    out.append(f"<footer>Umbra v{__version__} · {e(cfg.get('report.author', ''))} · "
               "Findings are automated signals — validate before acting.</footer></div></body></html>")
    return "".join(out)


# ---------------------------------------------------------------- pdf
_FONT_SETS = [
    ("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
     "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"),
    ("C:/Windows/Fonts/arial.ttf", "C:/Windows/Fonts/arialbd.ttf", "C:/Windows/Fonts/cour.ttf"),
    ("/System/Library/Fonts/Supplemental/Arial.ttf", "/System/Library/Fonts/Supplemental/Arial Bold.ttf",
     "/System/Library/Fonts/Supplemental/Courier New.ttf"),
    ("/usr/share/fonts/dejavu/DejaVuSans.ttf", "/usr/share/fonts/dejavu/DejaVuSans-Bold.ttf",
     "/usr/share/fonts/dejavu/DejaVuSansMono.ttf"),
]
_TR = str.maketrans("ğĞşŞıİöÖüÜçÇ", "gGsSiIoOuUcC")


def render_pdf(job: ScanJob, cfg, path: Path) -> None:
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_LEFT
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    from reportlab.platypus import (KeepTogether, Paragraph, Preformatted, SimpleDocTemplate,
                                    Spacer, Table, TableStyle)

    reg, bold, mono, unicode_ok = "Helvetica", "Helvetica-Bold", "Courier", False
    for r, b, m in _FONT_SETS:
        if all(os.path.exists(x) for x in (r, b, m)):
            pdfmetrics.registerFont(TTFont("U-Reg", r))
            pdfmetrics.registerFont(TTFont("U-Bold", b))
            pdfmetrics.registerFont(TTFont("U-Mono", m))
            reg, bold, mono, unicode_ok = "U-Reg", "U-Bold", "U-Mono", True
            break

    def T(s) -> str:  # escape for Paragraph + transliterate when no unicode font
        s = str(s)
        s = s if unicode_ok else s.translate(_TR).encode("latin-1", "replace").decode("latin-1")
        return xesc(s)

    st = lambda name, **kw: ParagraphStyle(name, fontName=kw.pop("fontName", reg), alignment=TA_LEFT, **kw)
    body = st("body", fontSize=9, leading=12)
    small = st("small", fontSize=7.5, leading=10, textColor=colors.HexColor("#475569"))
    h1 = st("h1", fontName=bold, fontSize=20, leading=24, spaceAfter=4)
    h2 = st("h2", fontName=bold, fontSize=13, leading=16, spaceBefore=14, spaceAfter=6)
    h3 = st("h3", fontName=bold, fontSize=10, leading=13)

    def code(text: str):
        lines = []
        for ln in str(text).splitlines() or [""]:
            lines += textwrap.wrap(ln, 88, break_long_words=True, replace_whitespace=False) or [""]
        s = "\n".join(lines)
        s = s if unicode_ok else s.translate(_TR).encode("latin-1", "replace").decode("latin-1")
        pre = Preformatted(s, ParagraphStyle("code", fontName=mono, fontSize=7.3, leading=9,
                                              textColor=colors.HexColor("#e2e8f0")))
        box = Table([[pre]], colWidths=[180 * mm])
        box.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#0f172a")),
                                 ("LEFTPADDING", (0, 0), (-1, -1), 6), ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                                 ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5)]))
        return box

    def sev(s):
        return f'<font color="{SEV_COLOR[s]}"><b>{s.upper()}</b></font>'

    counts = job.counts()
    scope = ", ".join(job.scope.get("domains", []) + job.scope.get("hosts", []) + job.scope.get("paths", []))
    story = [Paragraph(T(cfg.get("report.title", "Umbra Report")), h1),
             Paragraph(T(f"Scope: {scope or '-'}  |  profile: {job.profile}  |  {job.finished}"), small),
             Spacer(1, 8),
             Paragraph(f"<b>Grade {job.grade()}</b> &nbsp; Posture score {job.score()}/100", h2)]
    row = [[Paragraph(sev(s), body), str(counts[s])] for s in SEVERITIES]
    t = Table([[r[0] for r in row], [r[1] for r in row]], hAlign="LEFT", colWidths=[28 * mm] * 5)
    t.setStyle(TableStyle([("FONT", (0, 1), (-1, 1), bold, 14), ("GRID", (0, 0), (-1, -1), .4, colors.lightgrey),
                           ("ALIGN", (0, 0), (-1, -1), "CENTER")]))
    story.append(t)

    d = job.diff
    story.append(Paragraph("Changes since last scan", h2))
    if job.first_run:
        story.append(Paragraph("First run - this scan established the baseline.", body))
    else:
        story.append(Paragraph(T(f"New assets: {len(d.get('new_assets', []))}  |  Disappeared: "
                                 f"{len(d.get('gone_assets', []))}  |  New findings: {len(d.get('new_findings', []))}  |  "
                                 f"Resolved: {len(d.get('resolved_findings', []))}"), body))
        for k in d.get("new_assets", [])[:25]:
            story.append(Paragraph(T("+ " + k), small))

    plan = build_plan(job)
    story.append(Paragraph(f"Remediation plan ({len(plan)} actions)", h2))
    if not plan:
        story.append(Paragraph("Nothing to fix in the scanned scope.", body))
    for g in plan:
        blk = [Paragraph(f"{sev(g['severity'])} &nbsp;#{g['priority']} {T(g['title'])} "
                         f"<font color='#64748b' size=8>- {T(g['when'])}, {len(g['assets'])} asset(s)</font>", h3)]
        if g["description"]:
            blk.append(Paragraph(T(g["description"]), body))
        if g["remediation"]:
            blk.append(Paragraph("<b>How to fix:</b> " + T(g["remediation"]), body))
        if g["fix_snippet"]:
            blk.append(code(g["fix_snippet"]))
        shown = g["assets"][:12]
        blk.append(Paragraph("<b>Affected:</b> " + T("; ".join(
            a["asset"] + (f" ({a['evidence'][:70]})" if a["evidence"] else "") for a in shown))
            + (f" ... +{len(g['assets']) - 12} more" if len(g["assets"]) > 12 else ""), small))
        blk.append(Spacer(1, 8))
        story.append(KeepTogether(blk[:3]))
        story += blk[3:]

    story.append(Paragraph(f"Asset inventory ({len(job.assets)})", h2))
    rows = [[Paragraph("<b>Kind</b>", small), Paragraph("<b>Value</b>", small), Paragraph("<b>Source</b>", small)]]
    for a in job.assets[:150]:
        rows.append([Paragraph(T(a.kind), small), Paragraph(T(a.value), small), Paragraph(T(a.source), small)])
    at = Table(rows, colWidths=[28 * mm, 110 * mm, 36 * mm], repeatRows=1)
    at.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), .3, colors.lightgrey), ("VALIGN", (0, 0), (-1, -1), "TOP")]))
    story.append(at)
    if len(job.assets) > 150:
        story.append(Paragraph(f"... {len(job.assets) - 150} more in the JSON report.", small))

    def footer(canvas, doc):
        canvas.saveState()
        canvas.setFont(reg, 7)
        canvas.setFillColor(colors.HexColor("#64748b"))
        canvas.drawString(15 * mm, 8 * mm, T(f"Umbra v{__version__} - {cfg.get('report.author', '')}"))
        canvas.drawRightString(195 * mm, 8 * mm, f"Page {doc.page}")
        canvas.restoreState()

    SimpleDocTemplate(str(path), pagesize=A4, leftMargin=15 * mm, rightMargin=15 * mm,
                      topMargin=14 * mm, bottomMargin=16 * mm, title="Umbra Report",
                      author="Umbra").build(story, onFirstPage=footer, onLaterPages=footer)


# ---------------------------------------------------------------- entry
def generate(job: ScanJob, cfg, out_dir: Path, formats: list[str], slug: str = "scan") -> dict[str, str]:
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = job.finished.replace(":", "").replace("-", "")[:15]
    base = out_dir / f"umbra_{slug}_{stamp}"
    paths: dict[str, str] = {}
    if "json" in formats:
        p = base.with_suffix(".json")
        p.write_text(json.dumps(to_dict(job), indent=2, ensure_ascii=False), encoding="utf-8")
        paths["json"] = str(p)
    if "html" in formats:
        p = base.with_suffix(".html")
        p.write_text(render_html(job, cfg), encoding="utf-8")
        paths["html"] = str(p)
    if "pdf" in formats:
        p = base.with_suffix(".pdf")
        try:
            render_pdf(job, cfg, p)
            paths["pdf"] = str(p)
        except Exception as ex:  # a PDF problem must never lose the scan
            paths["pdf_error"] = f"{type(ex).__name__}: {ex}"
    return paths
