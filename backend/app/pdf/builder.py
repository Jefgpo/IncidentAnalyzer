"""Exportación del informe a PDF con ReportLab: portada, índice, tablas, gráficos, paginación y clasificación."""
from __future__ import annotations

import io
import os
from datetime import datetime

import matplotlib
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import cm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen import canvas as rl_canvas
from reportlab.platypus import (CondPageBreak, Image, KeepTogether, NextPageTemplate, PageBreak, PageTemplate,
                                Paragraph, Spacer, Table, TableStyle)
from reportlab.platypus.doctemplate import BaseDocTemplate
from reportlab.platypus.frames import Frame
from reportlab.platypus.tableofcontents import TableOfContents

from app.ingest.sanitizer import escape_markup
from app.lang import tx, using
from app.pdf.charts import CHARTS

# ---------------------------------------------------------------- fuentes (DejaVu viene con matplotlib)
_FONT_DIR = os.path.join(os.path.dirname(matplotlib.__file__), "mpl-data", "fonts", "ttf")
pdfmetrics.registerFont(TTFont("DejaVu", os.path.join(_FONT_DIR, "DejaVuSans.ttf")))
pdfmetrics.registerFont(TTFont("DejaVu-Bold", os.path.join(_FONT_DIR, "DejaVuSans-Bold.ttf")))
pdfmetrics.registerFont(TTFont("DejaVu-Oblique", os.path.join(_FONT_DIR, "DejaVuSans-Oblique.ttf")))
pdfmetrics.registerFont(TTFont("DejaVuMono", os.path.join(_FONT_DIR, "DejaVuSansMono.ttf")))
pdfmetrics.registerFontFamily("DejaVu", normal="DejaVu", bold="DejaVu-Bold", italic="DejaVu-Oblique",
                              boldItalic="DejaVu-Bold")

NAVY = colors.HexColor("#0f172a")
ACCENT = colors.HexColor("#0369a1")
MUTED = colors.HexColor("#64748b")
LINE = colors.HexColor("#cbd5e1")
ZEBRA = colors.HexColor("#f1f5f9")
RED = colors.HexColor("#b91c1c")
# colores por criticidad / nivel de riesgo (valores en español e inglés, según el idioma del informe)
SEV = {"Crítico": "#dc2626", "Alto": "#ea580c", "Medio": "#ca8a04", "Bajo": "#0284c7",
       "Critical": "#dc2626", "High": "#ea580c", "Medium": "#ca8a04", "Low": "#0284c7"}
KIND = {"hecho_observado": (("Hecho observado", "Observed fact"), "#047857"),
        "inferencia": (("Inferencia razonable", "Reasonable inference"), "#0369a1"),
        "hipotesis": (("Hipótesis a validar", "Hypothesis to validate"), "#b45309"),
        "recomendacion": (("Recomendación", "Recommendation"), "#475569")}
# columnas (en ambos idiomas) con contenido literal en monoespaciada, de criticidad y de texto libre
MONO_COLS = {"ID fila", "Row ID", "Fragmento", "Valor", "Value", "IP", "Timestamp", "Evento · fragmento literal",
             "Event · literal excerpt"}
SEV_COLS = ("Criticidad", "Nivel de riesgo", "Severity", "Risk level")
FLEX_COLS = {"Fragmento", "Evento · fragmento literal", "Por qué", "Qué es", "Cuándo actuar", "Nombre", "Factores",
             "Detalle", "Texto descartado", "Valor", "Mapeo de columnas (campo ← columna)", "Motivo", "Contexto",
             "Event · literal excerpt", "Why", "What it is", "When to act", "Name", "Factors", "Detail",
             "Discarded text", "Value", "Column mapping (field ← column)", "Reason", "Context"}

S = {
    "body": ParagraphStyle("body", fontName="DejaVu", fontSize=9, leading=12.5, spaceAfter=5),
    "small": ParagraphStyle("small", fontName="DejaVu", fontSize=7.5, leading=9.5),
    "cell": ParagraphStyle("cell", fontName="DejaVu", fontSize=7, leading=8.6),
    "cellmono": ParagraphStyle("cellmono", fontName="DejaVuMono", fontSize=6.4, leading=8),
    "cellhead": ParagraphStyle("cellhead", fontName="DejaVu-Bold", fontSize=7, leading=8.6, textColor=colors.white),
    "h1": ParagraphStyle("h1", fontName="DejaVu-Bold", fontSize=15, leading=19, textColor=NAVY, spaceBefore=4,
                         spaceAfter=8),
    "h2": ParagraphStyle("h2", fontName="DejaVu-Bold", fontSize=10.5, leading=13.5, textColor=ACCENT, spaceBefore=8,
                         spaceAfter=4),
    "h3": ParagraphStyle("h3", fontName="DejaVu-Bold", fontSize=9, leading=12, textColor=NAVY, spaceBefore=6,
                         spaceAfter=2),
    "toc1": ParagraphStyle("toc1", fontName="DejaVu", fontSize=10, leading=15, leftIndent=10),
    "cover_title": ParagraphStyle("ct", fontName="DejaVu-Bold", fontSize=24, leading=30, textColor=colors.white),
    "cover_sub": ParagraphStyle("cs", fontName="DejaVu", fontSize=12, leading=16, textColor=colors.HexColor("#cbd5e1")),
    "cover_meta": ParagraphStyle("cm", fontName="DejaVu", fontSize=10, leading=15, textColor=NAVY),
    "badge": ParagraphStyle("badge", fontName="DejaVu-Bold", fontSize=11, alignment=TA_CENTER, textColor=colors.white),
}


class NumberedCanvas(rl_canvas.Canvas):
    """Canvas que conoce el total de páginas para imprimir «Página X de Y»."""

    def __init__(self, *args, meta=None, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved = []
        self._meta = meta or {}

    def showPage(self):
        self._saved.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        total = len(self._saved)
        for state in self._saved:
            self.__dict__.update(state)
            if self._pageNumber > 1:
                self._decorate(total)
            super().showPage()
        super().save()

    def _decorate(self, total: int):
        w, h = A4
        m = self._meta
        self.setStrokeColor(LINE)
        self.setLineWidth(0.5)
        self.line(1.8 * cm, h - 1.45 * cm, w - 1.8 * cm, h - 1.45 * cm)
        self.line(1.8 * cm, 1.45 * cm, w - 1.8 * cm, 1.45 * cm)
        self.setFont("DejaVu", 7.5)
        self.setFillColor(MUTED)
        self.drawString(1.8 * cm, h - 1.2 * cm, f"IncidentAnalyzer · {m.get('title', '')}")
        self.setFillColor(RED)
        self.setFont("DejaVu-Bold", 7.5)
        self.drawRightString(w - 1.8 * cm, h - 1.2 * cm, m.get("classification", tx("CONFIDENCIAL", "CONFIDENTIAL")))
        self.setFont("DejaVu", 7.5)
        self.setFillColor(MUTED)
        self.drawString(1.8 * cm, 1.0 * cm, f"{m.get('client', '')} · v{m.get('version', 1)} · {m.get('date', '')}")
        self.drawRightString(w - 1.8 * cm, 1.0 * cm, tx(f"Página {self._pageNumber} de {total}",
                                                        f"Page {self._pageNumber} of {total}"))


class ReportDoc(BaseDocTemplate):
    def __init__(self, buf, meta, **kw):
        super().__init__(buf, pagesize=A4, leftMargin=1.8 * cm, rightMargin=1.8 * cm, topMargin=1.9 * cm,
                         bottomMargin=1.9 * cm, title=meta["title"], author=meta.get("analyst", ""),
                         subject=f"{meta['title']} – {meta.get('classification', 'CONFIDENCIAL')}", creator="IncidentAnalyzer", **kw)
        frame = Frame(self.leftMargin, self.bottomMargin, self.width, self.height, id="f")
        self.addPageTemplates([PageTemplate(id="cover", frames=[frame], onPage=self._cover_bg),
                               PageTemplate(id="body", frames=[frame])])
        self.meta = meta

    def _cover_bg(self, canv, doc):
        w, h = A4
        canv.saveState()
        canv.setFillColor(NAVY)
        canv.rect(0, h - 11 * cm, w, 11 * cm, fill=1, stroke=0)
        canv.setFillColor(ACCENT)
        canv.rect(0, h - 11.25 * cm, w, 0.25 * cm, fill=1, stroke=0)
        canv.setFillColor(RED)
        canv.rect(w - 6.3 * cm, h - 2.6 * cm, 4.5 * cm, 0.9 * cm, fill=1, stroke=0)
        canv.setFillColor(colors.white)
        canv.setFont("DejaVu-Bold", 11)
        canv.drawCentredString(w - 4.05 * cm, h - 2.27 * cm, self.meta.get("classification", tx("CONFIDENCIAL", "CONFIDENTIAL")))
        canv.restoreState()

    def afterFlowable(self, flowable):
        if isinstance(flowable, Paragraph) and flowable.style.name == "h1":
            text = flowable.getPlainText()
            key = f"h1-{abs(hash(text))}"
            self.canv.bookmarkPage(key)
            self.canv.addOutlineEntry(text, key, level=0)
            self.notify("TOCEntry", (0, text, self.page, key))


def _tag(kind: str, origin: str, review: list | None = None) -> str:
    parts = []
    if kind in KIND:
        label, color = KIND[kind]
        label = tx(*label)
        parts.append(f'<font color="{color}" size="7"><b>[{label}]</b></font>')
    if origin == "ia":
        parts.append('<font color="#6d28d9" size="7"><b>[' + tx("Generado por IA · validado", "AI-generated · validated") + ']</b></font>')
    elif origin == "editado":
        parts.append('<font color="#b45309" size="7"><b>[' + tx("Editado por analista", "Edited by analyst") + ']</b></font>')
    if review:
        parts.append('<font color="#b91c1c" size="7"><b>[' + tx("Requiere revisión", "Needs review") + ']</b></font>')
    return " ".join(parts) + (" " if parts else "")


def _refs(rows: list[str]) -> str:
    if not rows:
        return ""
    shown = ", ".join(escape_markup(r) for r in rows[:6])
    more = f" (+{len(rows) - 6})" if len(rows) > 6 else ""
    return f' <font color="#64748b" size="7">{tx("Filas", "Rows")}: {shown}{more}</font>'


def _cell(v, mono=False):
    text = escape_markup("" if v is None else str(v))
    return Paragraph(text, S["cellmono" if mono else "cell"])


def _table(block: dict, width: float):
    cols = block["columns"]
    mono_cols = {i for i, c in enumerate(cols) if c in MONO_COLS}
    data = [[Paragraph(escape_markup(c), S["cellhead"]) for c in cols]]
    sev_col = next((cols.index(c) for c in SEV_COLS if c in cols), -1)
    for row in block["rows"]:
        cells = [_cell(v, i in mono_cols) for i, v in enumerate(row)]
        if sev_col >= 0 and str(row[sev_col]) in SEV:
            cells[sev_col] = Paragraph(f'<font color="{SEV[str(row[sev_col])]}"><b>{row[sev_col]}</b></font>', S["cell"])
        data.append(cells)
    # anchos: columnas cortas a su ancho natural; el resto del ancho va a las columnas de texto libre
    flex_names = FLEX_COLS
    need = []
    for i, c in enumerate(cols):
        font, size = ("DejaVuMono", 6.4) if i in mono_cols else ("DejaVu", 7)
        split = c == "Timestamp" and len(cols) > 5  # fecha y hora en dos líneas
        longest = max((pdfmetrics.stringWidth(part, font, size) for r in block["rows"][:200] if i < len(r)
                       for part in (str(r[i]).split(" ") if split else [str(r[i])])), default=0)
        need.append(max(pdfmetrics.stringWidth(c, "DejaVu-Bold", 7), longest) + 8)
    flex = [i for i, c in enumerate(cols) if c in flex_names or need[i] > width * 0.3]
    fixed = sum(need[i] for i in range(len(cols)) if i not in flex)
    remaining = width - fixed
    if flex:
        min_flex = min(width * 0.33, sum(need[i] for i in flex))
        scale = 1.0
        if remaining < min_flex:  # encoger proporcionalmente las columnas cortas
            scale = (width - min_flex) / fixed
            remaining = min_flex
        total_flex = sum(min(need[i], width) for i in flex)
        widths = [need[i] * scale if i not in flex else remaining * min(need[i], width) / total_flex
                  for i in range(len(cols))]
    else:
        widths = [width * n / sum(need) for n in need]
    t = Table(data, colWidths=widths, repeatRows=1)
    style = [("BACKGROUND", (0, 0), (-1, 0), NAVY), ("VALIGN", (0, 0), (-1, -1), "TOP"),
             ("GRID", (0, 0), (-1, -1), 0.25, LINE), ("LEFTPADDING", (0, 0), (-1, -1), 3),
             ("RIGHTPADDING", (0, 0), (-1, -1), 3), ("TOPPADDING", (0, 0), (-1, -1), 2), ("BOTTOMPADDING", (0, 0), (-1, -1), 2)]
    for r in range(1, len(data)):
        if r % 2 == 0:
            style.append(("BACKGROUND", (0, r), (-1, r), ZEBRA))
    t.setStyle(TableStyle(style))
    return t


def build_pdf(report: dict, dashboard: dict) -> bytes:
    with using(report["meta"].get("lang", "es")):
        return _build_pdf(report, dashboard)


def _build_pdf(report: dict, dashboard: dict) -> bytes:
    meta = report["meta"]
    executive = meta.get("kind") == "ejecutivo"
    date = datetime.fromisoformat(meta["generated_at"]).strftime("%d/%m/%Y %H:%M")
    buf = io.BytesIO()
    doc = ReportDoc(buf, meta)
    width = doc.width
    story = []

    # portada
    story += [Spacer(1, 2.6 * cm), Paragraph("INCIDENTANALYZER", S["cover_sub"]), Spacer(1, 0.3 * cm),
              Paragraph(escape_markup(meta["title"]), S["cover_title"]), Spacer(1, 0.4 * cm),
              Paragraph(tx("Cliente: ", "Client: ") + escape_markup(meta["client"]), S["cover_sub"]), Spacer(1, 4.6 * cm)]
    ai_txt = (tx(f"Sí ({meta.get('ai_model')}) – textos rotulados y validados contra los logs",
                 f"Yes ({meta.get('ai_model')}) – texts labelled and validated against the logs")
              if meta.get("ai_used") else
              tx("No – informe generado con plantillas determinísticas", "No – report generated from deterministic templates"))
    cover_rows = [[tx("Clasificación", "Classification"),
                   meta["classification"] + tx(" – uso restringido al cliente y al equipo de respuesta",
                                               " – restricted to the client and the response team")],
                  [tx("Archivo analizado", "File analyzed"), meta["source_file"]], [tx("Analista", "Analyst"), meta["analyst"]],
                  [tx("Fecha de emisión", "Issue date"), date], [tx("Versión", "Version"), f"v{meta['version']}"],
                  [tx("Asistencia de IA", "AI assistance"), ai_txt]]
    ct = Table([[Paragraph(f"<b>{escape_markup(k)}</b>", S["cover_meta"]), Paragraph(escape_markup(v), S["cover_meta"])]
                for k, v in cover_rows], colWidths=[4.2 * cm, width - 4.2 * cm])
    ct.setStyle(TableStyle([("LINEBELOW", (0, 0), (-1, -1), 0.4, LINE), ("VALIGN", (0, 0), (-1, -1), "TOP"),
                            ("BOTTOMPADDING", (0, 0), (-1, -1), 6)]))
    story += [ct, Spacer(1, 1.2 * cm), Paragraph(
        tx("Este documento contiene información sensible sobre la seguridad del cliente. No distribuir fuera de los "
           "destinatarios autorizados. Todas las conclusiones se sustentan en filas identificadas del archivo provisto.",
           "This document contains sensitive information about the client's security. Do not distribute beyond the "
           "authorized recipients. Every conclusion is backed by identified rows of the provided file."),
        S["small"]), NextPageTemplate("body"), PageBreak()]

    # índice
    toc = TableOfContents()
    toc.levelStyles = [S["toc1"]]
    toc.dotsMinLevel = 0
    story += [Paragraph(tx("Índice", "Contents"), ParagraphStyle("toch", parent=S["h1"])), toc, PageBreak()]

    for sec in report["sections"]:
        if sec["number"] in ("A",):
            story.append(PageBreak())
        else:
            story.append(CondPageBreak(6 * cm))
        story.append(Paragraph(escape_markup(f"{sec['number']}. {sec['title']}" if sec["number"].isdigit()
                                             else sec["title"]), S["h1"]))
        for b in sec["blocks"]:
            title = b.get("title")
            if title and b["type"] != "chart":
                story.append(Paragraph(escape_markup(title), S["h3" if b["type"] == "paragraph" else "h2"]))
            if b["type"] == "paragraph":
                tag = "" if executive and b["origin"] == "determinista" else _tag(b["kind"], b["origin"], b.get("review"))
                story.append(Paragraph(tag + escape_markup(b["text"]) + _refs(b.get("row_refs", [])), S["body"]))
            elif b["type"] == "list":
                head = "" if executive and b["origin"] == "determinista" else _tag(b["kind"], b["origin"], b.get("review"))
                if head:
                    story.append(Paragraph(head, S["small"]))
                for item in b.get("items", []):
                    story.append(Paragraph("• " + escape_markup(item), ParagraphStyle(
                        "li", parent=S["body"], leftIndent=10, firstLineIndent=-7, spaceAfter=2)))
                story.append(Spacer(1, 4))
            elif b["type"] == "table":
                if b["rows"]:
                    story.append(_table(b, width))
                else:
                    story.append(Paragraph(tx("Sin datos.", "No data."), S["small"]))
                story.append(Spacer(1, 6))
            elif b["type"] == "chart" and b["chart"] in CHARTS:
                png = CHARTS[b["chart"]](dashboard)
                img = Image(png)
                ratio = img.imageHeight / img.imageWidth
                img.drawWidth = width * (0.92 if b["chart"] in ("timeline", "heatmap") else 0.8)
                img.drawHeight = img.drawWidth * ratio
                story.append(KeepTogether([Paragraph(escape_markup(b.get("title") or ""), S["h3"]), img, Spacer(1, 6)]))
        if sec["id"] == "limitaciones" and report.get("ai_review"):
            story.append(Paragraph(tx("Afirmaciones de IA descartadas por la validación automática",
                                      "AI claims discarded by automatic validation"), S["h2"]))
            story.append(_table({"columns": [tx("Sección", "Section"), tx("Motivo", "Reason"), tx("Texto descartado", "Discarded text")],
                                 "rows": [[r["section"], r["reason"], r["text"][:220]] for r in report["ai_review"]]},
                                width))

    def canvasmaker(*args, **kwargs):
        return NumberedCanvas(*args, meta={**meta, "date": date}, **kwargs)

    doc.multiBuild(story, canvasmaker=canvasmaker)
    return buf.getvalue()
