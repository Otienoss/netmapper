"""ReportLab (Platypus) ile PDF rapor üretimi."""

from datetime import datetime, timezone
from pathlib import Path
from xml.sax.saxutils import escape as xml_escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from app.config import settings
from app.normalization.schema import HostResult
from app.reporting.risk_rules import HostRisk

# ---------------------------------------------------------------------------
# Türkçe karakter (ı, ğ, ş, İ, ...) desteği: Helvetica WinAnsi'de bu karakterler
# YOKTUR ve PDF'te "■" olarak görünür. Sistemde Türkçe destekli bir TrueType
# font varsa onu kaydet, yoksa Helvetica'ya düş (içerik yine okunur ama
# Türkçe karakterler bozuk görünür — sistem fontlarını kontrol edin).
# ---------------------------------------------------------------------------
_FONT_CANDIDATES = [
    ("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
     "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"),
    ("/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf",
     "/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf"),
]


def _register_fonts() -> tuple[str, str]:
    for regular, bold in _FONT_CANDIDATES:
        if Path(regular).exists() and Path(bold).exists():
            pdfmetrics.registerFont(TTFont("NetMapperSans", regular))
            pdfmetrics.registerFont(TTFont("NetMapperSans-Bold", bold))
            return "NetMapperSans", "NetMapperSans-Bold"
    return "Helvetica", "Helvetica-Bold"


BASE_FONT, BOLD_FONT = _register_fonts()

LEVEL_COLORS = {
    "high": colors.HexColor("#C0392B"),
    "medium": colors.HexColor("#E67E22"),
    "low": colors.HexColor("#F1C40F"),
    "info": colors.HexColor("#27AE60"),
}

_CELL = ParagraphStyle("cell", fontSize=8, leading=10, fontName=BASE_FONT)
_CELL_BOLD = ParagraphStyle(
    "cellb", fontSize=8, leading=10, fontName=BOLD_FONT
)


def build_pdf_report(
    scan_id: str,
    subnet: str,
    hosts: list[tuple[HostResult, HostRisk]],
    out_dir: str | None = None,
) -> Path:
    """Tarama sonuçlarını PDF olarak üretir, dosya yolunu döner."""
    out_dir_path = Path(out_dir or settings.report_output_dir)
    out_dir_path.mkdir(parents=True, exist_ok=True)
    out_path = out_dir_path / f"report_{scan_id}.pdf"

    styles = getSampleStyleSheet()
    # Hazır stiller Helvetica kullanır; Türkçe için kayıtlı fonta çevir
    for _name in ("Title", "Normal", "Heading2", "Heading3"):
        _st = styles[_name]
        _st.fontName = BOLD_FONT if "Bold" in _st.fontName else BASE_FONT
    h3 = ParagraphStyle("h3", parent=styles["Heading3"], spaceBefore=10, spaceAfter=4)

    doc = SimpleDocTemplate(
        str(out_path),
        pagesize=A4,
        leftMargin=1.5 * cm,
        rightMargin=1.5 * cm,
        topMargin=1.5 * cm,
        bottomMargin=1.5 * cm,
        title=f"NetMapper Raporu — {subnet}",
    )

    story = []
    story.append(Paragraph("NetMapper Ağ Tarama Raporu", styles["Title"]))
    story.append(Paragraph(f"Ağ aralığı: <b>{subnet}</b>", styles["Normal"]))
    story.append(Paragraph(f"Job / Scan ID: <b>{scan_id}</b>", styles["Normal"]))
    story.append(Paragraph(
        f"Tarih: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        styles["Normal"],
    ))
    story.append(Spacer(1, 8))

    # Özet tablosu
    total_hosts = len(hosts)
    high = sum(1 for _, r in hosts if r.level == "high")
    medium = sum(1 for _, r in hosts if r.level == "medium")
    story.append(Paragraph("Özet", styles["Heading2"]))
    summary_data = [
        [Paragraph("Bulunan host", _CELL_BOLD), Paragraph(str(total_hosts), _CELL)],
        [Paragraph("Yüksek riskli host", _CELL_BOLD), Paragraph(str(high), _CELL)],
        [Paragraph("Orta riskli host", _CELL_BOLD), Paragraph(str(medium), _CELL)],
    ]
    summary = Table(summary_data, colWidths=[6 * cm, 3 * cm])
    summary.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#ECF0F1")),
    ]))
    story.append(summary)

    # Host bazlı detay
    for host, risk in hosts:
        title = f"{host.ip}"
        if host.hostname:
            title += f" ({host.hostname})"
        title += f" — Risk: {risk.level.upper()} · Skor {risk.score}/100"
        story.append(Paragraph(title, h3))

        if not host.services:
            story.append(Paragraph("Açık port bulunamadı (sadece host keşfi).", styles["Normal"]))
            continue

        rows: list[list[Paragraph]] = [[
            Paragraph("Port", _CELL_BOLD),
            Paragraph("Proto", _CELL_BOLD),
            Paragraph("Servis", _CELL_BOLD),
            Paragraph("Ürün / Sürüm", _CELL_BOLD),
            Paragraph("Risk", _CELL_BOLD),
            Paragraph("Gerekçe", _CELL_BOLD),
        ]]
        cell_styles = []
        for i, f in enumerate(risk.findings, start=1):
            rows.append([
                Paragraph(str(f.port), _CELL),
                Paragraph(f.protocol, _CELL),
                Paragraph(f.service_name or "-", _CELL),
                Paragraph(f.product, _CELL),
                Paragraph(f.level.upper(), _CELL),
                Paragraph("; ".join(f.reasons), _CELL),
            ])
            cell_styles.append(("TEXTCOLOR", (4, i), (4, i), LEVEL_COLORS[f.level]))

        table = Table(
            rows,
            colWidths=[1.4 * cm, 1.4 * cm, 2.4 * cm, 4.2 * cm, 1.8 * cm, 6.8 * cm],
            repeatRows=1,
        )
        table.setStyle(TableStyle([
            ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2C3E50")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1),
             [colors.white, colors.HexColor("#F7F9F9")]),
            *cell_styles,
        ]))
        story.append(table)

        # --- Nikto web bulguları ---
        if host.web_findings:
            nikto_h = ParagraphStyle(
                "nikto_h", parent=styles["Normal"],
                fontName=BOLD_FONT, fontSize=10.5,
                spaceBefore=10, spaceAfter=3,
            )
            story.append(Paragraph(
                f"Web Bulguları (Nikto) — {len(host.web_findings)} adet", nikto_h
            ))
            wrows: list[list[Paragraph]] = [[
                Paragraph("Seviye", _CELL_BOLD),
                Paragraph("Bulgu", _CELL_BOLD),
                Paragraph("URI", _CELL_BOLD),
            ]]
            wstyles = []
            for i, f in enumerate(host.web_findings[:30], start=1):
                wrows.append([
                    Paragraph(xml_escape(f.severity.upper()), _CELL),
                    Paragraph(xml_escape(f.message), _CELL),
                    Paragraph(xml_escape(f.uri or "-"), _CELL),
                ])
                wstyles.append(
                    ("TEXTCOLOR", (0, i), (0, i),
                     LEVEL_COLORS.get(f.severity, colors.black))
                )
            wtable = Table(wrows, colWidths=[2.0 * cm, 13.2 * cm, 2.8 * cm],
                           repeatRows=1)
            wtable.setStyle(TableStyle([
                ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#3D4A57")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1),
                 [colors.white, colors.HexColor("#F7F9F9")]),
                *wstyles,
            ]))
            story.append(wtable)
            if len(host.web_findings) > 30:
                story.append(Paragraph(
                    f"<i>… +{len(host.web_findings) - 30} bulgu daha (tamamı "
                    f"JSON sonuçlarında)</i>", styles["Normal"]
                ))

    story.append(Spacer(1, 14))
    story.append(Paragraph(
        "<i>Bu rapor yalnızca sahip olunan / tarama izni verilen ağlar için "
        "üretilmiştir. Risk skorları kural tabanlıdır (kural: risk_rules.py).</i>",
        styles["Normal"],
    ))

    doc.build(story)
    return out_path
