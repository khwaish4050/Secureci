from __future__ import annotations

from io import BytesIO
from typing import Any, Dict

try:
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.units import inch
    from reportlab.pdfgen import canvas
except Exception:  # pragma: no cover
    canvas = None


def build_pdf(*, scan: Dict[str, Any]) -> bytes:
    if canvas is None:
        raise RuntimeError("PDF support not installed (reportlab missing)")

    buf = BytesIO()
    c = canvas.Canvas(buf, pagesize=letter)
    width, height = letter

    y = height - 0.8 * inch
    c.setFont("Helvetica-Bold", 16)
    c.drawString(0.8 * inch, y, "SecureCI Report")

    y -= 0.35 * inch
    c.setFont("Helvetica", 10)
    c.drawString(0.8 * inch, y, f"Scan ID: {scan.get('id')}")
    y -= 0.2 * inch
    c.drawString(0.8 * inch, y, f"Target: {scan.get('target')}")
    y -= 0.2 * inch
    c.drawString(0.8 * inch, y, f"Status: {scan.get('status')}  Decision: {scan.get('decision')}  Risk: {scan.get('risk_score')}")

    y -= 0.35 * inch
    c.setFont("Helvetica-Bold", 12)
    c.drawString(0.8 * inch, y, "Summary")

    y -= 0.25 * inch
    c.setFont("Helvetica", 10)
    summary = scan.get("summary") or {}
    counts = (summary.get("counts") or {})
    c.drawString(0.8 * inch, y, f"Critical: {counts.get('critical', 0)}  High: {counts.get('high', 0)}  Medium: {counts.get('medium', 0)}  Low: {counts.get('low', 0)}")

    y -= 0.4 * inch
    c.setFont("Helvetica-Bold", 12)
    c.drawString(0.8 * inch, y, "Top Findings (first 12)")

    y -= 0.25 * inch
    c.setFont("Helvetica", 9)
    for f in (scan.get("findings") or [])[:12]:
        if y < 1.0 * inch:
            c.showPage()
            y = height - 0.8 * inch
            c.setFont("Helvetica", 9)
        sev = (f.get("severity") or "").upper()
        title = f.get("title") or ""
        loc = ""
        if f.get("file"):
            loc = f"{f.get('file')}:{f.get('line') or ''}".rstrip(":")
        line = f"[{sev}] {title} {loc}".strip()
        c.drawString(0.8 * inch, y, line[:110])
        y -= 0.18 * inch

    c.showPage()
    c.save()
    return buf.getvalue()

