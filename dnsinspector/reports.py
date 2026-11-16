"""Exportar informes en JSON y PDF."""

import json

from fpdf import FPDF

from dnsinspector.findings import SEVERITY_ORDER

SEVERITY_COLORS = {
    "critical": (153, 27, 27),
    "high": (194, 65, 12),
    "medium": (161, 98, 7),
    "low": (29, 78, 216),
    "info": (75, 85, 99),
}
AUDITS = (("SPF", "spf"), ("DKIM", "dkim"), ("DMARC", "dmarc"), ("DNSSEC", "dnssec"))


def to_json(report: dict) -> bytes:
    return json.dumps(report, indent=2, ensure_ascii=False).encode("utf-8")


def _latin1(text: object) -> str:
    # shortcut: las fuentes basicas del PDF solo tienen latin-1, lo raro sale como '?'.
    # si hace falta unicode completo, meter una fuente TTF
    return str(text).encode("latin-1", errors="replace").decode("latin-1")


class _ReportPDF(FPDF):
    def header(self) -> None:
        self.set_font("Helvetica", "B", 9)
        self.set_text_color(100, 100, 100)
        self.cell(0, 6, "DNSInspector report", new_x="LMARGIN", new_y="NEXT")
        self.ln(2)

    def footer(self) -> None:
        self.set_y(-12)
        self.set_font("Helvetica", "", 8)
        self.set_text_color(120, 120, 120)
        self.cell(0, 6, f"Page {self.page_no()}/{{nb}}", align="C")

    def heading(self, text: str) -> None:
        self.ln(3)
        self.set_font("Helvetica", "B", 13)
        self.set_text_color(17, 24, 39)
        self.cell(0, 8, _latin1(text), new_x="LMARGIN", new_y="NEXT")

    def line_text(self, text: str, size: int = 10, style: str = "", mono: bool = False) -> None:
        self.set_font("Courier" if mono else "Helvetica", style, size)
        self.set_text_color(31, 41, 55)
        self.multi_cell(0, 5, _latin1(text), align="L", new_x="LMARGIN", new_y="NEXT")

    def row(self, cells: list[str], widths: list[int], bold: bool = False) -> None:
        self.set_font("Helvetica", "B" if bold else "", 9)
        self.set_text_color(31, 41, 55)
        for text, width in zip(cells, widths, strict=True):
            self.cell(width, 6, _latin1(text)[:60], border="B")
        self.ln()


def to_pdf(report: dict) -> bytes:
    pdf = _ReportPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    pdf.set_font("Helvetica", "B", 20)
    pdf.cell(0, 12, _latin1(report["domain"]), new_x="LMARGIN", new_y="NEXT")
    pdf.line_text(
        f"Analysis date: {report['started_at']}    Duration: {report['duration_ms']} ms\n"
        f"Resolver: {', '.join(report.get('resolver', []))}    "
        f"Tool version: {report.get('tool_version', '-')}",
        size=9,
    )

    pdf.heading("Summary")
    counts = report["summary"]["counts"]
    pdf.row([s.value.capitalize() for s in SEVERITY_ORDER], [36] * 5, bold=True)
    pdf.row([str(counts[s.value]) for s in SEVERITY_ORDER], [36] * 5)
    pdf.ln(2)
    pdf.row(["Check", "Status"], [40, 140], bold=True)
    for label, key in AUDITS:
        pdf.row([label, str(report.get(key, {}).get("status", "-"))], [40, 140])

    pdf.heading("Findings")
    if not report["findings"]:
        pdf.line_text("No findings.")
    for finding in report["findings"]:
        _finding_block(pdf, finding)

    pdf.heading("DNS records")
    for rtype, result in report["records"].items():
        ttl = f"TTL {result['ttl']}" if result.get("ttl") is not None else ""
        pdf.line_text(f"{rtype}  [{result['status']}]  {ttl}", size=10, style="B")
        values = result["records"] or [result.get("error") or "-"]
        pdf.line_text("\n".join(values), size=8, mono=True)

    pdf.heading("Notes")
    pdf.line_text(
        "DKIM: only public key records were checked; this does not prove that mail is "
        "correctly signed. DNSSEC: the DS/DNSKEY link and the DNSKEY signature are verified "
        "locally; the full chain of trust to the root is not validated.",
        size=9,
    )
    return bytes(pdf.output())


def _finding_block(pdf: _ReportPDF, finding: dict) -> None:
    color = SEVERITY_COLORS.get(finding["severity"], (0, 0, 0))
    pdf.ln(2)
    pdf.set_font("Helvetica", "B", 9)
    pdf.set_fill_color(*color)
    pdf.set_text_color(255, 255, 255)
    pdf.cell(22, 6, finding["severity"].upper(), fill=True, align="C")
    pdf.set_text_color(17, 24, 39)
    pdf.set_font("Helvetica", "B", 11)
    pdf.cell(0, 6, _latin1(f"  {finding['id']}  {finding['title']}"), new_x="LMARGIN", new_y="NEXT")
    pdf.line_text(finding["description"], size=9)
    pdf.line_text(f"Category: {finding['category']}", size=8)
    pdf.line_text(finding["evidence"], size=8, mono=True)
    pdf.line_text(f"Recommendation: {finding['recommendation']}", size=9, style="B")
    if finding.get("reference"):
        pdf.line_text(f"Reference: {finding['reference']}", size=8)
