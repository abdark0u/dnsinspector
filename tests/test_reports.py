import json

from dnsinspector.reports import to_json, to_pdf
from tests.test_analyzer import GOOD_ZONE
from tests.test_storage import report_for


def test_json_report_roundtrip():
    report = report_for(GOOD_ZONE)
    data = json.loads(to_json(report))
    assert data["domain"] == "example.com"
    assert data["findings"] == report["findings"]


def test_pdf_report_is_valid_pdf():
    data = {**GOOD_ZONE, ("example.com", "TXT"): ['"v=spf1 +all"', '"ünïcode → text"']}
    pdf = to_pdf(report_for(data))
    assert pdf.startswith(b"%PDF-")
    assert pdf.rstrip().endswith(b"%%EOF")
    assert len(pdf) > 1500


def test_pdf_handles_long_unbroken_values():
    data = {**GOOD_ZONE, ("example.com", "TXT"): ['"v=spf1 -all"', '"' + "A" * 240 + '"']}
    assert to_pdf(report_for(data)).startswith(b"%PDF-")
