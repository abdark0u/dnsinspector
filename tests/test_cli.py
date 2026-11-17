import json

from dnsinspector.dns_engine import DnsEngine
from dnsinspector.main import build_parser, check, run
from tests.fakes import FakeResolver
from tests.test_analyzer import GOOD_ZONE


def run_check(argv, data=GOOD_ZONE):
    args = build_parser().parse_args(["check", *argv])
    return check(args, DnsEngine(resolver=FakeResolver(data)))


def test_text_output(capsys):
    assert run_check(["Example.com"]) == 0
    out = capsys.readouterr().out
    assert "example.com" in out
    assert "SPF    ok" in out
    assert "DNSSEC-001" in out


def test_json_output(capsys):
    assert run_check(["example.com", "--json", "-s", "s1"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["dkim"]["selectors"][0]["selector"] == "s1"


def test_fail_on():
    assert run_check(["example.com", "--fail-on", "high"]) == 0
    assert run_check(["example.com", "--fail-on", "low"]) == 1


def test_invalid_input(capsys):
    assert run_check(["localhost"]) == 2
    assert "error" in capsys.readouterr().err
    assert run(["check", "example.com", *["-s", "x"] * 6]) == 2
