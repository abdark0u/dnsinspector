"""Punto de entrada: servidor web o analisis por linea de comandos."""

import argparse
import os
import sys

import uvicorn

from dnsinspector.analyzer import MAX_SELECTORS, analyze
from dnsinspector.dns_engine import DnsEngine
from dnsinspector.findings import SEVERITY_ORDER
from dnsinspector.reports import to_json
from dnsinspector.validation import ValidationError, normalize_domain, normalize_selector


def serve() -> None:
    uvicorn.run(
        "dnsinspector.api:create_app",
        factory=True,
        host=os.getenv("HOST", "127.0.0.1"),
        port=int(os.getenv("PORT", "8000")),
    )


def format_text(report: dict) -> str:
    """Resumen corto para la terminal."""
    lines = [f"{report['domain']}  ({report['duration_ms']} ms)", ""]
    for key in ("nameservers", "spf", "dkim", "dmarc", "dnssec", "mta_sts", "bimi"):
        lines.append(f"  {key.upper():<12}{report[key]['status']}")
    lines.append("")
    for finding in report["findings"]:
        lines.append(f"  [{finding['severity'].upper():<8}] {finding['id']:<11} {finding['title']}")
    if not report["findings"]:
        lines.append("  No findings.")
    return "\n".join(lines)


def check(args: argparse.Namespace, engine: DnsEngine | None = None) -> int:
    """Analiza un dominio. Devuelve 1 si hay hallazgos de --fail-on o mas graves."""
    try:
        domain = normalize_domain(args.domain)
        selectors = [normalize_selector(s) for s in args.selector]
    except ValidationError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    report = analyze(engine or DnsEngine(), domain, selectors, args.probe_dkim)
    print(to_json(report).decode() if args.json else format_text(report))
    if args.fail_on:
        # severidades desde la mas grave hasta la elegida
        limit = [s.value for s in SEVERITY_ORDER[: SEVERITY_ORDER.index(args.fail_on) + 1]]
        if any(f["severity"] in limit for f in report["findings"]):
            return 1
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="dnsinspector")
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("serve", help="start the web app (default)")
    check_cmd = sub.add_parser("check", help="analyze a domain from the terminal")
    check_cmd.add_argument("domain")
    check_cmd.add_argument(
        "-s",
        "--selector",
        action="append",
        default=[],
        help=f"DKIM selector, can be repeated (max {MAX_SELECTORS})",
    )
    check_cmd.add_argument(
        "--probe-dkim",
        action="store_true",
        help="also probe 10 common DKIM selectors (10 extra DNS queries)",
    )
    check_cmd.add_argument("--json", action="store_true", help="print the full JSON report")
    check_cmd.add_argument(
        "--fail-on",
        choices=[s.value for s in SEVERITY_ORDER],
        help="exit with code 1 if there is a finding of this severity or worse",
    )
    return parser


def run(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "check":
        if len(args.selector) > MAX_SELECTORS:
            print(f"error: at most {MAX_SELECTORS} selectors", file=sys.stderr)
            return 2
        return check(args)
    serve()
    return 0


if __name__ == "__main__":
    sys.exit(run())
