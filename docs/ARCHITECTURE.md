# Architecture

DNSInspector is a small, layered Python application. Each layer only depends on the
layers below it, so the DNS and audit logic can be tested without the web API.

```
            Browser (static HTML/CSS/JS)
                       |
                 FastAPI (api.py)  -- rate limit, validation, HTTP errors
               /       |        \
      analyzer.py   storage.py   reports.py
           |         (SQLite)    (JSON / PDF)
   audits/ (spf, dkim, dmarc, dnssec, records)
           |
     dns_engine.py  (dnspython wrapper, status classification)
           |
   configured recursive resolver(s)
```

| Module | Responsibility |
|---|---|
| `config.py` | Settings loaded from environment variables. |
| `validation.py` | Domain, DKIM selector and IP validation (trust boundary). |
| `dns_engine.py` | Runs a single query and classifies the outcome as `ok`, `nodata`, `nxdomain`, `timeout` or `error`, with TTL, nameserver and response time. |
| `findings.py` | `Finding` model, severity levels and summary helpers. |
| `audits/*.py` | One module per check. Each returns a status dict and a list of findings. |
| `analyzer.py` | Orchestrates a full domain analysis and builds the report dict. |
| `storage.py` | SQLite persistence of reports (history) and the comparison logic. |
| `reports.py` | JSON and PDF export. |
| `api.py` | HTTP endpoints, rate limiting and static file serving. |

## Data model

A report is a plain JSON-serialisable dict:

```
{
  "domain", "started_at", "duration_ms", "resolver",
  "records":  { "A": QueryResult, "AAAA": ..., "MX", "CNAME", "TXT", "NS", "SOA" },
  "spf":      { "status", "record", "lookup_count", ... },
  "dkim":     { "status", "selectors": [...] },
  "dmarc":    { "status", "record", "tags", ... },
  "dnssec":   { "status", "ds", "dnskey", "ad_flag", "validation": {...} },
  "findings": [ Finding, ... ],
  "summary":  { "counts": {severity: n}, "highest_severity" }
}
```

SQLite table `analyses`: `id`, `domain`, `created_at`, `duration_ms`,
`highest_severity`, `counts` (JSON) and `report` (JSON). The full report is stored
as JSON because it is always read as a whole; the indexed columns are the ones
the history view filters and sorts by.

## Specifications used

| Topic | Reference |
|---|---|
| DNS basics, NXDOMAIN vs NODATA | RFC 1034, RFC 1035, RFC 2308 |
| Null MX | RFC 7505 |
| SPF syntax, 10 lookup limit, multiple records = permerror | RFC 7208 (sections 3.2, 4.6.4, 5) |
| DKIM key record tags | RFC 6376 section 3.6.1, RFC 8301 (RSA >= 1024, 2048 recommended), RFC 8463 (Ed25519) |
| DMARC tags and policy discovery | RFC 7489 sections 6.3 and 6.6.3 |
| DMARC organizational domain | RFC 7489 section 3.2, Public Suffix List |
| DNSSEC records, DS digest, AD bit | RFC 4033, RFC 4034, RFC 4035, RFC 6840 |

## Key decisions

| Decision | Alternative | Reason |
|---|---|---|
| Synchronous dnspython in FastAPI sync endpoints | `dns.asyncresolver` | FastAPI runs sync endpoints in a thread pool; an analysis is ~15 queries, so async adds complexity with no visible gain. |
| `publicsuffix2` for the Public Suffix List | Fetching the list at runtime, `tldextract` | Ships the list inside the package, so analysis stays offline and deterministic; tiny, pure Python. The list can go stale until the package is updated. |
| `fpdf2` for PDF | ReportLab, WeasyPrint | Pure Python, no system libraries, small API. |
| Own in-memory rate limiter | `slowapi` | ~20 lines, no extra dependency. Single-process only (documented). |
| stdlib `sqlite3` | SQLAlchemy | One table, a handful of queries. |
| `dnspython[dnssec]` (cryptography) | Only presence checks | Lets us verify the DS -> DNSKEY link and the DNSKEY RRSIG locally, and measure DKIM RSA key sizes exactly. |
| No numeric score | Weighted score | Requirements ask to avoid scores without a documented rule; we report counts per severity and the highest severity instead. See `docs/FINDINGS.md`. |
| Vanilla JS frontend | React/Vue | Three views, no build step needed. |
