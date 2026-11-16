"""API REST con FastAPI y el frontend estatico."""

import logging
import threading
import time
from collections import defaultdict, deque
from pathlib import Path
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator

from dnsinspector import __version__
from dnsinspector.analyzer import MAX_SELECTORS, analyze
from dnsinspector.compare import compare_reports
from dnsinspector.config import Settings
from dnsinspector.dns_engine import LOOKUP_TYPES, DnsEngine
from dnsinspector.reports import to_json, to_pdf
from dnsinspector.storage import Storage
from dnsinspector.validation import (
    ValidationError,
    normalize_domain,
    normalize_selector,
    parse_public_ip,
)

logger = logging.getLogger(__name__)
STATIC_DIR = Path(__file__).parent / "static"


class AnalysisRequest(BaseModel):
    domain: str = Field(..., max_length=300)
    dkim_selectors: list[str] = Field(default_factory=list, max_length=MAX_SELECTORS)

    @field_validator("domain")
    @classmethod
    def _domain(cls, value: str) -> str:
        return normalize_domain(value)

    @field_validator("dkim_selectors")
    @classmethod
    def _selectors(cls, value: list[str]) -> list[str]:
        # quitamos vacios y repetidos manteniendo el orden
        return list(dict.fromkeys(normalize_selector(s) for s in value if s.strip()))


class RateLimiter:
    """Limite simple por IP con ventana deslizante de 60 segundos.

    shortcut: vive en memoria de un solo proceso; con varios workers usar Redis o el proxy.
    """

    def __init__(self, per_minute: int) -> None:
        self.per_minute = per_minute
        self.hits: dict[str, deque[float]] = defaultdict(deque)
        self.lock = threading.Lock()

    def __call__(self, request: Request) -> None:
        if self.per_minute <= 0:
            return
        client = request.client.host if request.client else "unknown"
        now = time.monotonic()
        with self.lock:
            hits = self.hits[client]
            while hits and now - hits[0] > 60:
                hits.popleft()
            if len(hits) >= self.per_minute:
                raise HTTPException(429, "Too many requests, please wait a minute")
            hits.append(now)


def _bad_input(exc: ValidationError) -> HTTPException:
    return HTTPException(422, str(exc))


def create_app(
    settings: Settings | None = None,
    engine: DnsEngine | None = None,
    storage: Storage | None = None,
) -> FastAPI:
    settings = settings or Settings()
    logging.basicConfig(
        level=settings.log_level, format="%(asctime)s %(levelname)s %(name)s: %(message)s"
    )
    engine = engine or DnsEngine(settings)
    storage = storage or Storage(settings.database_path)
    limiter = RateLimiter(settings.rate_limit_per_minute)
    limited = [Depends(limiter)]

    app = FastAPI(title="DNSInspector", version=__version__, docs_url="/api/docs")

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        if not request.url.path.startswith("/api/docs"):
            # el swagger carga cosas de un CDN, por eso no le ponemos la CSP
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; img-src 'self' data:; frame-ancestors 'none'"
            )
        return response

    def get_report(analysis_id: int) -> dict:
        report = storage.get(analysis_id)
        if report is None:
            raise HTTPException(404, "Analysis not found")
        return report

    @app.get("/api/health")
    def health() -> dict:
        return {"status": "ok", "version": __version__}

    @app.get("/api/lookup", dependencies=limited)
    def lookup(
        name: Annotated[str, Query(max_length=300)],
        rtype: Annotated[str, Query(alias="type")] = "ALL",
    ) -> dict:
        try:
            ip = parse_public_ip(name)
            if ip:
                return {"query": ip, "kind": "ptr", "results": [engine.reverse(ip).to_dict()]}
            domain = normalize_domain(name)
        except ValidationError as exc:
            raise _bad_input(exc) from exc
        rtype = rtype.upper()
        if rtype != "ALL" and rtype not in LOOKUP_TYPES:
            raise HTTPException(422, f"Type must be ALL or one of {', '.join(LOOKUP_TYPES)}")
        types = LOOKUP_TYPES if rtype == "ALL" else [rtype]
        results = [engine.query(domain, t).to_dict() for t in types]
        return {"query": domain, "kind": "domain", "results": results}

    @app.post("/api/analyses", status_code=201, dependencies=limited)
    def create_analysis(body: AnalysisRequest) -> dict:
        report = analyze(engine, body.domain, body.dkim_selectors)
        return {"id": storage.save(report), **report}

    @app.get("/api/analyses")
    def list_analyses(
        domain: str | None = None,
        limit: Annotated[int, Query(ge=1, le=200)] = 50,
        offset: Annotated[int, Query(ge=0)] = 0,
    ) -> list[dict]:
        if domain:
            try:
                domain = normalize_domain(domain)
            except ValidationError as exc:
                raise _bad_input(exc) from exc
        return storage.list(domain, limit, offset)

    @app.get("/api/analyses/{analysis_id}")
    def read_analysis(analysis_id: int) -> dict:
        return get_report(analysis_id)

    @app.delete("/api/analyses/{analysis_id}", status_code=204)
    def delete_analysis(analysis_id: int) -> Response:
        if not storage.delete(analysis_id):
            raise HTTPException(404, "Analysis not found")
        return Response(status_code=204)

    @app.get("/api/analyses/{analysis_id}/report.{fmt}")
    def download_report(analysis_id: int, fmt: str) -> Response:
        report = get_report(analysis_id)
        filename = f"dnsinspector-{report['domain']}-{analysis_id}.{fmt}"
        headers = {"Content-Disposition": f'attachment; filename="{filename}"'}
        if fmt == "json":
            return Response(to_json(report), media_type="application/json", headers=headers)
        if fmt == "pdf":
            return Response(to_pdf(report), media_type="application/pdf", headers=headers)
        raise HTTPException(404, "Format must be json or pdf")

    @app.get("/api/compare")
    def compare(a: int, b: int) -> dict:
        try:
            return compare_reports(get_report(a), get_report(b))
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc

    app.mount("/", StaticFiles(directory=STATIC_DIR, html=True), name="static")
    return app
