FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    HOST=0.0.0.0 \
    PORT=8000 \
    DATABASE_PATH=/data/dnsinspector.db

WORKDIR /app

# usuario sin privilegios para no correr como root
RUN useradd --create-home --uid 1000 app && mkdir /data && chown app:app /data

COPY pyproject.toml README.md LICENSE ./
COPY dnsinspector ./dnsinspector
RUN pip install .

USER app
EXPOSE 8000
VOLUME ["/data"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/health')"

CMD ["dnsinspector"]
