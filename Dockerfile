FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim AS build
WORKDIR /app
# .pyc at build time: the venv is root-owned and the root filesystem may be read-only, so the
# process (uid 65532) could never write them, and every start would pay the import cost
ENV UV_COMPILE_BYTECODE=1
COPY pyproject.toml uv.lock README.md LICENSE ./
COPY src ./src
RUN uv sync --frozen --no-dev --no-editable --extra postgres --extra otlp

FROM python:3.12-slim-bookworm
COPY --from=build /app/.venv /app/.venv
ENV PATH=/app/.venv/bin:$PATH
RUN mkdir /data && chown 65532:65532 /data
WORKDIR /data
USER 65532:65532
EXPOSE 9000
# python, not curl (the image has none). -I keeps /data and PYTHON* env off the import path.
# No proxy: HTTP_PROXY would route 127.0.0.1 through it.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --start-interval=1s --retries=3 \
  CMD ["python", "-I", "-c", "import urllib.request as u; u.build_opener(u.ProxyHandler({})).open('http://127.0.0.1:9000/healthz', timeout=4)"]
ENTRYPOINT ["mcp-airlock", "--host", "0.0.0.0"]
CMD ["--help"]
