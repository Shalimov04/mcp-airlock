FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim AS build
WORKDIR /app
COPY pyproject.toml uv.lock README.md LICENSE ./
COPY src ./src
RUN uv sync --frozen --no-dev --no-editable

FROM python:3.12-slim-bookworm
COPY --from=build /app/.venv /app/.venv
ENV PATH=/app/.venv/bin:$PATH
RUN mkdir /data && chown 65532:65532 /data
WORKDIR /data
USER 65532:65532
EXPOSE 9000
ENTRYPOINT ["mcp-airlock", "--host", "0.0.0.0"]
CMD ["--help"]
