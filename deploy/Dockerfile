# syntax=docker/dockerfile:1.7
# Reproducible build: dependencies come from uv.lock, never from a fresh resolution.
FROM ghcr.io/astral-sh/uv:0.12.20 AS uv
FROM python:3.13-slim AS builder
WORKDIR /build
COPY --from=uv /uv /usr/local/bin/uv
COPY pyproject.toml uv.lock README.md LICENSE ./
# Resolve third-party dependencies from the lock first (cacheable layer), then the project.
RUN uv export --frozen --no-dev --no-emit-project --no-hashes -o /tmp/requirements.txt \
 && uv venv /venv \
 && VIRTUAL_ENV=/venv uv pip install --no-cache -r /tmp/requirements.txt
COPY src ./src
RUN VIRTUAL_ENV=/venv uv pip install --no-cache --no-deps .

FROM python:3.13-slim
RUN groupadd -r writ && useradd -r -g writ -d /var/lib/writ -m writ \
 && mkdir -p /var/lib/writ && chown writ:writ /var/lib/writ
COPY --from=builder /venv /venv
COPY config /app/config
COPY templates /app/templates
ENV PATH="/venv/bin:$PATH" PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 \
    WRIT_COMMANDS_PATH=/app/config/commands.yaml
WORKDIR /app
USER writ
VOLUME ["/var/lib/writ"]
LABEL org.opencontainers.image.title="writ" \
      org.opencontainers.image.description="Execution authority for AI agents" \
      org.opencontainers.image.licenses="Apache-2.0"
# Service is chosen per container: writ-gate | writ-executor | writ-demo-saas
CMD ["writ-gate"]
