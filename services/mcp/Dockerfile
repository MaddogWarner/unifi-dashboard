FROM python:3.12-alpine AS builder
ARG APP_VERSION

RUN apk add --no-cache build-base libffi-dev

RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir "mcp[cli]>=1.0" "httpx>=0.27" "pydantic>=2.0"

FROM python:3.12-alpine

RUN addgroup -S app \
    && adduser -S -G app -u 10001 app

WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PATH="/opt/venv/bin:$PATH"

COPY --from=builder /opt/venv /opt/venv
COPY server.py .

USER app

CMD ["python", "server.py"]
