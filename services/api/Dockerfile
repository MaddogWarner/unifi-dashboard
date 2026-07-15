FROM python:3.12-alpine AS builder

RUN apk add --no-cache build-base libffi-dev

WORKDIR /app
COPY pyproject.toml .
COPY app ./app
RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir .

FROM python:3.12-alpine

RUN addgroup -S app \
    && adduser -S -G app -u 10001 app

WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PATH="/opt/venv/bin:$PATH"

COPY --from=builder /opt/venv /opt/venv
COPY alembic.ini .
COPY alembic ./alembic
COPY app ./app

USER app

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
