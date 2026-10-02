FROM python:3.12-alpine AS builder
ARG APP_VERSION

RUN apk add --no-cache build-base libffi-dev

WORKDIR /app
COPY pyproject.toml .
COPY app ./app
RUN python -m venv /opt/venv \
    && /opt/venv/bin/python -m pip install --no-cache-dir --upgrade pip \
    && /opt/venv/bin/python -m pip install --no-cache-dir . \
    && /opt/venv/bin/python -m pip uninstall -y pip

FROM python:3.12-alpine AS runtime

RUN apk upgrade --no-cache \
    && /usr/local/bin/python -m pip uninstall -y pip

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
