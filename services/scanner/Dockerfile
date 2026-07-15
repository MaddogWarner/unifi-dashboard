FROM python:3.12-alpine AS builder

RUN apk add --no-cache build-base libffi-dev

RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir fastapi uvicorn pydantic

FROM python:3.12-alpine

RUN apk add --no-cache nmap

WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PATH="/opt/venv/bin:$PATH"

COPY --from=builder /opt/venv /opt/venv
COPY scanner.py .

CMD ["python3", "-m", "uvicorn", "scanner:app", "--host", "0.0.0.0", "--port", "8002"]
