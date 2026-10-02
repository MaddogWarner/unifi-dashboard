FROM python:3.12-alpine AS builder
ARG APP_VERSION

RUN apk add --no-cache build-base libffi-dev

RUN python -m venv /opt/venv \
    && /opt/venv/bin/python -m pip install --no-cache-dir --upgrade pip \
    && /opt/venv/bin/python -m pip install --no-cache-dir fastapi uvicorn pydantic \
    && /opt/venv/bin/python -m pip uninstall -y pip

FROM python:3.12-alpine AS runtime

RUN /usr/local/bin/python -m pip uninstall -y pip \
    && apk upgrade --no-cache \
    && apk add --no-cache nmap

WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PATH="/opt/venv/bin:$PATH"

COPY --from=builder /opt/venv /opt/venv
COPY scanner.py .

CMD ["python3", "-m", "uvicorn", "scanner:app", "--host", "0.0.0.0", "--port", "8002"]
