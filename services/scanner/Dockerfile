FROM python:3.12-slim

RUN apt-get update \
    && apt-get upgrade -y --no-install-recommends \
    && apt-get install -y --no-install-recommends nmap \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml .
RUN pip install --no-cache-dir fastapi uvicorn pydantic
COPY scanner.py .

CMD ["python3", "-m", "uvicorn", "scanner:app", "--host", "0.0.0.0", "--port", "8002"]
