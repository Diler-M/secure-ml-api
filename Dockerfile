# Multi-stage, slim, non-root, read-only-friendly
FROM python:3.11-slim AS builder
WORKDIR /app

# System deps (build tools kept only in builder)
RUN apt-get update && apt-get install -y --no-install-recommends build-essential gcc && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --upgrade pip && \
    pip wheel --wheel-dir=/wheels -r requirements.txt

# ---- Runtime image ----
FROM python:3.11-slim
WORKDIR /app

# Create non-root user
RUN useradd -u 10001 -m appuser

# Minimal runtime deps
RUN apt-get update && apt-get install -y --no-install-recommends curl && \
    rm -rf /var/lib/apt/lists/*

# Copy wheels and app
COPY --from=builder /wheels /wheels
COPY . /app

# Install from wheels for repeatable builds
RUN pip install --no-cache-dir --upgrade pip setuptools==78.1.1 wheel && \
    pip install --no-cache-dir /wheels/*

# Security hardening
USER appuser
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Uvicorn default port
EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]