# Tiny, production-friendly Python image
FROM python:3.11-slim

WORKDIR /app

# Create non-root user
RUN useradd -u 10001 -m appuser

# Minimal runtime deps (curl for health/debug; remove if not needed)
RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

# Install deps first for better layer caching
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip setuptools wheel \
 && pip install --no-cache-dir -r requirements.txt

# Copy app code
COPY . /app

# Security hardening
USER appuser
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]