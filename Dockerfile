FROM python:3.10-slim

# ---- Security posture: keep base minimal & up-to-date tooling ----
RUN pip install --upgrade --no-cache-dir pip "setuptools>=78.1.1"

WORKDIR /app

# Install Python deps first for better layer caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the application code
COPY app/ ./app

# ---- Security posture at runtime ----
RUN addgroup --system appgroup && adduser --system --ingroup appgroup appuser
USER appuser:appgroup

# Expose API port
EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
