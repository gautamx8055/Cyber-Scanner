FROM python:3.12-slim

WORKDIR /app

# Install system dependencies needed by some packages.
# - gcc / libpq-dev / libffi-dev: build hooks for psycopg-style wheels.
# - libpango-1.0-0, libpangoft2-1.0-0, libharfbuzz0b, libfontconfig1: required
#   by WeasyPrint (Phase 7.2) at *runtime*. WeasyPrint loads these via ctypes,
#   so they have to be in the final image, not just at build time.
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    libffi-dev \
    libpango-1.0-0 \
    libpangoft2-1.0-0 \
    libharfbuzz0b \
    libfontconfig1 \
    && rm -rf /var/lib/apt/lists/*

COPY backend/requirements.txt .
RUN pip install --no-cache-dir --timeout 120 --retries 10 -r requirements.txt

# In dev, source is volume-mounted at /app — no COPY needed.
# For production builds, uncomment:
# COPY backend/ .

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
