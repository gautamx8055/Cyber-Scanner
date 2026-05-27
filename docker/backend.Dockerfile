FROM python:3.12-slim

WORKDIR /app

# Install system dependencies needed by some packages (scapy, WeasyPrint, etc.)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

COPY backend/requirements.txt .
RUN pip install --no-cache-dir --timeout 120 --retries 10 -r requirements.txt

# In dev, source is volume-mounted at /app — no COPY needed.
# For production builds, uncomment:
# COPY backend/ .

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
