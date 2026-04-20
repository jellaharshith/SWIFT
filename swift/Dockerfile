# Stage 1: builder
FROM python:3.10-slim AS builder
WORKDIR /build
COPY requirement.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirement.txt

# Stage 2: runtime
FROM python:3.10-slim
WORKDIR /app
COPY --from=builder /install /usr/local
COPY . .

# Remove venv and test artifacts from image
RUN rm -rf .venv __pycache__ test/.venv

# Set environment
ENV PYTHONPATH=/app
ENV SWIFT_ENV=apprunner
ENV PYTHONUNBUFFERED=1

# Create data directory for SQLite (AppRunner needs writable dir)
RUN mkdir -p /data && chmod 777 /data

EXPOSE 8000

# Health check to track startup
HEALTHCHECK --interval=10s --timeout=5s --start-period=30s --retries=3 \
  CMD python -c "import requests; requests.get('http://localhost:8000/')" || exit 1

# Start uvicorn with error output
CMD ["uvicorn", "web.app:app", "--host", "0.0.0.0", "--port", "8000", "--log-level", "info"]
