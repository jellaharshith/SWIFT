# Stage 1: builder
FROM python:3.10-slim AS builder
WORKDIR /build
COPY swift/requirement.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirement.txt

# Stage 2: runtime
FROM python:3.10-slim
WORKDIR /app
COPY --from=builder /install /usr/local
COPY swift/ .

# Remove venv and test artifacts from image
RUN rm -rf .venv __pycache__ test/.venv

# Install git (required for git clone in github_cloner.py) and create data dir
RUN apt-get update && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /data && chmod 777 /data

# Set environment
ENV PYTHONPATH=/app
ENV SWIFT_ENV=production
ENV PYTHONUNBUFFERED=1

EXPOSE 8000

# Start uvicorn with error output
CMD ["sh", "-c", "uvicorn web.app:app --host 0.0.0.0 --port ${PORT:-8000} --log-level info"]
