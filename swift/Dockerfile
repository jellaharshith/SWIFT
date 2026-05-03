# syntax=docker/dockerfile:1
# ── Stage 1: Build Python venv ─────────────────────────────────────────────────
FROM python:3.12-slim-bookworm AS builder

WORKDIR /build
COPY . /build

RUN python3 -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir --upgrade pip \
    && /opt/venv/bin/pip install --no-cache-dir "/build[sandbox,web]"

# ── Stage 2: Runtime (Kali Linux for offensive tools) ──────────────────────────
FROM kalilinux/kali-rolling AS runtime

ARG SWIFT_VERSION=2.0.0

LABEL org.opencontainers.image.title="SWIFT" \
      org.opencontainers.image.description="AI-Powered Vulnerability Scanner" \
      org.opencontainers.image.source="https://github.com/jellaharshith/SWIFT" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${SWIFT_VERSION}"

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    SWIFT_ENV=production \
    PATH="/opt/venv/bin:$PATH"

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    nmap \
    masscan \
    nikto \
    sqlmap \
    hydra \
    dirb \
    gobuster \
    exploitdb \
    git \
    curl \
    unzip \
    ca-certificates \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install nuclei (Go binary)
RUN curl -sL https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_linux_amd64.zip \
    -o /tmp/nuclei.zip \
    && unzip /tmp/nuclei.zip -d /usr/local/bin/ \
    && rm /tmp/nuclei.zip \
    && chmod +x /usr/local/bin/nuclei \
    && nuclei -update-templates 2>/dev/null || true

# Copy Python venv from builder
COPY --from=builder /opt/venv /opt/venv

# Non-root user
RUN groupadd -g 10001 swift \
    && useradd -u 10001 -g swift -m -s /bin/bash swift

USER swift
WORKDIR /home/swift/work

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD swiftsec --version || exit 1

ENTRYPOINT ["swiftsec"]
CMD ["--help"]
