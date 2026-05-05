FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    nmap \
    masscan \
    nikto \
    sqlmap \
    hydra \
    gobuster \
    dirb \
    wordlists \
    exploitdb \
    git \
    curl \
    unzip \
    ca-certificates \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# nuclei — multi-arch (amd64 / arm64)
RUN ARCH=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/') \
    && curl -sL "https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_linux_${ARCH}.zip" \
       -o /tmp/nuclei.zip \
    && unzip /tmp/nuclei.zip -d /usr/local/bin/ \
    && rm /tmp/nuclei.zip \
    && chmod +x /usr/local/bin/nuclei \
    && nuclei -update-templates 2>/dev/null || true

WORKDIR /work
