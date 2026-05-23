# SWIFT v8 sandbox-daemon image.
#
# Bundles the Kali tool surface SWIFT LangGraph specialists invoke. Built
# once via `swiftsec lab up` -- skipped on subsequent runs.
FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive

# Core network + recon
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl wget jq git tmux \
        nmap masscan dnsutils whois \
        nikto sqlmap hydra \
    && rm -rf /var/lib/apt/lists/*

# Web fuzzers / scanners
RUN apt-get update && apt-get install -y --no-install-recommends \
        ffuf gobuster wfuzz \
    && rm -rf /var/lib/apt/lists/*

# Exploitation frameworks (optional; large layers)
RUN apt-get update && apt-get install -y --no-install-recommends \
        metasploit-framework \
        crackmapexec impacket-scripts \
    && rm -rf /var/lib/apt/lists/*

# Go-based PD tools (the bug-bounty skills lean on these)
RUN apt-get update && apt-get install -y --no-install-recommends golang-go \
    && go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
    && go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest \
    && go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
    && go install -v github.com/projectdiscovery/katana/cmd/katana@latest \
    && cp /root/go/bin/* /usr/local/bin/ \
    && apt-get purge -y golang-go && apt-get autoremove -y \
    && rm -rf /root/go /var/lib/apt/lists/*

WORKDIR /work
CMD ["tail", "-f", "/dev/null"]
