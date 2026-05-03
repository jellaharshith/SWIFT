# SWIFT — AI-Powered Vulnerability Scanner

> Finds, verifies, and fixes security vulnerabilities automatically. Continuous, AI-powered, built for CI/CD.

[![CI](https://github.com/jellaharshith/SWIFT/actions/workflows/ci.yml/badge.svg)](https://github.com/jellaharshith/SWIFT/actions/workflows/ci.yml)
[![PyPI version](https://badge.fury.io/py/swiftsec.svg)](https://pypi.org/project/swiftsec/)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

```
███████╗██╗    ██╗██╗███████╗████████╗
██╔════╝██║    ██║██║██╔════╝╚══██╔══╝
███████╗██║ █╗ ██║██║█████╗     ██║
╚════██║██║███╗██║██║██╔══╝     ██║
███████║╚███╔███╔╝██║██║        ██║
╚══════╝ ╚══╝╚══╝ ╚═╝╚═╝        ╚═╝

  AI-Powered Vulnerability Scanner
  v2.0.0 · mode: production
```

## What SWIFT does

| Step | Model | Result |
|------|-------|--------|
| **Triage** | Claude Haiku | Flags suspicious patterns (~50ms/file) |
| **Analysis** | Claude Sonnet | Confirms real vulnerabilities (≥95% confidence only) |
| **Patching** | Claude Sonnet + Docker | Generates and tests fixes in isolation |
| **Reporting** | Markdown / JSON / SARIF | Human + machine-readable output |

## Quick start

```bash
pip install swiftsec
export ANTHROPIC_API_KEY=sk-ant-...

# Scan a local repo
swiftsec scan ./my-project

# Scan a GitHub repo
swiftsec scan https://github.com/org/repo

# Full pipeline: scan → patch → validate
swiftsec full ./my-project --allow-patch-generation --allow-sandbox

# Offensive Kali scan
swiftsec kali-scan --target 10.0.0.1 --tools nmap,nikto,nuclei

# Interactive wizard
swiftsec wizard
```

## Docker

```bash
docker pull ghcr.io/jellaharshith/swift:latest
docker run --rm \
  -e ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY \
  -v $(pwd):/home/swift/work \
  ghcr.io/jellaharshith/swift scan .
```

## Commands

| Command | Description |
|---------|-------------|
| `scan` | Static vulnerability scan (local path or GitHub URL) |
| `triage` | Fast pattern-matching triage only |
| `patch` | Generate patches for found vulnerabilities |
| `validate` | Test patches in Docker sandbox |
| `full` | Scan → patch → validate pipeline |
| `full-scan` | Code + Kali + CVE scan simultaneously |
| `kali-scan` | Kali Linux tools against live target |
| `web-scan` | Playwright-driven web vulnerability scan |
| `attack-sim` | MITRE ATT&CK-mapped exploit simulation |
| `live-feed` | Stream live CVEs from NVD + CISA KEV |
| `wizard` | Interactive scanner wizard |
| `privesc` | Docker-based privilege escalation tester |

## Configuration

```bash
cp .env.example .env
# Set ANTHROPIC_API_KEY=sk-ant-...
```

## CI/CD integration

```yaml
- name: SWIFT security scan
  run: swiftsec scan . --output json > swift-report.json
  env:
    ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
    SWIFT_NO_BANNER: "1"
```

## Output is pipe-safe

Banner always goes to stderr. JSON to stdout. Safe to pipe:

```bash
swiftsec scan ./repo | jq '.findings[] | select(.severity == "HIGH")'
```

## Safety guarantees

- No network in sandbox (`--network=none`)
- Read-only filesystem except `/tmp`
- 2-core / 2 GB / 30-second hard limit
- **Only reports findings with confidence ≥ 95%**

## Docs

Full architecture and module reference: [`docs/README.md`](docs/README.md)

## Contributing

[`CONTRIBUTING.md`](CONTRIBUTING.md) · Run tests: `pytest test/ -v --cov`

## Security

[`SECURITY.md`](SECURITY.md)

## License

MIT — [`LICENSE`](LICENSE)
