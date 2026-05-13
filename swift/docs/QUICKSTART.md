# SWIFT Quickstart — Juice Shop CTF

## 5-Command Tutorial

```bash
# 1. Install with CTF extras
pip install "swiftsec[ctf]"

# 2. Start Juice Shop
docker run -p 3000:3000 bkimminich/juice-shop

# 3. Generate ROE config
swiftsec init --ctf juice-shop

# 4. Run web scan (live)
swiftsec web-scan http://localhost:3000

# 5. View findings
cat web-scan-*.json | python -m json.tool
```

## What You'll Find

SWIFT will discover XSS, SQLi, IDOR, JWT weaknesses, and more.
Each finding includes confidence >= 95%, CVSS score, and remediation advice.
