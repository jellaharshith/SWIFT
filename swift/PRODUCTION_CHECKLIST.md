# SWIFT Production Checklist

Use this checklist before every deployment to production.

## Environment Variables

- [ ] `ANTHROPIC_API_KEY` set (use AWS Secrets Manager in production — never hardcode)
- [ ] `SWIFT_LOG_LEVEL=INFO` (not `DEBUG` — debug logs include raw API payloads)
- [ ] `SWIFT_CONFIDENCE_THRESHOLD=0.95` (never lower this — it is the core trust guarantee)
- [ ] `SWIFT_DB_PATH` points to persistent storage (not a container-local temp path)
- [ ] `GITHUB_CLIENT_ID` and `GITHUB_CLIENT_SECRET` set (required for web OAuth flow)
- [ ] SMTP variables set if email notifications are enabled

## Docker

- [ ] `docker build -t swift-scanner:latest .` succeeds without errors
- [ ] `docker run --env ANTHROPIC_API_KEY=$KEY swift-scanner:latest scan --repo . --output json` runs without error
- [ ] Image size is reasonable (< 1GB)

## AWS App Runner

- [ ] ECR repository created: `swift-scanner`
- [ ] Docker image built and pushed to ECR
- [ ] `ANTHROPIC_API_KEY` stored in AWS Secrets Manager under: `swift/anthropic-api-key`
- [ ] App Runner service created with the secret ARN wired in via environment variable
- [ ] App Runner service URL is accessible from the internet

## Smoke Tests

Run these against the live deployment immediately after deploying:

- [ ] `GET /` returns `{"status": "ok", "service": "SWIFT Scanner"}`
- [ ] `GET /metrics` returns valid metrics JSON (no 500 error)
- [ ] `GET /dashboard` returns HTTP 200 with HTML content
- [ ] CLI scan completes: `python main.py scan --repo . --output json` (no crash)
- [ ] At least one scan result is returned (found or not-found, no unhandled exception)

## Security

- [ ] `.env` is listed in `.gitignore` and has never been committed
- [ ] No hardcoded API keys anywhere in source code (`grep -r "sk-ant" .` returns nothing)
- [ ] Docker sandbox patch testing uses `--network=none` (verify in `sandbox/` code)
- [ ] HTTPS is enabled on the App Runner endpoint (App Runner provides this automatically)

## Tests

- [ ] `pytest test/unit/ -v` — all unit tests pass
- [ ] Coverage is above 80%: `pytest test/ --cov=. --cov-report=term`
