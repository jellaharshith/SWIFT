# SWIFT MVP — TO-DO

## Status Legend

- ✅ DONE
- 🔄 IN PROGRESS
- ⬜ PENDING

## Security

### ✅ API Key Exposure — Fix .gitignore (2026-04-19)

- `.gitignore` had `.env/` (directory) not `.env` (file)
- Fixed: now has `.env` and `**/.env`
- Git history checked: key was NEVER committed — safe
- `swift/.env` now correctly git-ignored

## Deployment

### ⬜ Choose deployment platform (AWS removed)

AWS App Runner deployment removed. Needs new deployment target (e.g. Fly.io, Railway, Render, self-hosted Docker).
