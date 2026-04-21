# CLAUDE.md

## Purpose

Use GitHub Issues as the single source of truth for tracking work: features, bugs, tasks, and improvements.

---

## What is a GitHub Issue?

A GitHub Issue represents a piece of work. It can be:

- A feature request
- A bug
- A task or improvement
- Documentation work
- A blocker or follow-up item

Everything important should be tracked as an Issue, not only in conversation.

---

## When to Create an Issue

Create a GitHub Issue when:

- A new feature is requested
- A bug is reported or discovered
- Work is too large to complete immediately
- You find missing documentation
- You identify technical debt
- You discover follow-up work while coding
- Something blocks progress

---

## When NOT to Create an Issue

Do NOT create an issue for:

- Tiny fixes done immediately
- Minor cosmetic edits
- Duplicate work already tracked

---

## Issue Format

### Title

Use clear prefixes:

- `Feature: add user dashboard`
- `Bug: checkout button not working`
- `Docs: fix installation steps`

### Body

Include:

- Summary
- Why it matters
- Scope
- Acceptance criteria
- Notes or risks

---

## Labels (if available)

- feature
- bug
- docs
- refactor
- tech-debt
- blocked
- security

---

## Workflow Rules

### Before starting work

- Check if an issue already exists
- If yes → use it
- If no → create one (if needed)

### During work

- If new problems appear → create a new issue
- Do NOT hide important work in comments or chat

### After work

- Reference the issue in commits and PRs

---

## Branch Naming

Use issue-based naming:

- `feature/123-dashboard`
- `bugfix/456-login-error`

---

## Explaining Issues

If asked “what is this issue?”:
Explain:

- What it is
- Why it exists
- Who it affects
- What success looks like

Use simple language.

---

## If GitHub Tools Are Available

- Create issues using API / MCP / `gh issue create`
- Assign labels and link PRs

## If GitHub Tools Are NOT Available

- Write the full issue in markdown
- Tell the user it’s ready to paste into GitHub

---

## Templates

### Feature

Title: Feature: <name>

- Summary:
- Problem:
- Solution:
- Acceptance criteria:
- Notes:

### Bug

Title: Bug: <name>

- Summary:
- Expected:
- Actual:
- Steps to reproduce:
- Impact:
- Acceptance criteria:

### Docs

Title: Docs: <name>

- Summary:
- Problem:
- Fix:
- Acceptance criteria:

---

## Priority Guide

- High: broken features, security, blockers
- Medium: important features or bugs
- Low: improvements or polish

---

## Final Rule

If it matters → it should be a GitHub Issue.
Do not let important work exist only in chat.
