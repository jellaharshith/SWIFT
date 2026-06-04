"""Standalone CLI: ``python -m swiftsec_ai.cli {sync,ask,repl,info}``.

This builds a *bare* assistant (CVE RAG + reasoning, no SWIFTSEC tools wired). The
fully-wired entry point lives in the host tool at ``swiftsec ai ...`` (swift_cli.py).
"""
from __future__ import annotations

import argparse
import json
import sys

from .assistant import SwiftSecAssistant
from .config import load_settings


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="swiftsec_ai",
        description="SWIFTSEC-AI — ethical-hacker assistant with live-CVE RAG.",
    )
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("sync", help="Incrementally sync the local NVD/CVE mirror")
    s.add_argument("--force", action="store_true", help="ignore the min sync interval")
    s.add_argument("--days", type=int, default=None, help="initial backfill window (days)")

    a = sub.add_parser("ask", help="Ask the assistant a single question")
    a.add_argument("message", help="your question / instruction")

    sub.add_parser("repl", help="Interactive prompt loop")
    sub.add_parser("info", help="Show backend, model, and CVE store status")
    return p


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    settings = load_settings()
    assistant = SwiftSecAssistant(settings)
    try:
        if args.command == "info":
            print(json.dumps(assistant.info(), indent=2))
            return 0

        if args.command == "sync":
            print(json.dumps(assistant.update_cves(force=args.force, initial_days=args.days), indent=2))
            return 0

        if args.command == "ask":
            print(assistant.ask(args.message))
            return 0

        if args.command == "repl":
            print("SWIFTSEC-AI REPL — type 'exit' or Ctrl-D to quit.")
            while True:
                try:
                    line = input("swiftsec-ai> ").strip()
                except (EOFError, KeyboardInterrupt):
                    print()
                    break
                if line.lower() in {"exit", "quit"}:
                    break
                if not line:
                    continue
                try:
                    print(assistant.ask(line))
                except Exception as e:
                    print(f"[error] {e}", file=sys.stderr)
            return 0

        return 2
    finally:
        assistant.close()


if __name__ == "__main__":
    raise SystemExit(main())
