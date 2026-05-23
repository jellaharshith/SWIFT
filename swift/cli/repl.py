"""Interactive REPL for the SWIFT security scanner CLI."""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import Any

from log.audit import log_step

try:
    import readline as _readline
    _READLINE_AVAILABLE = True
except ImportError:
    _readline = None  # type: ignore[assignment]
    _READLINE_AVAILABLE = False

# Commands that produce their own stdout output — caller should NOT json-dump their return value
NO_JSON_DUMP_CMDS: frozenset[str] = frozenset({"live-feed", "wizard", "kali-scan", "version", "update"})

_HISTORY_FILE = Path.home() / ".swiftsec_history"
_MAX_HISTORY = 500


def _get_subcommand_choices(parser: argparse.ArgumentParser) -> dict[str, argparse.ArgumentParser]:
    """Extract subcommand name → subparser mapping from parser."""
    try:
        group_actions = parser._subparsers._group_actions  # type: ignore[union-attr]
        for action in group_actions:
            if hasattr(action, "choices") and action.choices:
                return dict(action.choices)
    except AttributeError:
        pass
    return {}


def _print_help(choices: dict[str, argparse.ArgumentParser]) -> None:
    """Print available subcommands with their help strings."""
    print("Available commands:")
    for name, subparser in sorted(choices.items()):
        help_text = getattr(subparser, "description", "") or ""
        if not help_text:
            # Fall back to the _defaults dict or the first positional description
            help_text = subparser.format_usage().split("\n")[0].strip()
        print(f"  {name:<20} {help_text}")
    print("\nBuilt-in commands: help (?), exit (quit), clear (cls)")


def _setup_readline(choices: dict[str, argparse.ArgumentParser]) -> None:
    """Configure readline history and tab-completion for top-level subcommands."""
    if not _READLINE_AVAILABLE or _readline is None:
        return

    if _HISTORY_FILE.exists():
        try:
            _readline.read_history_file(str(_HISTORY_FILE))
        except OSError:
            pass

    _readline.set_history_length(_MAX_HISTORY)

    command_names = sorted(choices.keys()) + ["help", "exit", "quit", "clear", "cls"]

    def _completer(text: str, state: int) -> str | None:
        matches = [c for c in command_names if c.startswith(text)]
        return matches[state] if state < len(matches) else None

    _readline.set_completer(_completer)
    _readline.parse_and_bind("tab: complete")


def _save_readline_history() -> None:
    """Save readline history to disk."""
    if not _READLINE_AVAILABLE or _readline is None:
        return
    try:
        _readline.set_history_length(_MAX_HISTORY)
        _readline.write_history_file(str(_HISTORY_FILE))
    except OSError:
        pass


def run_repl(parser: argparse.ArgumentParser, handlers: dict[str, Any]) -> int:
    """Run an interactive REPL for the SWIFT CLI.

    Args:
        parser: The top-level ArgumentParser built by build_parser().
        handlers: Mapping of subcommand name to handler callable.

    Returns:
        Exit code (0 on clean exit).
    """
    choices = _get_subcommand_choices(parser)
    _setup_readline(choices)

    print("Type 'help' for commands, 'exit' to quit.")

    while True:
        try:
            line = input("swiftsec> ")
        except EOFError:
            print()
            break
        except KeyboardInterrupt:
            print()
            break

        line = line.strip()
        if not line:
            continue

        # Built-in: help / ?
        if line in ("help", "?"):
            _print_help(choices)
            continue

        # Built-in: exit / quit
        if line in ("exit", "quit"):
            break

        # Built-in: clear / cls
        if line in ("clear", "cls"):
            if os.name == "nt":
                os.system("cls")
            else:
                os.system("clear")
            continue

        # Tokenize and dispatch
        try:
            import shlex
            tokens = shlex.split(line)
        except ValueError as exc:
            print(f"[ERROR] parse error: {exc}", file=sys.stderr)
            continue

        if not tokens:
            continue

        # Parse args — catch SystemExit so --help / bad args don't kill the REPL
        try:
            args = parser.parse_args(tokens)
        except SystemExit:
            continue

        command = getattr(args, "command", None)
        if command is None or command not in handlers:
            print(f"[ERROR] unknown command: {tokens[0]}", file=sys.stderr)
            continue

        log_step("cli.invoke", command=command, auto_confirmed=False)

        try:
            result = handlers[command](args)
            log_step("cli.complete", command=command)
        except Exception as exc:  # noqa: BLE001
            print(f"[ERROR] {exc}", file=sys.stderr)
            continue

        _ = result  # caller controls whether to json-dump based on NO_JSON_DUMP_CMDS

    _save_readline_history()
    return 0
