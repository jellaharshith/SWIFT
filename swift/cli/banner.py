"""SWIFT CLI startup banner — Rich-rendered, always pipe-safe."""
from __future__ import annotations

import os
import sys
from argparse import Namespace
from importlib.resources import files
from typing import Optional

from rich.console import Console
from rich.text import Text


def _load_ascii() -> str:
    try:
        return files("assets.logo").joinpath("swift_ascii.txt").read_text(encoding="utf-8")
    except Exception:
        return "SWIFT"


def should_show_banner(args: Optional[Namespace] = None, argv: Optional[list] = None) -> bool:
    """Return True only when an interactive human will see the banner."""
    argv = argv or sys.argv

    # Short-circuit before argparse: --version, --help, -h exit immediately
    for flag in ("--version", "--help", "-h"):
        if flag in argv:
            return False

    if args is not None:
        if getattr(args, "no_banner", False):
            return False
        if getattr(args, "quiet", False):
            return False

    if os.environ.get("SWIFT_NO_BANNER") == "1":
        return False

    # Never pollute piped/redirected stderr
    if not sys.stderr.isatty():
        return False

    # Suppress for JSON-output subcommands when output=json
    if args is not None:
        cmd = getattr(args, "command", None)
        output_fmt = getattr(args, "output", None)
        json_cmds = {"scan", "triage", "patch", "validate", "report", "full",
                     "full-scan", "kali-scan", "attack-sim", "web-scan", "privesc"}
        if cmd in json_cmds and output_fmt == "json":
            return False

    return True


def print_banner(stream=None) -> None:
    """Print SWIFT startup banner to stderr (never stdout)."""
    if stream is None:
        stream = sys.stderr

    from swift import __version__

    swift_env = os.environ.get("SWIFT_ENV", "dev")
    py_ver = f"{sys.version_info.major}.{sys.version_info.minor}"

    console = Console(file=stream, highlight=False)

    art = _load_ascii()
    banner_text = Text()
    # Gradient: alternate lines cyan → sky
    lines = art.rstrip("\n").split("\n")
    colors = ["cyan", "bright_cyan", "deep_sky_blue1", "sky_blue1", "steel_blue1", "cyan"]
    for i, line in enumerate(lines):
        banner_text.append(line + "\n", style=colors[i % len(colors)])

    console.print(banner_text, end="")
    console.print(
        f"  AI-Powered Vulnerability Scanner",
        style="dim slate_blue1",
    )
    console.print(
        f"  v{__version__} · mode: {swift_env} · py{py_ver}",
        style="dim",
    )
    console.print()
