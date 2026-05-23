"""v8.0 -- CLI smoke: every new subcommand appears in --help and parses."""
from __future__ import annotations

import io

import swift_cli


V8_COMMANDS = (
    "engage", "redteam-full", "vuln-pipeline", "hunt", "validate",
    "autopilot", "bb-report", "web3-audit", "lab", "skills", "kg",
)


def test_build_parser_no_crash():
    p = swift_cli.build_parser()
    assert p is not None


def test_every_v8_command_in_help():
    p = swift_cli.build_parser()
    buf = io.StringIO()
    p.print_help(buf)
    text = buf.getvalue()
    missing = [c for c in V8_COMMANDS if c not in text]
    assert not missing, f"missing from --help: {missing}"


def test_validate_subcommand_parses():
    p = swift_cli.build_parser()
    args = p.parse_args(["validate", "/tmp/finding.json"])
    assert args.command == "validate"
    assert args.finding == "/tmp/finding.json"
