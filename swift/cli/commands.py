"""SWIFT CLI commands — scan, patch, validate."""
from __future__ import annotations

import sys
from pathlib import Path

import click

from agent.orchestrator import generate_patches, scan_codebase
from output.formatters import format_output


@click.group()
def cli() -> None:
    """SWIFT — AI-powered continuous security scanner."""


@cli.command()
@click.option("--repo", required=True, help="Path to repository to scan.")
@click.option(
    "--output",
    default="json",
    type=click.Choice(["json", "markdown"], case_sensitive=False),
    show_default=True,
    help="Output format.",
)
@click.option(
    "--patches",
    "gen_patches",
    is_flag=True,
    default=False,
    help="Generate and sandbox-test patches after scanning.",
)
@click.option("--out-file", default=None, help="Write output to file instead of stdout.")
def scan(repo: str, output: str, gen_patches: bool, out_file: str | None) -> None:
    """Scan a repository for security vulnerabilities.

    Runs the full triage → Haiku → Sonnet pipeline. Only findings with
    ≥95% confidence are reported.
    """
    repo_path = str(Path(repo).resolve())
    click.echo(f"Scanning {repo_path} ...", err=True)

    try:
        result = scan_codebase(repo_path, generate_patches_flag=gen_patches)
    except Exception as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)

    click.echo(
        f"Found {len(result.vulnerabilities)} vulnerabilities "
        f"({len(result.patches)} patches) in {result.duration_seconds:.1f}s",
        err=True,
    )

    formatted = format_output(result, output.lower())
    if out_file:
        Path(out_file).write_text(formatted, encoding="utf-8")
        click.echo(f"Wrote {output.upper()} report to {out_file}", err=True)
    else:
        click.echo(formatted)


@cli.command()
@click.option("--repo", required=True, help="Path to repository to scan and patch.")
@click.option(
    "--output",
    default="json",
    type=click.Choice(["json", "markdown"], case_sensitive=False),
    show_default=True,
    help="Output format.",
)
@click.option("--out-file", default=None, help="Write output to file instead of stdout.")
def patch(repo: str, output: str, out_file: str | None) -> None:
    """Scan repository and auto-generate patches for all findings.

    Each patch is validated in a Docker sandbox (--network=none, read-only FS).
    """
    repo_path = str(Path(repo).resolve())
    click.echo(f"Scanning + patching {repo_path} ...", err=True)

    try:
        result = scan_codebase(repo_path, generate_patches_flag=True)
    except Exception as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)

    click.echo(
        f"Found {len(result.vulnerabilities)} vulnerabilities, "
        f"generated {len(result.patches)} patches in {result.duration_seconds:.1f}s",
        err=True,
    )

    formatted = format_output(result, output.lower())
    if out_file:
        Path(out_file).write_text(formatted, encoding="utf-8")
        click.echo(f"Wrote {output.upper()} report to {out_file}", err=True)
    else:
        click.echo(formatted)


@cli.command()
@click.option("--patch-id", required=True, help="Patch ID to validate (e.g. PATCH-001).")
def validate(patch_id: str) -> None:
    """Validate a patch through the Docker sandbox.

    Note: standalone validation requires a running scan session. Use
    'swift patch --repo <path>' which runs sandbox validation automatically
    during patch generation.
    """
    click.echo(
        f"Standalone validation for {patch_id}: use 'swift patch --repo <path>' "
        "to generate and validate patches in one step.",
        err=True,
    )
    sys.exit(0)
