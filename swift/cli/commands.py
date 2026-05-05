"""SWIFT CLI commands — scan, patch, validate."""
from __future__ import annotations

import sys
from pathlib import Path

import click

from agent.github_cloner import clone_repo, is_github_url
from agent.orchestrator import scan_codebase
from output.formatters import format_output


@click.group()
def cli() -> None:
    """SWIFT — AI-powered continuous security scanner."""


@cli.command()
@click.option("--repo", required=True, help="Local path or GitHub URL to scan.")
@click.option(
    "--output",
    default="json",
    type=click.Choice(["json", "markdown", "report"], case_sensitive=False),
    show_default=True,
    help=(
        "Output format. 'report' produces a normalised, human-readable security "
        "report that filters noise and is demo-ready (recommended for sharing)."
    ),
)
@click.option("--out-file", default=None, help="Write output to file instead of stdout.")
def scan(repo: str, output: str, out_file: str | None) -> None:
    """Scan a repository for security vulnerabilities.

    Runs the full triage → Haiku → Sonnet pipeline. Only findings with
    ≥95% confidence are reported. Accepts a local path or a GitHub URL.
    """
    cleanup = None
    try:
        if is_github_url(repo):
            click.echo(f"Cloning {repo} ...", err=True)
            repo_path, cleanup = clone_repo(repo)
        else:
            repo_path = str(Path(repo).resolve())

        click.echo(f"Scanning {repo_path} ...", err=True)
        result = scan_codebase(repo_path)
    except Exception as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)
    finally:
        if cleanup is not None:
            cleanup()

    click.echo(
        f"Found {len(result.vulnerabilities)} vulnerabilities "
        f"in {result.duration_seconds:.1f}s",
        err=True,
    )

    formatted = format_output(result, output.lower())
    if out_file:
        Path(out_file).write_text(formatted, encoding="utf-8")
        click.echo(f"Wrote {output.upper()} report to {out_file}", err=True)
    else:
        click.echo(formatted)


