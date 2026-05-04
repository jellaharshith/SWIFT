"""Legacy entry point — preserves original Click CLI surface. Use `swiftsec` instead."""
from cli.commands import cli

if __name__ == "__main__":
    cli()
