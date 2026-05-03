# SWIFT: cli/claude.md

## Purpose

Provide command-line interface for scanning, patching, and validating.

## Commands

### scan

```bash
swiftsec scan --repo <path> --output json|markdown --patches --confidence 95
```

**Options:**

- `--repo` (required): Local path or GitHub URL
- `--output` (default: json): Output format
- `--patches` (flag): Generate patches too
- `--confidence` (default: 95): Minimum threshold

**Output:** JSON or Markdown with findings + patches

```bash
swiftsec scan --repo . --output json > results.json
swiftsec scan --repo https://github.com/user/project --patches
```

### patch

```bash
swiftsec patch --vuln-id SWIFT-001 --review|--apply --sandbox-test
```

**Options:**

- `--vuln-id` (required): Vulnerability ID
- `--review` (flag): Show diff for review
- `--apply` (flag): Apply patch to code
- `--sandbox-test` (flag): Test in sandbox first

**Output:** Unified diff + reasoning

```bash
swiftsec patch --vuln-id SWIFT-001 --review
swiftsec patch --vuln-id SWIFT-001 --apply --sandbox-test
```

### validate

```bash
swiftsec validate --patch-id PATCH-001 --verbose
```

**Options:**

- `--patch-id` (required): Patch ID
- `--verbose` (flag): Show execution logs
- `--timeout` (default: 30): Sandbox timeout

**Output:** ✓/✗ PASSED/FAILED + exit code + logs

## Implementation (Using Click)

```python
import click
from agent import scan_codebase
from patches import generate_patches
from output import format_output
from config import CONFIG

@click.group()
def cli():
    """SWIFT: AI-Powered Vulnerability Scanner"""
    pass

@cli.command()
@click.option('--repo', required=True, help='Repo path or GitHub URL')
@click.option('--output', default='json', type=click.Choice(['json', 'markdown']))
@click.option('--patches', is_flag=True, help='Generate patches')
@click.option('--confidence', default=95, type=int)
def scan(repo, output, patches, confidence):
    """Scan repository for vulnerabilities"""
    try:
        result = scan_codebase(repo, CONFIG)

        # Filter by confidence
        result.vulnerabilities = [
            v for v in result.vulnerabilities
            if v.confidence * 100 >= confidence
        ]

        # Generate patches if requested
        if patches:
            result.patches = generate_patches(result.vulnerabilities)

        # Output
        click.echo(format_output(result, output))

    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        exit(1)

@cli.command()
@click.option('--vuln-id', required=True)
@click.option('--review', is_flag=True)
@click.option('--apply', is_flag=True)
@click.option('--sandbox-test', is_flag=True)
def patch(vuln_id, review, apply, sandbox_test):
    """Generate or apply patches"""
    try:
        if not review and not apply:
            click.echo("Error: Use --review or --apply", err=True)
            exit(2)

        # Load and patch
        patch_obj = generate_patch(vuln_id)

        if sandbox_test:
            result = test_patch(patch_obj)
            if not result.passed:
                click.echo(f"✗ Sandbox failed: {result.stderr}", err=True)
                exit(3)

        if review:
            click.echo(patch_obj.diff)
            click.echo(f"\nReasoning: {patch_obj.reasoning}")

        if apply:
            apply_patch(patch_obj)
            click.echo(f"✓ Applied to {patch_obj.file}")

    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        exit(1)

if __name__ == '__main__':
    cli()
```

## Error Messages (User-Friendly)

```
Error: Repository not found. Check URL or local path.
Error: Use --review or --apply
Error: ANTHROPIC_API_KEY not set. Add to .env
Error: Sandbox test failed (exit 1)
```

## Exit Codes

- `0` - Success
- `1` - General error (API, file, etc.)
- `2` - Invalid arguments
- `3` - Sandbox test failed
- `4` - Configuration error

## Testing

```bash
# Test scan command
pytest test/unit/test_cli.py::test_scan_command -v

# Integration test
swiftsec scan --repo ./test-repo --output json | jq '.summary'
```

---

**Location:** `swift/cli/claude.md`  
**Depends on:** agent, patches, output, config  
**Is depended on by:** swift_cli.py
