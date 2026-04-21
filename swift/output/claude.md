# SWIFT: output/claude.md

## Purpose

Format scan results in JSON (APIs) and Markdown (reports).

## Core Function: format_output()

```python
def format_output(result: ScanResult, format: str) -> str
```

**Formats:** `"json"`, `"markdown"`  
**Output:** Formatted string ready to print or save

## JSON Format

```json
{
  "scan": {
    "id": "scan-20240115-001",
    "timestamp": "2024-01-15T10:30:00Z",
    "repository": "https://github.com/user/project",
    "duration_seconds": 120
  },
  "summary": {
    "total_files": 45,
    "vulnerabilities_found": 5,
    "by_severity": {
      "critical": 2,
      "high": 2,
      "medium": 1
    },
    "patches_generated": 5,
    "patches_passed": 4
  },
  "vulnerabilities": [
    {
      "id": "SWIFT-001",
      "title": "SQL Injection",
      "severity": "critical",
      "confidence": 98,
      "file": "app.py",
      "line": 45,
      "cwe_id": "CWE-89"
    }
  ],
  "patches": [
    {
      "vuln_id": "SWIFT-001",
      "file": "app.py",
      "diff": "--- app.py\n+++ app.py",
      "reasoning": "Use parameterized queries",
      "test_passed": true
    }
  ]
}
```

## Markdown Format

```markdown
# SWIFT Vulnerability Report

**Repository:** https://github.com/user/project  
**Scan Date:** 2024-01-15  
**Duration:** 2 minutes

## Summary

- **Total:** 5 vulnerabilities
  - Critical: 2
  - High: 2
  - Medium: 1
- **Patches:** ✓ 4/5 passed tests

## Vulnerabilities

### 1. SQL Injection (SWIFT-001) - CRITICAL

**File:** `app.py:45` | **Confidence:** 98% | **CWE:** CWE-89

User input concatenated into SQL query.

**Vulnerable Code:**
query = f"SELECT \* FROM users WHERE id={user_id}"

**Fix:**
query = "SELECT \* FROM users WHERE id=?"
cursor.execute(query, (user_id,))
```

## Implementation

```python
class OutputFormatter:
    def format(self, result: ScanResult) -> str:
        raise NotImplementedError

class JSONFormatter(OutputFormatter):
    def format(self, result: ScanResult) -> str:
        import json
        return json.dumps({
            "scan": {
                "id": result.scan_id,
                "timestamp": result.timestamp,
                "repository": result.repository,
                "duration_seconds": result.duration_seconds
            },
            "summary": result.summary,
            "vulnerabilities": [v.__dict__ for v in result.vulnerabilities],
            "patches": [p.__dict__ for p in result.patches]
        }, indent=2)

class MarkdownFormatter(OutputFormatter):
    def format(self, result: ScanResult) -> str:
        lines = []
        lines.append("# SWIFT Vulnerability Report\n")
        lines.append(f"**Repository:** {result.repository}\n")

        lines.append("## Summary\n")
        lines.append(f"- Total: {result.summary['total']}\n")

        lines.append("## Vulnerabilities\n")
        for i, vuln in enumerate(result.vulnerabilities, 1):
            lines.append(f"### {i}. {vuln.title} ({vuln.id})\n")
            lines.append(f"**File:** {vuln.file}:{vuln.line}\n")

        return "\n".join(lines)

def format_output(result: ScanResult, format_type: str) -> str:
    formatters = {
        "json": JSONFormatter(),
        "markdown": MarkdownFormatter()
    }
    return formatters[format_type].format(result)

def export_to_file(result: ScanResult, format_type: str, path: str):
    content = format_output(result, format_type)
    with open(path, 'w') as f:
        f.write(content)
```

## Testing

```bash
# Test formatters
pytest test/unit/test_output.py -v

# Test JSON is valid
python -c "
import json
from output import format_output
result = ScanResult(...)
json_str = format_output(result, 'json')
json.loads(json_str)  # Verify valid
print('✓ JSON valid')
"

# Test Markdown contains sections
pytest test/unit/test_output.py::test_markdown_sections -v
```

## Key Commands

```bash
# Export JSON
python main.py scan --repo . --output json > results.json

# Export Markdown
python main.py scan --repo . --output markdown > REPORT.md

# Pretty print
python -c "
import json
with open('results.json') as f:
    data = json.load(f)
    print(f'Found {len(data[\"vulnerabilities\"])} vulnerabilities')
"
```

---

**Location:** `swift/output/claude.md`  
**Depends on:** None  
**Is depended on by:** cli, agent
