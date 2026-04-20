# SWIFT: triage/claude.md

## Purpose

Fast regex-based filtering using Haiku patterns. Optional module for cost optimization.

**Cost Impact:** Reduces scan cost by 60-70% by filtering before expensive Sonnet analysis.

## Why Triage?

```
No Triage (Sonnet on all code):
- 100 files × 50 lines = 5000 LOC
- Sonnet cost: 5000 lines × $0.01/line ≈ $50

With Triage (Haiku filter + Sonnet on flagged):
- Haiku: 100 files × $0.05 = $5
- Sonnet: 10 flagged locations × $0.50 = $5
- Total: $10 (80% savings!)
```

## Implementation (Optional)

If cost is not a constraint, skip triage entirely. The agent can directly call Sonnet on all code.

If cost matters, implement:

```python
import re

PATTERNS = {
    "sql_injection": [
        r'f".*SELECT.*{',     # f"SELECT {var}"
        r'SELECT.*\+',        # "SELECT" + var
        r'query\.format\(',   # query.format(var)
    ],
    "command_injection": [
        r'os\.system\(',      # os.system(input)
        r'subprocess\.run\(.*shell',
    ],
    "hardcoded_secrets": [
        r'password\s*=\s*["\']',
        r'api_key\s*=\s*["\']',
    ],
    # ... more patterns
}

class TriageScanner:
    def triage_file(self, file_path: str, content: str) -> Set[int]:
        """Return flagged line numbers"""
        flagged = set()

        for line_num, line in enumerate(content.split('\n'), 1):
            if line.strip().startswith('#'):
                continue  # Skip comments

            for patterns in PATTERNS.values():
                for pattern in patterns:
                    if re.search(pattern, line, re.IGNORECASE):
                        flagged.add(line_num)
                        break

        return flagged

    def triage_codebase(self, repo_path: str) -> Dict[str, List[int]]:
        """Triage entire repo"""
        flagged = {}

        for root, dirs, files in os.walk(repo_path):
            dirs[:] = [d for d in dirs if d not in ['.git', '__pycache__']]

            for file in files:
                if not self._is_code_file(file):
                    continue

                path = os.path.join(root, file)
                with open(path, 'r', errors='ignore') as f:
                    lines = self.triage_file(path, f.read())
                    if lines:
                        flagged[path] = sorted(list(lines))

        return flagged
```

## Coordinator Pattern

```python
class TriageCoordinator:
    def scan_with_triage(self, repo_path: str) -> List[Vulnerability]:
        # Phase 1: Fast triage
        flagged = TriageScanner().triage_codebase(repo_path)
        print(f"Flagged {sum(len(v) for v in flagged.values())} locations")

        # Phase 2: Deep analysis on flagged only
        findings = []
        for file_path, lines in flagged.items():
            for line_num in lines:
                context = get_code_context(file_path, line_num)
                vuln = sonnet_analyze(file_path, line_num, context)
                if vuln:  # Only >= 95% confidence
                    findings.append(vuln)

        return findings
```

## Testing

```bash
# Test pattern matching
pytest test/unit/test_triage.py -v

# Test SQL injection detection
python -c "
from triage import TriageScanner
scanner = TriageScanner()
code = 'query = f\"SELECT * FROM users WHERE id={var}\"'
flagged = scanner.triage_file('test.py', code)
assert 1 in flagged
print('✓ SQL detected')
"
```

---

**Location:** `swift/triage/claude.md`  
**Status:** Optional (cost optimization)  
**Depends on:** None  
**Is depended on by:** agent (optional)
