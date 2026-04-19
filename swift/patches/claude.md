# SWIFT: patches/claude.md

## Purpose

Generate, score, test, and output security patches for confirmed vulnerabilities.

## Core Function: generate_patches()

```python
def generate_patches(vulnerabilities: List[Vulnerability]) -> List[Patch]
```

**Input:** List of confirmed vulnerabilities (≥95% confidence)  
**Output:** List of `Patch` objects with diffs and test results  
**Skip if:** Vulnerability confidence < 90%

**Process per vulnerability:**

1. Generate 3 patch candidates (trade-offs matter)
2. Score each on: minimal changes, correctness, safety
3. Select best candidate
4. Create unified diff
5. Test in sandbox
6. Package with reasoning and logs

## Implementation

```python
class PatchGenerator:
    def generate_candidates(vuln: Vulnerability, code_context: str) -> List[Patch]:
        if vuln.confidence < 0.90:
            return []  # Skip low confidence

        # Ask Sonnet for 3 different patches
        prompt = f"""Generate 3 security patches for:
        {vuln.title}: {vuln.description}

        Vulnerable code: {code_context}

        Requirements:
        - Minimal changes (only fix, don't refactor)
        - Maintain code style
        - Include safety comments
        - Apply cleanly with 'git apply'
        """

        response = claude_sonnet(prompt)
        return parse_candidates(response)

    def select_best(candidates: List[Patch], original: str) -> Patch:
        scores = []
        for candidate in candidates:
            score = 0

            # Prefer minimal changes
            diff_lines = count_changed_lines(original, candidate.patched_code)
            if diff_lines < 5:
                score += 40
            elif diff_lines < 10:
                score += 30
            # ... more scoring

            scores.append((score, candidate))

        return max(scores, key=lambda x: x[0])[1]
```

## Unified Diff Format

Output must be valid `git apply` / `patch` compatible:

```
--- app.py (original)
+++ app.py (patched)
@@ -45,2 +45,3 @@
 def get_user(user_id):
-    query = f"SELECT * FROM users WHERE id={user_id}"
-    cursor.execute(query)
+    query = "SELECT * FROM users WHERE id=?"
+    # Use parameterized queries to prevent SQL injection
+    cursor.execute(query, (user_id,))
     return cursor.fetchone()
```

## Patch Testing (See sandbox/claude.md)

```python
from sandbox import SandboxTester

tester = SandboxTester(repo_path)
result = tester.test_patch(patched_code, "app.py")

if result.passed:
    patch.test_passed = True
    patch.test_logs = result.logs
else:
    patch.test_passed = False
    patch.test_logs = result.stderr
```

## Data Structure

```python
@dataclass
class Patch:
    id: str              # "PATCH-001"
    vuln_id: str         # "SWIFT-001"
    file: str            # "app.py"
    original_code: str
    patched_code: str
    diff: str            # Unified diff
    reasoning: str       # Why this patch
    sandbox_tested: bool
    test_passed: bool
    test_logs: str
```

## Scoring Logic

Patches are scored on:

1. **Minimal changes** (40 pts): Prefer <5 lines changed
2. **Correctness** (30 pts): Syntax valid, imports work
3. **Safety** (20 pts): Comments explaining fix
4. **Maintainability** (10 pts): Follows code style

Example:

- 3 lines changed + valid syntax + comments = 100/100 (excellent)
- 20 lines changed + works + no comments = 60/100 (acceptable)
- 50 lines refactored = 10/100 (avoid)

## Testing

```bash
# Unit test generation
pytest test/unit/test_patches.py::test_generate_candidates -v

# Unit test scoring
pytest test/unit/test_patches.py::test_patch_scoring -v

# Integration test (real API, mock sandbox)
pytest test/integration/test_patch_generation.py -v

# E2E test (real API, real sandbox)
SWIFT_RUN_E2E=1 pytest test/e2e/test_patch_end_to_end.py -v
```

## Key Commands

```bash
# Generate and review patch
python main.py patch --vuln-id SWIFT-001 --review

# Generate and apply patch
python main.py patch --vuln-id SWIFT-001 --apply --sandbox-test

# Test existing patch in sandbox
python main.py validate --patch-id PATCH-001 --verbose
```

---

**Location:** `swift/patches/claude.md`  
**Depends on:** config, sandbox, log  
**Is depended on by:** agent, main.py
