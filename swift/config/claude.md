# SWIFT: config/claude.md

## Purpose

Load and validate configuration from environment variables and files.

## Configuration Sources (Priority Order)

1. **Environment variables** (highest): From `.env` file
2. **settings.json** (optional): For advanced config
3. **Hardcoded defaults** (lowest)

## Environment Variables

**Required:**

```bash
ANTHROPIC_API_KEY=sk-ant-v0-...
```

**Optional:**

```bash
SWIFT_LOG_LEVEL=INFO              # DEBUG, INFO, WARNING, ERROR
SWIFT_CONFIDENCE_THRESHOLD=95     # 0-100
SWIFT_SANDBOX_TIMEOUT=30          # seconds
SWIFT_MAX_RETRIES=3               # API retry count
```

## .env File (Never Commit)

Create in project root:

```bash
# .env
ANTHROPIC_API_KEY=sk-ant-v0-...
SWIFT_LOG_LEVEL=DEBUG
SWIFT_CONFIDENCE_THRESHOLD=95
SWIFT_SANDBOX_TIMEOUT=30
SWIFT_MAX_RETRIES=3
```

## Implementation

```python
from dataclasses import dataclass
from dotenv import load_dotenv
import os

load_dotenv(".env")

@dataclass
class Config:
    api_key: str
    api_endpoint: str = "https://api.anthropic.com/v1/messages"
    triage_model: str = "claude-3-5-haiku-20241022"
    analysis_model: str = "claude-3-5-sonnet-20241022"
    confidence_threshold: int = 95
    sandbox_timeout: int = 30
    max_retries: int = 3
    log_level: str = "INFO"

    @classmethod
    def from_env(cls) -> "Config":
        api_key = os.getenv("ANTHROPIC_API_KEY")
        if not api_key:
            raise ValueError(
                "ANTHROPIC_API_KEY not set. "
                "Add to .env: ANTHROPIC_API_KEY=sk-..."
            )

        return cls(
            api_key=api_key,
            confidence_threshold=int(
                os.getenv("SWIFT_CONFIDENCE_THRESHOLD", "95")
            ),
            sandbox_timeout=int(
                os.getenv("SWIFT_SANDBOX_TIMEOUT", "30")
            ),
            max_retries=int(
                os.getenv("SWIFT_MAX_RETRIES", "3")
            ),
            log_level=os.getenv("SWIFT_LOG_LEVEL", "INFO")
        )

# Global config
CONFIG = Config.from_env()
```

## Usage

```python
from config import CONFIG

# Access config
api_timeout = CONFIG.sandbox_timeout
confidence = CONFIG.confidence_threshold

# In scanners
if vuln.confidence * 100 >= CONFIG.confidence_threshold:
    output_finding(vuln)
```

## Validation

```python
def validate_config(config: Config) -> List[str]:
    """Return list of validation errors"""
    errors = []

    if not config.api_key.startswith("sk-"):
        errors.append("Invalid API key (must start with 'sk-')")

    if not (0 <= config.confidence_threshold <= 100):
        errors.append("Confidence threshold must be 0-100")

    if not (1 <= config.sandbox_timeout <= 300):
        errors.append("Sandbox timeout must be 1-300 seconds")

    return errors
```

## Testing

```bash
# Test config loading
pytest test/unit/test_config.py -v

# Test missing API key
pytest test/unit/test_config.py::test_missing_api_key -v

# Test validation
pytest test/unit/test_config.py::test_validate_config -v
```

## Quick Check

```bash
# Verify config loads
python -c "from config import CONFIG; print('✓ Config OK')"

# Check confidence threshold
python -c "from config import CONFIG; print(f'Threshold: {CONFIG.confidence_threshold}%')"
```

---

**Location:** `swift/config/claude.md`  
**Is depended on by:** All modules  
**No dependencies**
