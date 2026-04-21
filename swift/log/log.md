# SWIFT: log/claude.md

## Purpose

Structured logging (JSON) for debugging and metrics tracking.

## Logging Setup

```python
import logging
import json
from datetime import datetime

class JSONFormatter(logging.Formatter):
    def format(self, record):
        return json.dumps({
            "timestamp": datetime.utcnow().isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName
        })

def setup_logging(level: str = "INFO", log_file: str = "log/swift.log"):
    logger = logging.getLogger("swift")
    logger.setLevel(getattr(logging, level))

    # Console (human-readable)
    console = logging.StreamHandler()
    console.setFormatter(logging.Formatter('%(levelname)s - %(message)s'))

    # File (JSON format)
    file_handler = logging.FileHandler(log_file)
    file_handler.setFormatter(JSONFormatter())

    logger.addHandler(console)
    logger.addHandler(file_handler)
    return logger

logger = setup_logging()
```

## Usage

```python
from log import logger

# Info
logger.info("Scanning started", extra={"scan_id": "scan-001"})

# Debug
logger.debug("API call completed", extra={
    "model": "claude-3-5-sonnet",
    "tokens": 1500,
    "cost": 0.0082
})

# Warning
logger.warning("Low confidence finding", extra={
    "confidence": 42,
    "threshold": 95
})

# Error
logger.error("API timeout", extra={"retry_attempt": 2})
```

## Metrics Collector

```python
class MetricsCollector:
    def __init__(self):
        self.scans = {}

    def start_scan(self, scan_id: str, files: int):
        self.scans[scan_id] = {
            "start_time": datetime.now(),
            "files": files,
            "vulns": 0,
            "cost": 0.0
        }

    def record_api_call(self, scan_id: str, cost: float):
        self.scans[scan_id]["cost"] += cost

    def record_vulnerability(self, scan_id: str):
        self.scans[scan_id]["vulns"] += 1

    def end_scan(self, scan_id: str):
        self.scans[scan_id]["end_time"] = datetime.now()

    def summary(self, scan_id: str) -> dict:
        m = self.scans[scan_id]
        duration = (m["end_time"] - m["start_time"]).total_seconds()
        return {
            "scan_id": scan_id,
            "duration_seconds": f"{duration:.2f}",
            "files_scanned": m["files"],
            "vulnerabilities": m["vulns"],
            "cost": f"${m['cost']:.4f}",
            "cost_per_file": f"${m['cost'] / m['files']:.4f}"
        }

metrics = MetricsCollector()
```

## Log Example

```json
{
  "timestamp": "2024-01-15T10:30:00Z",
  "level": "INFO",
  "logger": "swift.scan",
  "message": "Scanning started",
  "scan_id": "scan-001"
}

{
  "timestamp": "2024-01-15T10:30:15Z",
  "level": "DEBUG",
  "logger": "swift.api",
  "message": "API call completed",
  "model": "claude-3-5-sonnet",
  "tokens": 1500,
  "cost": 0.0082
}

{
  "timestamp": "2024-01-15T10:31:00Z",
  "level": "WARNING",
  "logger": "swift.scanner",
  "message": "Low confidence finding",
  "file": "app.py",
  "line": 45,
  "confidence": 42,
  "threshold": 95
}
```

## Reading Logs

```bash
# Watch logs in realtime
tail -f log/swift.log

# Parse JSON logs
cat log/swift.log | jq '.message, .level'

# Count vulnerabilities found
cat log/swift.log | jq -s '[.[] | select(.message | contains("Vulnerability"))] | length'

# Total cost
cat log/swift.log | jq -s '[.[] | .cost // 0] | add'

# Show summary
cat log/swift.log | jq 'select(.message | contains("Summary"))'
```

## Testing

```bash
# Test logging setup
pytest test/unit/test_log.py -v

# Test JSON format
python -c "
from log import setup_logging
import json
logger = setup_logging()
logger.info('Test')
with open('log/swift.log') as f:
    line = f.readline()
    json.loads(line)  # Valid JSON
    print('✓ JSON logging works')
"

# Test metrics
pytest test/unit/test_log.py::test_metrics -v
```

---

**Location:** `swift/log/claude.md`  
**Is depended on by:** All modules  
**No dependencies**
