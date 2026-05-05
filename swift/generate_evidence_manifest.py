"""Generate compliance-ready evidence manifest for local artifacts."""
from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(8192), b""):
            digest.update(chunk)
    return digest.hexdigest()


def collect_artifacts(artifacts_root: Path) -> list[dict]:
    items: list[dict] = []
    if not artifacts_root.exists():
        return items
    for path in sorted(p for p in artifacts_root.rglob("*") if p.is_file()):
        stat = path.stat()
        items.append(
            {
                "path": str(path),
                "relative_path": str(path.relative_to(artifacts_root)),
                "sha256": sha256_file(path),
                "size_bytes": stat.st_size,
                "modified_utc": datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat(),
            }
        )
    return items


def extract_audit_summary(artifacts: list[dict]) -> dict:
    summary = {
        "validator_runs": 0,
        "sandbox_runs": 0,
        "failed_events": 0,
        "successful_events": 0,
    }
    for item in artifacts:
        if not item["relative_path"].endswith("audit.log.jsonl"):
            continue
        log_path = Path(item["path"])
        for line in log_path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            event = json.loads(line)
            action = event.get("action", "")
            if "patch_validation" in action:
                summary["validator_runs"] += 1
            if "sandbox_" in action:
                summary["sandbox_runs"] += 1
            exit_code = event.get("exit_code")
            if isinstance(exit_code, int):
                if exit_code == 0:
                    summary["successful_events"] += 1
                else:
                    summary["failed_events"] += 1
            elif "failed" in str(event.get("result_summary", "")).lower():
                summary["failed_events"] += 1
    return summary


def build_manifest(repo: Path, artifacts_root: Path) -> dict:
    generated_at = datetime.now(timezone.utc).isoformat()
    artifacts = collect_artifacts(artifacts_root)
    summary = extract_audit_summary(artifacts)
    return {
        "manifest_version": "1.0",
        "generated_at_utc": generated_at,
        "repo_path": str(repo),
        "artifacts_root": str(artifacts_root),
        "artifact_count": len(artifacts),
        "audit_summary": summary,
        "artifacts": artifacts,
        "notes": [
            "Append-only logs are preserved as discovered.",
            "This manifest is local-only and contains no remote upload references.",
            "Treat hashes as immutable evidence fingerprints.",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate SWIFT evidence manifest.")
    parser.add_argument("--repo", required=True, help="Repository path containing .swift-artifacts")
    args = parser.parse_args()

    repo = Path(args.repo).resolve()
    artifacts_root = repo / ".swift-artifacts"
    manifest = build_manifest(repo=repo, artifacts_root=artifacts_root)
    output_file = artifacts_root / "evidence.manifest.json"
    output_file.parent.mkdir(parents=True, exist_ok=True)
    output_file.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps({"manifest": str(output_file), "artifact_count": manifest["artifact_count"]}, indent=2))


if __name__ == "__main__":
    main()
