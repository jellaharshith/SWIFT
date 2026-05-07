"""Engagement manifest with GPG or HMAC-SHA256 signing."""
import hashlib
import hmac
import json
import os
import subprocess
from dataclasses import dataclass, asdict
from pathlib import Path


@dataclass
class EngagementManifest:
    """Signed record of an engagement's identity and rules of engagement.

    Attributes:
        engagement_id: Unique identifier for the engagement.
        operator_email_hash: SHA-256 of operator email (PII-safe).
        roe_file_hash: SHA-256 of the ROE YAML file bytes.
        swift_version: SWIFT version string at time of engagement.
        timestamp: ISO-8601 UTC timestamp of manifest creation.
    """

    engagement_id: str
    operator_email_hash: str   # SHA-256 of operator email
    roe_file_hash: str         # SHA-256 of ROE YAML file bytes
    swift_version: str
    timestamp: str

    def signing_payload(self) -> bytes:
        """Return deterministic JSON bytes suitable for signing.

        Returns:
            UTF-8 encoded JSON with sorted keys and no extra whitespace.
        """
        return json.dumps(asdict(self), sort_keys=True, separators=(",", ":")).encode()

    def sign(self, out_path: Path) -> Path:
        """Write manifest JSON and a signature file alongside it.

        Uses GPG if SWIFT_GPG_KEY_ID env var is set, otherwise HMAC-SHA256
        keyed with ANTHROPIC_API_KEY (fallback to literal 'fallback-key').

        Args:
            out_path: Destination path for the manifest JSON file.

        Returns:
            Path to the .sig file written alongside out_path.

        Raises:
            subprocess.CalledProcessError: If GPG signing fails.
        """
        out_path = Path(out_path)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_bytes(self.signing_payload())

        sig_path = out_path.with_suffix(".sig")
        gpg_key = os.getenv("SWIFT_GPG_KEY_ID")
        if gpg_key:
            subprocess.run(
                ["gpg", "--detach-sign", "--armor", "-u", gpg_key, "-o", str(sig_path), str(out_path)],
                check=True,
            )
        else:
            key = os.getenv("ANTHROPIC_API_KEY", "fallback-key").encode()
            sig = hmac.new(key, self.signing_payload(), hashlib.sha256).hexdigest()
            sig_path.write_text(f"HMAC-SHA256:{sig}\n")

        return sig_path

    @classmethod
    def from_roe_file(
        cls,
        roe_path: Path,
        engagement_id: str,
        operator_email: str,
        swift_version: str,
        timestamp: str,
    ) -> "EngagementManifest":
        """Convenience constructor that hashes the ROE file automatically.

        Args:
            roe_path: Path to the ROE YAML file.
            engagement_id: Unique identifier for the engagement.
            operator_email: Operator's email (will be SHA-256 hashed).
            swift_version: SWIFT version string.
            timestamp: ISO-8601 UTC timestamp.

        Returns:
            EngagementManifest instance with hashed email and ROE file.
        """
        roe_bytes = Path(roe_path).read_bytes()
        roe_hash = hashlib.sha256(roe_bytes).hexdigest()
        op_hash = hashlib.sha256(operator_email.encode()).hexdigest()
        return cls(
            engagement_id=engagement_id,
            operator_email_hash=op_hash,
            roe_file_hash=roe_hash,
            swift_version=swift_version,
            timestamp=timestamp,
        )
