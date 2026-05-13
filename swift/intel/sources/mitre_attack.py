"""MITRE ATT&CK STIX source — fetches enterprise technique catalog."""
from __future__ import annotations

import uuid

import httpx

from intel.sources.models import IntelDocument

STIX_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"


class MitreAttackSource:
    name = "mitre_attack"

    async def fetch(self) -> list[IntelDocument]:
        try:
            async with httpx.AsyncClient(timeout=60) as client:
                resp = await client.get(STIX_URL)
                resp.raise_for_status()
                bundle = resp.json()
        except Exception:
            return []

        docs = []
        for obj in bundle.get("objects", []):
            if obj.get("type") != "attack-pattern":
                continue
            technique_id = ""
            url = ""
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    technique_id = ref.get("external_id", "")
                    url = ref.get("url", "")
                    break
            name = obj.get("name", "")
            desc = obj.get("description", "")[:2000]
            phases = [p.get("phase_name", "") for p in obj.get("kill_chain_phases", [])]
            content = f"Technique: {technique_id} — {name}\nPhases: {', '.join(phases)}\n\n{desc}"
            doc_id = f"mitre_{technique_id or uuid.uuid4().hex[:8]}"
            docs.append(IntelDocument(
                doc_id=doc_id,
                source=self.name,
                title=f"{technique_id}: {name}",
                content=content,
                metadata={"technique_id": technique_id, "phases": phases},
                url=url,
            ))
        return docs
