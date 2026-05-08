from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional


class CheckMetadata:
    def __init__(self, metadata: Dict[str, Any]):
        self.metadata = metadata

    @property
    def check_id(self) -> str:
        return self.metadata.get("CheckID", "")

    @property
    def title(self) -> str:
        return self.metadata.get("CheckTitle", "")

    @property
    def severity(self) -> str:
        return self.metadata.get("Severity", "UNKNOWN")

    @property
    def description(self) -> str:
        return self.metadata.get("Description", "")

    @property
    def risk(self) -> str:
        return self.metadata.get("Risk", "")

    @property
    def remediation(self) -> str:
        return self.metadata.get("Remediation", "")

    @property
    def service_name(self) -> str:
        return self.metadata.get("ServiceName", "")

    @property
    def resource_type(self) -> str:
        return self.metadata.get("ResourceType", "")

    @property
    def categories(self) -> List[str]:
        return self.metadata.get("Categories", [])

    @property
    def severity_basis(self) -> str:
        return self.metadata.get("SeverityBasis", "")

    @property
    def authoritative_source(self) -> str:
        return self.metadata.get("AuthoritativeSource", "")

    @property
    def cis_control(self) -> str:
        return self.metadata.get("CISControl", "")

    @property
    def nist_control(self) -> str:
        return self.metadata.get("NISTControl", "")

    @property
    def threat_reference(self) -> Optional[str]:
        return self.metadata.get("ThreatReference")

    @property
    def reference_url(self) -> Optional[str]:
        return self.metadata.get("ReferenceUrl")

    @property
    def reference_control_id(self) -> Optional[str]:
        return self.metadata.get("ReferenceControlId")

    @property
    def reference_source(self) -> Optional[str]:
        return self.metadata.get("ReferenceSource")


def load_check_metadata(path: Path) -> CheckMetadata:
    with path.open("r", encoding="utf-8") as fh:
        data = json.load(fh)
    return CheckMetadata(data)
