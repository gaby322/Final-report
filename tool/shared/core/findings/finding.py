from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class Evidence:
    summary: str
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Reference:

    source: str
    control_id: str
    url: Optional[str] = None


@dataclass
class Finding:
    check_id: str
    status: str
    status_extended: str
    resource_type: str
    resource_id: str
    account_id: str
    region: str
    partition: str
    service_name: str
    severity: str
    category: Optional[str] = None
    description: Optional[str] = None
    remediation: Optional[str] = None
    evidence: Optional[Evidence] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)
    severity_basis: str = ""
    authoritative_source: str = ""
    cis_control: str = ""
    nist_control: str = ""
    references: List[Reference] = field(default_factory=list)
    schema_version: str = "1.0"
