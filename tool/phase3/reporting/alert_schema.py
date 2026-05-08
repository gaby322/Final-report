from __future__ import annotations


import hashlib
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional


def make_deterministic_alert_id(
    event_id: str,
    phase1_check_ids: Iterable[str],
    phase2_path_ids: Iterable[str],
    principal_arns: Iterable[str],
) -> str:
    p1 = ",".join(sorted(s for s in phase1_check_ids if s))
    p2 = ",".join(sorted(s for s in phase2_path_ids if s))
    pa = ",".join(sorted(s for s in principal_arns if s))
    key = f"{event_id or 'static'}|{p1}|{p2}|{pa}"
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:12]


ALERT_TYPE_ACTIVE = "ACTIVE_EXPLOITATION"
ALERT_TYPE_LATENT = "LATENT_RISK"
ALERT_TYPE_SUSPICIOUS = "SUSPICIOUS_ACTIVITY"
ALERT_TYPE_INFO = "INFORMATIONAL"

SEVERITY_ORDER = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "INFORMATIONAL": 0,
}

STANDALONE_SEVERITY_SENTINEL = "SEE_EVENT_SENSITIVITY"


@dataclass
class CorrelatedAlert:
    alert_id: str = ""
    alert_type: str = ALERT_TYPE_INFO

    correlation_tier: str = ""
    correlation_reason: str = ""

    source_phase1_check_ids: List[str] = field(default_factory=list)
    source_phase2_path_ids: List[str] = field(default_factory=list)
    source_cloudtrail_event_ids: List[str] = field(default_factory=list)
    source_cloudtrail_event_names: List[str] = field(default_factory=list)

    principal_arns: List[str] = field(default_factory=list)
    affected_roles: List[str] = field(default_factory=list)
    affected_policies: List[str] = field(default_factory=list)
    account_id: str = ""
    aws_region: str = ""

    p1_severity_label: str = ""
    p2_risk_label: str = ""
    event_sensitivity: str = ""
    overall_severity: str = "INFORMATIONAL"

    p1_match_confidence: str = "NONE"

    evidence_completeness: str = "LIMITED"

    mitre_tactic_deterministic: str = ""
    mitre_tactic_id_deterministic: str = ""
    mitre_technique_deterministic: str = ""
    mitre_technique_id_deterministic: str = ""
    mitre_sub_technique_deterministic: Optional[str] = None
    mitre_sub_technique_id_deterministic: Optional[str] = None
    mitre_mapping_basis: str = "NONE"

    llm_explanation: str = ""
    llm_priority_justification: str = ""
    llm_false_positive_assessment: str = ""
    llm_mitre_tactic_confirmed: str = ""
    llm_mitre_technique_inferred: str = ""
    llm_remediation_steps: str = ""
    llm_backend_used: str = ""

    rag_sources_used: List[str] = field(default_factory=list)
    rag_chunks_count: int = 0

    grounding_valid: bool = True
    ungrounded_fields: List[str] = field(default_factory=list)
    grounding_details: Dict[str, Any] = field(default_factory=dict)

    evidence_summary: str = ""

    evidence_details: List[Dict[str, Any]] = field(default_factory=list)

    def severity_score(self) -> int:
        if self.overall_severity == STANDALONE_SEVERITY_SENTINEL:
            return 0
        return SEVERITY_ORDER.get(self.overall_severity, 0)

    def triage_summary(self) -> Dict[str, Any]:
        if self.mitre_technique_deterministic == "UNMAPPED":
            mitre_display = "UNMAPPED"
        else:
            mitre_display = (
                f"{self.mitre_technique_id_deterministic} "
                f"{self.mitre_technique_deterministic}"
            ).strip()

        severity_display = (
           "Not context-rated"
           if self.overall_severity == STANDALONE_SEVERITY_SENTINEL
           else self.overall_severity
        )

        return {
            "alert_id": self.alert_id,
            "alert_type": self.alert_type,
            "overall_severity_raw": self.overall_severity,
            "overall_severity_display": severity_display,
            "event_sensitivity": self.event_sensitivity,
            "evidence_completeness": self.evidence_completeness,
            "correlation_tier": self.correlation_tier,
            "principal_arns": self.principal_arns[:2],
            "p1_severity": self.p1_severity_label,
            "p2_risk": self.p2_risk_label,
            "mitre": mitre_display,
            "summary": self.evidence_summary[:200],
            "grounding_valid": self.grounding_valid,
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            "alert_id": self.alert_id,
            "alert_type": self.alert_type,
            "correlation_tier": self.correlation_tier,
            "correlation_reason": self.correlation_reason,
            "source_phase1_check_ids": self.source_phase1_check_ids,
            "source_phase2_path_ids": self.source_phase2_path_ids,
            "source_cloudtrail_event_ids": self.source_cloudtrail_event_ids,
            "source_cloudtrail_event_names": self.source_cloudtrail_event_names,
            "principal_arns": self.principal_arns,
            "affected_roles": self.affected_roles,
            "affected_policies": self.affected_policies,
            "account_id": self.account_id,
            "aws_region": self.aws_region,
            "p1_severity_label": self.p1_severity_label,
            "p2_risk_label": self.p2_risk_label,
            "event_sensitivity": self.event_sensitivity,
            "overall_severity": self.overall_severity,
            "evidence_completeness": self.evidence_completeness,
            "p1_match_confidence": self.p1_match_confidence,
            "mitre": {
                "tactic": self.mitre_tactic_deterministic,
                "tactic_id": self.mitre_tactic_id_deterministic,
                "technique": self.mitre_technique_deterministic,
                "technique_id": self.mitre_technique_id_deterministic,
                "sub_technique": self.mitre_sub_technique_deterministic,
                "sub_technique_id": self.mitre_sub_technique_id_deterministic,
                "mapping_basis": self.mitre_mapping_basis,
                "llm_tactic_confirmed": self.llm_mitre_tactic_confirmed,
                "llm_technique_inferred": self.llm_mitre_technique_inferred,
            },
            "llm_explanation": self.llm_explanation,
            "llm_priority_justification": self.llm_priority_justification,
            "llm_false_positive_assessment": self.llm_false_positive_assessment,
            "llm_remediation_steps": self.llm_remediation_steps,
            "llm_backend_used": self.llm_backend_used,
            "rag_sources_used": self.rag_sources_used,
            "rag_chunks_count": self.rag_chunks_count,
            "grounding_valid": self.grounding_valid,
            "ungrounded_fields": self.ungrounded_fields,
            "grounding_details": self.grounding_details,
            "evidence_summary": self.evidence_summary,
            "evidence_details": self.evidence_details,
        }