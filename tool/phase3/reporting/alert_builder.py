from __future__ import annotations


from typing import List

from phase3.analysis.correlator import (
    EvidenceBundle,
    CORRELATION_TIER_STRONGLY,
    CORRELATION_TIER_PARTIALLY,
    CORRELATION_TIER_DYNAMIC,
    CORRELATION_TIER_STATIC,
)
from phase3.llm.llm_adapter import LLMResponse
from phase3.llm.hallucination_guard import GroundingReport
from phase3.rag.retriever import RetrievedChunk
from phase3.reporting.alert_schema import (
    STANDALONE_SEVERITY_SENTINEL,
    CorrelatedAlert,
    ALERT_TYPE_ACTIVE,
    ALERT_TYPE_LATENT,
    ALERT_TYPE_SUSPICIOUS,
    ALERT_TYPE_INFO,
    make_deterministic_alert_id,
)


class AlertBuilder:
    def build(
        self,
        bundle: EvidenceBundle,
        llm_response: LLMResponse,
        grounding_report: GroundingReport,
        retrieved_chunks: List[RetrievedChunk],
    ) -> CorrelatedAlert:

        llm = llm_response.parsed_json or {}
        alert = CorrelatedAlert()

        alert.alert_type = self._determine_alert_type(bundle)
        alert.correlation_tier = bundle.correlation_tier
        alert.correlation_reason = bundle.correlation_reason

        alert.source_phase1_check_ids = [f.check_id for f in bundle.p1_findings]
        alert.source_phase2_path_ids = [p.path_id for p in bundle.p2_paths]
        alert.source_cloudtrail_event_ids = (
            [bundle.event.event_id] if bundle.event.event_id else []
        )

        alert.alert_id = make_deterministic_alert_id(
            event_id=bundle.event.event_id or "",
            phase1_check_ids=alert.source_phase1_check_ids,
            phase2_path_ids=alert.source_phase2_path_ids,
            principal_arns=bundle.all_principal_arns,
        )
        alert.source_cloudtrail_event_names = (
            [bundle.event.event_name]
            if self._has_observed_cloudtrail_event(bundle) and bundle.event.event_name
            else []
        )

        alert.principal_arns = bundle.all_principal_arns
        alert.affected_roles = self._extract_roles(bundle)
        alert.affected_policies = self._extract_policies(bundle)
        alert.account_id = self._extract_account_id(bundle)
        alert.aws_region = bundle.event.aws_region
        alert.evidence_details = self._extract_evidence_details(bundle)

        alert.p1_severity_label = bundle.p1_severity_label
        alert.p2_risk_label = bundle.p2_risk_label
        alert.event_sensitivity = bundle.event_sensitivity
        alert.overall_severity = self._determine_severity(bundle)
        alert.evidence_completeness = self._determine_evidence_completeness(bundle)
        alert.p1_match_confidence = bundle.p1_match_confidence.value

        if bundle.mitre_mapping and not bundle.mitre_mapping.is_unmapped:
            m = bundle.mitre_mapping
            alert.mitre_tactic_deterministic = m.tactic
            alert.mitre_tactic_id_deterministic = m.tactic_id
            alert.mitre_technique_deterministic = m.technique
            alert.mitre_technique_id_deterministic = m.technique_id
            alert.mitre_sub_technique_deterministic = m.sub_technique
            alert.mitre_sub_technique_id_deterministic = m.sub_technique_id
            alert.mitre_mapping_basis = m.mapping_basis
        else:
            alert.mitre_technique_deterministic = "UNMAPPED"
            alert.mitre_mapping_basis = "NONE"

        alert.llm_explanation = llm.get("explanation", "")
        alert.llm_priority_justification = llm.get("priority_justification", "")
        alert.llm_false_positive_assessment = llm.get("false_positive_assessment", "")
        alert.llm_mitre_tactic_confirmed = llm.get("mitre_tactic_confirmed", "")
        alert.llm_mitre_technique_inferred = llm.get("mitre_technique_inferred", "")
        alert.llm_remediation_steps = llm.get("remediation_steps", "")
        alert.llm_backend_used = llm_response.backend_used

        alert.rag_sources_used = list(dict.fromkeys(c.source for c in retrieved_chunks))
        alert.rag_chunks_count = len(retrieved_chunks)

        alert.grounding_valid = grounding_report.grounding_valid
        alert.ungrounded_fields = grounding_report.ungrounded_fields
        alert.grounding_details = grounding_report.to_dict()

        alert.evidence_summary = self._build_summary(bundle, alert)
        return alert

    def _determine_alert_type(self, bundle: EvidenceBundle) -> str:
        tier = bundle.correlation_tier
        if tier == CORRELATION_TIER_STRONGLY:
            return ALERT_TYPE_ACTIVE
        if tier == CORRELATION_TIER_STATIC:
            return ALERT_TYPE_LATENT
        if tier == CORRELATION_TIER_DYNAMIC:
            return ALERT_TYPE_SUSPICIOUS

        event_is_sensitive = bool(bundle.event_mitre_technique_id)
        if event_is_sensitive and (
            bundle.p1_severity_label in {"critical", "high"}
            or bundle.p2_risk_label in {"CRITICAL", "HIGH"}
        ):
            return ALERT_TYPE_ACTIVE
        if bundle.p1_severity_label or bundle.p2_risk_label:
            return ALERT_TYPE_LATENT
        return ALERT_TYPE_INFO
    
    def _has_observed_cloudtrail_event(self, bundle: EvidenceBundle) -> bool:
        return bundle.correlation_tier != CORRELATION_TIER_STATIC

    def _determine_severity(self, bundle: EvidenceBundle) -> str:
        tier = bundle.correlation_tier
        p1 = bundle.p1_severity_label.lower() if bundle.p1_severity_label else ""
        p2 = bundle.p2_risk_label.upper() if bundle.p2_risk_label else ""

        if tier == CORRELATION_TIER_STRONGLY:
            if p1 == "critical" or p2 == "CRITICAL":
                return "CRITICAL"
            return "HIGH"

        if tier == CORRELATION_TIER_PARTIALLY:
            if p1 in {"critical", "high"} or p2 == "CRITICAL":
                return "HIGH"
            if p1 == "medium" or p2 == "HIGH":
                return "MEDIUM"
            return "LOW"

        if tier == CORRELATION_TIER_DYNAMIC:
            return STANDALONE_SEVERITY_SENTINEL

        if tier == CORRELATION_TIER_STATIC:
            if p1 in {"critical", "high"}:
                return p1.upper()
            if p1 == "medium":
                return "MEDIUM"
            return "LOW"

        return "INFORMATIONAL"

    def _determine_evidence_completeness(self, bundle: EvidenceBundle) -> str:
        sources = 0
        has_cloudtrail = self._has_observed_cloudtrail_event(bundle)
        if has_cloudtrail:
            sources += 1
        if bundle.p1_findings:
            sources += 1
        if bundle.p2_paths:
            sources += 1

        if sources == 3:
            return "FULL"
        if sources == 2:
            return "PARTIAL"
        return "LIMITED"

    def _extract_roles(self, bundle: EvidenceBundle) -> List[str]:
        roles: List[str] = []
        for p in bundle.p2_paths:
            if p.end_arn and "role" in p.end_arn.lower() and p.end_arn not in roles:
                roles.append(p.end_arn)
            for step in p.steps:
                if "role" in step.target_arn.lower() and step.target_arn not in roles:
                    roles.append(step.target_arn)
        if bundle.event.assumed_role_arn and bundle.event.assumed_role_arn not in roles:
            roles.append(bundle.event.assumed_role_arn)
        for f in bundle.p1_findings:
            if (
                f.resource_type == "AWS::IAM::Role"
                and f.resource_id
                and f.resource_id not in roles
            ):
                roles.append(f.resource_id)
        return roles

    def _extract_policies(self, bundle: EvidenceBundle) -> List[str]:
        policies: List[str] = []
        if bundle.event.policy_arn:
            policies.append(bundle.event.policy_arn)
        for f in bundle.p1_findings:
            if not f.resource_id:
                continue
            is_policy = (
                f.resource_type == "AWS::IAM::Policy"
                or "policy" in f.resource_id.lower()
            )
            if is_policy and f.resource_id not in policies:
                policies.append(f.resource_id)
        return policies

    def _extract_account_id(self, bundle: EvidenceBundle) -> str:
        if bundle.event.principal_account_id:
            return bundle.event.principal_account_id
        for f in bundle.p1_findings:
            if f.account_id:
                return f.account_id
        return ""

    def _extract_evidence_details(self, bundle: EvidenceBundle) -> List[dict]:
        details: List[dict] = []
        for f in bundle.p1_findings:
            details.append({
                "check_id": f.check_id,
                "resource_type": f.resource_type or "",
                "resource_id": f.resource_id or "",
                "principal_arn": f.principal_arn or "",
                "severity": f.severity,
                "status_extended": f.status_extended or "",
                "description": f.description or "",
                "remediation": f.remediation or "",
                "evidence_summary": f.evidence_summary or "",
            })
        return details

    def _build_summary(self, bundle: EvidenceBundle, alert: CorrelatedAlert) -> str:
        principal = bundle.event.principal_display() or (
            alert.principal_arns[0] if alert.principal_arns else "unknown principal"
        )

        if alert.overall_severity == STANDALONE_SEVERITY_SENTINEL and alert.event_sensitivity:
            parts = [f"{alert.alert_type} (event sensitivity: {alert.event_sensitivity})"]
        else:
            parts = [f"{alert.alert_type} ({alert.overall_severity})"]

        if self._has_observed_cloudtrail_event(bundle) and bundle.event.event_name:
            parts.append(f"CloudTrail event '{bundle.event.event_name}' by {principal}")
        else:
            parts.append(f"Static posture finding for {principal}")

        if bundle.p1_findings:
            parts.append(f"{len(bundle.p1_findings)} Phase 1 finding(s)")
        if bundle.p2_paths:
            parts.append(f"{len(bundle.p2_paths)} Phase 2 escalation path(s)")

        if bundle.mitre_mapping and not bundle.mitre_mapping.is_unmapped:
            m = bundle.mitre_mapping
            tid = m.sub_technique_id or m.technique_id
            tname = m.sub_technique or m.technique
            parts.append(f"MITRE: {tid} {tname}")
        elif bundle.event_sensitivity:
            parts.append(f"Framework event sensitivity: {bundle.event_sensitivity}")

        return ". ".join(parts) + "."