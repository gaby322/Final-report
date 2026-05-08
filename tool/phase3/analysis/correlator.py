from __future__ import annotations


from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from phase3.ingestion.cloudtrail_normalizer import (
    NormalizedEvent,
    PrincipalType,
)
from phase3.ingestion.phase1_loader import (
    MatchConfidence,
    P1Finding,
    Phase1Loader,
    confidence_rank,
    max_confidence,
)
from phase3.ingestion.phase2_loader import P2Path, Phase2Loader
from phase3.analysis.mitre_mapper import MITREMapping, map_event


_TACTIC_TO_EVENT_SENSITIVITY: Dict[str, str] = {
    "Privilege Escalation": "HIGH",
    "Persistence": "HIGH",
    "Credential Access": "HIGH",
    "Lateral Movement": "HIGH",
    "Defense Evasion": "MEDIUM",
    "Discovery": "MEDIUM",
}

_MITRE_SENSITIVE_ACTIONS_RAW: List[Tuple[str, str, str, str]] = [

    ("CreateAccessKey",           "T1098.001", "Additional Cloud Credentials",          "Credential Access"),

    ("AttachRolePolicy",          "T1098.003", "Additional Cloud Roles",                "Privilege Escalation"),
    ("AttachUserPolicy",          "T1098.003", "Additional Cloud Roles",                "Privilege Escalation"),
    ("AttachGroupPolicy",         "T1098.003", "Additional Cloud Roles",                "Privilege Escalation"),
    ("PutRolePolicy",             "T1098.003", "Additional Cloud Roles",                "Privilege Escalation"),
    ("PutUserPolicy",             "T1098.003", "Additional Cloud Roles",                "Privilege Escalation"),
    ("CreatePolicyVersion",       "T1098.003", "Additional Cloud Roles",                "Privilege Escalation"),
    ("SetDefaultPolicyVersion",   "T1098.003", "Additional Cloud Roles",                "Privilege Escalation"),
    ("UpdateAssumeRolePolicy",    "T1098.003", "Additional Cloud Roles",                "Privilege Escalation"),
    ("AddUserToGroup",            "T1098.003", "Additional Cloud Roles",                "Privilege Escalation"),
    ("AddRoleToInstanceProfile",  "T1098.003", "Additional Cloud Roles",                "Privilege Escalation"),

    ("CreateUser",                "T1136.003", "Create Account: Cloud Account",         "Persistence"),
    ("CreateRole",                "T1136.003", "Create Account: Cloud Account",         "Persistence"),

    ("CreateLoginProfile",        "T1078.004", "Valid Accounts: Cloud Accounts",        "Persistence"),
    ("UpdateLoginProfile",        "T1078.004", "Valid Accounts: Cloud Accounts",        "Persistence"),

    ("AssumeRole",                "T1550.001", "Use Alternate Authentication Material", "Lateral Movement"),
    ("AssumeRoleWithSAML",        "T1550.001", "Use Alternate Authentication Material", "Lateral Movement"),
    ("AssumeRoleWithWebIdentity", "T1550.001", "Use Alternate Authentication Material", "Lateral Movement"),
    ("GetFederationToken",        "T1550.001", "Use Alternate Authentication Material", "Credential Access"),
    ("GetSessionToken",           "T1550.001", "Use Alternate Authentication Material", "Credential Access"),

    ("DeactivateMFADevice",       "T1556.006", "Modify Authentication Process",         "Defense Evasion"),
    ("DeleteVirtualMFADevice",    "T1556.006", "Modify Authentication Process",         "Defense Evasion"),
    ("CreateSAMLProvider",        "T1556.006", "Modify Authentication Process",         "Persistence"),
    ("UpdateSAMLProvider",        "T1556.006", "Modify Authentication Process",         "Persistence"),

    ("DeleteUser",                "T1070",     "Indicator Removal",                     "Defense Evasion"),
    ("DeleteRole",                "T1070",     "Indicator Removal",                     "Defense Evasion"),
    ("DeleteAccessKey",           "T1070",     "Indicator Removal",                     "Defense Evasion"),

    ("GenerateCredentialReport",  "T1087.004", "Account Discovery: Cloud Account",      "Discovery"),
    ("GetCredentialReport",       "T1087.004", "Account Discovery: Cloud Account",      "Discovery"),
]

MITRE_SENSITIVE_ACTIONS: Dict[str, Tuple[str, str, str, str]] = {
    action_name: (
        technique_id,
        technique_name,
        tactic,
        _TACTIC_TO_EVENT_SENSITIVITY[tactic],
    )
    for action_name, technique_id, technique_name, tactic in _MITRE_SENSITIVE_ACTIONS_RAW
}


CORRELATION_TIER_STRONGLY  = "STRONGLY_CORRELATED"
CORRELATION_TIER_PARTIALLY = "PARTIALLY_CORRELATED"
CORRELATION_TIER_DYNAMIC   = "DYNAMIC_STANDALONE"
CORRELATION_TIER_STATIC    = "STATIC_STANDALONE"


@dataclass
class EvidenceBundle:
    event: NormalizedEvent
    p1_findings: List[P1Finding] = field(default_factory=list)
    p2_paths: List[P2Path] = field(default_factory=list)
    correlation_tier: str = CORRELATION_TIER_DYNAMIC
    p1_severity_label: str = ""
    p2_risk_label: str = ""
    event_sensitivity: str = ""
    event_mitre_technique_id: str = ""
    correlation_reason: str = ""
    mitre_mapping: Optional[MITREMapping] = None
    is_mitre_grounded_standalone: bool = False
    p1_match_confidence: MatchConfidence = MatchConfidence.NONE

    @property
    def has_p1(self) -> bool:
        return bool(self.p1_findings)

    @property
    def has_p2(self) -> bool:
        return bool(self.p2_paths)

    @property
    def p2_edge_types(self) -> List[str]:
        types = []
        for path in self.p2_paths:
            types.extend(path.edge_types)
        return list(dict.fromkeys(types))

    @property
    def p1_categories(self) -> List[str]:
        cats = []
        for f in self.p1_findings:
            if f.category and f.category not in cats:
                cats.append(f.category)
        return cats

    @property
    def all_principal_arns(self) -> List[str]:
        arns = [self.event.principal_arn]
        if self.event.assumed_role_arn and self.event.assumed_role_arn not in arns:
            arns.append(self.event.assumed_role_arn)
        if self.event.session_issuer_arn and self.event.session_issuer_arn not in arns:
            arns.append(self.event.session_issuer_arn)
        return [a for a in arns if a]


class CorrelationEngine:
    def __init__(self, p1_loader: Phase1Loader, p2_loader: Phase2Loader):
        self.p1 = p1_loader
        self.p2 = p2_loader

    def correlate(self, events: List[NormalizedEvent]) -> List[EvidenceBundle]:
        bundles = []
        for event in events:
            bundle = self._correlate_event(event)
            if bundle:
                bundles.append(bundle)
        return bundles

    def static_only_bundles(
        self,
        exclude_principal_arns: Optional[Set[str]] = None,
    ) -> List[EvidenceBundle]:
        excluded = exclude_principal_arns or set()
        bundles = []

        for finding in self.p1.findings:
            if not self._severity_is_high_or_above(finding.severity):
                continue

            if finding.resource_id and finding.resource_id in excluded:
                continue
            if finding.principal_arn and finding.principal_arn in excluded:
                continue

            bundle = EvidenceBundle(
                event=_dummy_event(finding),
                p1_findings=[finding],
                p2_paths=[],
                correlation_tier=CORRELATION_TIER_STATIC,
                p1_severity_label=finding.severity,
                p2_risk_label="",
                event_sensitivity="",
                correlation_reason=(
                    f"Static posture finding: {finding.check_id} ({finding.severity}) "
                    f"with no observed CloudTrail activity for this principal "
                    f"in the current analysis window."
                ),
                p1_match_confidence=MatchConfidence.ARN_EXACT,
            )
            bundle.mitre_mapping = map_event(
                event_name="",
                p2_edge_types=None,
                p1_categories=finding.category.split(",") if finding.category else [],
            )
            bundles.append(bundle)

        return bundles

    def _correlate_event(self, event: NormalizedEvent) -> Optional[EvidenceBundle]:
        principal_arn = event.principal_arn
        principal_name = self._extract_name(event)
        principal_type = event.principal_type_canonical()

        typed_matches: Dict[str, Tuple[P1Finding, MatchConfidence]] = {}
        for f, conf in self.p1.findings_for_principal_typed(
            principal_arn, principal_name, principal_type
        ):
            typed_matches[f.check_id] = (f, conf)

        if event.session_issuer_arn:
            issuer_name = event.session_issuer_arn.split("/")[-1]
            issuer_matches = self.p1.findings_for_principal_typed(
                event.session_issuer_arn, issuer_name, PrincipalType.ROLE
            )
            for f, conf in issuer_matches:
                if conf in {MatchConfidence.ARN_EXACT, MatchConfidence.TYPE_LEAF}:
                    relabeled = MatchConfidence.ISSUER_TYPE_LEAF
                else:
                    relabeled = conf
                existing = typed_matches.get(f.check_id)
                if existing is None or confidence_rank(relabeled) > confidence_rank(existing[1]):
                    typed_matches[f.check_id] = (f, relabeled)

        target_arn, target_name, target_type = self._resolve_target_identity(event)
        if target_arn or target_name:
            for f, conf in self.p1.findings_for_principal_typed(
                target_arn or "", target_name or "", target_type
            ):
                if conf == MatchConfidence.ARN_EXACT:
                    relabeled = MatchConfidence.TARGET_ARN_EXACT
                elif conf == MatchConfidence.TYPE_LEAF:
                    relabeled = MatchConfidence.TARGET_TYPE_LEAF
                else:
                    relabeled = conf
                existing = typed_matches.get(f.check_id)
                if existing is None or confidence_rank(relabeled) > confidence_rank(existing[1]):
                    typed_matches[f.check_id] = (f, relabeled)

        p1_findings = [entry[0] for entry in typed_matches.values()]
        p1_match_confidence = max_confidence(
            *(entry[1] for entry in typed_matches.values())
        ) if typed_matches else MatchConfidence.NONE
        p1_severity_label = self._highest_p1_severity(p1_findings)

        p2_paths = self.p2.paths_for_principal(principal_arn, event.session_issuer_arn)
        p2_risk_label = self._highest_p2_risk(p2_paths)

        mitre_action_entry = MITRE_SENSITIVE_ACTIONS.get(event.event_name)

        if not p1_findings and not p2_paths and not mitre_action_entry:
            return None

        tier = self._assign_tier(
            p1_severity_label, p2_risk_label, mitre_action_entry, p1_match_confidence
        )

        event_sensitivity = ""
        event_mitre_technique_id = ""
        is_mitre_grounded_standalone = False

        if mitre_action_entry:
            event_mitre_technique_id = mitre_action_entry[0]
            if tier == CORRELATION_TIER_DYNAMIC:
                event_sensitivity = mitre_action_entry[3]
                is_mitre_grounded_standalone = True

        reason = self._build_reason(event, p1_findings, p2_paths, tier, mitre_action_entry)

        edge_types = []
        for p in p2_paths:
            edge_types.extend(p.edge_types)

        p1_categories = []
        for f in p1_findings:
            if f.category:
                p1_categories.extend(f.category.split(","))

        mitre = map_event(event.event_name, edge_types or None, p1_categories or None)

        return EvidenceBundle(
            event=event,
            p1_findings=p1_findings,
            p2_paths=p2_paths,
            correlation_tier=tier,
            p1_severity_label=p1_severity_label,
            p2_risk_label=p2_risk_label,
            event_sensitivity=event_sensitivity,
            event_mitre_technique_id=event_mitre_technique_id,
            correlation_reason=reason,
            mitre_mapping=mitre,
            is_mitre_grounded_standalone=is_mitre_grounded_standalone,
            p1_match_confidence=p1_match_confidence,
        )


    _P1_SEVERITY_ORDER = ["informational", "low", "medium", "high", "critical"]
    _P2_RISK_ORDER = ["HIGH", "CRITICAL"]

    def _severity_is_high_or_above(self, severity: str) -> bool:
        return severity.lower() in {"high", "critical"}

    def _highest_p1_severity(self, findings: List[P1Finding]) -> str:
        if not findings:
            return ""

        order = self._P1_SEVERITY_ORDER
        normalized = [
            f.severity.lower().strip()
            for f in findings
            if isinstance(f.severity, str) and f.severity.strip()
        ]
        valid = [s for s in normalized if s in order]

        if not valid:
            return "informational"

        return max(valid, key=order.index)

    def _highest_p2_risk(self, paths: List[P2Path]) -> str:
        if not paths:
            return ""

        order = self._P2_RISK_ORDER
        normalized = [
            p.risk_level.upper().strip()
            for p in paths
            if isinstance(p.risk_level, str) and p.risk_level.strip()
        ]
        valid = [s for s in normalized if s in order]

        if not valid:
            return ""

        return max(valid, key=order.index)

    _PROMOTING_P1_CONFIDENCES = {
        MatchConfidence.ARN_EXACT,
        MatchConfidence.TARGET_ARN_EXACT,
        MatchConfidence.TYPE_LEAF,
        MatchConfidence.TARGET_TYPE_LEAF,
        MatchConfidence.ISSUER_TYPE_LEAF,
    }

    def _resolve_target_identity(
        self, event: NormalizedEvent
    ) -> Tuple[Optional[str], Optional[str], PrincipalType]:
        rtype = (event.target_resource_type or "").strip()
        pt_map = {
            "IAMUser":  PrincipalType.USER,
            "IAMRole":  PrincipalType.ROLE,
            "IAMGroup": PrincipalType.GROUP,
        }
        ptype = pt_map.get(rtype, PrincipalType.UNKNOWN)

        target_arn = (event.target_resource_arn or "").strip() or None
        target_name = (event.target_resource_name or "").strip() or None
        if not target_name and target_arn and "/" in target_arn:
            target_name = target_arn.rsplit("/", 1)[-1]
        return target_arn, target_name, ptype

    def _assign_tier(
        self,
        p1_severity: str,
        p2_risk: str,
        mitre_action_entry: Optional[Tuple[str, str, str, str]],
        p1_match_confidence: MatchConfidence = MatchConfidence.NONE,
    ) -> str:
        has_significant_p1 = self._severity_is_high_or_above(p1_severity)
        has_any_p1 = bool(p1_severity)
        has_p2 = bool(p2_risk)
        p1_promotes = p1_match_confidence in self._PROMOTING_P1_CONFIDENCES

        if has_significant_p1 and has_p2 and p1_promotes:
            return CORRELATION_TIER_STRONGLY
        if has_any_p1 or has_p2:
            return CORRELATION_TIER_PARTIALLY
        if mitre_action_entry:
            return CORRELATION_TIER_DYNAMIC
        return CORRELATION_TIER_STATIC

    def _build_reason(
        self,
        event: NormalizedEvent,
        p1_findings: List[P1Finding],
        p2_paths: List[P2Path],
        tier: str,
        mitre_entry: Optional[Tuple[str, str, str, str]],
    ) -> str:
        parts = [
            f"CloudTrail event '{event.event_name}' by '{event.principal_display()}'."
        ]

        if p1_findings:
            severities = [f.severity for f in p1_findings]
            check_ids = [f.check_id for f in p1_findings[:3]]
            parts.append(
                f"Principal has {len(p1_findings)} Phase 1 finding(s) "
                f"({', '.join(severities[:3])}): {', '.join(check_ids)}."
            )

        if p2_paths:
            edges = list(dict.fromkeys(
                e for p in p2_paths[:2] for e in p.edge_types
            ))
            parts.append(
                f"Principal has {len(p2_paths)} reachable escalation path(s) "
                f"via: {', '.join(edges)}."
            )

        if tier == CORRELATION_TIER_STRONGLY:
            parts.append(
                "Tier: STRONGLY CORRELATED — dynamic event on a principal "
                "with Phase 1 misconfiguration and a reachable Phase 2 escalation path."
            )
        elif tier == CORRELATION_TIER_PARTIALLY:
            parts.append(
                "Tier: PARTIALLY CORRELATED — event matches Phase 1 or Phase 2 "
                "evidence but not both."
            )
        elif tier == CORRELATION_TIER_DYNAMIC and mitre_entry:
            tid, tname, tactic, sensitivity = mitre_entry
            parts.append(
                f"Tier: DYNAMIC STANDALONE — no prior-phase match. "
                f"Event maps to MITRE ATT&CK {tid} ({tname}, tactic: {tactic}). "
                f"Framework event sensitivity: {sensitivity}."
            )

        return " ".join(parts)

    def _extract_name(self, event: NormalizedEvent) -> str:
        arn = event.principal_arn
        if "/" in arn:
            return arn.split("/")[-1]
        if event.session_issuer_arn and "/" in event.session_issuer_arn:
            return event.session_issuer_arn.split("/")[-1]
        return ""


def _dummy_event(finding: P1Finding) -> NormalizedEvent:
    from phase3.ingestion.cloudtrail_normalizer import NormalizedEvent

    resource_type = (finding.resource_type or "").strip()
    principal_type_for_arn: Dict[str, str] = {
        "AWS::IAM::User":  "IAMUser",
        "AWS::IAM::Role":  "AssumedRole",
        "AWS::IAM::Group": "IAMGroup",
    }
    is_principal_scoped = resource_type in principal_type_for_arn
    principal_type = principal_type_for_arn.get(resource_type, "")

    return NormalizedEvent(
        event_id=f"static_{finding.check_id}",
        event_name="[StaticFinding]",
        event_source="iam.amazonaws.com",
        event_time="",
        aws_region="",
        principal_arn=finding.resource_id if is_principal_scoped else "",
        principal_type=principal_type,
        principal_account_id=finding.account_id,
        target_resource_arn=(
            finding.resource_id if not is_principal_scoped else None
        ),
        target_resource_type=resource_type or None,
    )