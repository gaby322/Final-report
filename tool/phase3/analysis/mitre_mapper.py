from __future__ import annotations


from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple


@dataclass
class MITREMapping:
    tactic: str
    tactic_id: str
    technique: str
    technique_id: str
    sub_technique: Optional[str] = None
    sub_technique_id: Optional[str] = None
    mapping_basis: str = "HIGH"
    is_unmapped: bool = False

    def display(self) -> str:
        if self.is_unmapped:
            return "UNMAPPED"
        tid = self.sub_technique_id or self.technique_id
        name = self.sub_technique or self.technique
        return f"{tid} — {name} ({self.tactic})"


_EVENT_TO_MITRE: Dict[str, Tuple[str, str, str, str, Optional[str], Optional[str]]] = {
    "CreateAccessKey":            ("TA0006", "Credential Access",    "T1098",    "Account Manipulation",          "T1098.001", "Additional Cloud Credentials"),

    "CreatePolicyVersion":        ("TA0004", "Privilege Escalation", "T1098",    "Account Manipulation",          "T1098.003", "Additional Cloud Roles"),
    "SetDefaultPolicyVersion":    ("TA0004", "Privilege Escalation", "T1098",    "Account Manipulation",          "T1098.003", "Additional Cloud Roles"),
    "AttachRolePolicy":           ("TA0004", "Privilege Escalation", "T1098",    "Account Manipulation",          "T1098.003", "Additional Cloud Roles"),
    "AttachUserPolicy":           ("TA0004", "Privilege Escalation", "T1098",    "Account Manipulation",          "T1098.003", "Additional Cloud Roles"),
    "AttachGroupPolicy":          ("TA0004", "Privilege Escalation", "T1098",    "Account Manipulation",          "T1098.003", "Additional Cloud Roles"),
    "PutRolePolicy":              ("TA0004", "Privilege Escalation", "T1098",    "Account Manipulation",          "T1098.003", "Additional Cloud Roles"),
    "PutUserPolicy":              ("TA0004", "Privilege Escalation", "T1098",    "Account Manipulation",          "T1098.003", "Additional Cloud Roles"),
    "UpdateAssumeRolePolicy":     ("TA0004", "Privilege Escalation", "T1098",    "Account Manipulation",          "T1098.003", "Additional Cloud Roles"),
    "AddUserToGroup":             ("TA0004", "Privilege Escalation", "T1098",    "Account Manipulation",          "T1098.003", "Additional Cloud Roles"),
    "AddRoleToInstanceProfile":   ("TA0004", "Privilege Escalation", "T1098",    "Account Manipulation",          "T1098.003", "Additional Cloud Roles"),

    "CreateUser":                 ("TA0003", "Persistence",          "T1136",    "Create Account",                "T1136.003", "Cloud Account"),
    "CreateRole":                 ("TA0003", "Persistence",          "T1136",    "Create Account",                "T1136.003", "Cloud Account"),

    "CreateLoginProfile":         ("TA0003", "Persistence",          "T1078",    "Valid Accounts",                "T1078.004", "Cloud Accounts"),
    "UpdateLoginProfile":         ("TA0003", "Persistence",          "T1078",    "Valid Accounts",                "T1078.004", "Cloud Accounts"),

    "AssumeRole":                 ("TA0008", "Lateral Movement",     "T1550",    "Use Alternate Authentication Material", "T1550.001", "Application Access Token"),
    "AssumeRoleWithSAML":         ("TA0008", "Lateral Movement",     "T1550",    "Use Alternate Authentication Material", "T1550.001", "Application Access Token"),
    "AssumeRoleWithWebIdentity":  ("TA0008", "Lateral Movement",     "T1550",    "Use Alternate Authentication Material", "T1550.001", "Application Access Token"),
    "GetSessionToken":            ("TA0006", "Credential Access",    "T1550",    "Use Alternate Authentication Material", "T1550.001", "Application Access Token"),
    "GetFederationToken":         ("TA0006", "Credential Access",    "T1550",    "Use Alternate Authentication Material", "T1550.001", "Application Access Token"),

    "DeactivateMFADevice":        ("TA0005", "Defense Evasion",      "T1556",    "Modify Authentication Process", "T1556.006", "Multi-Factor Authentication"),
    "DeleteVirtualMFADevice":     ("TA0005", "Defense Evasion",      "T1556",    "Modify Authentication Process", "T1556.006", "Multi-Factor Authentication"),
    "CreateSAMLProvider":         ("TA0003", "Persistence",          "T1556",    "Modify Authentication Process", "T1556.006", "Multi-Factor Authentication"),
    "UpdateSAMLProvider":         ("TA0003", "Persistence",          "T1556",    "Modify Authentication Process", "T1556.006", "Multi-Factor Authentication"),

    "DeleteUser":                 ("TA0005", "Defense Evasion",      "T1070",    "Indicator Removal",             None,        None),
    "DeleteRole":                 ("TA0005", "Defense Evasion",      "T1070",    "Indicator Removal",             None,        None),
    "DeleteAccessKey":            ("TA0005", "Defense Evasion",      "T1070",    "Indicator Removal",             None,        None),

    "GenerateCredentialReport":   ("TA0007", "Discovery",            "T1087",    "Account Discovery",             "T1087.004", "Cloud Account"),
    "GetCredentialReport":        ("TA0007", "Discovery",            "T1087",    "Account Discovery",             "T1087.004", "Cloud Account"),
    "ListAttachedRolePolicies":   ("TA0007", "Discovery",            "T1069",    "Permission Groups Discovery",   "T1069.003", "Cloud Groups"),
    "GetRolePolicy":              ("TA0007", "Discovery",            "T1069",    "Permission Groups Discovery",   "T1069.003", "Cloud Groups"),
}

_EDGE_TYPE_TO_MITRE: Dict[str, Tuple[str, str, str, str, str, str]] = {
    "sts:AssumeRole":             ("TA0008", "Lateral Movement",     "T1550",    "Use Alternate Authentication Material", "T1550.001", "Application Access Token"),
    "iam:PassRole_via_EC2":       ("TA0004", "Privilege Escalation", "T1098",    "Account Manipulation",          "T1098.003", "Additional Cloud Roles"),
    "iam:PassRole_via_Lambda":    ("TA0004", "Privilege Escalation", "T1098",    "Account Manipulation",          "T1098.003", "Additional Cloud Roles"),
    "iam:PassRole_via_Glue":      ("TA0004", "Privilege Escalation", "T1098",    "Account Manipulation",          "T1098.003", "Additional Cloud Roles"),
    "iam:CreatePolicyVersion":    ("TA0004", "Privilege Escalation", "T1098",    "Account Manipulation",          "T1098.003", "Additional Cloud Roles"),
    "iam:AttachRolePolicy":       ("TA0004", "Privilege Escalation", "T1098",    "Account Manipulation",          "T1098.003", "Additional Cloud Roles"),
    "iam:PutRolePolicy":          ("TA0004", "Privilege Escalation", "T1098",    "Account Manipulation",          "T1098.003", "Additional Cloud Roles"),
    "iam:UpdateAssumeRolePolicy": ("TA0004", "Privilege Escalation", "T1098",    "Account Manipulation",          "T1098.003", "Additional Cloud Roles"),
    "iam:AttachUserPolicy":       ("TA0004", "Privilege Escalation", "T1098",    "Account Manipulation",          "T1098.003", "Additional Cloud Roles"),
    "iam:CreateAccessKey":        ("TA0006", "Credential Access",    "T1098",    "Account Manipulation",          "T1098.001", "Additional Cloud Credentials"),
    "iam:AddUserToGroup":         ("TA0004", "Privilege Escalation", "T1098",    "Account Manipulation",          "T1098.003", "Additional Cloud Roles"),
}

_UNMAPPED = MITREMapping(
    tactic="",
    tactic_id="",
    technique="UNMAPPED",
    technique_id="",
    mapping_basis="NONE",
    is_unmapped=True,
)


def map_event(
    event_name: str,
    p2_edge_types: Optional[List[str]] = None,
    p1_categories: Optional[List[str]] = None,
) -> MITREMapping:
    _ = p1_categories

    if p2_edge_types:
        for edge_type in p2_edge_types:
            if edge_type in _EDGE_TYPE_TO_MITRE:
                t = _EDGE_TYPE_TO_MITRE[edge_type]
                return MITREMapping(
                    tactic=t[1],
                    tactic_id=t[0],
                    technique=t[3],
                    technique_id=t[2],
                    sub_technique=t[5],
                    sub_technique_id=t[4],
                    mapping_basis="MEDIUM",
                )

    if event_name and event_name in _EVENT_TO_MITRE:
        t = _EVENT_TO_MITRE[event_name]
        return MITREMapping(
            tactic=t[1],
            tactic_id=t[0],
            technique=t[3],
            technique_id=t[2],
            sub_technique=t[5],
            sub_technique_id=t[4],
            mapping_basis="HIGH",
        )

    return _UNMAPPED