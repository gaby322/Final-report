from typing import Dict, Any, Optional, List, Union
from phase1.aws_iam.rules.base_check import RBACCheck
from phase1.aws_iam.rules.rbac.rule_utils import policy_document_has_cross_account_trust
from shared.aws.models import Policy

READONLY_POLICY_KEYWORDS = [
    "readonlyaccess",
    "read-onlyaccess",
    "readonly",
]


def policy_name_is_readonly(policy: Union[Dict[str, Any], Policy]) -> bool:
    if isinstance(policy, Policy):
        name = (getattr(policy, "name", "") or "").lower()
        arn = (getattr(policy, "arn", "") or "").lower()
    elif isinstance(policy, dict):
        name = (policy.get("name", "") or "").lower()
        arn = (policy.get("arn", "") or "").lower()
    else:
        name = (getattr(policy, "name", "") or "").lower() if hasattr(policy, "name") else ""
        arn = (getattr(policy, "arn", "") or "").lower() if hasattr(policy, "arn") else ""
    return (
        any(keyword in name for keyword in READONLY_POLICY_KEYWORDS)
        or any(keyword in arn for keyword in READONLY_POLICY_KEYWORDS)
    )


def _policy_display_id(policy: Union[Dict[str, Any], Policy]) -> str:
    if isinstance(policy, Policy):
        return getattr(policy, "arn", None) or getattr(policy, "name", None) or "unknown"
    if isinstance(policy, dict):
        return policy.get("arn") or policy.get("name") or "unknown"
    return getattr(policy, "arn", None) or getattr(policy, "name", None) or "unknown"


class iam_role_cross_account_readonlyaccess_policy(RBACCheck):
    def execute(self) -> Optional[Dict[str, Any]]:
        violations: List[Dict[str, Any]] = []

        for role_name, role in self.inventory.roles.items():
            if not policy_document_has_cross_account_trust(role.assume_role_policy_document, self.provider.identity.account_id):
                continue
            matched_policies: List[str] = []
            for policy in role.attached_policies:
                if policy_name_is_readonly(policy):
                    matched_policies.append(_policy_display_id(policy))
            for policy in role.inline_policies:
                if policy_name_is_readonly({"name": policy.name, "arn": ""}):
                    matched_policies.append(policy.name)
            if matched_policies:
                violations.append({
                    "resource_type": "AWS::IAM::Role",
                    "resource_id": getattr(role, "arn", role_name),
                    "name": role_name,
                    "detail": {"readonly_policies": matched_policies},
                })

        if violations:
            names = ", ".join(v["name"] for v in violations)
            return {
                "status": "FAIL",
                "status_extended": f"Cross-account roles with read-only access detected: {names}",
                "resource_type": "AWS::IAM::Role",
                "resource_id": self.provider.identity.account_id,
                "category": "IAM",
                "evidence_summary": f"{len(violations)} cross-account roles grant read-only access",
                "evidence_details": {"violations": violations},
            }

        return {
            "status": "PASS",
            "status_extended": "No cross-account roles were identified with read-only policies attached",
            "resource_type": "AWS::IAM::Role",
            "resource_id": self.provider.identity.account_id,
            "category": "IAM",
            "evidence_summary": "Cross-account roles with read-only policies were not found",
            "evidence_details": {"violations": []},
        }