from typing import Dict, Any, Optional, List
from phase1.aws_iam.rules.base_check import RBACCheck
from phase1.aws_iam.rules.rbac.rule_utils import policy_document_has_wildcard_principal


class iam_role_cross_service_confused_deputy_prevention(RBACCheck):
    def execute(self) -> Optional[Dict[str, Any]]:
        failing_roles: List[str] = []

        for role_name, role in self.inventory.roles.items():
            if policy_document_has_wildcard_principal(role.assume_role_policy_document):
                failing_roles.append(role_name)

        if failing_roles:
            violations = [
                {
                    "resource_type": "AWS::IAM::Role",
                    "resource_id": getattr(self.inventory.roles.get(r), "arn", r) if r in self.inventory.roles else r,
                    "name": r,
                    "detail": {"trust_policy_has_broad_principal": True},
                }
                for r in failing_roles
            ]
            return {
                "status": "FAIL",
                "status_extended": f"Roles with broad service trust policies: {', '.join(failing_roles)}",
                "resource_type": "AWS::IAM::Role",
                "resource_id": self.provider.identity.account_id,
                "category": "IAM",
                "evidence_summary": f"{len(failing_roles)} roles have trust policies that may allow confused deputy scenarios",
                "evidence_details": {"violations": violations},
            }

        return {
            "status": "PASS",
            "status_extended": "No IAM roles have broad service principals in trust policies",
            "resource_type": "AWS::IAM::Role",
            "resource_id": self.provider.identity.account_id,
            "category": "IAM",
            "evidence_summary": "Role trust policies do not contain wildcard service principals",
            "evidence_details": {"violations": []},
        }