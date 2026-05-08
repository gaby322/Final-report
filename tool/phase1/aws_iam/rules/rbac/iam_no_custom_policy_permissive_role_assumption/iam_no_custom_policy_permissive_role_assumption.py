from typing import Dict, Any, Optional, List
from phase1.aws_iam.rules.base_check import RBACCheck
from phase1.aws_iam.rules.rbac.rule_utils import policy_document_has_wildcard_principal


class iam_no_custom_policy_permissive_role_assumption(RBACCheck):
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
                    "detail": {"wildcard_principal_in_trust_policy": True},
                }
                for r in failing_roles
            ]
            return {
                "status": "FAIL",
                "status_extended": f"Roles allow permissive role assumption: {', '.join(failing_roles)}",
                "resource_type": "AWS::IAM::Role",
                "resource_id": self.provider.identity.account_id,
                "category": "IAM",
                "evidence_summary": f"{len(failing_roles)} roles have wildcard principals in their trust policy",
                "evidence_details": {"violations": violations},
            }

        return {
            "status": "PASS",
            "status_extended": "No custom roles allow permissive role assumption",
            "resource_type": "AWS::IAM::Role",
            "resource_id": self.provider.identity.account_id,
            "category": "IAM",
            "evidence_summary": "Role trust policies do not contain wildcard principals",
            "evidence_details": {"violations": []},
        }