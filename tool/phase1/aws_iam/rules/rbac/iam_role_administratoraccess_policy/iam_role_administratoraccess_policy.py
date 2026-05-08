from typing import Dict, Any, Optional, List
from phase1.aws_iam.rules.base_check import RBACCheck
from phase1.aws_iam.rules.rbac.rule_utils import has_administrator_access_policy_name, policy_document_is_administrative


class iam_role_administratoraccess_policy(RBACCheck):
    def execute(self) -> Optional[Dict[str, Any]]:
        failing_roles: List[str] = []

        for role_name, role in self.inventory.roles.items():
            has_admin = False
            for policy in role.attached_policies:
                if has_administrator_access_policy_name(policy):
                    has_admin = True
                    break
                if policy_document_is_administrative(policy.document):
                    has_admin = True
                    break
            if has_admin:
                failing_roles.append(role_name)

        if failing_roles:
            violations = [
                {
                    "resource_type": "AWS::IAM::Role",
                    "resource_id": getattr(self.inventory.roles.get(r), "arn", r) if r in self.inventory.roles else r,
                    "name": r,
                    "detail": {"has_admin_policy": True},
                }
                for r in failing_roles
            ]
            return {
                "status": "FAIL",
                "status_extended": f"Roles with administrator access: {', '.join(failing_roles)}",
                "resource_type": "AWS::IAM::Role",
                "resource_id": self.provider.identity.account_id,
                "category": "IAM",
                "evidence_summary": f"{len(failing_roles)} roles have administrator-level permissions",
                "evidence_details": {"violations": violations},
            }

        return {
            "status": "PASS",
            "status_extended": "No roles grant administrator access",
            "resource_type": "AWS::IAM::Role",
            "resource_id": self.provider.identity.account_id,
            "category": "IAM",
            "evidence_summary": "No administrator access policies found on IAM roles",
            "evidence_details": {"violations": []},
        }