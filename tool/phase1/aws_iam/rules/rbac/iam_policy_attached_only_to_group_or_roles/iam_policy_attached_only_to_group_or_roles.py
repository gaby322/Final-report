from typing import Dict, Any, Optional, List
from phase1.aws_iam.rules.base_check import RBACCheck


class iam_policy_attached_only_to_group_or_roles(RBACCheck):
    def execute(self) -> Optional[Dict[str, Any]]:
        violations: List[Dict[str, Any]] = []

        for user_name, user in self.inventory.users.items():
            if user.attached_policies:
                violations.append({
                    "resource_type": "AWS::IAM::User",
                    "resource_id": getattr(user, "arn", user_name),
                    "name": user_name,
                    "detail": {"attached_policy_count": len(user.attached_policies)},
                })

        if violations:
            names = ", ".join(v["name"] for v in violations)
            return {
                "status": "FAIL",
                "status_extended": f"Users with direct policy attachments: {names}",
                "resource_type": "AWS::IAM::User",
                "resource_id": self.provider.identity.account_id,
                "category": "IAM",
                "evidence_summary": f"{len(violations)} users have policies attached directly instead of via groups or roles",
                "evidence_details": {"violations": violations},
            }

        return {
            "status": "PASS",
            "status_extended": "No users have policies attached directly",
            "resource_type": "AWS::IAM::User",
            "resource_id": self.provider.identity.account_id,
            "category": "IAM",
            "evidence_summary": "Policy attachment model meets group/role-only requirement",
            "evidence_details": {"violations": []},
        }