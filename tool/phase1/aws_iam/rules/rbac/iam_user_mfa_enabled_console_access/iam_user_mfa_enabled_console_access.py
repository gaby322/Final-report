from typing import Dict, Any, Optional, List
from phase1.aws_iam.rules.base_check import RBACCheck


class iam_user_mfa_enabled_console_access(RBACCheck):
    def execute(self) -> Optional[Dict[str, Any]]:
        failing_users = []
        passing_users = []

        for user_name, entry in self.inventory.credential_report.items():
            if entry.password_enabled == "true":
                if entry.mfa_active == "true":
                    passing_users.append(user_name)
                else:
                    failing_users.append(user_name)

        if failing_users:
            violations = [
                {
                    "resource_type": "AWS::IAM::User",
                    "resource_id": getattr(self.inventory.users.get(u), "arn", u) if u in self.inventory.users else u,
                    "name": u,
                    "detail": {"password_enabled": True, "mfa_active": False},
                }
                for u in failing_users
            ]
            return {
                "status": "FAIL",
                "status_extended": f"Users with console access missing MFA: {', '.join(failing_users)}",
                "resource_type": "AWS::IAM::User",
                "resource_id": self.provider.identity.account_id,
                "category": "IAM",
                "evidence_summary": f"{len(failing_users)} users have console access without MFA enabled",
                "evidence_details": {"violations": violations, "passing_users": passing_users},
            }

        return {
            "status": "PASS",
            "status_extended": f"All {len(passing_users)} users with console access have MFA enabled",
            "resource_type": "AWS::IAM::User",
            "resource_id": self.provider.identity.account_id,
            "category": "IAM",
            "evidence_summary": "All users with console access have MFA enabled",
            "evidence_details": {"violations": [], "passing_users": passing_users},
        }