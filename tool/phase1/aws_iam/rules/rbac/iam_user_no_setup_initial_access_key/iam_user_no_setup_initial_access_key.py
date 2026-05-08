from typing import Dict, Any, Optional, List
from phase1.aws_iam.rules.base_check import RBACCheck


class iam_user_no_setup_initial_access_key(RBACCheck):

    def execute(self) -> Optional[Dict[str, Any]]:
        dual_users: List[str] = []

        for user_name, entry in self.inventory.credential_report.items():
            if user_name == "<root_account>":
                continue
            if entry.password_enabled != "true":
                continue
            has_active_key = (
                entry.access_key_1_active == "true"
                or entry.access_key_2_active == "true"
            )
            if has_active_key:
                dual_users.append(user_name)

        if dual_users:
            violations = [
                {
                    "resource_type": "AWS::IAM::User",
                    "resource_id": getattr(self.inventory.users.get(u), "arn", u) if u in self.inventory.users else u,
                    "name": u,
                    "detail": {"has_console_password": True, "has_active_access_key": True},
                }
                for u in sorted(dual_users)
            ]
            return {
                "status": "FAIL",
                "status_extended": (
                    f"IAM users with both console password and active access key(s): "
                    f"{', '.join(sorted(dual_users))}. "
                    "CIS 1.11 recommends not creating access keys simultaneously with console accounts."
                ),
                "resource_type": "AWS::IAM::User",
                "resource_id": self.provider.identity.account_id,
                "category": "IAM",
                "evidence_summary": (
                    f"{len(dual_users)} user(s) have both console access and active programmatic credentials"
                ),
                "evidence_details": {"violations": violations},
            }

        return {
            "status": "PASS",
            "status_extended": (
                "No IAM users with a console password also have active access keys."
            ),
            "resource_type": "AWS::IAM::User",
            "resource_id": self.provider.identity.account_id,
            "category": "IAM",
            "evidence_summary": "Console and programmatic credentials are not combined for any user",
            "evidence_details": {"violations": []},
        }
