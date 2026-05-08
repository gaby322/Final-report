from typing import Dict, Any, Optional, List
from phase1.aws_iam.rules.base_check import RBACCheck


class iam_user_two_active_access_key(RBACCheck):
    def execute(self) -> Optional[Dict[str, Any]]:
        failing_users = []

        for user_name, entry in self.inventory.credential_report.items():
            active_keys = 0
            if entry.access_key_1_active == "true":
                active_keys += 1
            if entry.access_key_2_active == "true":
                active_keys += 1

            if active_keys > 1:
                failing_users.append(user_name)

        if failing_users:
            violations = [
                {
                    "resource_type": "AWS::IAM::User",
                    "resource_id": getattr(self.inventory.users.get(u), "arn", u) if u in self.inventory.users else u,
                    "name": u,
                    "detail": {"active_access_keys": 2},
                }
                for u in failing_users
            ]
            return {
                "status": "FAIL",
                "status_extended": f"Users with two active access keys: {', '.join(failing_users)}",
                "resource_type": "AWS::IAM::User",
                "resource_id": self.provider.identity.account_id,
                "category": "IAM",
                "evidence_summary": f"{len(failing_users)} users have two active access keys",
                "evidence_details": {"violations": violations},
            }

        return {
            "status": "PASS",
            "status_extended": "No users have two active access keys",
            "resource_type": "AWS::IAM::User",
            "resource_id": self.provider.identity.account_id,
            "category": "IAM",
            "evidence_summary": "All users comply with single active access key policy",
            "evidence_details": {"violations": []},
        }