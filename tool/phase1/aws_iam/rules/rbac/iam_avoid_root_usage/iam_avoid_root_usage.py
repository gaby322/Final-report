from typing import Dict, Any, Optional
from datetime import datetime, timedelta, timezone
from phase1.aws_iam.rules.base_check import RBACCheck


class iam_avoid_root_usage(RBACCheck):
    def execute(self) -> Optional[Dict[str, Any]]:
        root_user = "<root_account>"
        if root_user not in self.inventory.credential_report:
            return {
                "status": "PASS",
                "status_extended": "Root account usage cannot be determined from credential report",
                "resource_type": "AWS::IAM::User",
                "resource_id": "root",
                "category": "IAM",
                "evidence_summary": "Root account credential report entry missing",
                "evidence_details": {},
            }

        root_entry = self.inventory.credential_report[root_user]

        password_used_recently = False
        if root_entry.password_last_used:
            try:
                last_used = datetime.fromisoformat(root_entry.password_last_used.replace('Z', '+00:00'))
                if datetime.now(timezone.utc) - last_used < timedelta(days=30):
                    password_used_recently = True
            except ValueError:
                pass

        key_used_recently = False
        if root_entry.access_key_1_last_used_date:
            try:
                last_used = datetime.fromisoformat(root_entry.access_key_1_last_used_date.replace('Z', '+00:00'))
                if datetime.now(timezone.utc) - last_used < timedelta(days=30):
                    key_used_recently = True
            except ValueError:
                pass
        if root_entry.access_key_2_last_used_date:
            try:
                last_used = datetime.fromisoformat(root_entry.access_key_2_last_used_date.replace('Z', '+00:00'))
                if datetime.now(timezone.utc) - last_used < timedelta(days=30):
                    key_used_recently = True
            except ValueError:
                pass

        if password_used_recently or key_used_recently:
            usage_details = []
            if password_used_recently:
                usage_details.append("password")
            if key_used_recently:
                usage_details.append("access keys")
            return {
                "status": "FAIL",
                "status_extended": f"Root account has been used recently via: {', '.join(usage_details)}",
                "resource_type": "AWS::IAM::User",
                "resource_id": "root",
                "category": "IAM",
                "evidence_summary": f"Root account used via {', '.join(usage_details)} within last 30 days",
                "evidence_details": {
                    "password_used_recently": password_used_recently,
                    "key_used_recently": key_used_recently
                },
            }

        return {
            "status": "PASS",
            "status_extended": "Root account has not been used recently",
            "resource_type": "AWS::IAM::User",
            "resource_id": "root",
            "category": "IAM",
            "evidence_summary": "Root account usage avoided",
            "evidence_details": {},
        }