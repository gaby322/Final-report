from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta, timezone
from phase1.aws_iam.rules.base_check import RBACCheck


class iam_rotate_access_key_90_days(RBACCheck):
    def execute(self) -> Optional[Dict[str, Any]]:
        failing_keys = []
        now = datetime.now(timezone.utc)

        for user_name, entry in self.inventory.credential_report.items():
            if entry.access_key_1_active == "true" and entry.access_key_1_last_rotated:
                try:
                    last_rotated = datetime.fromisoformat(entry.access_key_1_last_rotated.replace('Z', '+00:00'))
                    if now - last_rotated > timedelta(days=90):
                        failing_keys.append(f"{user_name}:access_key_1")
                except ValueError:
                    failing_keys.append(f"{user_name}:access_key_1")

            if entry.access_key_2_active == "true" and entry.access_key_2_last_rotated:
                try:
                    last_rotated = datetime.fromisoformat(entry.access_key_2_last_rotated.replace('Z', '+00:00'))
                    if now - last_rotated > timedelta(days=90):
                        failing_keys.append(f"{user_name}:access_key_2")
                except ValueError:
                    failing_keys.append(f"{user_name}:access_key_2")

        if failing_keys:
            violations = []
            for k in failing_keys:
                user, keyn = k.split(":")
                violations.append({
                    "resource_type": "AWS::IAM::AccessKey",
                    "resource_id": k,
                    "name": k,
                    "detail": {"user": user, "key": keyn, "reason": "not_rotated_within_90_days"},
                })
            return {
                "status": "FAIL",
                "status_extended": f"Access keys not rotated within 90 days: {', '.join(failing_keys)}",
                "resource_type": "AWS::IAM::AccessKey",
                "resource_id": self.provider.identity.account_id,
                "category": "IAM",
                "evidence_summary": f"{len(failing_keys)} access keys need rotation",
                "evidence_details": {"violations": violations},
            }

        return {
            "status": "PASS",
            "status_extended": "All active access keys have been rotated within 90 days",
            "resource_type": "AWS::IAM::AccessKey",
            "resource_id": self.provider.identity.account_id,
            "category": "IAM",
            "evidence_summary": "All access keys are properly rotated",
            "evidence_details": {"violations": []},
        }