from typing import Dict, Any, Optional
from phase1.aws_iam.rules.base_check import RBACCheck


class iam_no_root_access_key(RBACCheck):
    def execute(self) -> Optional[Dict[str, Any]]:
        root_user = "<root_account>"
        if root_user not in self.inventory.credential_report:
            return {
                "status": "FAIL",
                "status_extended": "Root account not found in credential report",
                "resource_type": "AWS::IAM::User",
                "resource_id": "root",
                "category": "IAM",
                "evidence_summary": "Root account credential report entry missing",
                "evidence_details": {},
            }

        root_entry = self.inventory.credential_report[root_user]
        active_keys = []
        if root_entry.access_key_1_active == "true":
            active_keys.append("access_key_1")
        if root_entry.access_key_2_active == "true":
            active_keys.append("access_key_2")

        if active_keys:
            return {
                "status": "FAIL",
                "status_extended": f"Root account has active access keys: {', '.join(active_keys)}",
                "resource_type": "AWS::IAM::User",
                "resource_id": "root",
                "category": "IAM",
                "evidence_summary": f"Root account has {len(active_keys)} active access key(s)",
                "evidence_details": {"active_keys": active_keys},
            }

        return {
            "status": "PASS",
            "status_extended": "Root account has no active access keys",
            "resource_type": "AWS::IAM::User",
            "resource_id": "root",
            "category": "IAM",
            "evidence_summary": "Root account access keys are properly deactivated",
            "evidence_details": {},
        }