from typing import Dict, Any, Optional
from phase1.aws_iam.rules.base_check import RBACCheck


class iam_root_mfa_enabled(RBACCheck):
    def execute(self) -> Optional[Dict[str, Any]]:
        root_user = "<root_account>"
        if root_user in self.inventory.credential_report:
            root_entry = self.inventory.credential_report[root_user]
            if root_entry.mfa_active == "true":
                return {
                    "status": "PASS",
                    "status_extended": "Root account has MFA enabled",
                    "resource_type": "AWS::IAM::User",
                    "resource_id": "root",
                    "category": "IAM",
                    "evidence_summary": "Root account MFA is active",
                    "evidence_details": {"mfa_active": root_entry.mfa_active},
                }
            else:
                return {
                    "status": "FAIL",
                    "status_extended": "Root account does not have MFA enabled",
                    "resource_type": "AWS::IAM::User",
                    "resource_id": "root",
                    "category": "IAM",
                    "evidence_summary": "Root account MFA is not active",
                    "evidence_details": {"mfa_active": root_entry.mfa_active},
                }
        else:
            return {
                "status": "FAIL",
                "status_extended": "Root account not found in credential report",
                "resource_type": "AWS::IAM::User",
                "resource_id": "root",
                "category": "IAM",
                "evidence_summary": "Root account credential report entry missing",
                "evidence_details": {},
            }