from typing import Dict, Any, Optional
from phase1.aws_iam.rules.base_check import RBACCheck


class iam_password_policy_reuse_24(RBACCheck):
    def execute(self) -> Optional[Dict[str, Any]]:
        if not self.inventory.password_policy:
            return {
                "status": "FAIL",
                "status_extended": "No password policy found",
                "resource_type": "AWS::IAM::AccountPasswordPolicy",
                "resource_id": self.provider.identity.account_id,
                "category": "IAM",
                "evidence_summary": "Password policy not configured",
                "evidence_details": {},
            }

        reuse_prevention = self.inventory.password_policy.password_reuse_prevention
        if reuse_prevention is None or reuse_prevention < 24:
            return {
                "status": "FAIL",
                "status_extended": f"Password policy reuse prevention is {reuse_prevention}, should be at least 24",
                "resource_type": "AWS::IAM::AccountPasswordPolicy",
                "resource_id": self.provider.identity.account_id,
                "category": "IAM",
                "evidence_summary": f"Password policy reuse prevention: {reuse_prevention}",
                "evidence_details": {"password_reuse_prevention": reuse_prevention},
            }

        return {
            "status": "PASS",
            "status_extended": f"Password policy prevents reuse of last {reuse_prevention} passwords",
            "resource_type": "AWS::IAM::AccountPasswordPolicy",
            "resource_id": self.provider.identity.account_id,
            "category": "IAM",
            "evidence_summary": f"Password policy correctly prevents reuse of last {reuse_prevention} passwords",
            "evidence_details": {"password_reuse_prevention": reuse_prevention},
        }