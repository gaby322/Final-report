from typing import Dict, Any, Optional
from phase1.aws_iam.rules.base_check import RBACCheck


class iam_password_policy_minimum_length_14(RBACCheck):
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

        min_length = self.inventory.password_policy.minimum_password_length
        if min_length is None or min_length < 14:
            return {
                "status": "FAIL",
                "status_extended": f"Password policy minimum length is {min_length}, should be at least 14",
                "resource_type": "AWS::IAM::AccountPasswordPolicy",
                "resource_id": self.provider.identity.account_id,
                "category": "IAM",
                "evidence_summary": f"Password policy minimum length: {min_length}",
                "evidence_details": {"minimum_password_length": min_length},
            }

        return {
            "status": "PASS",
            "status_extended": f"Password policy requires minimum length of {min_length} characters",
            "resource_type": "AWS::IAM::AccountPasswordPolicy",
            "resource_id": self.provider.identity.account_id,
            "category": "IAM",
            "evidence_summary": f"Password policy correctly requires minimum length of {min_length} characters",
            "evidence_details": {"minimum_password_length": min_length},
        }