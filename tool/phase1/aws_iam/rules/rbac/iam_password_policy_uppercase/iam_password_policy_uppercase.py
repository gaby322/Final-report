from typing import Dict, Any, Optional
from phase1.aws_iam.rules.base_check import RBACCheck


class iam_password_policy_uppercase(RBACCheck):
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

        require_uppercase = self.inventory.password_policy.require_uppercase_characters
        if require_uppercase is None or not require_uppercase:
            return {
                "status": "FAIL",
                "status_extended": "Password policy does not require uppercase characters",
                "resource_type": "AWS::IAM::AccountPasswordPolicy",
                "resource_id": self.provider.identity.account_id,
                "category": "IAM",
                "evidence_summary": f"Password policy requires uppercase: {require_uppercase}",
                "evidence_details": {"require_uppercase_characters": require_uppercase},
            }

        return {
            "status": "PASS",
            "status_extended": "Password policy requires uppercase characters",
            "resource_type": "AWS::IAM::AccountPasswordPolicy",
            "resource_id": self.provider.identity.account_id,
            "category": "IAM",
            "evidence_summary": f"Password policy correctly requires uppercase characters",
            "evidence_details": {"require_uppercase_characters": require_uppercase},
        }