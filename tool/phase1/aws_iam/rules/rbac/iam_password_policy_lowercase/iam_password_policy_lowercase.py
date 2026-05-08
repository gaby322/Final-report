from typing import Dict, Any, Optional
from phase1.aws_iam.rules.base_check import RBACCheck


class iam_password_policy_lowercase(RBACCheck):
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

        require_lowercase = self.inventory.password_policy.require_lowercase_characters
        if require_lowercase is None or not require_lowercase:
            return {
                "status": "FAIL",
                "status_extended": "Password policy does not require lowercase characters",
                "resource_type": "AWS::IAM::AccountPasswordPolicy",
                "resource_id": self.provider.identity.account_id,
                "category": "IAM",
                "evidence_summary": f"Password policy requires lowercase: {require_lowercase}",
                "evidence_details": {"require_lowercase_characters": require_lowercase},
            }

        return {
            "status": "PASS",
            "status_extended": "Password policy requires lowercase characters",
            "resource_type": "AWS::IAM::AccountPasswordPolicy",
            "resource_id": self.provider.identity.account_id,
            "category": "IAM",
            "evidence_summary": f"Password policy correctly requires lowercase characters",
            "evidence_details": {"require_lowercase_characters": require_lowercase},
        }