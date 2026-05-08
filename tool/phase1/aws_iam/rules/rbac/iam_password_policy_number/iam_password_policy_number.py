from typing import Dict, Any, Optional
from phase1.aws_iam.rules.base_check import RBACCheck


class iam_password_policy_number(RBACCheck):
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

        require_numbers = self.inventory.password_policy.require_numbers
        if require_numbers is None or not require_numbers:
            return {
                "status": "FAIL",
                "status_extended": "Password policy does not require numbers",
                "resource_type": "AWS::IAM::AccountPasswordPolicy",
                "resource_id": self.provider.identity.account_id,
                "category": "IAM",
                "evidence_summary": f"Password policy requires numbers: {require_numbers}",
                "evidence_details": {"require_numbers": require_numbers},
            }

        return {
            "status": "PASS",
            "status_extended": "Password policy requires numbers",
            "resource_type": "AWS::IAM::AccountPasswordPolicy",
            "resource_id": self.provider.identity.account_id,
            "category": "IAM",
            "evidence_summary": f"Password policy correctly requires numbers",
            "evidence_details": {"require_numbers": require_numbers},
        }