from typing import Dict, Any, Optional
from phase1.aws_iam.rules.base_check import RBACCheck


class iam_password_policy_symbol(RBACCheck):
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

        require_symbols = self.inventory.password_policy.require_symbols
        if require_symbols is None or not require_symbols:
            return {
                "status": "FAIL",
                "status_extended": "Password policy does not require symbols",
                "resource_type": "AWS::IAM::AccountPasswordPolicy",
                "resource_id": self.provider.identity.account_id,
                "category": "IAM",
                "evidence_summary": f"Password policy requires symbols: {require_symbols}",
                "evidence_details": {"require_symbols": require_symbols},
            }

        return {
            "status": "PASS",
            "status_extended": "Password policy requires symbols",
            "resource_type": "AWS::IAM::AccountPasswordPolicy",
            "resource_id": self.provider.identity.account_id,
            "category": "IAM",
            "evidence_summary": f"Password policy correctly requires symbols",
            "evidence_details": {"require_symbols": require_symbols},
        }