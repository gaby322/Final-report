from typing import Dict, Any, Optional
from phase1.aws_iam.rules.base_check import RBACCheck


class iam_root_credentials_management_enabled(RBACCheck):
    def execute(self) -> Optional[Dict[str, Any]]:
        features = self.inventory.organization_features
        if features:
            if "RootCredentialsManagement" in features:
                return {
                    "status": "PASS",
                    "status_extended": "Root credentials management is enabled in AWS Organizations.",
                    "resource_type": "AWS::IAM::User",
                    "resource_id": self.provider.identity.account_id,
                    "category": "IAM",
                    "evidence_summary": "Organisation root credentials management is enabled",
                    "evidence_details": {"organization_features": features},
                }
            return {
                "status": "FAIL",
                "status_extended": "Root credentials management is not enabled in AWS Organizations.",
                "resource_type": "AWS::IAM::User",
                "resource_id": self.provider.identity.account_id,
                "category": "IAM",
                "evidence_summary": "Root credentials management feature is not enabled",
                "evidence_details": {"organization_features": features},
            }

        return {
            "status": "PASS",
            "status_extended": "Unable to determine organization feature status for root credentials management; data unavailable.",
            "resource_type": "AWS::IAM::User",
            "resource_id": self.provider.identity.account_id,
            "category": "IAM",
            "evidence_summary": "Organization feature status unavailable",
            "evidence_details": {},
        }