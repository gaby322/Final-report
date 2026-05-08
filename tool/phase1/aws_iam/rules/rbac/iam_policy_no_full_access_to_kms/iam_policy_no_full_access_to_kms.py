from typing import Dict, Any, Optional, List
from phase1.aws_iam.rules.base_check import RBACCheck
from phase1.aws_iam.rules.rbac.rule_utils import policy_document_has_full_kms


class iam_policy_no_full_access_to_kms(RBACCheck):
    def execute(self) -> Optional[Dict[str, Any]]:
        violations: List[Dict[str, Any]] = []

        for policy_name, policy in self.inventory.policies.items():
            if policy_document_has_full_kms(policy.document):
                violations.append({
                    "resource_type": "AWS::IAM::Policy",
                    "resource_id": getattr(policy, "arn", policy_name),
                    "name": policy_name,
                    "detail": {"grants": "kms:*"},
                })

        if violations:
            names = ", ".join(v["name"] for v in violations)
            return {
                "status": "FAIL",
                "status_extended": f"Policies grant KMS full access: {names}",
                "resource_type": "AWS::IAM::Policy",
                "resource_id": self.provider.identity.account_id,
                "category": "IAM",
                "evidence_summary": f"{len(violations)} policies grant full KMS access",
                "evidence_details": {"violations": violations},
            }

        return {
            "status": "PASS",
            "status_extended": "No local policies grant full KMS access",
            "resource_type": "AWS::IAM::Policy",
            "resource_id": self.provider.identity.account_id,
            "category": "IAM",
            "evidence_summary": "KMS full access not found in local policy documents",
            "evidence_details": {"violations": []},
        }