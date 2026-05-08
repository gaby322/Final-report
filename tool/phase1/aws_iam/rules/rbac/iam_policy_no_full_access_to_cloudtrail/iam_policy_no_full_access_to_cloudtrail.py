from typing import Dict, Any, Optional, List
from phase1.aws_iam.rules.base_check import RBACCheck
from phase1.aws_iam.rules.rbac.rule_utils import policy_document_has_full_cloudtrail


class iam_policy_no_full_access_to_cloudtrail(RBACCheck):
    def execute(self) -> Optional[Dict[str, Any]]:
        violations: List[Dict[str, Any]] = []

        for policy_name, policy in self.inventory.policies.items():
            if policy_document_has_full_cloudtrail(policy.document):
                violations.append({
                    "resource_type": "AWS::IAM::Policy",
                    "resource_id": getattr(policy, "arn", policy_name),
                    "name": policy_name,
                    "detail": {"grants": "cloudtrail:*"},
                })

        if violations:
            names = ", ".join(v["name"] for v in violations)
            return {
                "status": "FAIL",
                "status_extended": f"Policies grant CloudTrail full access: {names}",
                "resource_type": "AWS::IAM::Policy",
                "resource_id": self.provider.identity.account_id,
                "category": "IAM",
                "evidence_summary": f"{len(violations)} policies grant full CloudTrail access",
                "evidence_details": {"violations": violations},
            }

        return {
            "status": "PASS",
            "status_extended": "No local policies grant full CloudTrail access",
            "resource_type": "AWS::IAM::Policy",
            "resource_id": self.provider.identity.account_id,
            "category": "IAM",
            "evidence_summary": "CloudTrail full access not found in local policy documents",
            "evidence_details": {"violations": []},
        }