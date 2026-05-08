from typing import Dict, Any, Optional, List
from phase1.aws_iam.rules.base_check import RBACCheck
from phase1.aws_iam.rules.rbac.rule_utils import policy_document_is_administrative, is_policy_customer_managed


class iam_customer_unattached_policy_no_administrative_privileges(RBACCheck):
    def execute(self) -> Optional[Dict[str, Any]]:
        violations: List[Dict[str, Any]] = []

        for policy_name, policy in self.inventory.policies.items():
            if not policy.is_attached and is_policy_customer_managed(policy):
                if policy_document_is_administrative(policy.document):
                    violations.append({
                        "resource_type": "AWS::IAM::Policy",
                        "resource_id": getattr(policy, "arn", policy_name),
                        "name": policy_name,
                        "detail": {"is_attached": False, "customer_managed": True},
                    })

        if violations:
            names = ", ".join(v["name"] for v in violations)
            return {
                "status": "FAIL",
                "status_extended": f"Unattached customer-managed policies with admin privileges: {names}",
                "resource_type": "AWS::IAM::Policy",
                "resource_id": self.provider.identity.account_id,
                "category": "IAM",
                "evidence_summary": f"{len(violations)} unattached customer-managed policies grant administrator privileges",
                "evidence_details": {"violations": violations},
            }

        return {
            "status": "PASS",
            "status_extended": "No unattached customer-managed policies grant administrator privileges",
            "resource_type": "AWS::IAM::Policy",
            "resource_id": self.provider.identity.account_id,
            "category": "IAM",
            "evidence_summary": "Unattached customer-managed policies do not provide administrative access",
            "evidence_details": {"violations": []},
        }