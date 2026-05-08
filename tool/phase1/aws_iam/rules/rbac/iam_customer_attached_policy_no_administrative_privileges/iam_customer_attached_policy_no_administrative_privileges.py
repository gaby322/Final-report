from typing import Dict, Any, Optional, List
from phase1.aws_iam.rules.base_check import RBACCheck
from phase1.aws_iam.rules.rbac.rule_utils import (
    policy_document_is_administrative,
    is_policy_customer_managed,
    normalize_policy_identifier,
    get_policy_document,
)


class iam_customer_attached_policy_no_administrative_privileges(RBACCheck):
    def execute(self) -> Optional[Dict[str, Any]]:
        violations: List[Dict[str, Any]] = []

        def _scan(principal: Any, rtype: str, pname: str) -> None:
            for policy in getattr(principal, "attached_policies", []):
                if is_policy_customer_managed(policy) and policy_document_is_administrative(get_policy_document(self.inventory, policy)):
                    violations.append({
                        "resource_type": rtype,
                        "resource_id": getattr(principal, "arn", pname),
                        "name": pname,
                        "detail": {"admin_policy": normalize_policy_identifier(policy)},
                    })

        for user_name, user in self.inventory.users.items():
            _scan(user, "AWS::IAM::User", user_name)
        for group_name, group in self.inventory.groups.items():
            _scan(group, "AWS::IAM::Group", group_name)
        for role_name, role in self.inventory.roles.items():
            _scan(role, "AWS::IAM::Role", role_name)

        if violations:
            return {
                "status": "FAIL",
                "status_extended": "Customer-managed attached policies with admin privileges found",
                "resource_type": "AWS::IAM::Policy",
                "resource_id": self.provider.identity.account_id,
                "category": "IAM",
                "evidence_summary": f"{len(violations)} attached customer-managed admin policy attachment(s) detected",
                "evidence_details": {"violations": violations},
            }

        return {
            "status": "PASS",
            "status_extended": "No attached customer-managed policies grant administrator privileges",
            "resource_type": "AWS::IAM::Policy",
            "resource_id": self.provider.identity.account_id,
            "category": "IAM",
            "evidence_summary": "Attached customer-managed policies do not include administrative privileges",
            "evidence_details": {"violations": []},
        }