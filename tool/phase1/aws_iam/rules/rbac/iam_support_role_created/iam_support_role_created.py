from typing import Dict, Any, Optional, List
from phase1.aws_iam.rules.base_check import RBACCheck
from phase1.aws_iam.rules.rbac.rule_utils import get_policy_field


class iam_support_role_created(RBACCheck):

    def execute(self) -> Optional[Dict[str, Any]]:
        support_roles: List[str] = []

        for role_name, role in self.inventory.roles.items():
            for policy in role.attached_policies:
                policy_name = get_policy_field(policy, "name", "")
                policy_arn = get_policy_field(policy, "arn", "")
                if policy_name == "AWSSupportAccess" or policy_arn.endswith("/AWSSupportAccess"):
                    support_roles.append(role_name)
                    break

        if support_roles:
            return {
                "status": "PASS",
                "status_extended": (
                    f"AWS support role configured: {', '.join(support_roles)}"
                ),
                "resource_type": "AWS::IAM::Role",
                "resource_id": ",".join(support_roles),
                "category": "IAM",
                "evidence_summary": (
                    f"{len(support_roles)} role(s) have AWSSupportAccess attached"
                ),
                "evidence_details": {"support_roles": support_roles},
            }

        return {
            "status": "FAIL",
            "status_extended": (
                "No IAM role with AWSSupportAccess policy found. "
                "CIS 1.17 requires a dedicated support role to manage AWS Support incidents "
                "without granting users broader administrative access."
            ),
            "resource_type": "AWS::IAM::Role",
            "resource_id": self.provider.identity.account_id,
            "category": "IAM",
            "evidence_summary": "No AWSSupportAccess-attached role is configured in this account",
            "evidence_details": {},
        }
