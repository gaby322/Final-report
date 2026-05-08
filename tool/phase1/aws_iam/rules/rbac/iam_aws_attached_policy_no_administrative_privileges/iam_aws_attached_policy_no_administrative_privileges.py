from typing import Dict, Any, Optional, List
from phase1.aws_iam.rules.base_check import RBACCheck
from phase1.aws_iam.rules.rbac.rule_utils import (
    has_administrator_access_policy_name,
    normalize_policy_identifier,
)


class iam_aws_attached_policy_no_administrative_privileges(RBACCheck):
    def execute(self) -> Optional[Dict[str, Any]]:
        violations: List[Dict[str, Any]] = []

        def _record(principal: Any, rtype: str, pname: str) -> None:
            for policy in getattr(principal, "attached_policies", []):
                if has_administrator_access_policy_name(policy):
                    violations.append({
                        "resource_type": rtype,
                        "resource_id": getattr(principal, "arn", pname),
                        "name": pname,
                        "detail": {"admin_policy": normalize_policy_identifier(policy)},
                    })

        for user_name, user in self.inventory.users.items():
            _record(user, "AWS::IAM::User", user_name)
        for group_name, group in self.inventory.groups.items():
            _record(group, "AWS::IAM::Group", group_name)
        for role_name, role in self.inventory.roles.items():
            _record(role, "AWS::IAM::Role", role_name)

        if violations:
            return {
                "status": "FAIL",
                "status_extended": "AWS managed administrator privileges attached",
                "resource_type": "AWS::IAM::Policy",
                "resource_id": self.provider.identity.account_id,
                "category": "IAM",
                "evidence_summary": f"{len(violations)} AWS managed administrator policy attachments detected",
                "evidence_details": {"violations": violations},
            }

        return {
            "status": "PASS",
            "status_extended": "No AWS managed administrator policies attached to principals",
            "resource_type": "AWS::IAM::Policy",
            "resource_id": self.provider.identity.account_id,
            "category": "IAM",
            "evidence_summary": "AWS managed administrator privileges not attached to principals",
            "evidence_details": {"violations": []},
        }