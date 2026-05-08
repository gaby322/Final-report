from typing import Dict, Any, Optional, List
from phase1.aws_iam.rules.base_check import RBACCheck
from phase1.aws_iam.rules.rbac.rule_utils import has_cloudshell_admin_policy_name


class iam_policy_cloudshell_admin_not_attached(RBACCheck):
    def execute(self) -> Optional[Dict[str, Any]]:
        violations: List[Dict[str, Any]] = []

        def _scan(principal: Any, rtype: str, pname: str) -> None:
            for policy in getattr(principal, "attached_policies", []):
                if has_cloudshell_admin_policy_name(policy):
                    violations.append({
                        "resource_type": rtype,
                        "resource_id": getattr(principal, "arn", pname),
                        "name": pname,
                        "detail": {"attached_policy": "AWSCloudShellFullAccess"},
                    })

        for u_name, user in self.inventory.users.items():
            _scan(user, "AWS::IAM::User", u_name)
        for g_name, group in self.inventory.groups.items():
            _scan(group, "AWS::IAM::Group", g_name)
        for r_name, role in self.inventory.roles.items():
            _scan(role, "AWS::IAM::Role", r_name)

        if violations:
            names = ", ".join(v["name"] for v in violations)
            return {
                "status": "FAIL",
                "status_extended": f"AWSCloudShellFullAccess attached to: {names}",
                "resource_type": "AWS::IAM::Policy",
                "resource_id": self.provider.identity.account_id,
                "category": "IAM",
                "evidence_summary": f"{len(violations)} principals have AWSCloudShellFullAccess attached",
                "evidence_details": {"violations": violations},
            }

        return {
            "status": "PASS",
            "status_extended": "No principals have AWSCloudShellFullAccess attached",
            "resource_type": "AWS::IAM::Policy",
            "resource_id": self.provider.identity.account_id,
            "category": "IAM",
            "evidence_summary": "CloudShell admin access attachment not detected",
            "evidence_details": {"violations": []},
        }