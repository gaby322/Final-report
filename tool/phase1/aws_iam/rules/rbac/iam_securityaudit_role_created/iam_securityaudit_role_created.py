from typing import Dict, Any, Optional, List
from phase1.aws_iam.rules.base_check import RBACCheck
from phase1.aws_iam.rules.rbac.rule_utils import get_policy_field


class iam_securityaudit_role_created(RBACCheck):

    def execute(self) -> Optional[Dict[str, Any]]:
        matches: List[str] = []

        for role_name, role in self.inventory.roles.items():
            has_security_audit_policy = any(
                get_policy_field(p, "name", "") == "SecurityAudit"
                or get_policy_field(p, "arn", "").endswith("/SecurityAudit")
                for p in role.attached_policies
            )
            if has_security_audit_policy or "securityaudit" in role_name.lower():
                if role_name not in matches:
                    matches.append(role_name)

        if matches:
            return {
                "status": "PASS",
                "status_extended": (
                    f"Security audit role(s) found: {', '.join(sorted(matches))}"
                ),
                "resource_type": "AWS::IAM::Role",
                "resource_id": ",".join(sorted(matches)),
                "category": "IAM",
                "evidence_summary": (
                    f"{len(matches)} role(s) support security audit operations"
                ),
                "evidence_details": {"security_audit_roles": sorted(matches)},
            }

        return {
            "status": "FAIL",
            "status_extended": (
                "No IAM role with the SecurityAudit policy or a 'securityaudit' name was found. "
                "AWS best practices recommend a dedicated read-only audit role to support "
                "security reviews without requiring elevated credentials."
            ),
            "resource_type": "AWS::IAM::Role",
            "resource_id": self.provider.identity.account_id,
            "category": "IAM",
            "evidence_summary": "No SecurityAudit-capable role is configured in this account",
            "evidence_details": {},
        }
