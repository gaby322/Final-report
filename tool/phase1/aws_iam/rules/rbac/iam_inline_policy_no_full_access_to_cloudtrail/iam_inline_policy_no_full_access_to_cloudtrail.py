from typing import Dict, Any, Optional, List
from phase1.aws_iam.rules.base_check import RBACCheck
from phase1.aws_iam.rules.rbac.rule_utils import policy_document_has_full_cloudtrail


class iam_inline_policy_no_full_access_to_cloudtrail(RBACCheck):
    def execute(self) -> Optional[Dict[str, Any]]:
        violations: List[Dict[str, Any]] = []

        def _scan(principal: Any, rtype: str, pname: str) -> None:
            for policy in getattr(principal, "inline_policies", []):
                if policy_document_has_full_cloudtrail(getattr(policy, "document", {}) or {}):
                    violations.append({
                        "resource_type": rtype,
                        "resource_id": getattr(principal, "arn", pname),
                        "name": pname,
                        "detail": {"inline_policy": getattr(policy, "name", "<inline>")},
                    })

        for u_name, user in self.inventory.users.items():
            _scan(user, "AWS::IAM::User", u_name)
        for g_name, group in self.inventory.groups.items():
            _scan(group, "AWS::IAM::Group", g_name)
        for r_name, role in self.inventory.roles.items():
            _scan(role, "AWS::IAM::Role", r_name)

        if violations:
            return {
                "status": "FAIL",
                "status_extended": "Inline policies grant full CloudTrail access",
                "resource_type": "AWS::IAM::Policy",
                "resource_id": self.provider.identity.account_id,
                "category": "IAM",
                "evidence_summary": f"{len(violations)} inline policies grant full CloudTrail access",
                "evidence_details": {"violations": violations},
            }

        return {
            "status": "PASS",
            "status_extended": "No inline policies grant full CloudTrail access",
            "resource_type": "AWS::IAM::Policy",
            "resource_id": self.provider.identity.account_id,
            "category": "IAM",
            "evidence_summary": "Inline policy documents do not grant full CloudTrail access",
            "evidence_details": {"violations": []},
        }