from typing import Dict, Any, Optional, List
from phase1.aws_iam.rules.base_check import RBACCheck
from phase1.aws_iam.rules.rbac.rule_utils import has_administrator_access_policy_name, policy_document_is_administrative


class iam_group_administrator_access_policy(RBACCheck):
    def execute(self) -> Optional[Dict[str, Any]]:
        failing_groups: List[str] = []

        for group_name, group in self.inventory.groups.items():
            group_has_admin = False
            for policy in group.attached_policies:
                if has_administrator_access_policy_name(policy):
                    group_has_admin = True
                    break
                if policy_document_is_administrative(policy.document):
                    group_has_admin = True
                    break
            if not group_has_admin:
                for policy in group.inline_policies:
                    if policy_document_is_administrative(policy.document):
                        group_has_admin = True
                        break
            if group_has_admin:
                failing_groups.append(group_name)

        if failing_groups:
            violations = [
                {
                    "resource_type": "AWS::IAM::Group",
                    "resource_id": getattr(self.inventory.groups.get(g), "arn", g) if g in self.inventory.groups else g,
                    "name": g,
                    "detail": {"has_admin_policy": True},
                }
                for g in failing_groups
            ]
            return {
                "status": "FAIL",
                "status_extended": f"Groups with administrator access policy: {', '.join(failing_groups)}",
                "resource_type": "AWS::IAM::Group",
                "resource_id": self.provider.identity.account_id,
                "category": "IAM",
                "evidence_summary": f"{len(failing_groups)} groups have administrator access policies",
                "evidence_details": {"violations": violations},
            }

        return {
            "status": "PASS",
            "status_extended": "No groups have administrator access policies",
            "resource_type": "AWS::IAM::Group",
            "resource_id": self.provider.identity.account_id,
            "category": "IAM",
            "evidence_summary": "No group-wide administrator access policies were detected",
            "evidence_details": {"violations": []},
        }