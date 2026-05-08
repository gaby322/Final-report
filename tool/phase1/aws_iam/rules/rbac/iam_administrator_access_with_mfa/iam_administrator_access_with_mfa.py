from typing import Dict, Any, Optional, List
from phase1.aws_iam.rules.base_check import RBACCheck
from phase1.aws_iam.rules.rbac.rule_utils import has_administrator_access_policy_name, policy_document_is_administrative


class iam_administrator_access_with_mfa(RBACCheck):
    def execute(self) -> Optional[Dict[str, Any]]:
        groups_with_admin = []
        failures: List[str] = []

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
                groups_with_admin.append(group_name)
                for member in group.members:
                    credential = self.inventory.credential_report.get(member)
                    if not credential or credential.mfa_active != "true":
                        failures.append(member)

        if failures:
            unique_failures = sorted(set(failures))
            violations = [
                {"resource_type": "AWS::IAM::User", "resource_id": user, "name": user,
                 "detail": {"missing_mfa_in_admin_groups": [
                     g for g in groups_with_admin
                     if user in self.inventory.groups.get(g, type("_", (), {"members": []})()).members
                 ]}}
                for user in unique_failures
            ]
            return {
                "status": "FAIL",
                "status_extended": f"Users in admin groups without MFA: {', '.join(unique_failures)}",
                "resource_type": "AWS::IAM::User",
                "resource_id": self.provider.identity.account_id,
                "category": "IAM",
                "evidence_summary": f"{len(unique_failures)} users in administrator groups lack MFA",
                "evidence_details": {"violations": violations, "admin_groups": groups_with_admin},
            }

        return {
            "status": "PASS",
            "status_extended": "All users in administrator groups have MFA enabled",
            "resource_type": "AWS::IAM::User",
            "resource_id": self.provider.identity.account_id,
            "category": "IAM",
            "evidence_summary": "Administrator groups enforce MFA for users",
            "evidence_details": {"violations": [], "admin_groups": groups_with_admin},
        }