from typing import Dict, Any, Optional, List

from phase1.aws_iam.rules.base_check import ABACCheck
from phase1.aws_iam.rules.abac.abac_rule_utils import (
    policy_statements,
    statement_has_wildcard_action,
    statement_has_wildcard_resource,
)


class iam_identity_policy_overly_permissive_without_tag_conditions(ABACCheck):
    def execute(self) -> Optional[Dict[str, Any]]:
        suspicious_policies: List[Dict[str, Any]] = []
        policies_checked = 0

        for user_name, user in self.inventory.users.items():
            policies_checked += self._inspect_principal_policies(
                principal_type="user",
                principal_name=user_name,
                inline_policies=user.inline_policies,
                attached_policies=user.attached_policies,
                suspicious_policies=suspicious_policies,
            )

        for role_name, role in self.inventory.roles.items():
            policies_checked += self._inspect_principal_policies(
                principal_type="role",
                principal_name=role_name,
                inline_policies=role.inline_policies,
                attached_policies=role.attached_policies,
                suspicious_policies=suspicious_policies,
            )

        for group_name, group in self.inventory.groups.items():
            policies_checked += self._inspect_principal_policies(
                principal_type="group",
                principal_name=group_name,
                inline_policies=getattr(group, "inline_policies", []) or [],
                attached_policies=getattr(group, "attached_policies", []) or [],
                suspicious_policies=suspicious_policies,
            )

        if policies_checked == 0:
            return {
                "status": "PASS",
                "status_extended": "No identity policies found to evaluate.",
                "resource_type": "AWS::IAM::Policy",
                "resource_id": "identity-policies",
                "category": "IAM",
                "evidence_summary": "No identity policies were available for ABAC evaluation",
                "evidence_details": {
                    "policies_checked": 0,
                    "suspicious_policies": 0,
                },
            }

        principal_type_map = {
            "user": "AWS::IAM::User",
            "role": "AWS::IAM::Role",
            "group": "AWS::IAM::Group",
        }
        uniform_violations = [
            {
                "resource_type": principal_type_map.get(entry.get("principal_type"), "AWS::IAM::Policy"),
                "resource_id": entry.get("resource_ref", ""),
                "name": entry.get("principal_name", ""),
                "detail": entry,
            }
            for entry in suspicious_policies
        ]

        if not suspicious_policies:
            return {
                "status": "PASS",
                "status_extended": (
                    f"All {policies_checked} identity policies avoid the risky pattern of "
                    f"broad allow permissions on all resources with no condition block."
                ),
                "resource_type": "AWS::IAM::Policy",
                "resource_id": self.provider.identity.account_id,
                "category": "IAM",
                "evidence_summary": "No overly permissive identity policies without conditions were detected",
                "evidence_details": {
                    "violations": [],
                    "policies_checked": policies_checked,
                },
            }

        return {
            "status": "FAIL",
            "status_extended": (
                f"Found {len(suspicious_policies)} identity policies that allow broad access "
                f"on all resources without any condition block."
            ),
            "resource_type": "AWS::IAM::Policy",
            "resource_id": self.provider.identity.account_id,
            "category": "IAM",
            "evidence_summary": (
                f"{len(suspicious_policies)} of {policies_checked} identity policies match the "
                f"broad-allow + wildcard-resource + no-condition pattern"
            ),
            "evidence_details": {
                "violations": uniform_violations,
                "policies_checked": policies_checked,
            },
        }

    def _inspect_principal_policies(
        self,
        principal_type: str,
        principal_name: str,
        inline_policies: List[Any],
        attached_policies: List[Any],
        suspicious_policies: List[Dict[str, Any]],
    ) -> int:
        policies_checked = 0

        for policy in inline_policies:
            policies_checked += 1
            policy_name = getattr(policy, "name", "") or "inline-policy"
            policy_document = getattr(policy, "document", {}) or {}

            suspicious_statements = self._find_suspicious_statements(policy_document)
            if suspicious_statements:
                suspicious_policies.append(
                    {
                        "principal_type": principal_type,
                        "principal_name": principal_name,
                        "policy_type": "inline",
                        "policy_name": policy_name,
                        "policy_arn": getattr(policy, "arn", "") or "",
                        "resource_ref": f"{principal_type}/{principal_name}/inline/{policy_name}",
                        "suspicious_statements": suspicious_statements,
                    }
                )

        for policy in attached_policies:
            policies_checked += 1
            policy_name = getattr(policy, "name", "") or "attached-policy"
            policy_arn = getattr(policy, "arn", "") or ""
            policy_document = getattr(policy, "document", {}) or {}

            if not policy_document and policy_arn and policy_arn in self.inventory.policies:
                policy_document = getattr(self.inventory.policies[policy_arn], "document", {}) or {}

            suspicious_statements = self._find_suspicious_statements(policy_document)
            if suspicious_statements:
                suspicious_policies.append(
                    {
                        "principal_type": principal_type,
                        "principal_name": principal_name,
                        "policy_type": "attached",
                        "policy_name": policy_name,
                        "policy_arn": policy_arn,
                        "resource_ref": f"{principal_type}/{principal_name}/attached/{policy_name}",
                        "suspicious_statements": suspicious_statements,
                    }
                )

        return policies_checked

    def _find_suspicious_statements(self, policy_document: Dict[str, Any]) -> List[Dict[str, Any]]:
        suspicious: List[Dict[str, Any]] = []

        try:
            statements = policy_statements(policy_document)
        except Exception:
            return suspicious

        for idx, statement in enumerate(statements):
            try:
                effect = str(statement.get("Effect", "")).lower()
                if effect != "allow":
                    continue

                if not statement_has_wildcard_action(statement):
                    continue

                if not statement_has_wildcard_resource(statement):
                    continue

                condition = statement.get("Condition")
                if condition:
                    continue

                suspicious.append(
                    {
                        "statement_index": idx,
                        "action": statement.get("Action"),
                        "resource": statement.get("Resource"),
                        "condition_present": False,
                        "reason": "Allow statement grants broad wildcard access on all resources with no condition block",
                    }
                )
            except Exception:
                continue

        return suspicious