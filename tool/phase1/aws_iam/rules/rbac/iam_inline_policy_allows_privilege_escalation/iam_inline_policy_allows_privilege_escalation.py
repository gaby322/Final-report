from typing import Dict, Any, Optional, List
from phase1.aws_iam.rules.base_check import RBACCheck
from phase1.aws_iam.rules.rbac.rule_utils import (
    get_privilege_escalation_actions_allowed_by_document,
)
from shared.aws.iam_policy_evaluation import principal_has_explicit_deny


class iam_inline_policy_allows_privilege_escalation(RBACCheck):

    def execute(self) -> Optional[Dict[str, Any]]:
        violations: List[Dict[str, Any]] = []

        for user_name, user in self.inventory.users.items():
            for policy in user.inline_policies:
                self._check_inline(user, "user", user_name, policy, violations)

        for group_name, group in self.inventory.groups.items():
            for policy in group.inline_policies:
                self._check_inline(group, "group", group_name, policy, violations)

        for role_name, role in self.inventory.roles.items():
            for policy in role.inline_policies:
                self._check_inline(role, "role", role_name, policy, violations)

        if violations:
            return {
                "status": "FAIL",
                "status_extended": "Inline policies allow privilege escalation actions.",
                "resource_type": "AWS::IAM::Policy",
                "resource_id": self.provider.identity.account_id,
                "category": "IAM",
                "evidence_summary": (
                    f"{len(violations)} inline policy documents contain privilege "
                    f"escalation actions that are not blocked by explicit Deny"
                ),
                "evidence_details": {"violations": violations},
            }

        return {
            "status": "PASS",
            "status_extended": "No inline policies with privilege escalation actions were found.",
            "resource_type": "AWS::IAM::Policy",
            "resource_id": self.provider.identity.account_id,
            "category": "IAM",
            "evidence_summary": "Inline policy documents do not contain privilege escalation actions (after explicit-Deny filtering)",
            "evidence_details": {},
        }

    def _check_inline(
        self,
        principal: Any,
        scope_kind: str,
        principal_name: str,
        policy: Any,
        violations: List[Dict[str, Any]],
    ) -> None:
        document = getattr(policy, "document", {}) or {}
        allowed = get_privilege_escalation_actions_allowed_by_document(document)
        if not allowed:
            return
        unblocked: List[str] = []
        denied: List[str] = []
        conditional_notes: List[str] = []
        for action in sorted(allowed):
            is_denied, reason = principal_has_explicit_deny(
                principal, self.inventory, action
            )
            if is_denied:
                denied.append(action)
                if "conditional deny" in reason:
                    conditional_notes.append(f"{action}: {reason}")
            else:
                unblocked.append(action)
        if unblocked:
            policy_name = getattr(policy, "name", "<inline>")
            violations.append({
                "scope": scope_kind,
                "principal": principal_name,
                "policy": f"{scope_kind}/{principal_name}/{policy_name}",
                "allowed_privesc_actions": unblocked,
                "denied_privesc_actions": denied,
                "conditional_deny_notes": conditional_notes,
            })
