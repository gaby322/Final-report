from typing import Dict, Any, Optional, List
from phase1.aws_iam.rules.base_check import RBACCheck
from phase1.aws_iam.rules.rbac.rule_utils import (
    get_privilege_escalation_actions_allowed_by_document,
    is_policy_customer_managed,
    normalize_policy_identifier,
    get_policy_document,
)
from shared.aws.iam_policy_evaluation import principal_has_explicit_deny


class iam_policy_allows_privilege_escalation(RBACCheck):

    def execute(self) -> Optional[Dict[str, Any]]:
        violations: List[Dict[str, Any]] = []

        for policy_name, policy in self.inventory.policies.items():
            allowed = get_privilege_escalation_actions_allowed_by_document(policy.document)
            if allowed:
                violations.append({
                    "scope": "policy",
                    "principal": None,
                    "policy": policy_name,
                    "allowed_privesc_actions": sorted(allowed),
                    "denied_privesc_actions": [],
                    "conditional_deny_notes": [],
                })

        for user_name, user in self.inventory.users.items():
            self._evaluate_principal_policies(user, "user", user_name, violations)

        for group_name, group in self.inventory.groups.items():
            self._evaluate_principal_policies(group, "group", group_name, violations)

        for role_name, role in self.inventory.roles.items():
            self._evaluate_principal_policies(role, "role", role_name, violations)

        if violations:
            summary_policies = {v["policy"] for v in violations}
            return {
                "status": "FAIL",
                "status_extended": "Policies allow privilege escalation actions",
                "resource_type": "AWS::IAM::Policy",
                "resource_id": self.provider.identity.account_id,
                "category": "IAM",
                "evidence_summary": (
                    f"{len(summary_policies)} policy documents include privilege "
                    f"escalation actions across {len(violations)} (principal, policy) pair(s)"
                ),
                "evidence_details": {"violations": violations},
            }

        return {
            "status": "PASS",
            "status_extended": "No policies were identified that allow privilege escalation actions",
            "resource_type": "AWS::IAM::Policy",
            "resource_id": self.provider.identity.account_id,
            "category": "IAM",
            "evidence_summary": "Privilege escalation actions not found in inspected IAM documents",
            "evidence_details": {},
        }

    def _evaluate_principal_policies(
        self,
        principal: Any,
        scope_kind: str,
        principal_name: str,
        violations: List[Dict[str, Any]],
    ) -> None:
        for policy in getattr(principal, "inline_policies", []):
            doc = getattr(policy, "document", {}) or {}
            self._record_violation_if_any(
                principal, scope_kind, principal_name,
                getattr(policy, "name", "<inline>"), doc, violations,
            )
        for policy in getattr(principal, "attached_policies", []):
            if not is_policy_customer_managed(policy):
                continue
            doc = get_policy_document(self.inventory, policy) or {}
            self._record_violation_if_any(
                principal, scope_kind, principal_name,
                normalize_policy_identifier(policy), doc, violations,
            )

    def _record_violation_if_any(
        self,
        principal: Any,
        scope_kind: str,
        principal_name: str,
        policy_identifier: str,
        document: Dict[str, Any],
        violations: List[Dict[str, Any]],
    ) -> None:
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
            violations.append({
                "scope": scope_kind,
                "principal": principal_name,
                "policy": f"{scope_kind}/{principal_name}/{policy_identifier}",
                "allowed_privesc_actions": unblocked,
                "denied_privesc_actions": denied,
                "conditional_deny_notes": conditional_notes,
            })