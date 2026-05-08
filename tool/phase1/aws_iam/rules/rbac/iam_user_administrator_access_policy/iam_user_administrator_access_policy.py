from typing import Dict, Any, Optional, List
from phase1.aws_iam.rules.base_check import RBACCheck
from phase1.aws_iam.rules.rbac.rule_utils import (
    has_administrator_access_policy_name,
    policy_document_is_administrative,
)


class iam_user_administrator_access_policy(RBACCheck):

    def execute(self) -> Optional[Dict[str, Any]]:
        violations: List[Dict[str, Any]] = []

        for user_name, user in self.inventory.users.items():
            admin_sources: List[Dict[str, Any]] = []

            for policy in getattr(user, "attached_policies", []):
                if self._policy_grants_admin(policy):
                    admin_sources.append({
                        "source_type": "direct_attached",
                        "group": None,
                        "policy_name": getattr(policy, "name", ""),
                        "policy_arn": getattr(policy, "arn", None),
                    })

            for policy in getattr(user, "inline_policies", []):
                doc = getattr(policy, "document", {}) or {}
                if policy_document_is_administrative(doc):
                    admin_sources.append({
                        "source_type": "direct_inline",
                        "group": None,
                        "policy_name": getattr(policy, "name", "<inline>"),
                        "policy_arn": None,
                    })

            for group_name in getattr(user, "groups", []) or []:
                group = self.inventory.groups.get(group_name)
                if not group:
                    continue

                for policy in getattr(group, "attached_policies", []):
                    if self._policy_grants_admin(policy):
                        admin_sources.append({
                            "source_type": "group_attached",
                            "group": group_name,
                            "policy_name": getattr(policy, "name", ""),
                            "policy_arn": getattr(policy, "arn", None),
                        })

                for policy in getattr(group, "inline_policies", []):
                    doc = getattr(policy, "document", {}) or {}
                    if policy_document_is_administrative(doc):
                        admin_sources.append({
                            "source_type": "group_inline",
                            "group": group_name,
                            "policy_name": getattr(policy, "name", "<inline>"),
                            "policy_arn": None,
                        })

            if admin_sources:
                violations.append({
                    "user_name": user_name,
                    "user_arn": getattr(user, "arn", ""),
                    "admin_sources": admin_sources,
                })

        if violations:
            source_counts: Dict[str, int] = {}
            for v in violations:
                for s in v["admin_sources"]:
                    source_counts[s["source_type"]] = source_counts.get(s["source_type"], 0) + 1
            source_breakdown = ", ".join(
                f"{k}={source_counts[k]}" for k in sorted(source_counts)
            )
            user_names = ", ".join(v["user_name"] for v in violations)
            return {
                "status": "FAIL",
                "status_extended": (
                    f"Users with administrator access (direct or group-inherited): "
                    f"{user_names}"
                ),
                "resource_type": "AWS::IAM::User",
                "resource_id": self.provider.identity.account_id,
                "category": "IAM",
                "evidence_summary": (
                    f"{len(violations)} user(s) have administrator access. "
                    f"Source breakdown: {source_breakdown}."
                ),
                "evidence_details": {"violations": violations},
            }

        return {
            "status": "PASS",
            "status_extended": "No users have administrator access (direct or group-inherited)",
            "resource_type": "AWS::IAM::User",
            "resource_id": self.provider.identity.account_id,
            "category": "IAM",
            "evidence_summary": (
                "No user-level administrator access detected after checking "
                "direct_attached, direct_inline, group_attached, and group_inline paths"
            ),
            "evidence_details": {},
        }

    @staticmethod
    def _policy_grants_admin(policy: Any) -> bool:
        if has_administrator_access_policy_name(policy):
            return True
        doc = getattr(policy, "document", None) or {}
        return policy_document_is_administrative(doc)
