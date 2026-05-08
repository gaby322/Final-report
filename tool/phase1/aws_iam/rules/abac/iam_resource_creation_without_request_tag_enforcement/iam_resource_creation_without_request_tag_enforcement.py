from typing import Dict, Any, Optional, List

from phase1.aws_iam.rules.base_check import ABACCheck
from phase1.aws_iam.rules.abac.abac_rule_utils import (
    policy_statements,
    statement_has_wildcard_resource,
    statement_has_request_tag_conditions,
    statement_allows_any_action_from_set,
)

_IAM_CREATE_ACTIONS: frozenset = frozenset({
    "iam:createuser",
    "iam:createrole",
    "iam:createpolicy",
    "iam:creategroup",
    "iam:createinstanceprofile",
    "iam:createvirtualmfadevice",
})


class iam_resource_creation_without_request_tag_enforcement(ABACCheck):

    def execute(self) -> Optional[Dict[str, Any]]:
        violations: List[Dict[str, Any]] = []
        policies_checked = 0

        for principal_type, principal_iter in [
            ("user", self.inventory.users.items()),
            ("role", self.inventory.roles.items()),
            ("group", self.inventory.groups.items()),
        ]:
            for principal_name, principal in principal_iter:
                inline = getattr(principal, "inline_policies", []) or []
                attached = getattr(principal, "attached_policies", []) or []

                for policy in inline + attached:
                    policies_checked += 1
                    p_type = "inline" if policy in inline else "attached"
                    p_name = getattr(policy, "name", "") or ""
                    doc = getattr(policy, "document", {}) or {}
                    if not doc:
                        arn = getattr(policy, "arn", "") or ""
                        if arn and arn in self.inventory.policies:
                            doc = getattr(self.inventory.policies[arn], "document", {}) or {}

                    for idx, stmt in enumerate(policy_statements(doc)):
                        if not statement_allows_any_action_from_set(stmt, _IAM_CREATE_ACTIONS):
                            continue
                        if not statement_has_wildcard_resource(stmt):
                            continue
                        if statement_has_request_tag_conditions(stmt):
                            continue
                        violations.append({
                            "principal_type": principal_type,
                            "principal_name": principal_name,
                            "policy_type": p_type,
                            "policy_name": p_name,
                            "policy_arn": getattr(policy, "arn", "") or "",
                            "statement_index": idx,
                            "resource_ref": f"{principal_type}/{principal_name}/{p_type}/{p_name}",
                            "reason": (
                                "IAM resource creation action on Resource:* without "
                                "aws:RequestTag/* condition — permits creation of untagged "
                                "resources outside the ABAC governance model"
                            ),
                        })

        principal_type_map = {
            "user": "AWS::IAM::User",
            "role": "AWS::IAM::Role",
            "group": "AWS::IAM::Group",
        }
        uniform_violations = [
            {
                "resource_type": principal_type_map.get(v.get("principal_type"), "AWS::IAM::Policy"),
                "resource_id": v.get("resource_ref", ""),
                "name": v.get("principal_name", ""),
                "detail": v,
            }
            for v in violations
        ]

        if not violations:
            return {
                "status": "PASS",
                "status_extended": (
                    "All policies granting IAM resource creation actions on Resource:* include "
                    "aws:RequestTag/* conditions requiring tags at creation time."
                ),
                "resource_type": "AWS::IAM::Policy",
                "resource_id": self.provider.identity.account_id,
                "category": "IAM",
                "evidence_summary": "All IAM creation grants enforce tag requirements via aws:RequestTag",
                "evidence_details": {
                    "violations": [],
                    "policies_checked": policies_checked,
                },
            }

        return {
            "status": "FAIL",
            "status_extended": (
                f"{len(violations)} policy statement(s) grant IAM resource creation "
                "on Resource:* without aws:RequestTag/* conditions, allowing creation "
                "of untagged resources outside ABAC governance."
            ),
            "resource_type": "AWS::IAM::Policy",
            "resource_id": self.provider.identity.account_id,
            "category": "IAM",
            "evidence_summary": (
                f"{len(violations)} policy statement(s) allow IAM resource creation "
                "without mandatory tag enforcement"
            ),
            "evidence_details": {
                "violations": uniform_violations,
                "policies_checked": policies_checked,
            },
        }
