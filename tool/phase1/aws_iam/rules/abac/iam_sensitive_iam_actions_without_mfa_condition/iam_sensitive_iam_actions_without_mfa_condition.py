from typing import Dict, Any, Optional, List

from phase1.aws_iam.rules.base_check import ABACCheck
from phase1.aws_iam.rules.abac.abac_rule_utils import (
    policy_statements,
    statement_has_wildcard_resource,
    statement_has_mfa_condition,
    statement_allows_any_action_from_set,
)

_SENSITIVE_IAM_ACTIONS: frozenset = frozenset({
    "iam:deleteloginprofile",
    "iam:deleteaccesskey",
    "iam:deletevirtualmfadevice",
    "iam:deactivatemfadevice",
    "iam:deleteuser",
    "iam:deleterole",
    "iam:deletegroup",
    "iam:deletepolicy",
    "iam:deletepolicyversion",
    "iam:detachrolepolicy",
    "iam:detachuserpolicy",
    "iam:detachgrouppolicy",
    "iam:deleteuserpolicy",
    "iam:deleterolepolicy",
    "iam:deletegrouppolicy",
    "iam:createaccesskey",
})


class iam_sensitive_iam_actions_without_mfa_condition(ABACCheck):

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
                        if not statement_allows_any_action_from_set(stmt, _SENSITIVE_IAM_ACTIONS):
                            continue
                        if not statement_has_wildcard_resource(stmt):
                            continue
                        if statement_has_mfa_condition(stmt):
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
                                "Sensitive IAM action on Resource:* without "
                                "aws:MultiFactorAuthPresent condition — "
                                "permits destructive operations without MFA re-authentication"
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
                    "All policies granting sensitive IAM actions on Resource:* include "
                    "aws:MultiFactorAuthPresent conditions."
                ),
                "resource_type": "AWS::IAM::Policy",
                "resource_id": self.provider.identity.account_id,
                "category": "IAM",
                "evidence_summary": "All sensitive IAM operations require MFA re-authentication",
                "evidence_details": {
                    "violations": [],
                    "policies_checked": policies_checked,
                },
            }

        return {
            "status": "FAIL",
            "status_extended": (
                f"{len(violations)} policy statement(s) grant sensitive IAM actions on "
                "Resource:* without aws:MultiFactorAuthPresent conditions, allowing "
                "destructive credential and permission operations without MFA."
            ),
            "resource_type": "AWS::IAM::Policy",
            "resource_id": self.provider.identity.account_id,
            "category": "IAM",
            "evidence_summary": (
                f"{len(violations)} sensitive IAM grant(s) lack MFA re-authentication "
                "requirements — enables irreversible operations without step-up authentication"
            ),
            "evidence_details": {
                "violations": uniform_violations,
                "policies_checked": policies_checked,
            },
        }
