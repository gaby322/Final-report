from __future__ import annotations

import dataclasses
from typing import Any, Callable, Dict, FrozenSet, Iterable, List, Optional, Tuple

from phase1.aws_iam.rules.rbac.rule_utils import policy_statements
from phase2.graph.edge_conditions import (
    V4_RELEVANT_CREATE_ACTIONS,
    _extract_all_tag_conditions,
    _has_paired_null_check,
    analyse_boundary_tag_constraint,
    can_tag_role_target,
    can_tag_user_target,
)
from shared.aws.iam_policy_evaluation import get_all_policy_documents
from shared.aws.models.iam_models import Role, User
from shared.core.storage.inventory import Inventory


_V1_DUAL_REQUIRED_ACTIONS: FrozenSet[str] = frozenset({
    "iam:taguser",
    "iam:tagrole",
    "iam:tagpolicy",
    "ec2:createtags",
    "ec2:deletetags",
    "s3:putbuckettagging",
    "s3:deletebuckettagging",
    "iam:createrole",
    "iam:createuser",
})

_IF_EXISTS_OPERATORS: FrozenSet[str] = frozenset({
    "stringequalsifexists",
    "stringnotequalsifexists",
    "stringequalsignorecaseifexists",
    "stringnotequalsignorecaseifexists",
    "stringlikeifexists",
    "stringnotlikeifexists",
    "arnequalsifexists",
    "arnlikeifexists",
    "arnnotequalsifexists",
    "arnnotlikeifexists",
    "boolifexists",
    "numericequalsifexists",
})


@dataclasses.dataclass(frozen=True)
class VClassFinding:
    v_class: str
    principal_arn: str
    principal_name: str
    severity: str
    description: str
    evidence: Dict[str, Any] = dataclasses.field(default_factory=dict)


def detect_v1_dual_condition_omission(
    inventory: Inventory,
) -> List[VClassFinding]:
    findings: List[VClassFinding] = []

    def _scan_principal(principal: Any, kind: str) -> None:
        for doc in get_all_policy_documents(principal, inventory):
            for stmt in policy_statements(doc):
                if str(stmt.get("Effect", "")).lower() != "allow":
                    continue
                actions = _ensure_list_str(stmt.get("Action", []))
                actions_lower = {a.lower() for a in actions}
                if not (actions_lower & _V1_DUAL_REQUIRED_ACTIONS):
                    continue
                conditions = stmt.get("Condition") or {}
                if not isinstance(conditions, dict) or not conditions:
                    continue
                parsed = _extract_all_tag_conditions(conditions)
                request_keys: Dict[str, str] = {}
                resource_keys: Dict[str, str] = {}
                for tc in parsed:
                    if tc.key_family == "aws:requesttag" and tc.tag_key:
                        request_keys[tc.tag_key] = tc.raw_condition_key
                    elif tc.key_family == "aws:resourcetag" and tc.tag_key:
                        resource_keys[tc.tag_key] = tc.raw_condition_key
                request_only = set(request_keys) - set(resource_keys)
                resource_only = set(resource_keys) - set(request_keys)
                if not (request_only or resource_only):
                    continue
                arn = getattr(principal, "arn", "")
                name = (
                    getattr(principal, "user_name", None)
                    or getattr(principal, "role_name", None)
                    or getattr(principal, "group_name", "")
                )
                description_parts = [
                    f"{kind} {name} has an Allow statement on actions "
                    f"{sorted(actions_lower & _V1_DUAL_REQUIRED_ACTIONS)} "
                    f"with unbalanced tag conditions:"
                ]
                if request_only:
                    description_parts.append(
                        f"missing aws:ResourceTag for request keys "
                        f"{sorted(request_only)}"
                    )
                if resource_only:
                    description_parts.append(
                        f"missing aws:RequestTag for resource keys "
                        f"{sorted(resource_only)}"
                    )
                findings.append(VClassFinding(
                    v_class="V1",
                    principal_arn=arn,
                    principal_name=name,
                    severity="HIGH",
                    description="; ".join(description_parts),
                    evidence={
                        "action_set": sorted(actions_lower),
                        "request_only_tag_keys": sorted(request_only),
                        "resource_only_tag_keys": sorted(resource_only),
                    },
                ))

    for u in inventory.users.values():
        _scan_principal(u, "User")
    for r in inventory.roles.values():
        _scan_principal(r, "Role")
    for g in inventory.groups.values():
        _scan_principal(g, "Group")
    return findings


def detect_v2_principal_tag_self_escalation(
    inventory: Inventory,
) -> List[VClassFinding]:
    findings: List[VClassFinding] = []

    referenced_principal_tag_keys: set = set()
    for principal_iter in (
        inventory.users.values(),
        inventory.roles.values(),
        inventory.groups.values(),
    ):
        for principal in principal_iter:
            for doc in get_all_policy_documents(principal, inventory):
                for stmt in policy_statements(doc):
                    conditions = stmt.get("Condition") or {}
                    if not isinstance(conditions, dict):
                        continue
                    for tc in _extract_all_tag_conditions(conditions):
                        if tc.key_family == "aws:principaltag" and tc.tag_key:
                            referenced_principal_tag_keys.add(tc.tag_key)
    for pol in inventory.policies.values():
        for stmt in policy_statements(getattr(pol, "document", {}) or {}):
            conditions = stmt.get("Condition") or {}
            if not isinstance(conditions, dict):
                continue
            for tc in _extract_all_tag_conditions(conditions):
                if tc.key_family == "aws:principaltag" and tc.tag_key:
                    referenced_principal_tag_keys.add(tc.tag_key)

    if not referenced_principal_tag_keys:
        return findings

    for u in inventory.users.values():
        ok, _, _ = can_tag_user_target(u, u, inventory)
        if not ok:
            continue
        findings.append(VClassFinding(
            v_class="V2",
            principal_arn=u.arn,
            principal_name=u.user_name,
            severity="HIGH",
            description=(
                f"User {u.user_name} can iam:TagUser on itself and at "
                f"least one Allow statement in inventory references "
                f"aws:PrincipalTag/<key> — V2 self-escalation candidate"
            ),
            evidence={
                "self_tag_action": "iam:TagUser",
                "referenced_principal_tag_keys": sorted(
                    referenced_principal_tag_keys
                ),
            },
        ))
    for r in inventory.roles.values():
        ok, _, _ = can_tag_role_target(r, r, inventory)
        if not ok:
            continue
        findings.append(VClassFinding(
            v_class="V2",
            principal_arn=r.arn,
            principal_name=r.role_name,
            severity="HIGH",
            description=(
                f"Role {r.role_name} can iam:TagRole on itself and at "
                f"least one Allow statement in inventory references "
                f"aws:PrincipalTag/<key> — V2 self-escalation candidate"
            ),
            evidence={
                "self_tag_action": "iam:TagRole",
                "referenced_principal_tag_keys": sorted(
                    referenced_principal_tag_keys
                ),
            },
        ))
    return findings


def detect_v4_permission_boundary_tag_bypass(
    inventory: Inventory,
) -> List[VClassFinding]:
    findings: List[VClassFinding] = []
    for principal_iter, kind in (
        (inventory.users.values(), "User"),
        (inventory.roles.values(), "Role"),
    ):
        for principal in principal_iter:
            for action in sorted(V4_RELEVANT_CREATE_ACTIONS):
                analysis = analyse_boundary_tag_constraint(
                    principal, inventory, action
                )
                if not analysis.bypass_candidate:
                    continue
                arn = getattr(principal, "arn", "")
                name = (
                    getattr(principal, "user_name", None)
                    or getattr(principal, "role_name", "")
                )
                findings.append(VClassFinding(
                    v_class="V4",
                    principal_arn=arn,
                    principal_name=name,
                    severity="MEDIUM",
                    description=(
                        f"{kind} {name}: {analysis.evidence}"
                    ),
                    evidence={
                        "action": action,
                        "matching_statement_count": analysis.matching_statement_count,
                        "constraining_keys": list(analysis.constraining_keys),
                    },
                ))
    return findings


def detect_v5_if_exists_fail_open(
    inventory: Inventory,
) -> List[VClassFinding]:
    findings: List[VClassFinding] = []

    def _scan_principal(principal: Any, kind: str) -> None:
        for doc in get_all_policy_documents(principal, inventory):
            for stmt in policy_statements(doc):
                if str(stmt.get("Effect", "")).lower() != "allow":
                    continue
                conditions = stmt.get("Condition") or {}
                if not isinstance(conditions, dict) or not conditions:
                    continue
                affected_keys: List[str] = []
                for op, kv in conditions.items():
                    if op.lower() not in _IF_EXISTS_OPERATORS:
                        continue
                    if not isinstance(kv, dict):
                        continue
                    for ck in kv.keys():
                        if not _has_paired_null_check(conditions, ck):
                            affected_keys.append(ck)
                if not affected_keys:
                    continue
                arn = getattr(principal, "arn", "")
                name = (
                    getattr(principal, "user_name", None)
                    or getattr(principal, "role_name", None)
                    or getattr(principal, "group_name", "")
                )
                findings.append(VClassFinding(
                    v_class="V5",
                    principal_arn=arn,
                    principal_name=name,
                    severity="MEDIUM",
                    description=(
                        f"{kind} {name} has Allow statement using "
                        f"*IfExists operator on condition key(s) "
                        f"{sorted(set(affected_keys))} without paired "
                        f"Null check — fail-open if the request omits "
                        f"the key"
                    ),
                    evidence={
                        "affected_condition_keys": sorted(set(affected_keys)),
                    },
                ))

    for u in inventory.users.values():
        _scan_principal(u, "User")
    for r in inventory.roles.values():
        _scan_principal(r, "Role")
    for g in inventory.groups.values():
        _scan_principal(g, "Group")
    return findings


def run_all_detectors(inventory: Inventory) -> Dict[str, List[VClassFinding]]:
    return {
        "V1": detect_v1_dual_condition_omission(inventory),
        "V2": detect_v2_principal_tag_self_escalation(inventory),
        "V4": detect_v4_permission_boundary_tag_bypass(inventory),
        "V5": detect_v5_if_exists_fail_open(inventory),
    }


def _ensure_list_str(value: Any) -> List[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(v) for v in value]
    return []
