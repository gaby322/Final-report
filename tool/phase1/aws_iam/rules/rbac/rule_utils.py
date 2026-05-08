from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional, Union

def _ensure_list(value: Union[str, List[Any], None]) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def policy_statements(policy_document: Dict[str, Any]) -> List[Dict[str, Any]]:
    statements = policy_document.get("Statement", [])
    if isinstance(statements, dict):
        return [statements]
    return _ensure_list(statements)


def action_matches(action: Any, matcher: str) -> bool:
    if action == "*":
        return True
    if isinstance(action, str):
        return action.lower() == matcher.lower() or action.lower().endswith(":*") and matcher.lower().startswith(action.lower()[:-2] + ":")
    for item in _ensure_list(action):
        if action_matches(item, matcher):
            return True
    return False


def resource_matches(resource: Any, matcher: str) -> bool:
    if resource == "*":
        return True
    if isinstance(resource, str):
        return resource.lower() == matcher.lower()
    for item in _ensure_list(resource):
        if resource_matches(item, matcher):
            return True
    return False


def statement_allows_admin(statement: Dict[str, Any]) -> bool:
    if statement.get("Effect", "").lower() != "allow":
        return False
    actions = _ensure_list(statement.get("Action"))
    resources = _ensure_list(statement.get("Resource"))
    if any(a == "*" for a in actions) and any(r == "*" for r in resources):
        return True
    return False


def policy_document_is_administrative(policy_document: Dict[str, Any]) -> bool:
    for statement in policy_statements(policy_document):
        if statement_allows_admin(statement):
            return True
    return False


def policy_document_allows_service_full_access(policy_document: Dict[str, Any], service_prefix: str) -> bool:
    prefix = f"{service_prefix.lower()}:*"
    for statement in policy_statements(policy_document):
        if statement.get("Effect", "").lower() != "allow":
            continue
        actions = _ensure_list(statement.get("Action"))
        resources = _ensure_list(statement.get("Resource"))
        for action in actions:
            if isinstance(action, str) and action.lower() == prefix:
                if any(r == "*" for r in resources):
                    return True
    return False


def policy_document_has_full_cloudtrail(policy_document: Dict[str, Any]) -> bool:
    return policy_document_allows_service_full_access(policy_document, "cloudtrail")


def policy_document_has_full_kms(policy_document: Dict[str, Any]) -> bool:
    return policy_document_allows_service_full_access(policy_document, "kms")


def policy_document_has_wildcard_principal(policy_document: Dict[str, Any]) -> bool:
    for statement in policy_statements(policy_document):
        principal = statement.get("Principal")
        if principal is None:
            continue
        if principal == "*":
            return True
        if isinstance(principal, dict):
            for value in principal.values():
                if value == "*":
                    return True
                if isinstance(value, list) and "*" in value:
                    return True
        if isinstance(principal, list) and "*" in principal:
            return True
    return False


def policy_document_has_cross_account_trust(policy_document: Dict[str, Any], local_account_id: str) -> bool:
    for statement in policy_statements(policy_document):
        principal = statement.get("Principal")
        if not isinstance(principal, dict):
            continue
        aws_principal = principal.get("AWS")
        for item in _ensure_list(aws_principal):
            if isinstance(item, str) and item.startswith("arn:aws:iam::"):
                if item.split(":")[4] != local_account_id:
                    return True
    return False


def get_policy_field(policy: Any, field: str, default: Any = None) -> Any:
    if hasattr(policy, field):
        value = getattr(policy, field)
        return value if value is not None else default
    if isinstance(policy, dict):
        value = policy.get(field, default)
        return value if value is not None else default
    return default

def get_policy_document(inventory: Any, policy: Any) -> Dict[str, Any]:
    document = get_policy_field(policy, "document", {}) or {}
    if document:
        return document

    arn = get_policy_field(policy, "arn", "")
    if arn and arn in inventory.policies:
        return get_policy_field(inventory.policies[arn], "document", {}) or {}

    return {}


def normalize_policy_identifier(policy: Any) -> str:
    arn = get_policy_field(policy, "arn", "")
    if arn:
        return arn
    return get_policy_field(policy, "name", "")


def has_administrator_access_policy_name(policy: Any) -> bool:
    name = get_policy_field(policy, "name", "")
    arn = get_policy_field(policy, "arn", "")
    return name == "AdministratorAccess" or arn.endswith("/AdministratorAccess")


def has_cloudshell_admin_policy_name(policy: Any) -> bool:
    name = get_policy_field(policy, "name", "")
    arn = get_policy_field(policy, "arn", "")
    return name == "AWSCloudShellFullAccess" or arn.endswith("/AWSCloudShellFullAccess")


def is_policy_customer_managed(policy: Any) -> bool:
    arn = get_policy_field(policy, "arn", "")
    return arn.startswith("arn:aws:iam::") and ":policy/" in arn and not arn.startswith("arn:aws:iam::aws:")


_PRIVILEGE_ESCALATION_ACTIONS = {
    "iam:createpolicy",
    "iam:createpolicyversion",
    "iam:setdefaultpolicyversion",
    "iam:attachrolepolicy",
    "iam:putrolepolicy",
    "iam:updateassumerolepolicy",
    "iam:attachuserpolicy",
    "iam:putuserpolicy",
    "iam:attachgrouppolicy",
    "iam:putgrouppolicy",
    "iam:addusertogroup",
    "iam:createaccesskey",
    "iam:createloginprofile",
    "iam:updateloginprofile",
}


def policy_document_has_privilege_escalation_actions(policy_document: Dict[str, Any]) -> bool:
    for statement in policy_statements(policy_document):
        if statement.get("Effect", "").lower() != "allow":
            continue

        if "NotAction" in statement:
            not_actions = _ensure_list(statement.get("NotAction"))
            excluded: set = set()
            all_excluded = False
            for na in not_actions:
                if not isinstance(na, str):
                    continue
                na_lower = na.lower()
                if na_lower == "*":
                    all_excluded = True
                    break
                if na_lower.endswith(":*"):
                    svc = na_lower[:-2] + ":"
                    for ca in _PRIVILEGE_ESCALATION_ACTIONS:
                        if ca.startswith(svc):
                            excluded.add(ca)
                    continue
                if na_lower in _PRIVILEGE_ESCALATION_ACTIONS:
                    excluded.add(na_lower)
            if all_excluded:
                continue
            if _PRIVILEGE_ESCALATION_ACTIONS - excluded:
                return True
            continue

        actions = _ensure_list(statement.get("Action"))
        for action in actions:
            if not isinstance(action, str):
                continue
            action_lower = action.lower()
            if action_lower == "*" or (action_lower.endswith(":*") and any(
                e.startswith(action_lower[:-2] + ":") for e in _PRIVILEGE_ESCALATION_ACTIONS
            )):
                return True
            if action_lower in _PRIVILEGE_ESCALATION_ACTIONS:
                return True
    return False


def get_privilege_escalation_actions_allowed_by_document(
    policy_document: Dict[str, Any],
) -> "set[str]":
    matched: "set[str]" = set()
    for statement in policy_statements(policy_document):
        if statement.get("Effect", "").lower() != "allow":
            continue

        if "NotAction" in statement:
            not_actions = _ensure_list(statement.get("NotAction"))
            excluded_set = set()
            for na in not_actions:
                if not isinstance(na, str):
                    continue
                na_lower = na.lower()
                if na_lower == "*":
                    excluded_set.update(_PRIVILEGE_ESCALATION_ACTIONS)
                    continue
                if na_lower.endswith(":*"):
                    svc = na_lower[:-2] + ":"
                    for ca in _PRIVILEGE_ESCALATION_ACTIONS:
                        if ca.startswith(svc):
                            excluded_set.add(ca)
                    continue
                if na_lower in _PRIVILEGE_ESCALATION_ACTIONS:
                    excluded_set.add(na_lower)
            matched.update(_PRIVILEGE_ESCALATION_ACTIONS - excluded_set)
            continue

        actions = _ensure_list(statement.get("Action"))
        for action in actions:
            if not isinstance(action, str):
                continue
            action_lower = action.lower()
            if action_lower == "*":
                matched.update(_PRIVILEGE_ESCALATION_ACTIONS)
                continue
            if action_lower.endswith(":*"):
                service_prefix = action_lower[:-2] + ":"
                for catalogue_action in _PRIVILEGE_ESCALATION_ACTIONS:
                    if catalogue_action.startswith(service_prefix):
                        matched.add(catalogue_action)
                continue
            if action_lower in _PRIVILEGE_ESCALATION_ACTIONS:
                matched.add(action_lower)
    return matched
