from __future__ import annotations

from typing import Any, Dict, List, Union


def policy_statements(policy_document: Dict[str, Any]) -> List[Dict[str, Any]]:
    statements = policy_document.get("Statement", [])
    if isinstance(statements, dict):
        return [statements]
    if isinstance(statements, list):
        return statements
    return []


def extract_statement_condition(statement: Dict[str, Any]) -> Dict[str, Any]:
    return statement.get("Condition", {})


def list_condition_keys(statement: Dict[str, Any]) -> List[str]:
    condition = extract_statement_condition(statement)
    keys = []

    def _collect_keys(obj: Any) -> None:
        if isinstance(obj, dict):
            for key, value in obj.items():
                if key.startswith(("aws:", "sts:", "ec2:")):
                    keys.append(key)
                else:
                    _collect_keys(value)
        elif isinstance(obj, list):
            for item in obj:
                _collect_keys(item)

    _collect_keys(condition)
    return keys


def statement_has_condition_key_prefix(statement: Dict[str, Any], prefix: str) -> bool:
    keys = list_condition_keys(statement)
    return any(key.startswith(prefix) for key in keys)


def statement_has_principal_tag_conditions(statement: Dict[str, Any]) -> bool:
    return statement_has_condition_key_prefix(statement, "aws:PrincipalTag/")


def statement_has_resource_tag_conditions(statement: Dict[str, Any]) -> bool:
    return statement_has_condition_key_prefix(statement, "aws:ResourceTag/")


def statement_has_request_tag_conditions(statement: Dict[str, Any]) -> bool:
    return statement_has_condition_key_prefix(statement, "aws:RequestTag/")


def statement_has_tagkeys_condition(statement: Dict[str, Any]) -> bool:
    keys = list_condition_keys(statement)
    return "aws:TagKeys" in keys


def statement_has_sts_tagsession(statement: Dict[str, Any]) -> bool:
    keys = list_condition_keys(statement)
    return "sts:TagSession" in keys


def statement_has_transitive_tag_keys(statement: Dict[str, Any]) -> bool:
    keys = list_condition_keys(statement)
    return "sts:TransitiveTagKeys" in keys


def statement_has_ec2_create_action(statement: Dict[str, Any]) -> bool:
    keys = list_condition_keys(statement)
    return "ec2:CreateAction" in keys


def policy_has_condition_key_prefix(policy_document: Dict[str, Any], prefix: str) -> bool:
    for statement in policy_statements(policy_document):
        if statement_has_condition_key_prefix(statement, prefix):
            return True
    return False


def policy_has_principal_tag_conditions(policy_document: Dict[str, Any]) -> bool:
    return policy_has_condition_key_prefix(policy_document, "aws:PrincipalTag/")


def policy_has_resource_tag_conditions(policy_document: Dict[str, Any]) -> bool:
    return policy_has_condition_key_prefix(policy_document, "aws:ResourceTag/")


def policy_has_request_tag_conditions(policy_document: Dict[str, Any]) -> bool:
    return policy_has_condition_key_prefix(policy_document, "aws:RequestTag/")


def policy_has_tagkeys_condition(policy_document: Dict[str, Any]) -> bool:
    for statement in policy_statements(policy_document):
        if statement_has_tagkeys_condition(statement):
            return True
    return False


def policy_has_sts_tagsession(policy_document: Dict[str, Any]) -> bool:
    for statement in policy_statements(policy_document):
        if statement_has_sts_tagsession(statement):
            return True
    return False


def policy_has_transitive_tag_keys(policy_document: Dict[str, Any]) -> bool:
    for statement in policy_statements(policy_document):
        if statement_has_transitive_tag_keys(statement):
            return True
    return False


def policy_has_ec2_create_action(policy_document: Dict[str, Any]) -> bool:
    for statement in policy_statements(policy_document):
        if statement_has_ec2_create_action(statement):
            return True
    return False


def extract_ec2_create_action_values(statement: Dict[str, Any]) -> List[str]:
    condition = extract_statement_condition(statement)
    values = []

    def _collect_values(obj: Any) -> None:
        if isinstance(obj, dict):
            for key, value in obj.items():
                if key == "ec2:CreateAction":
                    if isinstance(value, list):
                        values.extend(value)
                    else:
                        values.append(str(value))
                else:
                    _collect_values(value)
        elif isinstance(obj, list):
            for item in obj:
                _collect_values(item)

    _collect_values(condition)
    return values


def list_abac_condition_keys(policy_document: Dict[str, Any]) -> List[str]:
    abac_keys = set()
    for statement in policy_statements(policy_document):
        keys = list_condition_keys(statement)
        for key in keys:
            if (key.startswith(("aws:PrincipalTag/", "aws:ResourceTag/", "aws:RequestTag/")) or
                key in ["aws:TagKeys", "sts:TagSession", "sts:TransitiveTagKeys", "ec2:CreateAction"]):
                abac_keys.add(key)
    return sorted(list(abac_keys))


def statement_has_wildcard_action(statement: Dict[str, Any]) -> bool:
    action = statement.get("Action", [])
    
    if isinstance(action, str):
        actions = [action]
    elif isinstance(action, list):
        actions = action
    else:
        return False
    
    for act in actions:
        if not isinstance(act, str):
            continue
        if act == "*":
            return True
        if act.endswith(":*") and ":" in act:
            return True
    
    return False


def statement_has_wildcard_resource(statement: Dict[str, Any]) -> bool:
    resource = statement.get("Resource", [])
    
    if isinstance(resource, str):
        resources = [resource]
    elif isinstance(resource, list):
        resources = resource
    else:
        return False
    
    return "*" in resources


def statement_has_any_tag_condition(statement: Dict[str, Any]) -> bool:
    keys = list_condition_keys(statement)
    for key in keys:
        if (key.startswith(("aws:PrincipalTag/", "aws:ResourceTag/", "aws:RequestTag/")) or
            key == "aws:TagKeys"):
            return True
    return False


def policy_has_any_tag_condition(policy_document: Dict[str, Any]) -> bool:
    for statement in policy_statements(policy_document):
        if statement_has_any_tag_condition(statement):
            return True
    return False


def _ensure_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _condition_has_key(condition: Dict[str, Any], key_lower: str) -> bool:
    for operator_val in condition.values():
        if isinstance(operator_val, dict):
            for k in operator_val:
                if k.lower() == key_lower:
                    return True
    return False


def statement_allows_specific_action(statement: Dict[str, Any], target_action: str) -> bool:
    if statement.get("Effect", "").lower() != "allow":
        return False
    target_lower = target_action.lower()
    service_prefix = target_lower.split(":")[0] + ":"
    for act in _ensure_list(statement.get("Action")):
        if not isinstance(act, str):
            continue
        act_lower = act.lower()
        if act_lower == "*" or act_lower == target_lower:
            return True
        if act_lower == service_prefix + "*":
            return True
    return False


def statement_allows_any_action_from_set(
    statement: Dict[str, Any], action_set: "set[str]"
) -> bool:
    return any(statement_allows_specific_action(statement, act) for act in action_set)


def statement_has_passed_to_service_condition(statement: Dict[str, Any]) -> bool:
    return _condition_has_key(extract_statement_condition(statement), "iam:passedtoservice")


def statement_has_mfa_condition(statement: Dict[str, Any]) -> bool:
    return _condition_has_key(extract_statement_condition(statement), "aws:multifactorauthpresent")


def statement_has_permission_boundary_condition(statement: Dict[str, Any]) -> bool:
    return _condition_has_key(extract_statement_condition(statement), "iam:permissionsboundary")