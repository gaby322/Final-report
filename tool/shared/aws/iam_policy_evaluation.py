from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple, Union

from shared.aws.models import Policy, Role, User
from shared.core.storage.inventory import Inventory


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


def _action_glob_match(pattern: str, target: str) -> bool:
    if pattern == "*":
        return True
    p = pattern.lower()
    t = target.lower()
    if p == t:
        return True
    if p.endswith(":*"):
        service = p[:-2]
        return t.startswith(service + ":")
    return False


def _resolve_document(policy: Any, inventory: Inventory) -> Optional[Dict[str, Any]]:
    doc = getattr(policy, "document", None)
    if doc:
        return doc
    arn = getattr(policy, "arn", "")
    if arn and arn in inventory.policies:
        return getattr(inventory.policies[arn], "document", {}) or {}
    return None


def get_all_policy_documents(
    principal: Any, inventory: Inventory
) -> List[Dict[str, Any]]:
 
    documents: List[Dict[str, Any]] = []

    for p in getattr(principal, "attached_policies", []):
        doc = _resolve_document(p, inventory)
        if doc:
            documents.append(doc)

    for p in getattr(principal, "inline_policies", []):
        doc = getattr(p, "document", {}) or {}
        if doc:
            documents.append(doc)

    if isinstance(principal, User):
        for group_name in getattr(principal, "groups", []):
            group = inventory.groups.get(group_name)
            if not group:
                continue
            for p in getattr(group, "attached_policies", []):
                doc = _resolve_document(p, inventory)
                if doc:
                    documents.append(doc)
            for p in getattr(group, "inline_policies", []):
                doc = getattr(p, "document", {}) or {}
                if doc:
                    documents.append(doc)

    return documents


def principal_has_explicit_deny(
    principal: Any,
    inventory: Inventory,
    action: str,
    resource: str = "*",
) -> Tuple[bool, str]:
    
    action_lower = action.lower()

    for doc in get_all_policy_documents(principal, inventory):
        for stmt in policy_statements(doc):
            if stmt.get("Effect", "").lower() != "deny":
                continue


            if "NotResource" in stmt:
                not_resources = _ensure_list(stmt["NotResource"])

                in_exclusion = any(
                    r == "*" or (isinstance(r, str) and r.lower() == resource.lower())
                    for r in not_resources
                )
                if in_exclusion:
                    continue
            else:
                resources = _ensure_list(stmt.get("Resource", ["*"]))
                if resource == "*":
                    resource_in_scope = any(r == "*" for r in resources)
                else:
                    resource_in_scope = any(
                        r == "*" or (isinstance(r, str) and r.lower() == resource.lower())
                        for r in resources
                    )
                if not resource_in_scope:
                    continue

            conditions = stmt.get("Condition", {})
            condition_note = (
                f" [conditional deny — conditions not fully evaluated: {list(conditions.keys())}]"
                if conditions else ""
            )

            if "NotAction" in stmt:
                not_actions = _ensure_list(stmt["NotAction"])
                in_exclusion = any(
                    _action_glob_match(a, action_lower) for a in not_actions
                )
                if not in_exclusion:
                    return (
                        True,
                        f"Deny via NotAction — '{action}' is not in the "
                        f"exclusion list{condition_note}",
                    )
            else:
                actions = _ensure_list(stmt.get("Action", []))
                if any(_action_glob_match(a, action_lower) for a in actions):
                    return True, f"Explicit Deny on '{action}'{condition_note}"

    return False, ""
