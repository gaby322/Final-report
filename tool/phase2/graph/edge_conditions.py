from __future__ import annotations


from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, List, Optional, Tuple

from shared.aws.models import Policy, Role, User
from shared.core.storage.inventory import Inventory
from phase1.aws_iam.rules.rbac.rule_utils import (
    _ensure_list,
    policy_statements,
)
from shared.aws.iam_policy_evaluation import (
    get_all_policy_documents as _get_all_policy_documents,
    principal_has_explicit_deny as _principal_is_explicitly_denied,
    _resolve_document,
)


def _principal_allows_action(
    principal: Any,
    inventory: Inventory,
    action: str,
    resource: str = "*",
) -> bool:
    action_lower = action.lower()
    identity_allows = False
    for doc in _get_all_policy_documents(principal, inventory):
        for stmt in policy_statements(doc):
            if stmt.get("Effect", "").lower() != "allow":
                continue
            actions = _ensure_list(stmt.get("Action", []))
            resources = _ensure_list(stmt.get("Resource", []))
            action_match = any(
                _action_glob_match(a, action_lower) for a in actions
            )
            resource_match = any(
                r == "*" or r.lower() == resource.lower() for r in resources
            )
            if action_match and resource_match:
                identity_allows = True
                break
        if identity_allows:
            break
    if not identity_allows:
        return False

    boundary_doc = _load_permission_boundary_document(principal, inventory)
    if boundary_doc is None:
        return True
    for stmt in policy_statements(boundary_doc):
        if stmt.get("Effect", "").lower() != "allow":
            continue
        actions = _ensure_list(stmt.get("Action", []))
        resources = _ensure_list(stmt.get("Resource", []))
        action_match = any(_action_glob_match(a, action_lower) for a in actions)
        resource_match = any(
            r == "*" or r.lower() == resource.lower() for r in resources
        )
        if action_match and resource_match:
            return True
    return False


def _load_permission_boundary_document(
    principal: Any, inventory: Inventory
) -> Optional[Dict[str, Any]]:
    boundary = getattr(principal, "permissions_boundary", None) or getattr(
        principal, "permission_boundary", None
    )
    if not boundary:
        return None
    if isinstance(boundary, str):
        arn = boundary
    elif isinstance(boundary, dict):
        arn = boundary.get("PermissionsBoundaryArn") or boundary.get("arn") or ""
    else:
        arn = getattr(boundary, "arn", None) or getattr(
            boundary, "permissions_boundary_arn", None
        ) or ""
    if not arn:
        return None
    boundary_policy = inventory.policies.get(arn)
    if not boundary_policy:
        return None
    return getattr(boundary_policy, "document", {}) or {}


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


def _trust_policy_allows_principal(role: Role, principal_arn: str, account_id: str) -> Tuple[bool, Dict]:
    trust_doc = getattr(role, "assume_role_policy_document", {}) or {}
    for stmt in policy_statements(trust_doc):
        if stmt.get("Effect", "").lower() != "allow":
            continue
        principal_block = stmt.get("Principal", {})
        not_principal_block = stmt.get("NotPrincipal")
        conditions = stmt.get("Condition", {})

        if not_principal_block is not None:
            excluded_aws = _ensure_list(
                not_principal_block.get("AWS", [])
                if isinstance(not_principal_block, dict)
                else not_principal_block
            )
            excluded_set = {
                p for p in excluded_aws if isinstance(p, str)
            }
            if "*" in excluded_set:
                continue
            root_arn = f"arn:aws:iam::{account_id}:root"
            if root_arn in excluded_set and principal_arn.startswith(
                f"arn:aws:iam::{account_id}:"
            ):
                continue
            if principal_arn not in excluded_set:
                return True, conditions
            continue

        if principal_block == "*":
            return True, conditions

        aws_principals = _ensure_list(
            principal_block.get("AWS", []) if isinstance(principal_block, dict) else principal_block
        )
        service_principals = _ensure_list(
            principal_block.get("Service", []) if isinstance(principal_block, dict) else []
        )

        for p in aws_principals:
            if isinstance(p, str):
                if p == principal_arn:
                    return True, conditions
                if p == f"arn:aws:iam::{account_id}:root":
                    return True, conditions
                if p == "*":
                    return True, conditions

        _ = service_principals
    return False, {}


def can_assume_role(
    source: Any,
    target_role: Role,
    inventory: Inventory,
    account_id: str,
) -> Tuple[bool, str, Dict]:
    source_arn = getattr(source, "arn", "")
    role_arn = getattr(target_role, "arn", "")

    has_action = _principal_allows_action(source, inventory, "sts:AssumeRole", role_arn) or \
                 _principal_allows_action(source, inventory, "sts:AssumeRole", "*")

    if has_action:
        denied, _ = _principal_is_explicitly_denied(source, inventory, "sts:AssumeRole", role_arn)
        if denied:
            return False, "", {}

    trust_ok, conditions = _trust_policy_allows_principal(target_role, source_arn, account_id)

    if has_action and trust_ok:
        reason = (
            f"{getattr(source, 'user_name', None) or getattr(source, 'role_name', '')} "
            f"has sts:AssumeRole permission and the role trust policy allows this principal"
        )
        return True, reason, conditions

    return False, "", {}


def can_pass_role_via_ec2(
    source: Any,
    target_role: Role,
    inventory: Inventory,
) -> Tuple[bool, str, Dict]:
    role_arn = getattr(target_role, "arn", "")

    can_pass = (
        _principal_allows_action(source, inventory, "iam:PassRole", role_arn)
        or _principal_allows_action(source, inventory, "iam:PassRole", "*")
    )
    can_run = _principal_allows_action(source, inventory, "ec2:RunInstances")

    if can_pass:
        denied, _ = _principal_is_explicitly_denied(source, inventory, "iam:PassRole", role_arn)
        if denied:
            return False, "", {}
    if can_run:
        denied, _ = _principal_is_explicitly_denied(source, inventory, "ec2:RunInstances")
        if denied:
            return False, "", {}

    trust_doc = getattr(target_role, "assume_role_policy_document", {}) or {}
    ec2_trusted = False
    for stmt in policy_statements(trust_doc):
        if stmt.get("Effect", "").lower() != "allow":
            continue
        principal = stmt.get("Principal", {})
        services = _ensure_list(
            principal.get("Service", []) if isinstance(principal, dict) else []
        )
        if "ec2.amazonaws.com" in [s.lower() for s in services]:
            ec2_trusted = True
            break

    if can_pass and can_run and ec2_trusted:
        name = getattr(source, "user_name", None) or getattr(source, "role_name", "")
        reason = (
            f"{name} can iam:PassRole + ec2:RunInstances; "
            f"role {target_role.role_name} trusts ec2.amazonaws.com — "
            f"can attach this role to an EC2 instance to gain its permissions"
        )
        return True, reason, {}

    return False, "", {}


def can_pass_role_via_lambda(
    source: Any,
    target_role: Role,
    inventory: Inventory,
) -> Tuple[bool, str, Dict]:
    role_arn = getattr(target_role, "arn", "")

    can_pass = (
        _principal_allows_action(source, inventory, "iam:PassRole", role_arn)
        or _principal_allows_action(source, inventory, "iam:PassRole", "*")
    )
    can_create = _principal_allows_action(source, inventory, "lambda:CreateFunction")
    can_invoke = _principal_allows_action(source, inventory, "lambda:InvokeFunction")

    if can_pass:
        denied, _ = _principal_is_explicitly_denied(source, inventory, "iam:PassRole", role_arn)
        if denied:
            return False, "", {}
    if can_create:
        denied, _ = _principal_is_explicitly_denied(source, inventory, "lambda:CreateFunction")
        if denied:
            return False, "", {}
    if can_invoke:
        denied, _ = _principal_is_explicitly_denied(source, inventory, "lambda:InvokeFunction")
        if denied:
            return False, "", {}

    trust_doc = getattr(target_role, "assume_role_policy_document", {}) or {}
    lambda_trusted = False
    for stmt in policy_statements(trust_doc):
        if stmt.get("Effect", "").lower() != "allow":
            continue
        principal = stmt.get("Principal", {})
        services = _ensure_list(
            principal.get("Service", []) if isinstance(principal, dict) else []
        )
        if "lambda.amazonaws.com" in [s.lower() for s in services]:
            lambda_trusted = True
            break

    if can_pass and can_create and can_invoke and lambda_trusted:
        name = getattr(source, "user_name", None) or getattr(source, "role_name", "")
        reason = (
            f"{name} can iam:PassRole + lambda:CreateFunction + lambda:InvokeFunction; "
            f"role {target_role.role_name} trusts lambda.amazonaws.com — "
            f"can create a Lambda function with this role to execute privileged code"
        )
        return True, reason, {}

    return False, "", {}


def can_create_policy_version(
    source: Any,
    target_role: Role,
    inventory: Inventory,
    account_id: str,
) -> Tuple[bool, str, Dict]:
    can_create_version = _principal_allows_action(
        source, inventory, "iam:CreatePolicyVersion", "*"
    ) or _principal_allows_action(
        source, inventory, "iam:CreatePolicyVersion"
    )

    if not can_create_version:
        return False, "", {}

    denied, _ = _principal_is_explicitly_denied(source, inventory, "iam:CreatePolicyVersion", "*")
    if denied:
        return False, "", {}

    for p in getattr(target_role, "attached_policies", []):
        arn = getattr(p, "arn", "")
        if arn and f"::{account_id}:policy/" in arn:
            name = getattr(source, "user_name", None) or getattr(source, "role_name", "")
            reason = (
                f"{name} has iam:CreatePolicyVersion; can overwrite policy "
                f"{getattr(p, 'name', arn)} attached to role {target_role.role_name}, "
                f"injecting admin permissions into that role"
            )
            return True, reason, {}

    return False, "", {}


def can_attach_role_policy(
    source: Any,
    target_role: Role,
    inventory: Inventory,
) -> Tuple[bool, str, Dict]:
    can_attach = (
        _principal_allows_action(source, inventory, "iam:AttachRolePolicy", target_role.arn)
        or _principal_allows_action(source, inventory, "iam:AttachRolePolicy", "*")
    )
    if can_attach:
        denied, _ = _principal_is_explicitly_denied(source, inventory, "iam:AttachRolePolicy", target_role.arn)
        if denied:
            return False, "", {}
        name = getattr(source, "user_name", None) or getattr(source, "role_name", "")
        reason = (
            f"{name} can iam:AttachRolePolicy on role {target_role.role_name} — "
            f"can attach AdministratorAccess or any escalating managed policy to this role"
        )
        return True, reason, {}
    return False, "", {}


def can_put_role_policy(
    source: Any,
    target_role: Role,
    inventory: Inventory,
) -> Tuple[bool, str, Dict]:
    can_put = (
        _principal_allows_action(source, inventory, "iam:PutRolePolicy", target_role.arn)
        or _principal_allows_action(source, inventory, "iam:PutRolePolicy", "*")
    )
    if can_put:
        denied, _ = _principal_is_explicitly_denied(source, inventory, "iam:PutRolePolicy", target_role.arn)
        if denied:
            return False, "", {}
        name = getattr(source, "user_name", None) or getattr(source, "role_name", "")
        reason = (
            f"{name} can iam:PutRolePolicy on role {target_role.role_name} — "
            f"can inject an inline policy with *:* on * to escalate this role to admin"
        )
        return True, reason, {}
    return False, "", {}


def can_update_assume_role_policy(
    source: Any,
    target_role: Role,
    inventory: Inventory,
) -> Tuple[bool, str, Dict]:
    can_update = (
        _principal_allows_action(source, inventory, "iam:UpdateAssumeRolePolicy", target_role.arn)
        or _principal_allows_action(source, inventory, "iam:UpdateAssumeRolePolicy", "*")
    )
    if can_update:
        denied, _ = _principal_is_explicitly_denied(source, inventory, "iam:UpdateAssumeRolePolicy", target_role.arn)
        if denied:
            return False, "", {}
        name = getattr(source, "user_name", None) or getattr(source, "role_name", "")
        reason = (
            f"{name} can iam:UpdateAssumeRolePolicy on role {target_role.role_name} — "
            f"can modify the trust policy to allow itself to assume the role"
        )
        return True, reason, {}
    return False, "", {}


def can_attach_user_policy(
    source: Any,
    target_user: User,
    inventory: Inventory,
) -> Tuple[bool, str, Dict]:
    can_attach = (
        _principal_allows_action(source, inventory, "iam:AttachUserPolicy", target_user.arn)
        or _principal_allows_action(source, inventory, "iam:AttachUserPolicy", "*")
    )
    if can_attach:
        denied, _ = _principal_is_explicitly_denied(source, inventory, "iam:AttachUserPolicy", target_user.arn)
        if denied:
            return False, "", {}
        name = getattr(source, "user_name", None) or getattr(source, "role_name", "")
        reason = (
            f"{name} can iam:AttachUserPolicy on user {target_user.user_name} — "
            f"can attach AdministratorAccess directly to this user"
        )
        return True, reason, {}
    return False, "", {}


def can_create_access_key(
    source: Any,
    target_user: User,
    inventory: Inventory,
) -> Tuple[bool, str, Dict]:
    can_create = (
        _principal_allows_action(source, inventory, "iam:CreateAccessKey", target_user.arn)
        or _principal_allows_action(source, inventory, "iam:CreateAccessKey", "*")
    )
    if can_create:
        denied, _ = _principal_is_explicitly_denied(source, inventory, "iam:CreateAccessKey", target_user.arn)
        if denied:
            return False, "", {}
        name = getattr(source, "user_name", None) or getattr(source, "role_name", "")
        reason = (
            f"{name} can iam:CreateAccessKey for user {target_user.user_name} — "
            f"can generate credentials for this user and act as them"
        )
        return True, reason, {}
    return False, "", {}


def _extract_principal_tag_conditions(conditions: Dict) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    for operator, kv_map in conditions.items():
        if not isinstance(kv_map, dict):
            continue
        if operator.lower() not in ("stringequals", "stringlike", "stringequalsignorecase"):
            continue
        for condition_key, expected_value in kv_map.items():
            if condition_key.lower().startswith("aws:principaltag/"):
                tag_key = condition_key.split("/", 1)[1]
                result[tag_key] = expected_value
    return result


def _tags_satisfy_conditions(source_tags: Dict[str, str], tag_conditions: Dict[str, Any]) -> bool:
    for tag_key, expected in tag_conditions.items():
        actual = source_tags.get(tag_key, "")
        if isinstance(expected, list):
            if actual not in expected:
                return False
        elif actual != expected:
            return False
    return True


def _can_mutate_own_tags(source: Any, inventory: Inventory) -> bool:
    source_arn = getattr(source, "arn", "")
    if isinstance(source, User):
        return (
            _principal_allows_action(source, inventory, "iam:TagUser", source_arn)
            or _principal_allows_action(source, inventory, "iam:TagUser", "*")
        )
    return (
        _principal_allows_action(source, inventory, "iam:TagRole", source_arn)
        or _principal_allows_action(source, inventory, "iam:TagRole", "*")
    )


def can_assume_role_abac(
    source: Any,
    target_role: Role,
    inventory: Inventory,
    account_id: str,
) -> Tuple[bool, str, Dict]:
    source_arn = getattr(source, "arn", "")
    source_tags: Dict[str, str] = getattr(source, "tags", {}) or {}
    role_arn = getattr(target_role, "arn", "")

    has_assume_action = (
        _principal_allows_action(source, inventory, "sts:AssumeRole", role_arn)
        or _principal_allows_action(source, inventory, "sts:AssumeRole", "*")
    )
    if not has_assume_action:
        return False, "", {}

    trust_doc = getattr(target_role, "assume_role_policy_document", {}) or {}

    for stmt in policy_statements(trust_doc):
        if stmt.get("Effect", "").lower() != "allow":
            continue

        conditions = stmt.get("Condition", {})
        if not conditions:
            continue

        principal_block = stmt.get("Principal", {})
        principal_trusted = False
        if principal_block == "*":
            principal_trusted = True
        elif isinstance(principal_block, dict):
            for p in _ensure_list(principal_block.get("AWS", [])):
                if p in (source_arn, f"arn:aws:iam::{account_id}:root", "*"):
                    principal_trusted = True
                    break

        if not principal_trusted:
            continue

        tag_conditions = _extract_principal_tag_conditions(conditions)
        if not tag_conditions:
            continue

        name = getattr(source, "user_name", None) or getattr(source, "role_name", "")

        if _tags_satisfy_conditions(source_tags, tag_conditions):
            reason = (
                f"{name} has sts:AssumeRole and role {target_role.role_name} trust policy "
                f"requires tags {tag_conditions} — source tags match, condition satisfied"
            )
            return True, reason, conditions

        if _can_mutate_own_tags(source, inventory):
            reason = (
                f"{name} can mutate its own tags (iam:TagUser/iam:TagRole) to satisfy "
                f"ABAC condition {tag_conditions} on role {target_role.role_name} trust policy"
            )
            return True, reason, {**conditions, "via_tag_mutation": True}

        injected_via = _can_inject_session_tags(source, inventory, account_id)
        if injected_via:
            reason = (
                f"{name} can assume intermediate role {injected_via} which permits "
                f"sts:TagSession — session-tag injection satisfies ABAC condition "
                f"{tag_conditions} on role {target_role.role_name} trust policy"
            )
            return True, reason, {
                **conditions,
                "via_session_tag_injection": True,
                "injection_role": injected_via,
            }

    return False, "", {}


def _can_inject_session_tags(
    source: Any, inventory: Inventory, account_id: str
) -> Optional[str]:
    source_arn = getattr(source, "arn", "")
    for role in inventory.roles.values():
        role_arn = getattr(role, "arn", "")
        if role_arn == source_arn:
            continue
        has_assume = (
            _principal_allows_action(source, inventory, "sts:AssumeRole", role_arn)
            or _principal_allows_action(source, inventory, "sts:AssumeRole", "*")
        )
        if not has_assume:
            continue
        trust_doc = getattr(role, "assume_role_policy_document", {}) or {}
        for stmt in policy_statements(trust_doc):
            if stmt.get("Effect", "").lower() != "allow":
                continue
            actions = _ensure_list(stmt.get("Action", []))
            action_set = {a.lower() for a in actions if isinstance(a, str)}
            if any(
                a in action_set
                for a in ("sts:tagsession", "sts:*", "*")
            ):
                principal_block = stmt.get("Principal", {})
                if principal_block == "*":
                    return role_arn
                if isinstance(principal_block, dict):
                    for p in _ensure_list(principal_block.get("AWS", [])):
                        if p in (source_arn, f"arn:aws:iam::{account_id}:root", "*"):
                            return role_arn
    return None


def _can_pass_role_via_service(
    source: Any,
    target_role: Role,
    inventory: Inventory,
    trusted_service: str,
    required_actions: Tuple[str, ...],
    service_label: str,
) -> Tuple[bool, str, Dict]:
    role_arn = getattr(target_role, "arn", "")

    can_pass = (
        _principal_allows_action(source, inventory, "iam:PassRole", role_arn)
        or _principal_allows_action(source, inventory, "iam:PassRole", "*")
    )
    if not can_pass:
        return False, "", {}

    denied, _ = _principal_is_explicitly_denied(source, inventory, "iam:PassRole", role_arn)
    if denied:
        return False, "", {}

    for act in required_actions:
        if not _principal_allows_action(source, inventory, act):
            return False, "", {}
        denied_act, _ = _principal_is_explicitly_denied(source, inventory, act)
        if denied_act:
            return False, "", {}

    trust_doc = getattr(target_role, "assume_role_policy_document", {}) or {}
    service_trusted = False
    for stmt in policy_statements(trust_doc):
        if stmt.get("Effect", "").lower() != "allow":
            continue
        principal = stmt.get("Principal", {})
        services = _ensure_list(
            principal.get("Service", []) if isinstance(principal, dict) else []
        )
        if trusted_service.lower() in [s.lower() for s in services if isinstance(s, str)]:
            service_trusted = True
            break

    if not service_trusted:
        return False, "", {}

    name = getattr(source, "user_name", None) or getattr(source, "role_name", "")
    reason = (
        f"{name} can iam:PassRole + {', '.join(required_actions)}; role "
        f"{target_role.role_name} trusts {trusted_service} — can attach this "
        f"role to a {service_label} resource to gain its permissions"
    )
    return True, reason, {}


def can_pass_role_via_cloudformation(
    source: Any, target_role: Role, inventory: Inventory
) -> Tuple[bool, str, Dict]:
    return _can_pass_role_via_service(
        source, target_role, inventory,
        trusted_service="cloudformation.amazonaws.com",
        required_actions=("cloudformation:CreateStack",),
        service_label="CloudFormation",
    )


def can_pass_role_via_glue(
    source: Any, target_role: Role, inventory: Inventory
) -> Tuple[bool, str, Dict]:
    return _can_pass_role_via_service(
        source, target_role, inventory,
        trusted_service="glue.amazonaws.com",
        required_actions=("glue:CreateDevEndpoint",),
        service_label="Glue",
    )


def can_pass_role_via_sagemaker(
    source: Any, target_role: Role, inventory: Inventory
) -> Tuple[bool, str, Dict]:
    return _can_pass_role_via_service(
        source, target_role, inventory,
        trusted_service="sagemaker.amazonaws.com",
        required_actions=("sagemaker:CreateNotebookInstance",),
        service_label="SageMaker",
    )


def can_pass_role_via_datapipeline(
    source: Any, target_role: Role, inventory: Inventory
) -> Tuple[bool, str, Dict]:
    return _can_pass_role_via_service(
        source, target_role, inventory,
        trusted_service="datapipeline.amazonaws.com",
        required_actions=(
            "datapipeline:CreatePipeline",
            "datapipeline:PutPipelineDefinition",
            "datapipeline:ActivatePipeline",
        ),
        service_label="DataPipeline",
    )


def _can_pass_role_via_service_multi(
    source: Any,
    target_role: Role,
    inventory: Inventory,
    trusted_service: str,
    variant_action_sets: Tuple[Tuple[str, ...], ...],
    service_label: str,
) -> Tuple[bool, str, Dict]:
    role_arn = getattr(target_role, "arn", "")

    can_pass = (
        _principal_allows_action(source, inventory, "iam:PassRole", role_arn)
        or _principal_allows_action(source, inventory, "iam:PassRole", "*")
    )
    if not can_pass:
        return False, "", {}

    denied, _ = _principal_is_explicitly_denied(source, inventory, "iam:PassRole", role_arn)
    if denied:
        return False, "", {}

    matched_variant: Optional[Tuple[str, ...]] = None
    for variant in variant_action_sets:
        all_present = True
        any_denied = False
        for act in variant:
            if not _principal_allows_action(source, inventory, act):
                all_present = False
                break
            denied_act, _ = _principal_is_explicitly_denied(source, inventory, act)
            if denied_act:
                any_denied = True
                break
        if all_present and not any_denied:
            matched_variant = variant
            break

    if matched_variant is None:
        return False, "", {}

    trust_doc = getattr(target_role, "assume_role_policy_document", {}) or {}
    service_trusted = False
    for stmt in policy_statements(trust_doc):
        if stmt.get("Effect", "").lower() != "allow":
            continue
        principal = stmt.get("Principal", {})
        services = _ensure_list(
            principal.get("Service", []) if isinstance(principal, dict) else []
        )
        if trusted_service.lower() in [s.lower() for s in services if isinstance(s, str)]:
            service_trusted = True
            break

    if not service_trusted:
        return False, "", {}

    name = getattr(source, "user_name", None) or getattr(source, "role_name", "")
    reason = (
        f"{name} can iam:PassRole + {', '.join(matched_variant)}; role "
        f"{target_role.role_name} trusts {trusted_service} — can attach this "
        f"role to a {service_label} resource to gain its permissions"
    )
    return True, reason, {}


def can_pass_role_via_apprunner(
    source: Any, target_role: Role, inventory: Inventory
) -> Tuple[bool, str, Dict]:
    return _can_pass_role_via_service_multi(
        source, target_role, inventory,
        trusted_service="tasks.apprunner.amazonaws.com",
        variant_action_sets=(("apprunner:CreateService",),),
        service_label="AppRunner",
    )


def can_pass_role_via_bedrock_agentcore(
    source: Any, target_role: Role, inventory: Inventory
) -> Tuple[bool, str, Dict]:
    return _can_pass_role_via_service_multi(
        source, target_role, inventory,
        trusted_service="bedrock-agentcore.amazonaws.com",
        variant_action_sets=((
            "bedrock-agentcore:CreateCodeInterpreter",
            "bedrock-agentcore:StartCodeInterpreterSession",
            "bedrock-agentcore:InvokeCodeInterpreter",
        ),),
        service_label="Bedrock-AgentCore",
    )


def can_pass_role_via_codebuild(
    source: Any, target_role: Role, inventory: Inventory
) -> Tuple[bool, str, Dict]:
    return _can_pass_role_via_service_multi(
        source, target_role, inventory,
        trusted_service="codebuild.amazonaws.com",
        variant_action_sets=(
            ("codebuild:CreateProject", "codebuild:StartBuild"),
            ("codebuild:CreateProject", "codebuild:StartBuildBatch"),
        ),
        service_label="CodeBuild",
    )


def can_pass_role_via_ecs(
    source: Any, target_role: Role, inventory: Inventory
) -> Tuple[bool, str, Dict]:
    return _can_pass_role_via_service_multi(
        source, target_role, inventory,
        trusted_service="ecs-tasks.amazonaws.com",
        variant_action_sets=(
            ("ecs:CreateCluster", "ecs:RegisterTaskDefinition", "ecs:CreateService"),
            ("ecs:CreateCluster", "ecs:RegisterTaskDefinition", "ecs:RunTask"),
            ("ecs:RegisterTaskDefinition", "ecs:CreateService"),
            ("ecs:RegisterTaskDefinition", "ecs:RunTask"),
            ("ecs:RegisterTaskDefinition", "ecs:StartTask"),
        ),
        service_label="ECS",
    )


def can_pass_role_via_glue_job(
    source: Any, target_role: Role, inventory: Inventory
) -> Tuple[bool, str, Dict]:
    return _can_pass_role_via_service_multi(
        source, target_role, inventory,
        trusted_service="glue.amazonaws.com",
        variant_action_sets=(
            ("glue:CreateJob", "glue:StartJobRun"),
            ("glue:CreateJob", "glue:CreateTrigger"),
            ("glue:UpdateJob", "glue:StartJobRun"),
            ("glue:UpdateJob", "glue:CreateTrigger"),
        ),
        service_label="Glue (job)",
    )


def can_pass_role_via_lambda_variant(
    source: Any, target_role: Role, inventory: Inventory
) -> Tuple[bool, str, Dict]:
    return _can_pass_role_via_service_multi(
        source, target_role, inventory,
        trusted_service="lambda.amazonaws.com",
        variant_action_sets=(
            ("lambda:CreateFunction", "lambda:CreateEventSourceMapping"),
            ("lambda:CreateFunction", "lambda:AddPermission"),
        ),
        service_label="Lambda (variant)",
    )


def can_pass_role_via_sagemaker_job(
    source: Any, target_role: Role, inventory: Inventory
) -> Tuple[bool, str, Dict]:
    return _can_pass_role_via_service_multi(
        source, target_role, inventory,
        trusted_service="sagemaker.amazonaws.com",
        variant_action_sets=(
            ("sagemaker:CreateTrainingJob",),
            ("sagemaker:CreateProcessingJob",),
        ),
        service_label="SageMaker (job)",
    )


def can_pass_role_via_cloudformation_stacksets(
    source: Any, target_role: Role, inventory: Inventory
) -> Tuple[bool, str, Dict]:
    return _can_pass_role_via_service_multi(
        source, target_role, inventory,
        trusted_service="cloudformation.amazonaws.com",
        variant_action_sets=(
            ("cloudformation:CreateStackSet", "cloudformation:CreateStackInstances"),
            ("cloudformation:UpdateStackSet",),
        ),
        service_label="CloudFormation StackSets",
    )


def can_pass_role_via_ec2_spot(
    source: Any, target_role: Role, inventory: Inventory
) -> Tuple[bool, str, Dict]:
    return _can_pass_role_via_service_multi(
        source, target_role, inventory,
        trusted_service="ec2.amazonaws.com",
        variant_action_sets=(("ec2:RequestSpotInstances",),),
        service_label="EC2 (spot)",
    )


def can_set_default_policy_version(
    source: Any,
    target_role: Role,
    inventory: Inventory,
    account_id: str,
) -> Tuple[bool, str, Dict]:
    can_set = (
        _principal_allows_action(source, inventory, "iam:SetDefaultPolicyVersion", "*")
        or _principal_allows_action(source, inventory, "iam:SetDefaultPolicyVersion")
    )
    if not can_set:
        return False, "", {}
    denied, _ = _principal_is_explicitly_denied(
        source, inventory, "iam:SetDefaultPolicyVersion", "*"
    )
    if denied:
        return False, "", {}
    for p in getattr(target_role, "attached_policies", []):
        arn = getattr(p, "arn", "")
        if arn and f"::{account_id}:policy/" in arn:
            name = getattr(source, "user_name", None) or getattr(source, "role_name", "")
            reason = (
                f"{name} has iam:SetDefaultPolicyVersion; can revert policy "
                f"{getattr(p, 'name', arn)} attached to role {target_role.role_name} "
                f"to a previously-more-permissive version"
            )
            return True, reason, {}
    return False, "", {}


def can_create_login_profile(
    source: Any,
    target_user: User,
    inventory: Inventory,
) -> Tuple[bool, str, Dict]:
    if not (
        _principal_allows_action(source, inventory, "iam:CreateLoginProfile", target_user.arn)
        or _principal_allows_action(source, inventory, "iam:CreateLoginProfile", "*")
    ):
        return False, "", {}
    denied, _ = _principal_is_explicitly_denied(
        source, inventory, "iam:CreateLoginProfile", target_user.arn
    )
    if denied:
        return False, "", {}
    name = getattr(source, "user_name", None) or getattr(source, "role_name", "")
    reason = (
        f"{name} can iam:CreateLoginProfile for user {target_user.user_name} — "
        f"can set a console password and take over interactively"
    )
    return True, reason, {}


def can_update_login_profile(
    source: Any,
    target_user: User,
    inventory: Inventory,
) -> Tuple[bool, str, Dict]:
    if not (
        _principal_allows_action(source, inventory, "iam:UpdateLoginProfile", target_user.arn)
        or _principal_allows_action(source, inventory, "iam:UpdateLoginProfile", "*")
    ):
        return False, "", {}
    denied, _ = _principal_is_explicitly_denied(
        source, inventory, "iam:UpdateLoginProfile", target_user.arn
    )
    if denied:
        return False, "", {}
    name = getattr(source, "user_name", None) or getattr(source, "role_name", "")
    reason = (
        f"{name} can iam:UpdateLoginProfile for user {target_user.user_name} — "
        f"can reset their console password and take over interactively"
    )
    return True, reason, {}


def can_attach_group_policy(
    source: Any, target_group: Any, inventory: Inventory
) -> Tuple[bool, str, Dict]:
    group_arn = getattr(target_group, "arn", "")
    if not (
        _principal_allows_action(source, inventory, "iam:AttachGroupPolicy", group_arn)
        or _principal_allows_action(source, inventory, "iam:AttachGroupPolicy", "*")
    ):
        return False, "", {}
    denied, _ = _principal_is_explicitly_denied(
        source, inventory, "iam:AttachGroupPolicy", group_arn
    )
    if denied:
        return False, "", {}
    name = getattr(source, "user_name", None) or getattr(source, "role_name", "")
    gname = getattr(target_group, "group_name", "")
    reason = (
        f"{name} can iam:AttachGroupPolicy on group {gname} — can attach "
        f"AdministratorAccess or any escalating managed policy that propagates "
        f"to every member of the group"
    )
    return True, reason, {}


def can_put_group_policy(
    source: Any, target_group: Any, inventory: Inventory
) -> Tuple[bool, str, Dict]:
    group_arn = getattr(target_group, "arn", "")
    if not (
        _principal_allows_action(source, inventory, "iam:PutGroupPolicy", group_arn)
        or _principal_allows_action(source, inventory, "iam:PutGroupPolicy", "*")
    ):
        return False, "", {}
    denied, _ = _principal_is_explicitly_denied(
        source, inventory, "iam:PutGroupPolicy", group_arn
    )
    if denied:
        return False, "", {}
    name = getattr(source, "user_name", None) or getattr(source, "role_name", "")
    gname = getattr(target_group, "group_name", "")
    reason = (
        f"{name} can iam:PutGroupPolicy on group {gname} — can inject an "
        f"inline policy with *:* on * that propagates to every member"
    )
    return True, reason, {}


def can_add_user_to_group(
    source: Any, target_group: Any, inventory: Inventory
) -> Tuple[bool, str, Dict]:
    group_arn = getattr(target_group, "arn", "")
    if not (
        _principal_allows_action(source, inventory, "iam:AddUserToGroup", group_arn)
        or _principal_allows_action(source, inventory, "iam:AddUserToGroup", "*")
    ):
        return False, "", {}
    denied, _ = _principal_is_explicitly_denied(
        source, inventory, "iam:AddUserToGroup", group_arn
    )
    if denied:
        return False, "", {}
    name = getattr(source, "user_name", "")
    gname = getattr(target_group, "group_name", "")
    reason = (
        f"{name} can iam:AddUserToGroup on group {gname} — can add themselves "
        f"(or any user) to the admin group, inheriting its permissions"
    )
    return True, reason, {}


_STRING_EQ_OPERATORS: FrozenSet[str] = frozenset({
    "stringequals",
    "stringequalsignorecase",
    "stringlike",
})
_STRING_NEQ_OPERATORS: FrozenSet[str] = frozenset({
    "stringnotequals",
    "stringnotequalsignorecase",
    "stringnotlike",
})
_IF_EXISTS_SUFFIX = "ifexists"

_ARN_OPERATORS: FrozenSet[str] = frozenset({
    "arnequals",
    "arnlike",
    "arnnotequals",
    "arnnotlike",
})

_BOOL_OPERATORS: FrozenSet[str] = frozenset({"bool"})

_QUANTIFIER_PREFIXES: FrozenSet[str] = frozenset({"forallvalues:", "foranyvalue:"})

_NULL_OPERATOR = "null"


_TAG_KEY_FAMILIES: FrozenSet[str] = frozenset({
    "aws:principaltag",
    "aws:resourcetag",
    "aws:requesttag",
    "aws:tagkeys",
})


@dataclass(frozen=True)
class TagCondition:

    operator: str
    operator_normalized: str
    operator_base: str
    is_if_exists: bool
    is_negated: bool
    key_family: str
    tag_key: str
    expected: Any
    raw_condition_key: str
    paired_null_check: bool = False


def _split_operator(operator: str) -> Tuple[str, bool, bool]:
    op = operator.lower()
    is_if_exists = op.endswith(_IF_EXISTS_SUFFIX)
    if is_if_exists:
        op = op[: -len(_IF_EXISTS_SUFFIX)]
    is_negated = op in _STRING_NEQ_OPERATORS or op in {"arnnotequals", "arnnotlike"}
    return op, is_if_exists, is_negated


def _classify_tag_key(condition_key: str) -> Tuple[Optional[str], str]:
    lowered = condition_key.lower()
    for family in _TAG_KEY_FAMILIES:
        if lowered == family:
            return family, ""
        if lowered.startswith(family + "/"):
            tag_key = condition_key.split("/", 1)[1]
            return family, tag_key
    return None, ""


def _has_paired_null_check(
    conditions: Dict[str, Any], condition_key: str
) -> bool:
    for op_name, kv_map in conditions.items():
        if op_name.lower() != _NULL_OPERATOR:
            continue
        if not isinstance(kv_map, dict):
            continue
        for k in kv_map.keys():
            if str(k).lower() == condition_key.lower():
                return True
    return False


def _extract_all_tag_conditions(conditions: Dict[str, Any]) -> List[TagCondition]:
    if not isinstance(conditions, dict):
        return []

    out: List[TagCondition] = []
    for operator, kv_map in conditions.items():
        if not isinstance(operator, str) or not isinstance(kv_map, dict):
            continue
        op_lower = operator.lower()

        unprefixed = op_lower
        for prefix in _QUANTIFIER_PREFIXES:
            if op_lower.startswith(prefix):
                unprefixed = op_lower[len(prefix):]
                break

        if unprefixed == _NULL_OPERATOR:
            continue

        base, is_if_exists, is_negated = _split_operator(unprefixed)
        if (
            base not in _STRING_EQ_OPERATORS
            and base not in _STRING_NEQ_OPERATORS
            and base not in _ARN_OPERATORS
            and base not in _BOOL_OPERATORS
        ):
            continue

        for raw_key, expected_value in kv_map.items():
            if not isinstance(raw_key, str):
                continue
            family, tag_key = _classify_tag_key(raw_key)
            if family is None:
                continue
            paired = _has_paired_null_check(conditions, raw_key)
            out.append(
                TagCondition(
                    operator=operator,
                    operator_normalized=op_lower,
                    operator_base=base,
                    is_if_exists=is_if_exists,
                    is_negated=is_negated,
                    key_family=family,
                    tag_key=tag_key,
                    expected=expected_value,
                    raw_condition_key=raw_key,
                    paired_null_check=paired,
                )
            )
    return out


def _evaluate_string_operator(
    base_operator: str,
    expected: Any,
    actual: Optional[str],
    is_if_exists: bool,
    is_negated: bool,
) -> bool:
    if actual is None:
        return is_if_exists
    expected_list = expected if isinstance(expected, list) else [expected]

    def _match_one(exp: Any) -> bool:
        if not isinstance(exp, str):
            exp_s = str(exp)
        else:
            exp_s = exp
        if base_operator in {"stringequals", "stringnotequals"}:
            equal = exp_s == actual
        elif base_operator in {
            "stringequalsignorecase",
            "stringnotequalsignorecase",
        }:
            equal = exp_s.lower() == actual.lower()
        elif base_operator in {"stringlike", "stringnotlike"}:
            import re

            pattern = "^" + re.escape(exp_s).replace(r"\*", ".*").replace(
                r"\?", "."
            ) + "$"
            equal = re.match(pattern, actual) is not None
        else:
            return False
        return equal

    matched = any(_match_one(e) for e in expected_list)
    return (not matched) if is_negated else matched


def _evaluate_bool_operator(expected: Any, actual: Optional[bool]) -> bool:
    if actual is None:
        return False
    expected_str = str(expected).lower() if not isinstance(expected, list) else None
    if expected_str is not None:
        return ("true" if actual else "false") == expected_str
    return any(
        ("true" if actual else "false") == str(e).lower() for e in expected
    )


def _evaluate_arn_operator(
    base_operator: str,
    expected: Any,
    actual: Optional[str],
    is_if_exists: bool,
    is_negated: bool,
) -> bool:
    if actual is None:
        return is_if_exists
    expected_list = expected if isinstance(expected, list) else [expected]
    import re

    def _arn_match(exp: Any) -> bool:
        if not isinstance(exp, str):
            return False
        if base_operator in {"arnequals", "arnnotequals"}:
            return exp == actual
        pattern = "^" + re.escape(exp).replace(r"\*", ".*").replace(r"\?", ".") + "$"
        return re.match(pattern, actual) is not None

    matched = any(_arn_match(e) for e in expected_list)
    return (not matched) if is_negated else matched


V4_RELEVANT_CREATE_ACTIONS: FrozenSet[str] = frozenset({
    "iam:createrole",
    "iam:createuser",
    "iam:createpolicy",
    "iam:createaccesskey",
})


@dataclass(frozen=True)
class BoundaryTagAnalysis:

    action: str
    boundary_attached: bool
    action_allowed_by_boundary: bool
    has_tag_constraint: bool
    constraining_keys: Tuple[str, ...]
    matching_statement_count: int
    bypass_candidate: bool

    @property
    def evidence(self) -> str:
        if not self.boundary_attached:
            return f"no permission boundary attached; action {self.action} unconstrained by boundary"
        if not self.action_allowed_by_boundary:
            return f"boundary blocks {self.action}; V4 not applicable"
        if self.has_tag_constraint:
            keys = ", ".join(self.constraining_keys) if self.constraining_keys else "(unspecified)"
            return f"boundary allows {self.action} but constrains it via {keys} — V4 not applicable"
        return (
            f"boundary allows {self.action} with no aws:RequestTag/aws:TagKeys constraint — "
            f"V4 bypass candidate"
        )


def _statement_has_tag_request_constraint(stmt: Dict[str, Any]) -> Tuple[bool, Tuple[str, ...]]:
    conditions = stmt.get("Condition") or {}
    if not isinstance(conditions, dict):
        return False, ()
    parsed = _extract_all_tag_conditions(conditions)
    relevant = [
        tc for tc in parsed
        if tc.key_family in {"aws:requesttag", "aws:tagkeys", "aws:principaltag"}
    ]
    keys = tuple(sorted({tc.raw_condition_key for tc in relevant}))
    return bool(relevant), keys


def _check_simple_action(
    source: Any,
    inventory: Inventory,
    action: str,
    target_arn: str,
    target_label: str,
) -> Tuple[bool, str, Dict[str, Any]]:
    if not (
        _principal_allows_action(source, inventory, action, target_arn)
        or _principal_allows_action(source, inventory, action, "*")
    ):
        return False, "", {}
    denied, _ = _principal_is_explicitly_denied(source, inventory, action, target_arn)
    if denied:
        return False, "", {}
    name = getattr(source, "user_name", None) or getattr(source, "role_name", "")
    reason = f"{name} can {action} on {target_label}"
    return True, reason, {}


def can_tag_user_target(
    source: Any, target_user: User, inventory: Inventory
) -> Tuple[bool, str, Dict[str, Any]]:
    target_arn = getattr(target_user, "arn", "")
    target_name = getattr(target_user, "user_name", "") or "<unknown>"
    return _check_simple_action(
        source, inventory, "iam:TagUser", target_arn, f"user {target_name}"
    )


def can_untag_user_target(
    source: Any, target_user: User, inventory: Inventory
) -> Tuple[bool, str, Dict[str, Any]]:
    target_arn = getattr(target_user, "arn", "")
    target_name = getattr(target_user, "user_name", "") or "<unknown>"
    return _check_simple_action(
        source, inventory, "iam:UntagUser", target_arn, f"user {target_name}"
    )


def can_tag_role_target(
    source: Any, target_role: Role, inventory: Inventory
) -> Tuple[bool, str, Dict[str, Any]]:
    target_arn = getattr(target_role, "arn", "")
    target_name = getattr(target_role, "role_name", "") or "<unknown>"
    return _check_simple_action(
        source, inventory, "iam:TagRole", target_arn, f"role {target_name}"
    )


def can_untag_role_target(
    source: Any, target_role: Role, inventory: Inventory
) -> Tuple[bool, str, Dict[str, Any]]:
    target_arn = getattr(target_role, "arn", "")
    target_name = getattr(target_role, "role_name", "") or "<unknown>"
    return _check_simple_action(
        source, inventory, "iam:UntagRole", target_arn, f"role {target_name}"
    )


def can_tag_policy_target(
    source: Any, target_policy: Policy, inventory: Inventory
) -> Tuple[bool, str, Dict[str, Any]]:
    target_arn = getattr(target_policy, "arn", "")
    target_name = getattr(target_policy, "name", "") or "<unknown>"
    return _check_simple_action(
        source, inventory, "iam:TagPolicy", target_arn, f"policy {target_name}"
    )


def can_untag_policy_target(
    source: Any, target_policy: Policy, inventory: Inventory
) -> Tuple[bool, str, Dict[str, Any]]:
    target_arn = getattr(target_policy, "arn", "")
    target_name = getattr(target_policy, "name", "") or "<unknown>"
    return _check_simple_action(
        source, inventory, "iam:UntagPolicy", target_arn, f"policy {target_name}"
    )


def can_create_ec2_tags(
    source: Any, inventory: Inventory
) -> Tuple[bool, str, Dict[str, Any]]:
    return _check_simple_action(
        source, inventory, "ec2:CreateTags", "*", "EC2 resources"
    )


def can_delete_ec2_tags(
    source: Any, inventory: Inventory
) -> Tuple[bool, str, Dict[str, Any]]:
    return _check_simple_action(
        source, inventory, "ec2:DeleteTags", "*", "EC2 resources"
    )


def can_put_s3_bucket_tagging(
    source: Any, inventory: Inventory
) -> Tuple[bool, str, Dict[str, Any]]:
    return _check_simple_action(
        source, inventory, "s3:PutBucketTagging", "*", "S3 buckets"
    )


def can_delete_s3_bucket_tagging(
    source: Any, inventory: Inventory
) -> Tuple[bool, str, Dict[str, Any]]:
    return _check_simple_action(
        source, inventory, "s3:DeleteBucketTagging", "*", "S3 buckets"
    )


_STRICTLY_EVALUATABLE_KEY_FAMILIES: FrozenSet[str] = frozenset({
    "aws:principaltag",
    "aws:resourcetag",
})

_MAY_ALLOW_KEY_FAMILIES: FrozenSet[str] = frozenset({
    "aws:requesttag",
    "aws:tagkeys",
})


def _build_principal_tag_context(source: Any) -> Dict[str, str]:
    return dict(getattr(source, "tags", {}) or {})


def _resolve_target_tags(
    inventory: Inventory, target_arn: Optional[str]
) -> Optional[Dict[str, str]]:
    if not target_arn:
        return None
    for u in inventory.users.values():
        if getattr(u, "arn", "") == target_arn:
            return dict(getattr(u, "tags", {}) or {})
    for r in inventory.roles.values():
        if getattr(r, "arn", "") == target_arn:
            return dict(getattr(r, "tags", {}) or {})
    for g in inventory.groups.values():
        if getattr(g, "arn", "") == target_arn:
            return dict(getattr(g, "tags", {}) or {})
    return None


def _evaluate_statement_conditions(
    stmt: Dict[str, Any],
    source: Any,
    inventory: Inventory,
    target_arn: Optional[str] = None,
) -> Tuple[bool, str, List[TagCondition]]:
    conditions = stmt.get("Condition") or {}
    if not isinstance(conditions, dict) or not conditions:
        return True, "", []

    parsed = _extract_all_tag_conditions(conditions)
    if not parsed:
        return True, "non-tag conditions present; may-allow", []

    source_tags = _build_principal_tag_context(source)
    target_tags = _resolve_target_tags(inventory, target_arn)

    failures: List[str] = []
    for tc in parsed:
        if tc.key_family in _MAY_ALLOW_KEY_FAMILIES:
            continue

        if tc.key_family == "aws:principaltag":
            actual = source_tags.get(tc.tag_key) if tc.tag_key else None
        elif tc.key_family == "aws:resourcetag":
            if target_tags is None:
                continue
            actual = target_tags.get(tc.tag_key) if tc.tag_key else None
        else:
            continue

        ok = False
        if tc.operator_base in {
            "stringequals", "stringequalsignorecase", "stringlike",
            "stringnotequals", "stringnotequalsignorecase", "stringnotlike",
        }:
            ok = _evaluate_string_operator(
                tc.operator_base, tc.expected, actual,
                is_if_exists=tc.is_if_exists, is_negated=tc.is_negated,
            )
        elif tc.operator_base in {"arnequals", "arnlike", "arnnotequals", "arnnotlike"}:
            ok = _evaluate_arn_operator(
                tc.operator_base, tc.expected, actual,
                is_if_exists=tc.is_if_exists, is_negated=tc.is_negated,
            )
        elif tc.operator_base == "bool":
            ok = _evaluate_bool_operator(tc.expected, _coerce_bool(actual))
        else:
            ok = True

        if not ok:
            failures.append(
                f"{tc.raw_condition_key} {tc.operator}={tc.expected!r} "
                f"vs actual={actual!r}"
            )

    if failures:
        return False, "; ".join(failures), parsed
    return True, "", parsed


def _coerce_bool(value: Optional[str]) -> Optional[bool]:
    if value is None:
        return None
    s = str(value).lower()
    if s in {"true", "1"}:
        return True
    if s in {"false", "0"}:
        return False
    return None


def _find_allowing_statement(
    principal: Any,
    inventory: Inventory,
    action: str,
    resource: str,
) -> Optional[Dict[str, Any]]:
    action_lower = action.lower()
    for doc in _get_all_policy_documents(principal, inventory):
        for stmt in policy_statements(doc):
            if stmt.get("Effect", "").lower() != "allow":
                continue
            actions = _ensure_list(stmt.get("Action", []))
            resources = _ensure_list(stmt.get("Resource", []))
            action_match = any(
                _action_glob_match(a, action_lower) for a in actions
            )
            resource_match = any(
                r == "*" or r.lower() == resource.lower() for r in resources
            )
            if action_match and resource_match:
                return stmt
    return None


def statement_is_abac_conditioned(stmt: Dict[str, Any]) -> bool:
    conditions = stmt.get("Condition") or {}
    if not isinstance(conditions, dict):
        return False
    return len(_extract_all_tag_conditions(conditions)) > 0


def analyse_boundary_tag_constraint(
    principal: Any,
    inventory: Inventory,
    action: str,
) -> BoundaryTagAnalysis:
    action_lower = action.lower()
    boundary_doc = _load_permission_boundary_document(principal, inventory)
    if boundary_doc is None:
        return BoundaryTagAnalysis(
            action=action,
            boundary_attached=False,
            action_allowed_by_boundary=False,
            has_tag_constraint=False,
            constraining_keys=(),
            matching_statement_count=0,
            bypass_candidate=False,
        )

    matching_stmts: List[Dict[str, Any]] = []
    for stmt in policy_statements(boundary_doc):
        if stmt.get("Effect", "").lower() != "allow":
            continue
        actions = _ensure_list(stmt.get("Action", []))
        if not any(_action_glob_match(a, action_lower) for a in actions):
            continue
        matching_stmts.append(stmt)

    if not matching_stmts:
        return BoundaryTagAnalysis(
            action=action,
            boundary_attached=True,
            action_allowed_by_boundary=False,
            has_tag_constraint=False,
            constraining_keys=(),
            matching_statement_count=0,
            bypass_candidate=False,
        )

    all_keys: List[str] = []
    every_allowing_stmt_constrained = True
    for stmt in matching_stmts:
        constrained, keys = _statement_has_tag_request_constraint(stmt)
        if not constrained:
            every_allowing_stmt_constrained = False
        all_keys.extend(keys)

    has_constraint = every_allowing_stmt_constrained
    constraining_keys = tuple(sorted(set(all_keys)))
    bypass_candidate = not has_constraint

    return BoundaryTagAnalysis(
        action=action,
        boundary_attached=True,
        action_allowed_by_boundary=True,
        has_tag_constraint=has_constraint,
        constraining_keys=constraining_keys,
        matching_statement_count=len(matching_stmts),
        bypass_candidate=bypass_candidate,
    )