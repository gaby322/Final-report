from __future__ import annotations


import logging
from typing import Dict, List, Optional, Tuple

from phase2.models.graph_models import AttackPath, EdgeType
from phase1.aws_iam.rules.rbac.rule_utils import _ensure_list, policy_statements

logger = logging.getLogger(__name__)

_EDGE_TYPE_TO_ACTIONS: Dict[EdgeType, List[str]] = {
    EdgeType.ASSUME_ROLE:               ["sts:AssumeRole"],
    EdgeType.CREATE_POLICY_VERSION:     ["iam:CreatePolicyVersion"],
    EdgeType.ATTACH_ROLE_POLICY:        ["iam:AttachRolePolicy"],
    EdgeType.PUT_ROLE_POLICY:           ["iam:PutRolePolicy"],
    EdgeType.UPDATE_ASSUME_ROLE_POLICY: ["iam:UpdateAssumeRolePolicy"],
    EdgeType.ATTACH_USER_POLICY:        ["iam:AttachUserPolicy"],
    EdgeType.CREATE_ACCESS_KEY:         ["iam:CreateAccessKey"],
    EdgeType.PASS_ROLE_EC2:             ["iam:PassRole", "ec2:RunInstances"],
    EdgeType.PASS_ROLE_LAMBDA:          ["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"],
    EdgeType.ABAC_TAG_CONDITIONED:      ["sts:AssumeRole"],
    EdgeType.PUT_USER_POLICY:           ["iam:PutUserPolicy"],
    EdgeType.MEMBER_OF:                 [],
    EdgeType.ATTACH_GROUP_POLICY:       ["iam:AttachGroupPolicy"],
    EdgeType.PUT_GROUP_POLICY:          ["iam:PutGroupPolicy"],
    EdgeType.ADD_USER_TO_GROUP:         ["iam:AddUserToGroup"],
    EdgeType.SET_DEFAULT_POLICY_VERSION:["iam:SetDefaultPolicyVersion"],
    EdgeType.CREATE_LOGIN_PROFILE:      ["iam:CreateLoginProfile"],
    EdgeType.UPDATE_LOGIN_PROFILE:      ["iam:UpdateLoginProfile"],
    EdgeType.PASS_ROLE_GLUE:            ["iam:PassRole", "glue:CreateDevEndpoint"],
    EdgeType.PASS_ROLE_CLOUDFORMATION:  ["iam:PassRole", "cloudformation:CreateStack"],
    EdgeType.PASS_ROLE_SAGEMAKER:       ["iam:PassRole", "sagemaker:CreateNotebookInstance"],
    EdgeType.PASS_ROLE_DATAPIPELINE:    [
        "iam:PassRole",
        "datapipeline:CreatePipeline",
        "datapipeline:PutPipelineDefinition",
        "datapipeline:ActivatePipeline",
    ],
    EdgeType.PASS_ROLE_APPRUNNER:       ["iam:PassRole", "apprunner:CreateService"],
    EdgeType.PASS_ROLE_BEDROCK_AGENTCORE: [
        "iam:PassRole",
        "bedrock-agentcore:CreateCodeInterpreter",
        "bedrock-agentcore:StartCodeInterpreterSession",
        "bedrock-agentcore:InvokeCodeInterpreter",
    ],
    EdgeType.PASS_ROLE_EC2_SPOT:        ["iam:PassRole", "ec2:RequestSpotInstances"],
    EdgeType.PASS_ROLE_CODEBUILD:       ["iam:PassRole", "codebuild:CreateProject"],
    EdgeType.PASS_ROLE_ECS:             ["iam:PassRole", "ecs:RegisterTaskDefinition"],
    EdgeType.PASS_ROLE_GLUE_JOB:        ["iam:PassRole"],
    EdgeType.PASS_ROLE_LAMBDA_VARIANT:  ["iam:PassRole", "lambda:CreateFunction"],
    EdgeType.PASS_ROLE_SAGEMAKER_JOB:   ["iam:PassRole"],
    EdgeType.PASS_ROLE_CLOUDFORMATION_STACKSETS: ["iam:PassRole"],
}


def apply_scp_filter(
    paths: List[AttackPath],
    scp_documents: List[Dict],
) -> Tuple[List[AttackPath], List[AttackPath]]:
    if not scp_documents:
        logger.info("[SCPFilter] No SCP documents provided — SCP filter skipped.")
        return paths, []

    active: List[AttackPath] = []
    blocked: List[AttackPath] = []

    for path in paths:
        block_reason = _check_path_against_scps(path, scp_documents)
        path.scp_evaluated = True
        if block_reason:
            path.scp_blocked = True
            path.scp_block_reason = block_reason
            blocked.append(path)
        else:
            path.scp_blocked = False
            active.append(path)

    logger.info(
        "[SCPFilter] %d paths active, %d paths SCP-blocked (latent risk)",
        len(active),
        len(blocked),
    )
    return active, blocked


def _check_path_against_scps(
    path: AttackPath, scp_documents: List[Dict]
) -> Optional[str]:
    for edge in path.steps:
        required_actions = _EDGE_TYPE_TO_ACTIONS.get(edge.edge_type, [])
        for action in required_actions:
            blocked, reason = _scp_denies_action(scp_documents, action)
            if blocked:
                return (
                    f"Edge '{edge.edge_type.value}' requires '{action}' — {reason}"
                )
    return None


def _scp_denies_action(
    scp_documents: List[Dict], action: str
) -> Tuple[bool, str]:
    action_lower = action.lower()

    for doc in scp_documents:
        policy_name = doc.get("_scp_policy_name", "unknown-scp")
        for stmt in policy_statements(doc):
            if stmt.get("Effect", "").lower() != "deny":
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
                        f"SCP '{policy_name}': Deny via NotAction — '{action}' is not in the exclusion list{condition_note}",
                    )
            else:
                actions = _ensure_list(stmt.get("Action", []))
                if any(_action_glob_match(a, action_lower) for a in actions):
                    return (
                        True,
                        f"SCP '{policy_name}': Explicit Deny on '{action}'{condition_note}",
                    )

    return False, ""


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
