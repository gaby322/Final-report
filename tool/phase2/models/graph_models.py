from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple


class NodeType(str, Enum):
    USER = "iam_user"
    ROLE = "iam_role"
    GROUP = "iam_group"


class EdgeType(str, Enum):
    ASSUME_ROLE = "sts:AssumeRole"
    CREATE_POLICY_VERSION = "iam:CreatePolicyVersion"
    ATTACH_ROLE_POLICY = "iam:AttachRolePolicy"
    PUT_ROLE_POLICY = "iam:PutRolePolicy"
    UPDATE_ASSUME_ROLE_POLICY = "iam:UpdateAssumeRolePolicy"
    ATTACH_USER_POLICY = "iam:AttachUserPolicy"
    PUT_USER_POLICY = "iam:PutUserPolicy"
    CREATE_ACCESS_KEY = "iam:CreateAccessKey"
    PASS_ROLE_EC2 = "iam:PassRole_via_EC2"
    PASS_ROLE_LAMBDA = "iam:PassRole_via_Lambda"
    ABAC_TAG_CONDITIONED = "abac:tag_conditioned_assume"
    MEMBER_OF = "iam:MemberOf"
    ATTACH_GROUP_POLICY = "iam:AttachGroupPolicy"
    PUT_GROUP_POLICY = "iam:PutGroupPolicy"
    ADD_USER_TO_GROUP = "iam:AddUserToGroup"
    PASS_ROLE_GLUE = "iam:PassRole_via_Glue"
    PASS_ROLE_CLOUDFORMATION = "iam:PassRole_via_CloudFormation"
    PASS_ROLE_SAGEMAKER = "iam:PassRole_via_SageMaker"
    PASS_ROLE_DATAPIPELINE = "iam:PassRole_via_DataPipeline"
    SET_DEFAULT_POLICY_VERSION = "iam:SetDefaultPolicyVersion"
    CREATE_LOGIN_PROFILE = "iam:CreateLoginProfile"
    UPDATE_LOGIN_PROFILE = "iam:UpdateLoginProfile"
    TAG_USER = "iam:TagUser"
    TAG_ROLE = "iam:TagRole"
    UNTAG_USER = "iam:UntagUser"
    UNTAG_ROLE = "iam:UntagRole"
    TAG_POLICY = "iam:TagPolicy"
    UNTAG_POLICY = "iam:UntagPolicy"
    PASS_ROLE_APPRUNNER = "iam:PassRole_via_AppRunner"
    PASS_ROLE_BEDROCK_AGENTCORE = "iam:PassRole_via_BedrockAgentCore"
    PASS_ROLE_CODEBUILD = "iam:PassRole_via_CodeBuild"
    PASS_ROLE_ECS = "iam:PassRole_via_ECS"
    PASS_ROLE_GLUE_JOB = "iam:PassRole_via_Glue_Job"
    PASS_ROLE_LAMBDA_VARIANT = "iam:PassRole_via_Lambda_Variant"
    PASS_ROLE_SAGEMAKER_JOB = "iam:PassRole_via_SageMaker_Job"
    PASS_ROLE_CLOUDFORMATION_STACKSETS = "iam:PassRole_via_CloudFormation_StackSets"
    PASS_ROLE_EC2_SPOT = "iam:PassRole_via_EC2_Spot"


ACTIVE_EDGE_TYPES = frozenset({
    EdgeType.ASSUME_ROLE,
    EdgeType.CREATE_POLICY_VERSION,
    EdgeType.ATTACH_ROLE_POLICY,
    EdgeType.PUT_ROLE_POLICY,
    EdgeType.UPDATE_ASSUME_ROLE_POLICY,
    EdgeType.ATTACH_USER_POLICY,
    EdgeType.PUT_USER_POLICY,
    EdgeType.CREATE_ACCESS_KEY,
    EdgeType.PASS_ROLE_EC2,
    EdgeType.PASS_ROLE_LAMBDA,
    EdgeType.ABAC_TAG_CONDITIONED,
    EdgeType.MEMBER_OF,
    EdgeType.ATTACH_GROUP_POLICY,
    EdgeType.PUT_GROUP_POLICY,
    EdgeType.ADD_USER_TO_GROUP,
    EdgeType.PASS_ROLE_GLUE,
    EdgeType.PASS_ROLE_CLOUDFORMATION,
    EdgeType.PASS_ROLE_SAGEMAKER,
    EdgeType.PASS_ROLE_DATAPIPELINE,
    EdgeType.SET_DEFAULT_POLICY_VERSION,
    EdgeType.CREATE_LOGIN_PROFILE,
    EdgeType.UPDATE_LOGIN_PROFILE,
    EdgeType.PASS_ROLE_APPRUNNER,
    EdgeType.PASS_ROLE_BEDROCK_AGENTCORE,
    EdgeType.PASS_ROLE_CODEBUILD,
    EdgeType.PASS_ROLE_ECS,
    EdgeType.PASS_ROLE_GLUE_JOB,
    EdgeType.PASS_ROLE_LAMBDA_VARIANT,
    EdgeType.PASS_ROLE_SAGEMAKER_JOB,
    EdgeType.PASS_ROLE_CLOUDFORMATION_STACKSETS,
    EdgeType.PASS_ROLE_EC2_SPOT,
})

DEFERRED_EDGE_TYPES = frozenset(set(EdgeType) - ACTIVE_EDGE_TYPES)


@dataclass
class Node:
    node_id: str
    node_type: NodeType
    name: str
    is_admin: bool = False
    tags: Dict[str, str] = field(default_factory=dict)
    has_star_star: bool = False
    can_self_escalate: bool = False
    self_escalation_edges: List[Tuple[EdgeType, Dict[str, Any]]] = field(
        default_factory=list
    )
    permission_boundary_arn: Optional[str] = None


@dataclass
class Edge:
    source_id: str
    target_id: str
    edge_type: EdgeType
    reason: str
    conditions: Dict[str, Any] = field(default_factory=dict)
    is_abac_conditioned: bool = False
    confidence: str = "HIGH"
    deny_evaluated: bool = True


@dataclass
class AttackPath:
    path_id: str
    start_node_id: str
    end_node_id: str
    steps: List[Edge]
    start_name: str = ""
    end_name: str = ""
    hop_count: int = 0
    risk_level: str = "HIGH"
    summary: str = ""
    scp_evaluated: bool = False
    scp_blocked: bool = False
    scp_block_reason: str = ""

    def __post_init__(self) -> None:
        self.hop_count = len(self.steps)
        if not self.summary:
            self.summary = self._build_summary()

    def _build_summary(self) -> str:
        if not self.steps:
            return f"{self.start_name} is directly an admin"
        if (
            len(self.steps) == 1
            and self.steps[0].source_id == self.steps[0].target_id
            and self.start_node_id == self.end_node_id
        ):
            edge = self.steps[0]
            return f"{self.start_name} self-escalates via {edge.edge_type.value}"
        parts = [self.start_name]
        for edge in self.steps:
            parts.append(f"--[{edge.edge_type.value}]--> {edge.target_id.split('/')[-1]}")
        return " ".join(parts)


@dataclass
class IAMGraph:
    account_id: str
    nodes: Dict[str, Node] = field(default_factory=dict)
    edges: List[Edge] = field(default_factory=list)
    admin_nodes: List[str] = field(default_factory=list)
    state_transition_edges: List[Edge] = field(default_factory=list)

    def add_node(self, node: Node) -> None:
        self.nodes[node.node_id] = node
        if node.is_admin and node.node_id not in self.admin_nodes:
            self.admin_nodes.append(node.node_id)

    def add_edge(self, edge: Edge) -> None:
        for existing in self.edges:
            if (existing.source_id == edge.source_id
                    and existing.target_id == edge.target_id
                    and existing.edge_type == edge.edge_type):
                return
        self.edges.append(edge)

    def add_state_transition_edge(self, edge: Edge) -> None:
        for existing in self.state_transition_edges:
            if (existing.source_id == edge.source_id
                    and existing.target_id == edge.target_id
                    and existing.edge_type == edge.edge_type):
                return
        self.state_transition_edges.append(edge)

    def edges_from(self, node_id: str) -> List[Edge]:
        return [e for e in self.edges if e.source_id == node_id]

    def state_transitions_from(self, node_id: str) -> List[Edge]:
        return [e for e in self.state_transition_edges if e.source_id == node_id]

    def stats(self) -> Dict[str, int]:
        return {
            "total_nodes": len(self.nodes),
            "admin_nodes": len(self.admin_nodes),
            "total_edges": len(self.edges),
            "total_state_transition_edges": len(self.state_transition_edges),
            "user_nodes": sum(1 for n in self.nodes.values() if n.node_type == NodeType.USER),
            "role_nodes": sum(1 for n in self.nodes.values() if n.node_type == NodeType.ROLE),
            "group_nodes": sum(1 for n in self.nodes.values() if n.node_type == NodeType.GROUP),
        }