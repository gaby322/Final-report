from __future__ import annotations


from typing import Any, Dict, List, Optional, Tuple

from shared.core.storage.inventory import Inventory
from shared.aws.models import Role, User
from phase1.aws_iam.rules.rbac.rule_utils import (
    _ensure_list,
    policy_statements,
    policy_document_is_administrative,
    has_administrator_access_policy_name,
)
from phase2.models.graph_models import (
    Edge,
    EdgeType,
    IAMGraph,
    Node,
    NodeType,
)
from phase2.graph.edge_conditions import (
    can_assume_role,
    can_assume_role_abac,
    can_attach_role_policy,
    can_attach_user_policy,
    can_create_access_key,
    can_create_policy_version,
    can_pass_role_via_ec2,
    can_pass_role_via_lambda,
    can_put_role_policy,
    can_update_assume_role_policy,
    can_pass_role_via_cloudformation,
    can_pass_role_via_glue,
    can_pass_role_via_sagemaker,
    can_pass_role_via_datapipeline,
    can_set_default_policy_version,
    can_create_login_profile,
    can_update_login_profile,
    can_attach_group_policy,
    can_put_group_policy,
    can_add_user_to_group,
    can_pass_role_via_apprunner,
    can_pass_role_via_bedrock_agentcore,
    can_pass_role_via_codebuild,
    can_pass_role_via_ecs,
    can_pass_role_via_glue_job,
    can_pass_role_via_lambda_variant,
    can_pass_role_via_sagemaker_job,
    can_pass_role_via_cloudformation_stacksets,
    can_pass_role_via_ec2_spot,
    can_tag_user_target,
    can_tag_role_target,
    can_untag_user_target,
    can_untag_role_target,
    can_tag_policy_target,
    can_untag_policy_target,
    _principal_is_explicitly_denied,
)


class GraphBuilder:
    def __init__(self, inventory: Inventory, account_id: str):
        self.inventory = inventory
        self.account_id = account_id

    def build(self) -> IAMGraph:
        graph = IAMGraph(account_id=self.account_id)
        self._build_nodes(graph)
        self._build_edges(graph)
        self._build_tag_mutation_edges(graph)
        return graph


    def _build_nodes(self, graph: IAMGraph) -> None:
        for user in self.inventory.users.values():
            is_admin, has_ss, self_esc, self_esc_edges = self._check_admin(user)
            node = Node(
                node_id=user.arn,
                node_type=NodeType.USER,
                name=user.user_name,
                is_admin=is_admin,
                tags=user.tags or {},
                has_star_star=has_ss,
                can_self_escalate=self_esc,
                self_escalation_edges=self_esc_edges,
                permission_boundary_arn=self._extract_boundary_arn(user),
            )
            graph.add_node(node)

        for role in self.inventory.roles.values():
            is_admin, has_ss, self_esc, self_esc_edges = self._check_admin(role)
            node = Node(
                node_id=role.arn,
                node_type=NodeType.ROLE,
                name=role.role_name,
                is_admin=is_admin,
                tags=role.tags or {},
                has_star_star=has_ss,
                can_self_escalate=self_esc,
                self_escalation_edges=self_esc_edges,
                permission_boundary_arn=self._extract_boundary_arn(role),
            )
            graph.add_node(node)

        for group in self.inventory.groups.values():
            group_is_admin, group_has_ss = self._group_is_admin(group)
            node = Node(
                node_id=group.arn,
                node_type=NodeType.GROUP,
                name=group.group_name,
                is_admin=group_is_admin,
                tags=getattr(group, "tags", {}) or {},
                has_star_star=group_has_ss,
                can_self_escalate=False,
                self_escalation_edges=[],
                permission_boundary_arn=None,
            )
            graph.add_node(node)

    @staticmethod
    def _extract_boundary_arn(principal: Any) -> Optional[str]:
        boundary = getattr(principal, "permissions_boundary", None) or getattr(
            principal, "permission_boundary", None
        )
        if not boundary:
            return None
        if isinstance(boundary, str):
            return boundary
        return (
            getattr(boundary, "arn", None)
            or getattr(boundary, "permissions_boundary_arn", None)
            or (boundary.get("PermissionsBoundaryArn") if isinstance(boundary, dict) else None)
        )

    def _group_is_admin(self, group: Any) -> Tuple[bool, bool]:
        for p in getattr(group, "attached_policies", []):
            if has_administrator_access_policy_name(p):
                return True, True
            doc = getattr(p, "document", None)
            if not doc:
                arn = getattr(p, "arn", "")
                if arn and arn in self.inventory.policies:
                    doc = getattr(self.inventory.policies[arn], "document", {}) or {}
            if doc and policy_document_is_administrative(doc):
                return True, True
        for p in getattr(group, "inline_policies", []):
            if policy_document_is_administrative(getattr(p, "document", {}) or {}):
                return True, True
        return False, False

    def _check_admin(self, principal: Any) -> tuple:
        has_star_star = False
        self_escalation_edges: List[Tuple[EdgeType, Dict[str, Any]]] = []

        for doc in self._get_all_documents(principal):
            if policy_document_is_administrative(doc):
                has_star_star = True
                break

        if not has_star_star:
            for p in getattr(principal, "attached_policies", []):
                if has_administrator_access_policy_name(p):
                    has_star_star = True
                    break

        if not has_star_star:
            self_escalation_edges = self._self_escalation_edges(principal)

        can_self_escalate = bool(self_escalation_edges)
        is_admin = has_star_star or can_self_escalate
        return is_admin, has_star_star, can_self_escalate, self_escalation_edges

    def _self_escalation_edges(
        self, principal: Any
    ) -> List[Tuple[EdgeType, Dict[str, Any]]]:
        arn = getattr(principal, "arn", "")
        if isinstance(principal, User):
            action_to_edge = {
                "iam:attachuserpolicy": EdgeType.ATTACH_USER_POLICY,
                "iam:putuserpolicy": EdgeType.PUT_USER_POLICY,
            }
        elif isinstance(principal, Role):
            action_to_edge = {
                "iam:attachrolepolicy": EdgeType.ATTACH_ROLE_POLICY,
                "iam:putrolepolicy": EdgeType.PUT_ROLE_POLICY,
            }
        else:
            action_to_edge = {}

        found: Dict[EdgeType, Dict[str, Any]] = {}

        def _record(edge: EdgeType, conditions: Dict[str, Any]) -> None:
            existing = found.get(edge)
            if existing is None:
                found[edge] = dict(conditions) if conditions else {}
                return
            if not existing:
                return
            if not conditions:
                found[edge] = {}

        for doc in self._get_all_documents(principal):
            for stmt in policy_statements(doc):
                if stmt.get("Effect", "").lower() != "allow":
                    continue
                stmt_conditions = stmt.get("Condition", {}) or {}
                actions = _ensure_list(stmt.get("Action", []))
                resources = _ensure_list(stmt.get("Resource", []))
                for action in actions:
                    if not isinstance(action, str):
                        continue
                    action_l = action.lower()
                    for matched_action, edge_type in action_to_edge.items():
                        if action_l == matched_action or action_l in {"iam:*", "*"}:
                            for r in resources:
                                if r == "*" or r == arn:
                                    _record(edge_type, stmt_conditions)
                                    break
                    if action_l in {"iam:createpolicyversion", "iam:*", "*"}:
                        for p in getattr(principal, "attached_policies", []):
                            arn_p = getattr(p, "arn", "")
                            if not arn_p or f"::{self.account_id}:policy/" not in arn_p:
                                continue
                            for r in resources:
                                if r == "*" or r == arn_p:
                                    _record(EdgeType.CREATE_POLICY_VERSION, stmt_conditions)
                                    break

                    if action_l in {"iam:setdefaultpolicyversion", "iam:*", "*"}:
                        for p in getattr(principal, "attached_policies", []):
                            arn_p = getattr(p, "arn", "")
                            if not arn_p or f"::{self.account_id}:policy/" not in arn_p:
                                continue
                            for r in resources:
                                if r == "*" or r == arn_p:
                                    _record(EdgeType.SET_DEFAULT_POLICY_VERSION, stmt_conditions)
                                    break

                    if isinstance(principal, User):
                        member_groups = getattr(principal, "groups", []) or []
                        if action_l in {"iam:attachgrouppolicy", "iam:*", "*"}:
                            for g_name in member_groups:
                                group = self.inventory.groups.get(g_name)
                                if not group:
                                    continue
                                g_arn = getattr(group, "arn", "")
                                for r in resources:
                                    if r == "*" or r == g_arn:
                                        _record(EdgeType.ATTACH_GROUP_POLICY, stmt_conditions)
                                        break
                        if action_l in {"iam:putgrouppolicy", "iam:*", "*"}:
                            for g_name in member_groups:
                                group = self.inventory.groups.get(g_name)
                                if not group:
                                    continue
                                g_arn = getattr(group, "arn", "")
                                for r in resources:
                                    if r == "*" or r == g_arn:
                                        _record(EdgeType.PUT_GROUP_POLICY, stmt_conditions)
                                        break
                        if action_l in {"iam:addusertogroup", "iam:*", "*"}:
                            for g_name, group in self.inventory.groups.items():
                                g_is_admin, _ = self._group_is_admin(group)
                                if not g_is_admin:
                                    continue
                                g_arn = getattr(group, "arn", "")
                                for r in resources:
                                    if r == "*" or r == g_arn:
                                        _record(EdgeType.ADD_USER_TO_GROUP, stmt_conditions)
                                        break

        filtered: List[Tuple[EdgeType, Dict[str, Any]]] = []
        for edge_type, conditions in found.items():
            denied_self, _ = _principal_is_explicitly_denied(
                principal, self.inventory, edge_type.value, arn
            )
            if denied_self:
                continue
            denied_wildcard, _ = _principal_is_explicitly_denied(
                principal, self.inventory, edge_type.value, "*"
            )
            if denied_wildcard:
                continue
            filtered.append((edge_type, conditions))
        return filtered

    def _get_all_documents(self, principal: Any) -> list:
        docs = []
        for p in getattr(principal, "attached_policies", []):
            doc = getattr(p, "document", None)
            if not doc:
                arn = getattr(p, "arn", "")
                if arn and arn in self.inventory.policies:
                    doc = getattr(self.inventory.policies[arn], "document", {}) or {}
            if doc:
                docs.append(doc)

        for p in getattr(principal, "inline_policies", []):
            doc = getattr(p, "document", {}) or {}
            if doc:
                docs.append(doc)

        if isinstance(principal, User):
            for group_name in getattr(principal, "groups", []):
                group = self.inventory.groups.get(group_name)
                if not group:
                    continue
                for p in getattr(group, "attached_policies", []):
                    doc = getattr(p, "document", None)
                    if not doc:
                        arn = getattr(p, "arn", "")
                        if arn and arn in self.inventory.policies:
                            doc = getattr(self.inventory.policies[arn], "document", {}) or {}
                    if doc:
                        docs.append(doc)
                for p in getattr(group, "inline_policies", []):
                    doc = getattr(p, "document", {}) or {}
                    if doc:
                        docs.append(doc)

        return docs


    def _build_edges(self, graph: IAMGraph) -> None:
        all_users = list(self.inventory.users.values())
        all_roles = list(self.inventory.roles.values())
        all_groups = list(self.inventory.groups.values())
        all_principals: List[Any] = all_users + all_roles

        for user in all_users:
            for group_name in getattr(user, "groups", []) or []:
                group = self.inventory.groups.get(group_name)
                if not group:
                    continue
                graph.add_edge(Edge(
                    source_id=user.arn,
                    target_id=group.arn,
                    edge_type=EdgeType.MEMBER_OF,
                    reason=f"{user.user_name} is a member of group {group_name}",
                    conditions={},
                    is_abac_conditioned=False,
                ))

        for source in all_principals:
            source_node = graph.nodes.get(getattr(source, "arn", ""))
            if not source_node:
                continue
            if source_node.is_admin:
                continue

            for target_role in all_roles:
                if target_role.arn == getattr(source, "arn", ""):
                    continue

                self._try_edge(
                    graph, source, target_role,
                    EdgeType.ASSUME_ROLE,
                    can_assume_role(source, target_role, self.inventory, self.account_id),
                )
                self._try_edge(
                    graph, source, target_role,
                    EdgeType.PASS_ROLE_EC2,
                    can_pass_role_via_ec2(source, target_role, self.inventory),
                )
                self._try_edge(
                    graph, source, target_role,
                    EdgeType.PASS_ROLE_LAMBDA,
                    can_pass_role_via_lambda(source, target_role, self.inventory),
                )
                self._try_edge(
                    graph, source, target_role,
                    EdgeType.PASS_ROLE_CLOUDFORMATION,
                    can_pass_role_via_cloudformation(source, target_role, self.inventory),
                )
                self._try_edge(
                    graph, source, target_role,
                    EdgeType.PASS_ROLE_GLUE,
                    can_pass_role_via_glue(source, target_role, self.inventory),
                )
                self._try_edge(
                    graph, source, target_role,
                    EdgeType.PASS_ROLE_SAGEMAKER,
                    can_pass_role_via_sagemaker(source, target_role, self.inventory),
                )
                self._try_edge(
                    graph, source, target_role,
                    EdgeType.PASS_ROLE_DATAPIPELINE,
                    can_pass_role_via_datapipeline(source, target_role, self.inventory),
                )
                self._try_edge(
                    graph, source, target_role,
                    EdgeType.CREATE_POLICY_VERSION,
                    can_create_policy_version(source, target_role, self.inventory, self.account_id),
                )
                self._try_edge(
                    graph, source, target_role,
                    EdgeType.ATTACH_ROLE_POLICY,
                    can_attach_role_policy(source, target_role, self.inventory),
                )
                self._try_edge(
                    graph, source, target_role,
                    EdgeType.PUT_ROLE_POLICY,
                    can_put_role_policy(source, target_role, self.inventory),
                )
                self._try_edge(
                    graph, source, target_role,
                    EdgeType.UPDATE_ASSUME_ROLE_POLICY,
                    can_update_assume_role_policy(source, target_role, self.inventory),
                )
                self._try_edge(
                    graph, source, target_role,
                    EdgeType.SET_DEFAULT_POLICY_VERSION,
                    can_set_default_policy_version(source, target_role, self.inventory, self.account_id),
                )
                self._try_edge(
                    graph, source, target_role,
                    EdgeType.ABAC_TAG_CONDITIONED,
                    can_assume_role_abac(source, target_role, self.inventory, self.account_id),
                )
                self._try_edge(
                    graph, source, target_role,
                    EdgeType.PASS_ROLE_APPRUNNER,
                    can_pass_role_via_apprunner(source, target_role, self.inventory),
                )
                self._try_edge(
                    graph, source, target_role,
                    EdgeType.PASS_ROLE_BEDROCK_AGENTCORE,
                    can_pass_role_via_bedrock_agentcore(source, target_role, self.inventory),
                )
                self._try_edge(
                    graph, source, target_role,
                    EdgeType.PASS_ROLE_CODEBUILD,
                    can_pass_role_via_codebuild(source, target_role, self.inventory),
                )
                self._try_edge(
                    graph, source, target_role,
                    EdgeType.PASS_ROLE_ECS,
                    can_pass_role_via_ecs(source, target_role, self.inventory),
                )
                self._try_edge(
                    graph, source, target_role,
                    EdgeType.PASS_ROLE_GLUE_JOB,
                    can_pass_role_via_glue_job(source, target_role, self.inventory),
                )
                self._try_edge(
                    graph, source, target_role,
                    EdgeType.PASS_ROLE_LAMBDA_VARIANT,
                    can_pass_role_via_lambda_variant(source, target_role, self.inventory),
                )
                self._try_edge(
                    graph, source, target_role,
                    EdgeType.PASS_ROLE_SAGEMAKER_JOB,
                    can_pass_role_via_sagemaker_job(source, target_role, self.inventory),
                )
                self._try_edge(
                    graph, source, target_role,
                    EdgeType.PASS_ROLE_CLOUDFORMATION_STACKSETS,
                    can_pass_role_via_cloudformation_stacksets(source, target_role, self.inventory),
                )
                self._try_edge(
                    graph, source, target_role,
                    EdgeType.PASS_ROLE_EC2_SPOT,
                    can_pass_role_via_ec2_spot(source, target_role, self.inventory),
                )

            for target_user in all_users:
                if target_user.arn == getattr(source, "arn", ""):
                    continue

                target_node = graph.nodes.get(target_user.arn)
                if not target_node:
                    continue

                self._try_edge(
                    graph, source, target_user,
                    EdgeType.ATTACH_USER_POLICY,
                    can_attach_user_policy(source, target_user, self.inventory),
                )
                self._try_edge(
                    graph, source, target_user,
                    EdgeType.CREATE_ACCESS_KEY,
                    can_create_access_key(source, target_user, self.inventory),
                )
                self._try_edge(
                    graph, source, target_user,
                    EdgeType.CREATE_LOGIN_PROFILE,
                    can_create_login_profile(source, target_user, self.inventory),
                )
                self._try_edge(
                    graph, source, target_user,
                    EdgeType.UPDATE_LOGIN_PROFILE,
                    can_update_login_profile(source, target_user, self.inventory),
                )

            for target_group in all_groups:
                target_node = graph.nodes.get(target_group.arn)
                if not target_node or not target_node.is_admin:
                    continue
                self._try_edge(
                    graph, source, target_group,
                    EdgeType.ATTACH_GROUP_POLICY,
                    can_attach_group_policy(source, target_group, self.inventory),
                )
                self._try_edge(
                    graph, source, target_group,
                    EdgeType.PUT_GROUP_POLICY,
                    can_put_group_policy(source, target_group, self.inventory),
                )
                if isinstance(source, User):
                    self._try_edge(
                        graph, source, target_group,
                        EdgeType.ADD_USER_TO_GROUP,
                        can_add_user_to_group(source, target_group, self.inventory),
                    )

    def _try_edge(
        self,
        graph: IAMGraph,
        source: Any,
        target: Any,
        edge_type: EdgeType,
        result: tuple,
    ) -> None:
        can, reason, conditions = result
        if not can:
            return
        edge = Edge(
            source_id=getattr(source, "arn", ""),
            target_id=getattr(target, "arn", ""),
            edge_type=edge_type,
            reason=reason,
            conditions=conditions,
            is_abac_conditioned=bool(conditions),
        )
        graph.add_edge(edge)

    def _try_state_transition_edge(
        self,
        graph: IAMGraph,
        source: Any,
        target: Any,
        edge_type: EdgeType,
        result: tuple,
    ) -> None:
        can, reason, conditions = result
        if not can:
            return
        edge = Edge(
            source_id=getattr(source, "arn", ""),
            target_id=getattr(target, "arn", ""),
            edge_type=edge_type,
            reason=reason,
            conditions=conditions,
            is_abac_conditioned=bool(conditions),
        )
        graph.add_state_transition_edge(edge)

    def _build_tag_mutation_edges(self, graph: IAMGraph) -> None:
        all_users = list(self.inventory.users.values())
        all_roles = list(self.inventory.roles.values())
        all_principals: List[Any] = all_users + all_roles

        from phase2.graph.edge_conditions import _principal_allows_action

        for source in all_principals:
            source_arn = getattr(source, "arn", "")
            source_node = graph.nodes.get(source_arn)
            if not source_node:
                continue
            if source_node.is_admin:
                continue

            has_tag_user = _principal_allows_action(
                source, self.inventory, "iam:TagUser"
            )
            has_untag_user = _principal_allows_action(
                source, self.inventory, "iam:UntagUser"
            )
            has_tag_role = _principal_allows_action(
                source, self.inventory, "iam:TagRole"
            )
            has_untag_role = _principal_allows_action(
                source, self.inventory, "iam:UntagRole"
            )
            has_tag_policy = _principal_allows_action(
                source, self.inventory, "iam:TagPolicy"
            )
            has_untag_policy = _principal_allows_action(
                source, self.inventory, "iam:UntagPolicy"
            )

            if has_tag_user or has_untag_user:
                for target_user in all_users:
                    if has_tag_user:
                        self._try_state_transition_edge(
                            graph, source, target_user, EdgeType.TAG_USER,
                            can_tag_user_target(source, target_user, self.inventory),
                        )
                    if has_untag_user:
                        self._try_state_transition_edge(
                            graph, source, target_user, EdgeType.UNTAG_USER,
                            can_untag_user_target(source, target_user, self.inventory),
                        )

            if has_tag_role or has_untag_role:
                for target_role in all_roles:
                    if has_tag_role:
                        self._try_state_transition_edge(
                            graph, source, target_role, EdgeType.TAG_ROLE,
                            can_tag_role_target(source, target_role, self.inventory),
                        )
                    if has_untag_role:
                        self._try_state_transition_edge(
                            graph, source, target_role, EdgeType.UNTAG_ROLE,
                            can_untag_role_target(source, target_role, self.inventory),
                        )

            if has_tag_policy or has_untag_policy:
                for policy in self.inventory.policies.values():
                    if has_tag_policy:
                        self._try_state_transition_edge(
                            graph, source, policy, EdgeType.TAG_POLICY,
                            can_tag_policy_target(source, policy, self.inventory),
                        )
                    if has_untag_policy:
                        self._try_state_transition_edge(
                            graph, source, policy, EdgeType.UNTAG_POLICY,
                            can_untag_policy_target(source, policy, self.inventory),
                        )