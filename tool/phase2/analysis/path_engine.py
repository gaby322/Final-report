from __future__ import annotations


import uuid
from collections import deque
from typing import Any, Dict, List, Optional, Set, Tuple

from phase2.models.graph_models import AttackPath, Edge, EdgeType, IAMGraph, Node, NodeType


class PathEngine:
    def __init__(self, graph: IAMGraph, max_hops: int = 5):
        self.graph = graph
        self.max_hops = max_hops

    def find_attack_paths(self) -> List[AttackPath]:
        paths: List[AttackPath] = []

        non_admin_nodes = [
            node for node in self.graph.nodes.values()
            if not node.is_admin
        ]

        for source_node in non_admin_nodes:
            discovered = self._bfs(source_node)
            paths.extend(discovered)

        for node in self.graph.nodes.values():
            if not node.is_admin:
                continue
            if node.has_star_star:
                continue
            for edge_type, conditions in node.self_escalation_edges:
                paths.append(
                    self._build_self_escalation_path(node, edge_type, conditions)
                )

        for source_node in non_admin_nodes:
            paths.extend(self._compose_principal_access_paths(source_node))

        return paths

    _ROLE_ELEVATION_EDGES = frozenset({
        EdgeType.ATTACH_ROLE_POLICY,
        EdgeType.PUT_ROLE_POLICY,
        EdgeType.CREATE_POLICY_VERSION,
    })
    _ROLE_ACCESS_EDGES = frozenset({
        EdgeType.ASSUME_ROLE,
        EdgeType.UPDATE_ASSUME_ROLE_POLICY,
    })
    _USER_ELEVATION_EDGES = frozenset({
        EdgeType.ATTACH_USER_POLICY,
        EdgeType.PUT_USER_POLICY,
    })
    _USER_ACCESS_EDGES = frozenset({
        EdgeType.CREATE_ACCESS_KEY,
        EdgeType.CREATE_LOGIN_PROFILE,
        EdgeType.UPDATE_LOGIN_PROFILE,
    })

    def _compose_principal_access_paths(self, source: Node) -> List[AttackPath]:
        results: List[AttackPath] = []
        edges_by_target: Dict[str, List[Edge]] = {}
        for edge in self.graph.edges_from(source.node_id):
            edges_by_target.setdefault(edge.target_id, []).append(edge)

        for target_id, target_edges in edges_by_target.items():
            target_node = self.graph.nodes.get(target_id)
            if target_node is None:
                continue
            if target_node.is_admin:
                continue
            if target_id == source.node_id:
                continue

            edge_types = {e.edge_type for e in target_edges}
            elev: Optional[Edge] = None
            access: Optional[Edge] = None

            if target_node.node_type == NodeType.ROLE:
                elev_set = edge_types & self._ROLE_ELEVATION_EDGES
                access_set = edge_types & self._ROLE_ACCESS_EDGES
                if elev_set and access_set:
                    elev = next(
                        e for e in target_edges
                        if e.edge_type in self._ROLE_ELEVATION_EDGES
                    )
                    access = next(
                        e for e in target_edges
                        if e.edge_type in self._ROLE_ACCESS_EDGES
                    )

            elif target_node.node_type == NodeType.USER:
                elev_set = edge_types & self._USER_ELEVATION_EDGES
                access_set = edge_types & self._USER_ACCESS_EDGES
                if elev_set and access_set:
                    elev = next(
                        e for e in target_edges
                        if e.edge_type in self._USER_ELEVATION_EDGES
                    )
                    access = next(
                        e for e in target_edges
                        if e.edge_type in self._USER_ACCESS_EDGES
                    )

            if elev is not None and access is not None:
                results.append(self._build_attack_path(
                    source, target_node, [elev, access]
                ))
        return results

    def find_all_paths(self) -> List[AttackPath]:
        return self.find_attack_paths()

    def _bfs(self, source: Node) -> List[AttackPath]:
        results: List[AttackPath] = []

        queue: deque[Tuple[str, List[Edge]]] = deque()
        queue.append((source.node_id, []))

        visited: Set[str] = {source.node_id}
        seen_admin_destinations: Set[str] = set()

        while queue:
            current_id, path_so_far = queue.popleft()

            if len(path_so_far) >= self.max_hops:
                continue

            for edge in self.graph.edges_from(current_id):
                target_id = edge.target_id

                target_node = self.graph.nodes.get(target_id)
                if target_node is None:
                    continue

                new_path = path_so_far + [edge]

                if target_node.is_admin:
                    if target_id in seen_admin_destinations:
                        continue
                    seen_admin_destinations.add(target_id)
                    attack_path = self._build_attack_path(source, target_node, new_path)
                    results.append(attack_path)
                    continue

                if target_id in visited:
                    continue

                visited.add(target_id)
                queue.append((target_id, new_path))

        return results

    def _build_attack_path(
        self, source: Node, destination: Node, steps: List[Edge]
    ) -> AttackPath:
        hop_count = len(steps)
        risk_level = "CRITICAL" if hop_count == 1 else "HIGH"

        summary_parts = [f"[{source.node_type.value}] {source.name}"]
        for edge in steps:
            target_node = self.graph.nodes.get(edge.target_id)
            target_name = target_node.name if target_node else edge.target_id.split("/")[-1]
            target_type = target_node.node_type.value if target_node else "unknown"
            summary_parts.append(
                f"  --[{edge.edge_type.value}]-->\n  [{target_type}] {target_name}"
            )

        summary = "\n".join(summary_parts)

        return AttackPath(
            path_id=str(uuid.uuid4())[:8],
            start_node_id=source.node_id,
            end_node_id=destination.node_id,
            steps=steps,
            start_name=source.name,
            end_name=destination.name,
            hop_count=hop_count,
            risk_level=risk_level,
            summary=summary,
        )

    def _build_self_escalation_path(
        self,
        node: Node,
        edge_type: EdgeType,
        conditions: Dict[str, Any] | None = None,
    ) -> AttackPath:
        cond: Dict[str, Any] = dict(conditions) if conditions else {}
        is_conditioned = bool(cond)
        edge = Edge(
            source_id=node.node_id,
            target_id=node.node_id,
            edge_type=edge_type,
            reason=(
                f"{node.name} can perform {edge_type.value} targeting itself "
                f"(or a customer-managed policy it controls) — directly "
                f"escalates own permissions without a second principal"
                + (
                    f" [gated by Condition keys: {list(cond.keys())}]"
                    if is_conditioned else ""
                )
            ),
            conditions=cond,
            is_abac_conditioned=is_conditioned,
        )
        return AttackPath(
            path_id=str(uuid.uuid4())[:8],
            start_node_id=node.node_id,
            end_node_id=node.node_id,
            steps=[edge],
            start_name=node.name,
            end_name=node.name,
            hop_count=1,
            risk_level="HIGH" if is_conditioned else "CRITICAL",
        )


    def find_abac_attack_paths(
        self, k: int = 3, max_hops: int | None = None
    ) -> List[AttackPath]:
        results: List[AttackPath] = []
        hop_cap = self.max_hops if max_hops is None else max_hops

        non_admin = [n for n in self.graph.nodes.values() if not n.is_admin]

        for source in non_admin:
            stage1 = self._bfs(source)
            if stage1:
                continue

            mutation_paths = self._abac_two_stage(source, k=k, hop_cap=hop_cap)
            results.extend(mutation_paths)

        return results

    def _abac_two_stage(
        self, source: Node, k: int, hop_cap: int
    ) -> List[AttackPath]:
        results: List[AttackPath] = []
        seen_admin_destinations: Set[str] = set()

        initial_state: frozenset = frozenset(
            getattr(source, "name", "") and {}
        )

        queue: deque[Tuple[str, List[Edge], int, frozenset]] = deque()
        queue.append((source.node_id, [], 0, initial_state))
        visited: Set[Tuple[str, frozenset]] = {(source.node_id, initial_state)}

        while queue:
            current_id, path_so_far, mutations_used, tag_state = queue.popleft()

            if mutations_used < k:
                for st_edge in self.graph.state_transitions_from(current_id):
                    new_state = frozenset(
                        list(tag_state) + [(st_edge.target_id, st_edge.edge_type.value)]
                    )
                    key = (current_id, new_state)
                    if key in visited:
                        continue
                    visited.add(key)
                    extended_paths = self._bfs_with_state(
                        Node(
                            node_id=current_id,
                            node_type=self.graph.nodes[current_id].node_type,
                            name=self.graph.nodes[current_id].name,
                        ),
                        path_prefix=path_so_far + [st_edge],
                        hop_cap=hop_cap,
                        seen_admins=seen_admin_destinations,
                    )
                    for ap in extended_paths:
                        results.append(ap)

            if len(path_so_far) >= hop_cap:
                continue
            for edge in self.graph.edges_from(current_id):
                target_id = edge.target_id
                target_node = self.graph.nodes.get(target_id)
                if target_node is None:
                    continue
                new_path = path_so_far + [edge]
                if target_node.is_admin:
                    if target_id in seen_admin_destinations:
                        continue
                    if mutations_used > 0:
                        seen_admin_destinations.add(target_id)
                        results.append(self._build_attack_path(source, target_node, new_path))
                    continue
                key = (target_id, tag_state)
                if key in visited:
                    continue
                visited.add(key)
                queue.append((target_id, new_path, mutations_used, tag_state))

        return results

    def _bfs_with_state(
        self,
        source: Node,
        path_prefix: List[Edge],
        hop_cap: int,
        seen_admins: Set[str],
    ) -> List[AttackPath]:
        results: List[AttackPath] = []
        queue: deque[Tuple[str, List[Edge]]] = deque()
        queue.append((source.node_id, list(path_prefix)))
        local_visited: Set[str] = {source.node_id}

        while queue:
            current_id, path_so_far = queue.popleft()
            if len(path_so_far) >= hop_cap:
                continue
            for edge in self.graph.edges_from(current_id):
                target_id = edge.target_id
                target_node = self.graph.nodes.get(target_id)
                if target_node is None:
                    continue
                new_path = path_so_far + [edge]
                if target_node.is_admin:
                    if target_id in seen_admins:
                        continue
                    seen_admins.add(target_id)
                    results.append(self._build_attack_path(source, target_node, new_path))
                    continue
                if target_id in local_visited:
                    continue
                local_visited.add(target_id)
                queue.append((target_id, new_path))
        return results

    def find_paths_from(self, principal_arn: str) -> List[AttackPath]:
        source = self.graph.nodes.get(principal_arn)
        if not source:
            return []
        if source.is_admin:
            if not source.has_star_star and source.self_escalation_edges:
                return [
                    self._build_self_escalation_path(source, et, cond)
                    for et, cond in source.self_escalation_edges
                ]
            return []
        return self._bfs(source)

    def find_paths_to_admin(self, admin_arn: str) -> List[AttackPath]:
        all_paths = self.find_attack_paths()
        return [p for p in all_paths if p.end_node_id == admin_arn]

    def get_risky_principals(self) -> List[Node]:
        all_paths = self.find_attack_paths()
        risky_ids = {p.start_node_id for p in all_paths}
        return [self.graph.nodes[nid] for nid in risky_ids if nid in self.graph.nodes]

    def summary_stats(self, paths: List[AttackPath]) -> Dict[str, int]:
        return {
            "total_paths": len(paths),
            "critical_paths": sum(1 for p in paths if p.risk_level == "CRITICAL"),
            "high_paths": sum(1 for p in paths if p.risk_level == "HIGH"),
            "unique_risky_principals": len({p.start_node_id for p in paths}),
            "unique_admin_destinations": len({p.end_node_id for p in paths}),
            "single_hop_paths": sum(1 for p in paths if p.hop_count == 1),
            "multi_hop_paths": sum(1 for p in paths if p.hop_count > 1),
        }