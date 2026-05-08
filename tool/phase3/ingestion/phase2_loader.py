from __future__ import annotations


import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set


@dataclass
class P2Step:
    source_arn: str
    target_arn: str
    target_name: str
    edge_type: str
    reason: str
    conditions: Dict = field(default_factory=dict)
    is_abac_conditioned: bool = False
    confidence: str = "HIGH"


@dataclass
class P2Path:
    path_id: str
    risk_level: str
    hop_count: int
    start_arn: str
    start_name: str
    end_arn: str
    end_name: str
    steps: List[P2Step] = field(default_factory=list)
    summary: str = ""

    @property
    def edge_types(self) -> List[str]:
        return [s.edge_type for s in self.steps]

    def to_summary(self) -> str:
        edges = " -> ".join(self.edge_types) if self.steps else "direct"
        return (
            f"[{self.risk_level}] path {self.path_id}: "
            f"{self.start_name} -> {self.end_name} via [{edges}]"
        )


@dataclass
class P2AdminNode:
    arn: str
    name: str
    node_type: str
    has_star_star: bool = False
    can_self_escalate: bool = False


class Phase2Loader:
    def __init__(self):
        self.paths: List[P2Path] = []
        self.admin_nodes: List[P2AdminNode] = []
        self.graph_stats: Dict = {}
        self._by_start_arn: Dict[str, List[P2Path]] = {}
        self._by_path_id: Dict[str, P2Path] = {}
        self._admin_arns: Set[str] = set()

    def load(self, path: Path) -> "Phase2Loader":
        if not path.exists():
            return self

        self.paths = []
        self.admin_nodes = []
        self.graph_stats = {}
        self._by_start_arn = {}
        self._by_path_id = {}
        self._admin_arns = set()

        with path.open("r", encoding="utf-8") as fh:
            raw = json.load(fh)

        self.graph_stats = raw.get("graph_stats", {})

        for node_data in raw.get("admin_nodes", []):
            node = P2AdminNode(
                 arn=node_data.get("arn", ""),
                 name=node_data.get("name", ""),
                 node_type=node_data.get("type", ""),
                 has_star_star=node_data.get("has_star_star", False),
                 can_self_escalate=node_data.get("can_self_escalate", False),
            )
            self.admin_nodes.append(node)
            if node.arn:
                 self._admin_arns.add(node.arn)

        for path_data in raw.get("attack_paths", []):
            p2path = self._parse_path(path_data)
            if p2path:
                self.paths.append(p2path)
                self._index(p2path)

        return self

    def _parse_path(self, data: Dict) -> Optional[P2Path]:
        if not isinstance(data, dict):
            return None

        start = data.get("start_principal", {})
        end = data.get("end_principal", {})
        steps = [
            P2Step(
                source_arn=s.get("source_arn", ""),
                target_arn=s.get("target_arn", ""),
                target_name=s.get("target_name", ""),
                edge_type=s.get("edge_type", ""),
                reason=s.get("reason", ""),
                conditions=s.get("conditions", {}),
                is_abac_conditioned=s.get("is_abac_conditioned", False),
                confidence=s.get("confidence", "HIGH"),
            )
            for s in data.get("steps", [])
            if isinstance(s, dict)
        ]

        return P2Path(
            path_id=data.get("path_id", ""),
            risk_level=data.get("risk_level", "HIGH"),
            hop_count=data.get("hop_count", len(steps)),
            start_arn=start.get("arn", ""),
            start_name=start.get("name", ""),
            end_arn=end.get("arn", ""),
            end_name=end.get("name", ""),
            steps=steps,
            summary=data.get("summary", ""),
        )

    def _index(self, path: P2Path) -> None:
        if path.start_arn:
            self._by_start_arn.setdefault(path.start_arn, []).append(path)
        if path.path_id:
            self._by_path_id[path.path_id] = path

    def paths_for_principal(
        self,
        principal_arn: str,
        session_issuer_arn: Optional[str] = None,
    ) -> List[P2Path]:
        results = list(self._by_start_arn.get(principal_arn, []))
        if session_issuer_arn and session_issuer_arn != principal_arn:
            for p in self._by_start_arn.get(session_issuer_arn, []):
                if p not in results:
                    results.append(p)
        return results

    def get_by_path_id(self, path_id: str) -> Optional[P2Path]:
        return self._by_path_id.get(path_id)

    def is_admin_arn(self, arn: str) -> bool:
        return arn in self._admin_arns