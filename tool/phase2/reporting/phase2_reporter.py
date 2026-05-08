from __future__ import annotations

import csv
import io
import json
from pathlib import Path
from typing import Dict, List, Optional

from phase2.models.graph_models import AttackPath, IAMGraph


class Phase2JSONReporter:
    def __init__(self, output_path: Optional[Path] = None):
        self.output_path = output_path

    def report(
        self,
        graph: IAMGraph,
        paths: List[AttackPath],
        stats: Optional[Dict] = None,
    ) -> str:
        data = {
            "account_id": graph.account_id,
            "graph_stats": graph.stats(),
            "path_stats": stats or {},
            "admin_nodes": [
                {
                    "arn": nid,
                    "name": graph.nodes[nid].name,
                    "type": graph.nodes[nid].node_type.value,
                    "has_star_star": graph.nodes[nid].has_star_star,
                    "can_self_escalate": graph.nodes[nid].can_self_escalate,
                }
                for nid in graph.admin_nodes
                if nid in graph.nodes
            ],
            "attack_paths": [self._path_to_dict(p, graph) for p in paths],
        }
        json_str = json.dumps(data, indent=2, default=str)
        if self.output_path:
            with self.output_path.open("w", encoding="utf-8") as fh:
                fh.write(json_str)
        return json_str

    @staticmethod
    def _path_to_dict(path: AttackPath, graph: IAMGraph) -> dict:
        steps = []
        for edge in path.steps:
            target_node = graph.nodes.get(edge.target_id)
            steps.append({
                "source_arn": edge.source_id,
                "target_arn": edge.target_id,
                "target_name": target_node.name if target_node else "",
                "edge_type": edge.edge_type.value,
                "reason": edge.reason,
                "conditions": edge.conditions,
                "is_abac_conditioned": edge.is_abac_conditioned,
                "confidence": edge.confidence,
            })
        return {
            "path_id": path.path_id,
            "risk_level": path.risk_level,
            "hop_count": path.hop_count,
            "start_principal": {
                "arn": path.start_node_id,
                "name": path.start_name,
            },
            "end_principal": {
                "arn": path.end_node_id,
                "name": path.end_name,
            },
            "steps": steps,
            "scp_evaluated": path.scp_evaluated,
            "scp_blocked": path.scp_blocked,
            "scp_block_reason": getattr(path, "scp_block_reason", "") or "",
            "summary": path.summary,
        }


class Phase2CSVReporter:
    def __init__(self, output_path: Optional[Path] = None):
        self.output_path = output_path

    def report(self, paths: List[AttackPath]) -> str:
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow([
            "path_id", "risk_level", "hop_count",
            "start_arn", "start_name",
            "end_arn", "end_name",
            "edge_types", "summary",
        ])
        for path in paths:
            edge_types = " -> ".join(e.edge_type.value for e in path.steps)
            writer.writerow([
                path.path_id,
                path.risk_level,
                path.hop_count,
                path.start_node_id,
                path.start_name,
                path.end_node_id,
                path.end_name,
                edge_types,
                path.summary.replace("\n", " "),
            ])
        csv_str = output.getvalue()
        if self.output_path:
            with self.output_path.open("w", newline="", encoding="utf-8") as fh:
                fh.write(csv_str)
        return csv_str