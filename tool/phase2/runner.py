from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Dict, List, Optional

project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from shared.aws.provider.aws_provider import AwsProvider
from shared.core.storage.inventory import Inventory
from shared.aws.collectors.organizations.scp_collector import SCPCollector

from phase2.graph.graph_builder import GraphBuilder
from phase2.analysis.path_engine import PathEngine
from phase2.analysis.scp_filter import apply_scp_filter
from phase2.reporting.phase2_reporter import Phase2JSONReporter, Phase2CSVReporter
from phase2.models.graph_models import IAMGraph, AttackPath

logger = logging.getLogger(__name__)


def run_phase2_from_inventory(
    provider: AwsProvider,
    inventory: Inventory,
    max_hops: int = 5,
    output_dir: Optional[Path] = None,
    enable_scp_filter: bool = True,
) -> Dict[str, object]:
    account_id = provider.identity.account_id
    logger.info("Reusing existing inventory for account: %s", account_id)

    user_count = len(inventory.users)
    role_count = len(inventory.roles)
    group_count = len(inventory.groups)
    policy_count = len(inventory.policies)

    logger.info(
        "Existing inventory: %d users, %d roles, %d groups, %d policies",
        user_count, role_count, group_count, policy_count,
    )

    logger.info("Building privilege graph...")
    builder = GraphBuilder(inventory, account_id)
    graph: IAMGraph = builder.build()

    gstats = graph.stats()
    logger.info(
        "Graph: %d nodes, %d admin nodes, %d edges",
        gstats["total_nodes"], gstats["admin_nodes"], gstats["total_edges"],
    )

    logger.info("Running privilege escalation path analysis...")
    engine = PathEngine(graph, max_hops=max_hops)
    paths: List[AttackPath] = engine.find_attack_paths()

    scp_blocked_paths: List[AttackPath] = []
    if enable_scp_filter:
        logger.info("Collecting effective SCPs from AWS Organizations...")
        scp_collector = SCPCollector(provider.get_session())
        scp_documents = scp_collector.collect_effective_scps(account_id)
        if scp_documents:
            logger.info("Applying SCP filter (%d SCP(s) found)...", len(scp_documents))
            paths, scp_blocked_paths = apply_scp_filter(paths, scp_documents)
            logger.info(
                "SCP filter: %d path(s) blocked by SCPs (marked as latent risk, not removed)",
                len(scp_blocked_paths),
            )
        else:
            logger.info("No SCPs collected — SCP filter skipped (not in org or insufficient permissions).")
        paths = paths + scp_blocked_paths

    pstats = engine.summary_stats(paths)

    logger.info(
        "Found %d escalation paths (%d CRITICAL, %d HIGH)",
        pstats["total_paths"], pstats["critical_paths"], pstats["high_paths"],
    )
    logger.info(
        "Risky principals: %d, Single-hop paths: %d",
        pstats["unique_risky_principals"], pstats["single_hop_paths"],
    )

    if output_dir is None:
        output_dir = Path(__file__).parent / "outputs"
    output_dir.mkdir(parents=True, exist_ok=True)

    json_path = output_dir / "phase2_attack_paths.json"
    csv_path = output_dir / "phase2_attack_paths.csv"

    json_reporter = Phase2JSONReporter(output_path=json_path)
    csv_reporter = Phase2CSVReporter(output_path=csv_path)

    json_reporter.report(graph, paths, stats=pstats)
    csv_reporter.report(paths)

    scp_blocked_count = sum(1 for p in paths if p.scp_blocked)
    logger.info(
        "Phase 2 complete: total=%d critical=%d high=%d risky=%d admins=%d scp_blocked=%d json=%s csv=%s",
        pstats["total_paths"],
        pstats["critical_paths"],
        pstats["high_paths"],
        pstats["unique_risky_principals"],
        pstats["unique_admin_destinations"],
        scp_blocked_count,
        json_path,
        csv_path,
    )

    return {
        "graph": graph,
        "paths": paths,
        "graph_stats": gstats,
        "path_stats": pstats,
        "json_path": json_path,
        "csv_path": csv_path,
    }


if __name__ == "__main__":
    raise SystemExit(
        "phase2/runner.py no longer collects inventory by itself. "
        "Call run_phase2_from_inventory(provider, inventory) from the same process that created the Phase 1 inventory."
    )