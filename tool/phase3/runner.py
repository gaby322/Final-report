from __future__ import annotations


import argparse
import logging
import sys
from pathlib import Path
from typing import Iterable, List, Optional

project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

logger = logging.getLogger(__name__)

from phase3.ingestion.cloudtrail_normalizer import (
    CloudTrailNormalizer,
    expand_operator_identity_arns,
)
from phase3.ingestion.phase1_loader import Phase1Loader
from phase3.ingestion.phase2_loader import Phase2Loader
from phase3.analysis.correlator import CorrelationEngine
from phase3.analysis.query_builder import QueryBuilder
from phase3.rag.retriever import KnowledgeRetriever
from phase3.llm.llm_adapter import LLMAdapter, LLMConfig
from phase3.llm.prompt_builder import PromptBuilder
from phase3.llm.hallucination_guard import HallucinationGuard
from phase3.reporting.alert_builder import AlertBuilder
from phase3.reporting.reporters import Phase3JSONReporter, Phase3CSVReporter


DEFAULT_P1_RBAC = project_root / "phase1" / "outputs" / "phase1_rbac_findings.json"
DEFAULT_P1_ABAC = project_root / "phase1" / "outputs" / "phase1_abac_findings.json"
DEFAULT_P2 = project_root / "phase2" / "outputs" / "phase2_attack_paths.json"
DEFAULT_CT_OUT = project_root / "phase3" / "outputs" / "cloudtrail_events.json"


def collect_cloudtrail(
    profile: Optional[str], lookback_hours: int, output_path: Path
) -> tuple[Path, Optional[str]]:
    from shared.aws.provider.aws_provider import AwsProvider
    from shared.aws.collectors.cloudtrail.cloudtrail_collector import CloudTrailCollector

    logger.info("Collecting CloudTrail events (lookback: %dh)...", lookback_hours)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    provider = AwsProvider(profile=profile if profile else None)
    collector = CloudTrailCollector(
        provider=provider,
        lookback_hours=lookback_hours,
        output_path=output_path,
    )
    collector.collect()
    caller_arn = getattr(provider.identity, "arn", None)
    return output_path, caller_arn


def run_phase3(
    phase1_rbac_path: Path,
    phase1_abac_path: Path,
    phase2_path: Path,
    cloudtrail_path: Path,
    llm_backend: str = "openai_compatible",
    llm_model: str = "llama-3-1-8b-instruct",
    llm_api_base: Optional[str] = "http://localhost:11434/v1",
    llm_api_key: Optional[str] = None,
    output_dir: Optional[Path] = None,
    include_static_only: bool = True,
    exclude_operator_arns: Optional[Iterable[str]] = None,
) -> list:
    required_inputs = {
        "phase1_rbac_path": phase1_rbac_path,
        "phase1_abac_path": phase1_abac_path,
        "phase2_path": phase2_path,
        "cloudtrail_path": cloudtrail_path,
    }

    for label, required_path in required_inputs.items():
        if required_path is None:
            raise ValueError(f"Required input path is missing: {label}")
        if str(required_path).strip() == "":
            raise ValueError(f"Required input path is empty: {label}")
        if not required_path.exists():
            raise FileNotFoundError(f"Required input file not found: {required_path}")


    output_dir = output_dir or (Path(__file__).parent / "outputs")
    output_dir.mkdir(parents=True, exist_ok=True)

    logger.info("Loading Phase 1 findings...")
    p1_loader = Phase1Loader()
    p1_loader.load(phase1_rbac_path, phase1_abac_path)
    logger.info("Phase 1: %d FAIL findings loaded", len(p1_loader.findings))

    logger.info("Loading Phase 2 attack paths...")
    p2_loader = Phase2Loader()
    p2_loader.load(phase2_path)
    logger.info(
        "Phase 2: %d attack paths, %d admin nodes",
        len(p2_loader.paths), len(p2_loader.admin_nodes),
    )

    logger.info("Normalizing CloudTrail events...")
    operator_arns = list(exclude_operator_arns or [])
    if operator_arns:
        logger.info(
            "Excluding operator identity from CloudTrail input: %s",
            ", ".join(operator_arns),
        )
    normalizer = CloudTrailNormalizer(
        iam_only=True,
        exclude_operator_arns=operator_arns,
    )
    events = normalizer.normalize_file(cloudtrail_path)
    logger.info("CloudTrail: %d IAM-relevant events normalized", len(events))

    logger.info("Running deterministic correlation...")
    correlator = CorrelationEngine(p1_loader, p2_loader)
    bundles = correlator.correlate(events)

    covered_principals: set[str] = set()
    for bundle in bundles:
        covered_principals.update(bundle.all_principal_arns)
        for finding in bundle.p1_findings:
            if finding.resource_id:
                covered_principals.add(finding.resource_id)
            if finding.principal_arn:
                covered_principals.add(finding.principal_arn)

    if include_static_only:
        static_bundles = correlator.static_only_bundles(
            exclude_principal_arns=covered_principals
        )
        bundles.extend(static_bundles)
        logger.info(
            "Added %d static-only bundles for uncovered high-severity P1 findings",
            len(static_bundles),
        )

    logger.info("Correlation complete: %d evidence bundles", len(bundles))

    if not bundles:
        logger.info("No evidence bundles generated; proceeding to write empty reports.")

    logger.info("Initializing knowledge retriever...")
    retriever = KnowledgeRetriever(top_k=5)
    query_builder = QueryBuilder()

    llm_config = LLMConfig(
        backend=llm_backend,
        model_name=llm_model,
        api_base=llm_api_base,
        api_key=llm_api_key,
    )
    llm = LLMAdapter(config=llm_config)
    prompt_builder = PromptBuilder()
    guard = HallucinationGuard()
    alert_builder = AlertBuilder()

    alerts: list = []
    total = len(bundles)

    for i, bundle in enumerate(bundles, 1):
        event_name = bundle.event.event_name if getattr(bundle, "event", None) else "STATIC_ONLY"
        logger.debug(
            "Processing bundle %d/%d: %s [%s]",
            i, total, event_name, bundle.correlation_tier,
        )

        query = query_builder.build(bundle)

        chunks = []
        if query and query.strip():
            try:
                chunks = retriever.retrieve(query)
            except Exception:
                logger.exception("Retrieval failed for query %r", query)
                chunks = []

        if not chunks and bundle.p2_edge_types:
            try:
                chunks = retriever.retrieve_for_actions(bundle.p2_edge_types, top_k=3)
            except Exception:
                logger.exception("Action-based retrieval failed")
                chunks = []

        system_p, user_p = prompt_builder.build(bundle, chunks)
        llm_response = llm.call(system_p, user_p)

        grounding_report = guard.validate(
            bundle,
            llm_response.parsed_json,
            backend_used=llm_response.backend_used,
        )

        alert = alert_builder.build(bundle, llm_response, grounding_report, chunks)
        alerts.append(alert)

    logger.info("%d alerts assembled", len(alerts))

    json_path = output_dir / "phase3_alerts.json"
    csv_path = output_dir / "phase3_alerts.csv"

    stats = _compute_stats(alerts)
    json_reporter = Phase3JSONReporter(output_path=json_path)
    csv_reporter = Phase3CSVReporter(output_path=csv_path)
    json_reporter.report(alerts, stats=stats)
    csv_reporter.report(alerts)

    _print_summary(stats, json_path, csv_path)
    return alerts


def _compute_stats(alerts: list) -> dict:
    from collections import Counter
    from phase3.reporting.alert_schema import STANDALONE_SEVERITY_SENTINEL

    severity_counter = Counter()
    event_sensitivity_counter = Counter()

    for alert in alerts:
        if alert.overall_severity == STANDALONE_SEVERITY_SENTINEL:
            if alert.event_sensitivity:
                event_sensitivity_counter[alert.event_sensitivity] += 1
        else:
            severity_counter[alert.overall_severity] += 1

    return {
        "total_alerts": len(alerts),
        "by_alert_type": dict(Counter(a.alert_type for a in alerts)),
        "by_severity": dict(severity_counter),
        "by_event_sensitivity": dict(event_sensitivity_counter),
        "by_tier": dict(Counter(a.correlation_tier for a in alerts)),
        "grounding_valid_count": sum(1 for a in alerts if a.grounding_valid),
        "strongly_correlated": sum(1 for a in alerts if a.correlation_tier == "STRONGLY_CORRELATED"),
    }


def _print_summary(stats, json_path, csv_path) -> None:
    logger.info(
        "Phase 3 complete: total=%d active=%d latent=%d suspicious=%d "
        "strongly_correlated=%d grounding_valid=%d/%d critical=%d high=%d json=%s csv=%s",
        stats["total_alerts"],
        stats["by_alert_type"].get("ACTIVE_EXPLOITATION", 0),
        stats["by_alert_type"].get("LATENT_RISK", 0),
        stats["by_alert_type"].get("SUSPICIOUS_ACTIVITY", 0),
        stats["strongly_correlated"],
        stats["grounding_valid_count"],
        stats["total_alerts"],
        stats["by_severity"].get("CRITICAL", 0),
        stats["by_severity"].get("HIGH", 0),
        json_path,
        csv_path,
    )


def main():
    parser = argparse.ArgumentParser(description="Phase 3 — IAM Correlation + LLM Reasoning")
    parser.add_argument("--phase1-rbac", type=Path, default=DEFAULT_P1_RBAC)
    parser.add_argument("--phase1-abac", type=Path, default=DEFAULT_P1_ABAC)
    parser.add_argument("--phase2", type=Path, default=DEFAULT_P2)

    parser.add_argument(
        "--cloudtrail",
        type=Path,
        default=None,
        help="Path to an existing CloudTrail JSON file.",
    )
    parser.add_argument(
        "--collect-cloudtrail",
        action="store_true",
        help="Run the CloudTrail collector before normalization.",
    )
    parser.add_argument("--lookback-hours", type=int, default=24)
    parser.add_argument("--profile", default=None, help="AWS CLI profile name for collection")

    parser.add_argument(
        "--llm-backend",
        default="openai_compatible",
        choices=["openai_compatible", "none"],
        help=(
            "LLM backend. 'openai_compatible' (default) is the runtime mode: "
            "the framework calls an OpenAI-compatible HTTP API (typically a "
            "local Ollama daemon). 'none' is the paper's deterministic-only "
            "reference baseline; it produces alerts with no LLM fields and is "
            "not the recommended runtime mode."
        ),
    )
    parser.add_argument(
        "--llm-model",
        default="llama-3-1-8b-instruct",
        help=(
            "Model identifier. For the openai_compatible backend served by "
            "Ollama, pass the Ollama model tag (default: 'llama-3-1-8b-instruct')."
        ),
    )
    parser.add_argument(
        "--llm-api-base",
        default="http://localhost:11434/v1",
        help=(
            "For openai_compatible backend: API base URL. Defaults to a local "
            "Ollama daemon at http://localhost:11434/v1."
        ),
    )
    parser.add_argument(
        "--llm-api-key",
        default=None,
        help="For openai_compatible backend: bearer token. Prefer OPENAI_API_KEY env var.",
    )
    parser.add_argument("--output-dir", type=Path, default=None)
    parser.add_argument("--no-static", action="store_true", help="Skip static-only bundles")
    parser.add_argument(
        "--exclude-operator-arn",
        action="append",
        default=None,
        metavar="ARN",
        help=(
            "ARN whose CloudTrail events should be dropped before correlation. "
            "Intended to exclude the tool operator's own API traffic (IAMCollector, "
            "CloudTrail LookupEvents, sts:GetCallerIdentity, etc.) so Phase 3 does "
            "not alert on the reader that ran it. Repeatable. When --collect-cloudtrail "
            "is used, the operator ARN is auto-detected from sts:GetCallerIdentity "
            "and combined with any --exclude-operator-arn values supplied here. "
            "Use --no-exclude-operator to disable auto-detection."
        ),
    )
    parser.add_argument(
        "--no-exclude-operator",
        action="store_true",
        help=(
            "Disable operator-identity auto-detection and drop no events based on "
            "operator identity. Use when you want the raw correlation output "
            "including the tool's own API calls (e.g., integration debugging)."
        ),
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
    )

    args = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )

    cloudtrail_path = args.cloudtrail
    auto_detected_operator_arn: Optional[str] = None
    if args.collect_cloudtrail:
        cloudtrail_path, auto_detected_operator_arn = collect_cloudtrail(
            profile=args.profile,
            lookback_hours=args.lookback_hours,
            output_path=DEFAULT_CT_OUT,
        )
    elif cloudtrail_path is None:
        parser.error("Either --cloudtrail <path> or --collect-cloudtrail must be provided.")

    operator_arns: List[str] = []
    if not args.no_exclude_operator:
        if auto_detected_operator_arn:
            operator_arns.extend(expand_operator_identity_arns(auto_detected_operator_arn))
        if args.exclude_operator_arn:
            for arn in args.exclude_operator_arn:
                operator_arns.extend(expand_operator_identity_arns(arn))
    if (
        not args.no_exclude_operator
        and not operator_arns
        and not args.collect_cloudtrail
    ):
        logger.warning(
            "No operator ARN excluded from CloudTrail ingest. If this CloudTrail "
            "file contains API calls made by the tool itself (e.g., you ran the "
            "collector earlier from the same account), those events will appear "
            "as Phase 3 alerts. Pass --exclude-operator-arn <arn> to filter them, "
            "or --no-exclude-operator to acknowledge this is intentional."
        )

    seen: set = set()
    deduped: List[str] = []
    for arn in operator_arns:
        if arn not in seen:
            seen.add(arn)
            deduped.append(arn)

    run_phase3(
        phase1_rbac_path=args.phase1_rbac,
        phase1_abac_path=args.phase1_abac,
        phase2_path=args.phase2,
        cloudtrail_path=cloudtrail_path,
        llm_backend=args.llm_backend,
        llm_model=args.llm_model,
        llm_api_base=args.llm_api_base,
        llm_api_key=args.llm_api_key,
        output_dir=args.output_dir,
        include_static_only=not args.no_static,
        exclude_operator_arns=deduped,
    )


if __name__ == "__main__":
    main()