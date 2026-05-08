from __future__ import annotations

import json
import logging
import sys
from pathlib import Path
from typing import List

project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from shared.aws.provider.aws_provider import AwsProvider
from phase1.aws_iam.engine.phase1_engine import Phase1Engine, RuleExecutionError
from phase1.aws_iam.reporting.reporters import JSONReporter, CSVReporter
from phase2.runner import run_phase2_from_inventory


def _resolve_phase1_rule_paths(scope: str) -> List[Path]:
    base = Path(__file__).parent / "phase1" / "aws_iam" / "rules"

    if scope == "rbac":
        return [base / "rbac"]
    if scope == "abac":
        return [base / "abac"]
    if scope == "both":
        return [base / "rbac", base / "abac"]

    raise ValueError(f"Unsupported phase1 scope: {scope}")


def _phase1_output_names(scope: str) -> tuple[Path, Path]:
    output_dir = Path(__file__).parent / "phase1" / "outputs"
    output_dir.mkdir(parents=True, exist_ok=True)

    if scope == "rbac":
        return (
            output_dir / "phase1_rbac_findings.json",
            output_dir / "phase1_rbac_findings.csv",
        )
    if scope == "abac":
        return (
            output_dir / "phase1_abac_findings.json",
            output_dir / "phase1_abac_findings.csv",
        )
    if scope == "both":
        return (
            output_dir / "phase1_combined_findings.json",
            output_dir / "phase1_combined_findings.csv",
        )

    raise ValueError(f"Unsupported phase1 scope: {scope}")


def run_phase1_with_existing_inventory(
    engine: Phase1Engine,
    scope: str,
):

    rule_paths = _resolve_phase1_rule_paths(scope)
    all_findings = []
    all_errors: List[RuleExecutionError] = []

    for rules_path in rule_paths:
        if not rules_path.exists():
            print(f"[Hybrid] Skipping missing rules path: {rules_path}")
            continue

        engine.findings = []
        engine.rule_errors = []
        rules = engine.load_rules(rules_path)
        scope_findings = engine.execute_rules(rules)
        all_findings.extend(scope_findings)
        all_errors.extend(engine.rule_errors)

    json_path, csv_path = _phase1_output_names(scope)

    json_reporter = JSONReporter(output_path=json_path)
    csv_reporter = CSVReporter(output_path=csv_path)

    json_reporter.report(all_findings)
    csv_reporter.report(all_findings)

    errors_path = json_path.with_name(json_path.stem + "_errors.json")
    with errors_path.open("w", encoding="utf-8") as fh:
        json.dump(
            {
                "scope": scope,
                "error_count": len(all_errors),
                "errors": [e.to_dict() for e in all_errors],
            },
            fh,
            indent=2,
        )

    total = len(all_findings)
    passed = sum(1 for f in all_findings if f.status == "PASS")
    failed = sum(1 for f in all_findings if f.status == "FAIL")
    other = total - passed - failed

    label = {
        "rbac": "Phase 1 RBAC",
        "abac": "Phase 1 ABAC",
        "both": "Phase 1 RBAC + ABAC",
    }[scope]

    print(f"\n{label} scan completed")
    print("=" * 40)
    print(f"Total findings: {total}")
    print(f"PASS: {passed}")
    print(f"FAIL: {failed}")
    print(f"OTHER: {other}")
    print(f"Rule execution errors: {len(all_errors)}")
    if all_errors:
        print("  WARNING: some rules raised during execution; see errors JSON.")
        print(f"  Errors report: {errors_path}")
    print(f"JSON report: {json_path}")
    print(f"CSV report:  {csv_path}")

    return {
        "findings": all_findings,
        "errors": all_errors,
        "json_path": json_path,
        "csv_path": csv_path,
        "errors_path": errors_path,
        "total": total,
        "passed": passed,
        "failed": failed,
        "other": other,
    }


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(
        description="Hybrid Runner — Phase 1 + Phase 2 using the same Inventory object"
    )
    parser.add_argument(
        "--profile",
        default=None,
        help=(
            "AWS CLI profile name. If not provided, boto3 falls back to the "
            "default credential chain (environment, shared credentials file, "
            "SSO, instance role, etc.). See PERMISSIONS.txt for required IAM "
            "permissions."
        ),
    )
    parser.add_argument(
        "--phase1-scope",
        choices=["rbac", "abac", "both"],
        default="rbac",
        help="Which Phase 1 rules to run before Phase 2",
    )
    parser.add_argument(
        "--max-hops",
        type=int,
        default=5,
        help="Maximum hop depth for Phase 2 path analysis",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help=(
            "Root logging level. At INFO, Phase 2 progress messages and "
            "collector warnings (missing permissions, etc.) are visible. "
            "Drop to WARNING for quieter output, DEBUG for verbose tracing."
        ),
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )

    provider = AwsProvider(profile=args.profile)
    engine = Phase1Engine(provider)

    print("[Hybrid] Collecting shared inventory once...")
    inventory = engine.collect_inventory()

    print(
        f"[Hybrid] Shared inventory ready: "
        f"{len(inventory.users)} users, "
        f"{len(inventory.roles)} roles, "
        f"{len(inventory.groups)} groups, "
        f"{len(inventory.policies)} policies"
    )

    run_phase1_with_existing_inventory(
        engine=engine,
        scope=args.phase1_scope,
    )

    run_phase2_from_inventory(
        provider=provider,
        inventory=inventory,
        max_hops=args.max_hops,
    )


if __name__ == "__main__":
    main()