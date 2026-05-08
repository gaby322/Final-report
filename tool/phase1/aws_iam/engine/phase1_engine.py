from __future__ import annotations

import logging
import traceback
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional
import importlib.util

from shared.core.findings.finding import Finding, Evidence, Reference
from shared.core.metadata import CheckMetadata, load_check_metadata
from shared.core.storage.inventory import Inventory
from shared.aws.provider.aws_provider import AwsProvider
from shared.aws.collectors.iam.iam_collector import IAMCollector
from phase1.aws_iam.rules.base_check import BaseCheck

logger = logging.getLogger(__name__)


@dataclass
class RuleExecutionError:

    check_id: str
    exception_type: str
    exception_message: str
    traceback_excerpt: str = ""

    def to_dict(self) -> Dict[str, str]:
        return {
            "check_id": self.check_id,
            "exception_type": self.exception_type,
            "exception_message": self.exception_message,
            "traceback_excerpt": self.traceback_excerpt,
        }


class Phase1Engine:
    def __init__(self, provider: AwsProvider):
        self.provider = provider
        self.inventory = Inventory()
        self.findings: List[Finding] = []
        self.rule_errors: List[RuleExecutionError] = []

    def collect_inventory(self) -> Inventory:
        iam_collector = IAMCollector(self.provider, self.inventory)
        iam_collector.collect_all()
        return self.inventory

    def load_rules(self, rules_path: Path) -> List[Dict[str, Any]]:
        rules = []
        for rule_dir in rules_path.iterdir():
            if rule_dir.is_dir():
                py_file = rule_dir / f"{rule_dir.name}.py"
                json_file = rule_dir / "metadata.json"
                if py_file.exists() and json_file.exists():
                    rules.append({
                        "module_path": py_file,
                        "metadata": load_check_metadata(json_file),
                    })
        return rules

    def execute_rules(self, rules: List[Dict[str, Any]]) -> List[Finding]:
        for rule in rules:
            check_id = rule["metadata"].check_id
            try:
                module_path = rule["module_path"]
                metadata = rule["metadata"]
                spec = importlib.util.spec_from_file_location(metadata.check_id, module_path)
                if spec and spec.loader:
                    module = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(module)
                    check_class = getattr(module, metadata.check_id, None)
                    if check_class:
                        check_instance = check_class(self.inventory, self.provider)
                        result = check_instance.execute()
                        if result:
                            finding = self._build_finding(result, metadata)
                            self.findings.append(finding)
            except Exception as exc:
                tb_lines = traceback.format_exc().splitlines()
                excerpt = "\n".join(tb_lines[-6:]) if tb_lines else ""
                self.rule_errors.append(
                    RuleExecutionError(
                        check_id=check_id,
                        exception_type=type(exc).__name__,
                        exception_message=str(exc),
                        traceback_excerpt=excerpt,
                    )
                )
                logger.warning(
                    "Phase 1 rule %s raised %s: %s — no finding emitted for this rule.",
                    check_id, type(exc).__name__, exc,
                )
                logger.debug("Phase 1 rule %s traceback:\n%s", check_id, excerpt)
        if self.rule_errors:
            logger.warning(
                "Phase 1 execution finished with %d rule error(s) out of %d rules. "
                "Run results should not be treated as a clean pass.",
                len(self.rule_errors), len(rules),
            )
        return self.findings

    def get_execution_errors(self) -> List[RuleExecutionError]:
        return list(self.rule_errors)

    def _build_finding(self, result: Dict[str, Any], metadata: CheckMetadata) -> Finding:
        region = (
            "global"
            if metadata.service_name.lower() == "iam"
            else self.provider.region
        )

        severity = (metadata.severity or "UNKNOWN").upper()

        references: List[Reference] = []
        auth = metadata.authoritative_source or ""
        if metadata.cis_control and not metadata.cis_control.strip().upper().startswith("N/A"):
            references.append(Reference(
                source="CIS AWS Foundations Benchmark",
                control_id=metadata.cis_control,
                url=None,
            ))
        if metadata.nist_control:
            references.append(Reference(
                source="NIST SP 800-53 Rev. 5",
                control_id=metadata.nist_control,
                url=None,
            ))
        ref_ctrl = metadata.reference_control_id
        ref_src = metadata.reference_source
        ref_url = metadata.reference_url
        if ref_ctrl and ref_src:
            references.append(Reference(
                source=ref_src,
                control_id=ref_ctrl,
                url=ref_url,
            ))
        elif ref_url and not references:
            references.append(Reference(
                source=auth or "AWS documentation",
                control_id="",
                url=ref_url,
            ))

        return Finding(
            check_id=metadata.check_id,
            status=result.get("status", "UNKNOWN"),
            status_extended=result.get("status_extended", ""),
            resource_type=result.get("resource_type", ""),
            resource_id=result.get("resource_id", ""),
            account_id=self.provider.identity.account_id,
            region=region,
            partition=self.provider.identity.partition,
            service_name=metadata.service_name,
            severity=severity,
            category=result.get("category"),
            description=metadata.description,
            remediation=metadata.remediation,
            evidence=Evidence(
                summary=result.get("evidence_summary", ""),
                details=result.get("evidence_details", {}),
            ),
            metadata={"risk": metadata.risk, "categories": metadata.categories},
            severity_basis=metadata.severity_basis,
            authoritative_source=auth,
            cis_control=metadata.cis_control,
            nist_control=metadata.nist_control,
            references=references,
            schema_version="1.0",
        )

    def run(self, rules_path: Path) -> List[Finding]:
        self.inventory = Inventory()
        self.findings = []
        self.collect_inventory()
        rules = self.load_rules(rules_path)
        return self.execute_rules(rules)

