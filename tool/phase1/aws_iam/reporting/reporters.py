from __future__ import annotations

import json
from pathlib import Path
from typing import List, Optional

from shared.core.findings import Finding


class JSONReporter:


    def __init__(self, output_path: Optional[Path] = None):
        self.output_path = output_path

    def report(self, findings: List[Finding]) -> str:
        data = [self._finding_to_dict(f) for f in findings]
        json_str = json.dumps(data, indent=2, default=str)
        if self.output_path:
            with self.output_path.open("w", encoding="utf-8") as fh:
                fh.write(json_str)
        return json_str

    @staticmethod
    def _finding_to_dict(finding: Finding) -> dict:
        return {
            "schema_version": finding.schema_version,
            "check_id": finding.check_id,
            "status": finding.status,
            "status_extended": finding.status_extended,
            "resource": {
                "type": finding.resource_type,
                "id": finding.resource_id,
                "account_id": finding.account_id,
                "region": finding.region,
                "partition": finding.partition,
            },
            "service_name": finding.service_name,
            "severity": finding.severity,
            "severity_basis": finding.severity_basis,
            "category": finding.category,
            "description": finding.description,
            "remediation": finding.remediation,
            "evidence": {
                "summary": finding.evidence.summary if finding.evidence else "",
                "details": finding.evidence.details if finding.evidence else {},
            } if finding.evidence else None,
            "references": {
                "authoritative_source": finding.authoritative_source,
                "cis_control": finding.cis_control,
                "nist_control": finding.nist_control,
                "items": [
                    {
                        "source": ref.source,
                        "control_id": ref.control_id,
                        "url": ref.url,
                    }
                    for ref in finding.references
                ],
            },
            "metadata": finding.metadata,
            "tags": finding.tags,
        }


class CSVReporter:


    def __init__(self, output_path: Optional[Path] = None):
        self.output_path = output_path

    def report(self, findings: List[Finding]) -> str:
        import csv
        import io
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow([
            "check_id", "status", "status_extended",
            "resource_type", "resource_id",
            "account_id", "region", "partition", "service_name",
            "severity", "severity_basis",
            "cis_control", "nist_control", "authoritative_source",
            "category", "evidence_summary",
        ])
        for finding in findings:
            writer.writerow([
                finding.check_id,
                finding.status,
                finding.status_extended,
                finding.resource_type,
                finding.resource_id,
                finding.account_id,
                finding.region,
                finding.partition,
                finding.service_name,
                finding.severity,
                finding.severity_basis,
                finding.cis_control,
                finding.nist_control,
                finding.authoritative_source,
                finding.category,
                finding.evidence.summary if finding.evidence else "",
            ])
        csv_str = output.getvalue()
        if self.output_path:
            with self.output_path.open("w", newline="", encoding="utf-8") as fh:
                fh.write(csv_str)
        return csv_str
