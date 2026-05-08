from __future__ import annotations

import csv
import io
import json
from pathlib import Path
from typing import List, Optional

from phase3.reporting.alert_schema import (
    CorrelatedAlert,
    STANDALONE_SEVERITY_SENTINEL,
)


class Phase3JSONReporter:
    def __init__(self, output_path: Optional[Path] = None):
        self.output_path = output_path

    def report(self, alerts: List[CorrelatedAlert], stats: Optional[dict] = None) -> str:
        data = {
            "phase3_stats": stats or self._compute_stats(alerts),
            "alerts": [a.to_dict() for a in alerts],
        }
        json_str = json.dumps(data, indent=2, default=str)
        if self.output_path:
            with self.output_path.open("w", encoding="utf-8") as fh:
                fh.write(json_str)
        return json_str

    @staticmethod
    def _compute_stats(alerts: List[CorrelatedAlert]) -> dict:
        from collections import Counter

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
            "by_evidence_completeness": dict(Counter(a.evidence_completeness for a in alerts)),
            "grounding_valid_count": sum(1 for a in alerts if a.grounding_valid),
        }


class Phase3CSVReporter:
    def __init__(self, output_path: Optional[Path] = None):
        self.output_path = output_path

    @staticmethod
    def _severity_display(alert: CorrelatedAlert) -> str:
        if alert.overall_severity == STANDALONE_SEVERITY_SENTINEL:
            if alert.event_sensitivity:
                return f"N/A (see event_sensitivity={alert.event_sensitivity})"
            return "N/A (standalone dynamic event)"
        return alert.overall_severity

    def report(self, alerts: List[CorrelatedAlert]) -> str:
        output = io.StringIO()
        writer = csv.writer(output)

        writer.writerow([
            "alert_id",
            "alert_type",
            "correlation_tier",
            "overall_severity_raw",
            "overall_severity_display",
            "event_sensitivity",
            "evidence_completeness",
            "principal_arns",
            "p1_check_ids",
            "p2_path_ids",
            "cloudtrail_events",
            "mitre_technique_id",
            "mitre_technique",
            "mitre_mapping_basis",
            "grounding_valid",
            "evidence_summary",
        ])

        for a in alerts:
            writer.writerow([
                a.alert_id,
                a.alert_type,
                a.correlation_tier,
                a.overall_severity,
                self._severity_display(a),
                a.event_sensitivity,
                a.evidence_completeness,
                "; ".join(a.principal_arns),
                "; ".join(a.source_phase1_check_ids),
                "; ".join(a.source_phase2_path_ids),
                "; ".join(a.source_cloudtrail_event_names),
                a.mitre_technique_id_deterministic,
                a.mitre_technique_deterministic,
                a.mitre_mapping_basis,
                a.grounding_valid,
                a.evidence_summary[:200],
            ])

        csv_str = output.getvalue()
        if self.output_path:
            with self.output_path.open("w", newline="", encoding="utf-8") as fh:
                fh.write(csv_str)
        return csv_str