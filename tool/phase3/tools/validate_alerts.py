from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict, List

PHASE3_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = PHASE3_ROOT.parent
DEFAULT_OUTPUT = PHASE3_ROOT / "outputs" / "phase3_alerts.json"

_VALID_ALERT_TYPE = {
    "ACTIVE_EXPLOITATION", "LATENT_RISK", "SUSPICIOUS_ACTIVITY", "INFORMATIONAL"
}
_VALID_TIER = {
    "STRONGLY_CORRELATED", "PARTIALLY_CORRELATED",
    "DYNAMIC_STANDALONE", "STATIC_STANDALONE"
}
_VALID_EVIDENCE_COMPLETENESS = {"FULL", "PARTIAL", "LIMITED"}
_VALID_OVERALL_SEVERITY = {
    "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL", "SEE_EVENT_SENSITIVITY"
}
_VALID_EVENT_SENSITIVITY = {"", "HIGH", "MEDIUM"}
_VALID_MAPPING_BASIS = {"HIGH", "MEDIUM", "NONE"}
_VALID_P1_MATCH_CONFIDENCE = {
    "ARN_EXACT", "TYPE_LEAF", "ISSUER_TYPE_LEAF", "NAME_ONLY", "NONE"
}
_PROMOTING_P1_CONFIDENCE = {"ARN_EXACT", "TYPE_LEAF", "ISSUER_TYPE_LEAF"}

_REQUIRED_ALERT = [
    "alert_id", "alert_type", "correlation_tier", "correlation_reason",
    "source_phase1_check_ids", "source_phase2_path_ids",
    "source_cloudtrail_event_ids", "source_cloudtrail_event_names",
    "principal_arns", "affected_roles", "affected_policies",
    "account_id", "aws_region",
    "p1_severity_label", "p2_risk_label", "event_sensitivity",
    "overall_severity", "evidence_completeness",
    "p1_match_confidence",
    "mitre",
    "llm_explanation", "llm_priority_justification",
    "llm_false_positive_assessment", "llm_remediation_steps",
    "llm_backend_used", "rag_sources_used", "rag_chunks_count",
    "grounding_valid", "ungrounded_fields", "grounding_details",
    "evidence_summary",
]
_REQUIRED_MITRE = [
    "tactic", "tactic_id", "technique", "technique_id",
    "mapping_basis", "llm_tactic_confirmed", "llm_technique_inferred",
]
_REQUIRED_STATS = [
    "total_alerts", "by_alert_type", "by_severity",
    "by_event_sensitivity", "by_tier", "grounding_valid_count",
]


def _err(errors: List[str], msg: str) -> None:
    errors.append(msg)


def _validate_alert(alert: Dict[str, Any], idx: int, errors: List[str]) -> None:
    for f in _REQUIRED_ALERT:
        if f not in alert:
            _err(errors, f"alerts[{idx}]: missing '{f}'")

    at = alert.get("alert_type")
    if at not in _VALID_ALERT_TYPE:
        _err(errors, f"alerts[{idx}]: invalid alert_type '{at}'")

    tier = alert.get("correlation_tier")
    if tier not in _VALID_TIER:
        _err(errors, f"alerts[{idx}]: invalid correlation_tier '{tier}'")

    ec = alert.get("evidence_completeness")
    if ec not in _VALID_EVIDENCE_COMPLETENESS:
        _err(errors, f"alerts[{idx}]: invalid evidence_completeness '{ec}'")

    ovs = alert.get("overall_severity")
    if ovs not in _VALID_OVERALL_SEVERITY:
        _err(errors, f"alerts[{idx}]: invalid overall_severity '{ovs}'")

    es = alert.get("event_sensitivity", "")
    if es not in _VALID_EVENT_SENSITIVITY:
        _err(errors, f"alerts[{idx}]: invalid event_sensitivity '{es}'")

    p1c = alert.get("p1_match_confidence")
    if p1c not in _VALID_P1_MATCH_CONFIDENCE:
        _err(errors, f"alerts[{idx}]: invalid p1_match_confidence '{p1c}'")

    if tier == "DYNAMIC_STANDALONE":
        if ovs != "SEE_EVENT_SENSITIVITY":
            _err(
                errors,
                f"alerts[{idx}]: DYNAMIC_STANDALONE tier must use overall_severity="
                f"'SEE_EVENT_SENSITIVITY', got '{ovs}'",
            )
        if es not in {"HIGH", "MEDIUM"}:
            _err(
                errors,
                f"alerts[{idx}]: DYNAMIC_STANDALONE tier must carry event_sensitivity "
                f"HIGH or MEDIUM, got '{es}'",
            )
    else:
        if ovs == "SEE_EVENT_SENSITIVITY":
            _err(
                errors,
                f"alerts[{idx}]: non-DYNAMIC_STANDALONE tier '{tier}' must not use "
                f"the SEE_EVENT_SENSITIVITY sentinel",
            )

    if tier == "STRONGLY_CORRELATED" and p1c not in _PROMOTING_P1_CONFIDENCE:
        _err(
            errors,
            f"alerts[{idx}]: STRONGLY_CORRELATED tier requires p1_match_confidence "
            f"in {sorted(_PROMOTING_P1_CONFIDENCE)}, got '{p1c}'",
        )

    mitre = alert.get("mitre", {})
    if not isinstance(mitre, dict):
        _err(errors, f"alerts[{idx}]: 'mitre' must be an object")
    else:
        for f in _REQUIRED_MITRE:
            if f not in mitre:
                _err(errors, f"alerts[{idx}].mitre: missing '{f}'")
        mb = mitre.get("mapping_basis")
        if mb not in _VALID_MAPPING_BASIS:
            _err(errors, f"alerts[{idx}].mitre: invalid mapping_basis '{mb}'")

    for list_field in (
        "source_phase1_check_ids", "source_phase2_path_ids",
        "source_cloudtrail_event_ids", "source_cloudtrail_event_names",
        "principal_arns", "affected_roles", "affected_policies",
        "rag_sources_used", "ungrounded_fields",
    ):
        v = alert.get(list_field)
        if not isinstance(v, list):
            _err(errors, f"alerts[{idx}]: '{list_field}' must be a list, got {type(v).__name__}")

    gv = alert.get("grounding_valid")
    if not isinstance(gv, bool):
        _err(errors, f"alerts[{idx}]: 'grounding_valid' must be a boolean")


def validate(doc: Dict[str, Any]) -> List[str]:
    errors: List[str] = []
    if "phase3_stats" not in doc:
        _err(errors, "missing top-level 'phase3_stats'")
    if "alerts" not in doc:
        _err(errors, "missing top-level 'alerts'")
        return errors

    stats = doc.get("phase3_stats", {})
    for f in _REQUIRED_STATS:
        if f not in stats:
            _err(errors, f"phase3_stats: missing '{f}'")

    for idx, alert in enumerate(doc.get("alerts", [])):
        _validate_alert(alert, idx, errors)

    return errors


def main() -> int:
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_OUTPUT
    if not target.exists():
        print(f"ERROR: {target} does not exist.", file=sys.stderr)
        return 1
    try:
        data = json.loads(target.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        print(f"ERROR: {target} is not valid JSON: {exc}", file=sys.stderr)
        return 1
    errors = validate(data)
    if errors:
        print(f"Validated {target} — {len(errors)} error(s):", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        return 1
    print(f"OK: {target} conforms to phase3/schemas/alert_schema.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
