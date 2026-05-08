from __future__ import annotations


import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

from phase3.analysis.correlator import EvidenceBundle


@dataclass
class FieldGroundingResult:
    field_name: str
    grounded: bool
    reason: str


@dataclass
class GroundingReport:
    field_results: List[FieldGroundingResult] = field(default_factory=list)

    CRITICAL_FIELDS = {"llm_output", "explanation", "mitre_tactic_confirmed"}

    @property
    def grounding_valid(self) -> bool:
        for r in self.field_results:
            if r.field_name in self.CRITICAL_FIELDS and not r.grounded:
                return False
        return True

    @property
    def ungrounded_fields(self) -> List[str]:
        return [r.field_name for r in self.field_results if not r.grounded]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "grounding_valid": self.grounding_valid,
            "ungrounded_fields": self.ungrounded_fields,
            "field_details": [
                {"field": r.field_name, "grounded": r.grounded, "reason": r.reason}
                for r in self.field_results
            ],
        }


_VALID_MITRE_TACTICS = frozenset({
    "reconnaissance",
    "resource development",
    "initial access",
    "execution",
    "persistence",
    "privilege escalation",
    "defense evasion",
    "credential access",
    "discovery",
    "lateral movement",
    "collection",
    "command and control",
    "exfiltration",
    "impact",
})

_MITRE_TECHNIQUE_ID_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")


class HallucinationGuard:
    def validate(
        self,
        bundle: EvidenceBundle,
        llm_output: Optional[Dict[str, Any]],
        backend_used: Optional[str] = None,
    ) -> GroundingReport:
        report = GroundingReport()

        if backend_used == "none":
            report.field_results.append(
                FieldGroundingResult(
                    field_name="llm_output",
                    grounded=True,
                    reason=(
                        "Backend 'none': deterministic-only baseline. No LLM "
                        "claims were generated, so hallucination-grounding "
                        "validation is not applicable."
                    ),
                )
            )
            return report

        if not llm_output:
            report.field_results.append(
                FieldGroundingResult(
                    field_name="llm_output",
                    grounded=False,
                    reason=(
                        "LLM produced no parseable output. With the strict "
                        "guard, llm_output is a CRITICAL field so this alert "
                        "is flagged as ungrounded."
                    ),
                )
            )
            return report

        known_ids = self._collect_known_ids(bundle)
        known_mitre_tactics = self._known_mitre_tactics(bundle)
        known_mitre_techniques = self._known_mitre_techniques(bundle)

        referenced_ids = llm_output.get("evidence_ids_referenced", [])
        if isinstance(referenced_ids, list) and referenced_ids:
            unknown = [i for i in referenced_ids if i not in known_ids]
            if unknown:
                report.field_results.append(
                    FieldGroundingResult(
                        field_name="evidence_ids_referenced",
                        grounded=False,
                        reason=f"LLM referenced IDs not present in evidence bundle IDs: {unknown}",
                    )
                )
            else:
                report.field_results.append(
                    FieldGroundingResult(
                        field_name="evidence_ids_referenced",
                        grounded=True,
                        reason="All referenced IDs are valid evidence IDs from the bundle",
                    )
                )
        else:
            report.field_results.append(
                FieldGroundingResult(
                    field_name="evidence_ids_referenced",
                    grounded=True,
                    reason="No evidence IDs referenced (acceptable in low-evidence cases)",
                )
            )

        tactic = llm_output.get("mitre_tactic_confirmed", "")
        if tactic and "INSUFFICIENT" not in tactic.upper():
            if not self._tactic_string_is_valid_mitre(tactic):
                report.field_results.append(
                    FieldGroundingResult(
                        field_name="mitre_tactic_confirmed",
                        grounded=False,
                        reason=(
                            f"LLM MITRE tactic '{tactic}' is not a recognised "
                            f"MITRE ATT&CK Enterprise tactic."
                        ),
                    )
                )
            elif known_mitre_tactics:
                if any(t.lower() in tactic.lower() for t in known_mitre_tactics):
                    report.field_results.append(
                        FieldGroundingResult(
                            field_name="mitre_tactic_confirmed",
                            grounded=True,
                            reason="MITRE tactic is consistent with deterministic mapping",
                        )
                    )
                else:
                    report.field_results.append(
                        FieldGroundingResult(
                            field_name="mitre_tactic_confirmed",
                            grounded=False,
                            reason=(
                                f"LLM MITRE tactic '{tactic}' is not consistent with "
                                f"deterministic mapping {known_mitre_tactics}"
                            ),
                        )
                    )
            else:
                report.field_results.append(
                    FieldGroundingResult(
                        field_name="mitre_tactic_confirmed",
                        grounded=False,
                        reason="LLM asserted a MITRE tactic, but no deterministic MITRE tactic exists in the bundle",
                    )
                )
        else:
            report.field_results.append(
                FieldGroundingResult(
                    field_name="mitre_tactic_confirmed",
                    grounded=True,
                    reason="MITRE tactic not asserted by LLM (acceptable)",
                )
            )

        technique = llm_output.get("mitre_technique_inferred", "")
        if technique and "INSUFFICIENT" not in technique.upper():
            if bundle.mitre_mapping and not bundle.mitre_mapping.is_unmapped:
                report.field_results.append(
                    FieldGroundingResult(
                        field_name="mitre_technique_inferred",
                        grounded=False,
                        reason=(
                            "LLM provided mitre_technique_inferred even though a deterministic "
                            f"MITRE technique already exists: {known_mitre_techniques}"
                        ),
                    )
                )
            elif not self._technique_string_has_valid_id_format(technique):
                report.field_results.append(
                    FieldGroundingResult(
                        field_name="mitre_technique_inferred",
                        grounded=False,
                        reason=(
                            f"LLM technique inference '{technique}' does not contain a "
                            f"valid ATT&CK technique ID (expected format T####[.###])."
                        ),
                    )
                )
            else:
                report.field_results.append(
                    FieldGroundingResult(
                        field_name="mitre_technique_inferred",
                        grounded=True,
                        reason=(
                            "Technique inference is allowed for UNMAPPED events. "
                            "Validated for ID format (T####[.###]); semantic correctness "
                            "is not asserted by this guard."
                        ),
                    )
                )
        else:
            report.field_results.append(
                FieldGroundingResult(
                    field_name="mitre_technique_inferred",
                    grounded=True,
                    reason="MITRE technique inference not asserted (acceptable)",
                )
            )

        explanation = llm_output.get("explanation", "")
        explanation_stripped = explanation.strip() if isinstance(explanation, str) else ""
        bundle_has_any_evidence = bool(
            bundle.p1_findings or bundle.p2_paths or bundle.event.event_id
        )

        if not explanation_stripped and bundle_has_any_evidence:
            report.field_results.append(
                FieldGroundingResult(
                    field_name="explanation",
                    grounded=False,
                    reason=(
                        "LLM produced an empty or whitespace-only explanation "
                        "for an alert whose evidence bundle contains prior-phase "
                        "or CloudTrail findings."
                    ),
                )
            )
        else:
            phantom_arns = self._find_phantom_arns(explanation, bundle)
            if phantom_arns:
                report.field_results.append(
                    FieldGroundingResult(
                        field_name="explanation",
                        grounded=False,
                        reason=f"Explanation references ARNs not in evidence: {phantom_arns[:3]}",
                    )
                )
            else:
                report.field_results.append(
                    FieldGroundingResult(
                        field_name="explanation",
                        grounded=True,
                        reason="No phantom ARNs detected in explanation",
                    )
                )

        return report

    @staticmethod
    def _tactic_string_is_valid_mitre(tactic: str) -> bool:
        if not tactic:
            return False
        lowered = tactic.lower()
        return any(name in lowered for name in _VALID_MITRE_TACTICS)

    @staticmethod
    def _technique_string_has_valid_id_format(technique: str) -> bool:
        if not technique:
            return False
        for token in re.findall(r"\bT\d+(?:\.\d+)?\b", technique):
            if _MITRE_TECHNIQUE_ID_RE.match(token):
                return True
        return False

    def _collect_known_ids(self, bundle: EvidenceBundle) -> Set[str]:
        ids: Set[str] = set()

        if bundle.event.event_id:
            ids.add(bundle.event.event_id)

        for f in bundle.p1_findings:
            if f.check_id:
                ids.add(f.check_id)

        for p in bundle.p2_paths:
            if p.path_id:
                ids.add(p.path_id)

        return ids

    def _known_mitre_tactics(self, bundle: EvidenceBundle) -> List[str]:
        if bundle.mitre_mapping and not bundle.mitre_mapping.is_unmapped:
            vals = [bundle.mitre_mapping.tactic, bundle.mitre_mapping.tactic_id]
            return [v for v in vals if v]
        return []

    def _known_mitre_techniques(self, bundle: EvidenceBundle) -> List[str]:
        if bundle.mitre_mapping and not bundle.mitre_mapping.is_unmapped:
            vals = [
                bundle.mitre_mapping.technique,
                bundle.mitre_mapping.technique_id,
                bundle.mitre_mapping.sub_technique,
                bundle.mitre_mapping.sub_technique_id,
            ]
            return [v for v in vals if v]
        return []

    def _find_phantom_arns(self, text: str, bundle: EvidenceBundle) -> List[str]:
        known_arns = set(bundle.all_principal_arns)

        for p in bundle.p2_paths:
            if p.start_arn:
                known_arns.add(p.start_arn)
            if p.end_arn:
                known_arns.add(p.end_arn)
            for step in p.steps:
                if step.source_arn:
                    known_arns.add(step.source_arn)
                if step.target_arn:
                    known_arns.add(step.target_arn)

        for f in bundle.p1_findings:
            if f.resource_id and f.resource_id.startswith("arn:"):
                known_arns.add(f.resource_id)

        arn_pattern = re.compile(r"\barn:(aws|aws-cn|aws-us-gov):(iam|sts)::\d{12}:[A-Za-z0-9+=,.@_/\-]+(?=[\s\]\)\}\.,;:\"']|$)")
        found_arns = {m.group(0) for m in arn_pattern.finditer(text)}
        phantom = [a for a in found_arns if a not in known_arns]
        return phantom