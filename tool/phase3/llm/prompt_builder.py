from __future__ import annotations


from typing import List

from phase3.analysis.correlator import EvidenceBundle
from phase3.rag.retriever import RetrievedChunk

SYSTEM_PROMPT = """You are a cybersecurity analyst specializing in AWS IAM security, privilege escalation, and cloud identity threats. You reason precisely over structured evidence and produce concise, grounded security assessments.

STRICT RULES:
1. Base every claim ONLY on the structured evidence provided in this prompt.
2. Do NOT invent, infer, or assume permissions, events, or context not present in the evidence.
3. If the evidence is insufficient to support a conclusion, say so explicitly with "INSUFFICIENT EVIDENCE".
4. Output ONLY a valid JSON object. No preamble, no markdown, no explanation outside the JSON.
5. Every field you populate must reference specific evidence IDs (event_id, check_id, path_id) from the evidence section.
6. If a deterministic MITRE mapping is present and not UNMAPPED, do NOT propose a different MITRE technique; use the deterministic mapping or state INSUFFICIENT EVIDENCE.
"""

OUTPUT_SCHEMA = """{
  "explanation": "<string: why this alert matters, referencing specific evidence>",
  "priority_justification": "<string: why this alert is high/medium/low priority>",
  "false_positive_assessment": "<string: likelihood this is benign and why>",
  "mitre_tactic_confirmed": "<string: restate the deterministic MITRE tactic if supported by the evidence, or state INSUFFICIENT EVIDENCE>",
  "mitre_technique_inferred": "<string: for UNMAPPED events only, suggest a MITRE technique with justification; otherwise state INSUFFICIENT EVIDENCE>",
  "remediation_steps": "<string: specific remediation steps grounded in the evidence>",
  "evidence_ids_referenced": ["<list of check_id, path_id, event_id values you referenced>"]
}"""


class PromptBuilder:
    def build(
        self,
        bundle: EvidenceBundle,
        retrieved_chunks: List[RetrievedChunk],
    ) -> tuple[str, str]:
        user_prompt = self._build_user_prompt(bundle, retrieved_chunks)
        return SYSTEM_PROMPT, user_prompt

    def _build_user_prompt(
        self,
        bundle: EvidenceBundle,
        retrieved_chunks: List[RetrievedChunk],
    ) -> str:
        sections: List[str] = []

        sections.append(self._section_header("ALERT CONTEXT"))
        sections.append(f"Correlation tier: {bundle.correlation_tier}")
        sections.append(f"Matched Phase 1 findings: {len(bundle.p1_findings)}")
        sections.append(f"Matched Phase 2 paths: {len(bundle.p2_paths)}")
        sections.append(f"Deterministic correlation reason: {bundle.correlation_reason}")

        if bundle.event_sensitivity:
            sections.append(f"Framework event sensitivity: {bundle.event_sensitivity}")

        if bundle.mitre_mapping:
            m = bundle.mitre_mapping
            if m.is_unmapped:
                sections.append(
                    "Deterministic MITRE mapping: UNMAPPED (mapping_basis=NONE)"
                )
            else:
                mapping_text = (
                    f"Deterministic MITRE mapping (mapping_basis={m.mapping_basis}): "
                    f"{m.tactic_id} {m.tactic} / {m.technique_id} {m.technique}"
                )
                if m.sub_technique:
                    mapping_text += f" / {m.sub_technique_id} {m.sub_technique}"
                sections.append(mapping_text)

        sections.append(self._section_header("CLOUDTRAIL EVENT"))
        event = bundle.event
        sections.append(f"event_id: {event.event_id}")
        sections.append(f"event_name: {event.event_name}")
        sections.append(f"event_source: {event.event_source}")
        sections.append(f"event_time: {event.event_time}")
        sections.append(f"principal_arn: {event.principal_arn}")

        if event.assumed_role_arn:
            sections.append(f"assumed_role_arn: {event.assumed_role_arn}")

        if event.target_resource_arn:
            sections.append(f"target_resource: {event.target_resource_arn}")
        elif event.target_resource_name:
            sections.append(
                f"target_resource: {event.target_resource_name} ({event.target_resource_type})"
            )

        if event.error_code:
            sections.append(f"error_code: {event.error_code} — {event.error_message or ''}")

        if event.source_ip:
            sections.append(f"source_ip: {event.source_ip}")

        sections.append(self._section_header("PHASE 1 — STATIC IAM FINDINGS"))
        if bundle.p1_findings:
            for f in bundle.p1_findings[:5]:
                sections.append(
                    f"check_id={f.check_id} | severity={f.severity} | "
                    f"resource={f.resource_id} | {f.status_extended}"
                )
                if f.evidence_summary:
                    sections.append(f"  evidence: {f.evidence_summary}")
        else:
            sections.append("No Phase 1 findings matched this principal.")

        sections.append(self._section_header("PHASE 2 — ESCALATION PATHS"))
        if bundle.p2_paths:
            for p in bundle.p2_paths[:3]:
                sections.append(
                    f"path_id={p.path_id} | risk={p.risk_level} | hops={p.hop_count} | "
                    f"{p.start_name} -> {p.end_name}"
                )
                sections.append(f"  edges: {' -> '.join(p.edge_types)}")
                if p.summary:
                    sections.append(f"  summary: {p.summary[:200]}")
        else:
            sections.append("No reachable escalation paths matched this principal.")

        sections.append(self._section_header("RETRIEVED CYBERSECURITY KNOWLEDGE"))
        if retrieved_chunks:
            for chunk in retrieved_chunks:
                label = "AUTHORITATIVE" if chunk.authoritative else "SUPPLEMENTAL"
                sections.append(f"[{label} — {chunk.category.upper()} — {chunk.source}]")
                sections.append(chunk.text[:600])
                sections.append("")
        else:
            sections.append("No knowledge base available. Reason from provided evidence only.")

        sections.append(self._section_header("YOUR TASK"))
        sections.append(
            "Analyze the above evidence and produce a structured security assessment. "
            "Reference specific evidence IDs in your response. "
            "Output ONLY the following JSON object:"
        )
        sections.append(OUTPUT_SCHEMA)

        return "\n".join(sections)

    @staticmethod
    def _section_header(title: str) -> str:
        return f"\n{'='*60}\n{title}\n{'='*60}"