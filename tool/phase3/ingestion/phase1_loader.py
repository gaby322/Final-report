from __future__ import annotations


import json
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from phase3.ingestion.cloudtrail_normalizer import (
    PrincipalType,
    canonical_principal_type,
)


class MatchConfidence(str, Enum):
    ARN_EXACT = "ARN_EXACT"
    TARGET_ARN_EXACT = "TARGET_ARN_EXACT"
    TYPE_LEAF = "TYPE_LEAF"
    TARGET_TYPE_LEAF = "TARGET_TYPE_LEAF"
    ISSUER_TYPE_LEAF = "ISSUER_TYPE_LEAF"
    NAME_ONLY = "NAME_ONLY"
    NONE = "NONE"


_CONFIDENCE_RANK = {
    MatchConfidence.NONE: 0,
    MatchConfidence.NAME_ONLY: 1,
    MatchConfidence.ISSUER_TYPE_LEAF: 2,
    MatchConfidence.TARGET_TYPE_LEAF: 3,
    MatchConfidence.TYPE_LEAF: 4,
    MatchConfidence.TARGET_ARN_EXACT: 5,
    MatchConfidence.ARN_EXACT: 6,
}


def confidence_rank(confidence: MatchConfidence) -> int:
    return _CONFIDENCE_RANK.get(confidence, 0)


def max_confidence(*values: MatchConfidence) -> MatchConfidence:
    if not values:
        return MatchConfidence.NONE
    return max(values, key=confidence_rank)


_RESOURCE_TYPE_TO_PRINCIPAL_TYPE: Dict[str, PrincipalType] = {
    "AWS::IAM::User":   PrincipalType.USER,
    "AWS::IAM::Role":   PrincipalType.ROLE,
    "AWS::IAM::Group":  PrincipalType.GROUP,
    "AWS::IAM::Account": PrincipalType.ROOT,
}


def _resource_type_to_principal_type(resource_type: str) -> PrincipalType:
    return _RESOURCE_TYPE_TO_PRINCIPAL_TYPE.get(
        (resource_type or "").strip(), PrincipalType.UNKNOWN
    )


@dataclass
class P1Finding:
    check_id: str
    status: str
    status_extended: str
    resource_type: str
    resource_id: str
    account_id: str
    severity: str
    category: Optional[str] = None
    description: Optional[str] = None
    remediation: Optional[str] = None
    evidence_summary: Optional[str] = None
    evidence_details: Dict = field(default_factory=dict)
    service_name: str = "iam"
    metadata: Dict = field(default_factory=dict)
    principal_arn: Optional[str] = None
    principal_type: PrincipalType = PrincipalType.UNKNOWN

    def to_summary(self) -> str:
        return f"[{self.severity.upper()}] {self.check_id}: {self.status_extended}"


class Phase1Loader:
    def __init__(self):
        self.findings: List[P1Finding] = []
        self._by_principal: Dict[str, List[P1Finding]] = {}
        self._by_check_id: Dict[str, P1Finding] = {}
        self._by_arn: Dict[str, List[P1Finding]] = {}
        self._by_type_and_name: Dict[Tuple[PrincipalType, str], List[P1Finding]] = {}
        self._by_bare_name: Dict[str, List[P1Finding]] = {}


    def load(self, *paths: Path) -> "Phase1Loader":
        missing_paths = []

        for path in paths:
            if not path or not path.exists():
                missing_paths.append(str(path))
                continue

            with path.open("r", encoding="utf-8") as fh:
                raw = json.load(fh)

            records = raw if isinstance(raw, list) else [raw]
            for record in records:
                finding = self._parse(record)
                if not (finding and finding.status == "FAIL"):
                    continue

                children = self._expand_aggregate_by_violations(finding)
                if children:
                    for child in children:
                        self.findings.append(child)
                        self._index(child)
                else:
                    self.findings.append(finding)
                    self._index(finding)

        if missing_paths:
            raise FileNotFoundError(
                f"Phase 1 input file(s) not found: {', '.join(missing_paths)}"
            )

        return self


    _VIOLATION_ARN_KEYS_BY_TYPE: List[Tuple[str, str]] = [
        ("user_arn", "AWS::IAM::User"),
        ("role_arn", "AWS::IAM::Role"),
        ("group_arn", "AWS::IAM::Group"),
        ("policy_arn", "AWS::IAM::Policy"),
        ("policy", "AWS::IAM::Policy"),
    ]

    _VIOLATION_GENERIC_ARN_KEYS: Tuple[str, ...] = (
        "principal_arn",
        "principal",
        "arn",
    )

    def _expand_aggregate_by_violations(
        self, aggregate: "P1Finding"
    ) -> List["P1Finding"]:
        ed = aggregate.evidence_details if isinstance(aggregate.evidence_details, dict) else {}
        violations = ed.get("violations")
        if not isinstance(violations, list) or not violations:
            return []

        seen: set = set()
        children: List["P1Finding"] = []
        for v in violations:
            if not isinstance(v, dict):
                continue
            for arn, rtype, rid in self._extract_violator_identities(v, aggregate.account_id):
                if not arn or arn in seen:
                    continue
                seen.add(arn)

                child = P1Finding(
                    check_id=aggregate.check_id,
                    status=aggregate.status,
                    status_extended=aggregate.status_extended,
                    resource_type=rtype or aggregate.resource_type,
                    resource_id=rid or arn,
                    account_id=aggregate.account_id,
                    severity=aggregate.severity,
                    category=aggregate.category,
                    description=aggregate.description,
                    remediation=aggregate.remediation,
                    evidence_summary=aggregate.evidence_summary,
                    evidence_details=aggregate.evidence_details,
                    service_name=aggregate.service_name,
                    metadata={
                        **(aggregate.metadata or {}),
                        "expanded_from_aggregate": True,
                    },
                )
                child.principal_arn = arn
                children.append(child)
        return children

    def _extract_violator_identities(
        self, v: Dict, account_id: str
    ) -> List[Tuple[Optional[str], str, str]]:
        found: List[Tuple[str, str, str]] = []
        seen_in_violation: set = set()

        def _add(arn: str, rtype: str, leaf: str) -> None:
            if arn and arn not in seen_in_violation:
                seen_in_violation.add(arn)
                found.append((arn, rtype, leaf))

        for key, rtype in self._VIOLATION_ARN_KEYS_BY_TYPE:
            val = v.get(key)
            if isinstance(val, str) and val.startswith("arn:"):
                _add(val, rtype, self._leaf_from_arn(val))

        for key in self._VIOLATION_GENERIC_ARN_KEYS:
            val = v.get(key)
            if isinstance(val, str) and val.startswith("arn:"):
                _add(val, self._rtype_from_arn(val), self._leaf_from_arn(val))

        if not found:
            rtype = (v.get("resource_type") or "").strip()
            rid = (v.get("resource_id") or "").strip()
            if rtype and rid and rid.startswith("arn:"):
                _add(rid, rtype, self._leaf_from_arn(rid))
            elif rtype and rid and account_id:
                parts = rid.split("/")
                if len(parts) >= 2 and parts[0] in ("user", "role", "group"):
                    leaf = parts[1]
                    if rtype == "AWS::IAM::User":
                        _add(f"arn:aws:iam::{account_id}:user/{leaf}", rtype, leaf)
                    elif rtype == "AWS::IAM::Role":
                        _add(f"arn:aws:iam::{account_id}:role/{leaf}", rtype, leaf)
                    elif rtype == "AWS::IAM::Group":
                        _add(f"arn:aws:iam::{account_id}:group/{leaf}", rtype, leaf)
                elif "/" not in rid:
                    if rtype == "AWS::IAM::User":
                        _add(f"arn:aws:iam::{account_id}:user/{rid}", rtype, rid)
                    elif rtype == "AWS::IAM::Role":
                        _add(f"arn:aws:iam::{account_id}:role/{rid}", rtype, rid)
                    elif rtype == "AWS::IAM::Group":
                        _add(f"arn:aws:iam::{account_id}:group/{rid}", rtype, rid)

        return found

    @staticmethod
    def _leaf_from_arn(arn: str) -> str:
        if "/" in arn:
            return arn.rsplit("/", 1)[-1]
        if ":" in arn:
            return arn.rsplit(":", 1)[-1]
        return arn

    @staticmethod
    def _rtype_from_arn(arn: str) -> str:
        a = arn.lower()
        if ":user/" in a:
            return "AWS::IAM::User"
        if ":role/" in a:
            return "AWS::IAM::Role"
        if ":group/" in a:
            return "AWS::IAM::Group"
        if ":policy/" in a:
            return "AWS::IAM::Policy"
        if a.endswith(":root"):
            return "AWS::IAM::Account"
        return ""

    def _parse(self, record: Dict) -> Optional[P1Finding]:
        if not isinstance(record, dict):
            return None

        evidence = record.get("evidence") or {}
        resource_block = record.get("resource") or {}
        resource_type = (
            record.get("resource_type")
            or resource_block.get("type", "")
        )
        resource_id = (
            record.get("resource_id")
            or resource_block.get("id", "")
        )
        account_id = (
            record.get("account_id")
            or resource_block.get("account_id", "")
        )

        finding = P1Finding(
            check_id=record.get("check_id", ""),
            status=record.get("status", ""),
            status_extended=record.get("status_extended", ""),
            resource_type=resource_type,
            resource_id=resource_id,
            account_id=account_id,
            severity=record.get("severity", "informational"),
            category=record.get("category"),
            description=record.get("description"),
            remediation=record.get("remediation"),
            evidence_summary=evidence.get("summary", ""),
            evidence_details=evidence.get("details", {}),
            service_name=record.get("service_name", "iam"),
            metadata=record.get("metadata", {}),
        )
        finding.principal_arn = self._infer_principal_arn(finding)
        return finding

    def _infer_principal_arn(self, finding: P1Finding) -> Optional[str]:
        rid = (finding.resource_id or "").strip()
        account_id = (finding.account_id or "").strip()
        resource_type = (finding.resource_type or "").strip()

        if not rid or not account_id:
            return None
 
        if rid.startswith("arn:aws:iam::"):
            return rid
 
        if "," in rid:
            return None

        if rid == "root":
            return f"arn:aws:iam::{account_id}:root"

        if resource_type == "AWS::IAM::User":
            return f"arn:aws:iam::{account_id}:user/{rid}"

        if resource_type == "AWS::IAM::Role":
            return f"arn:aws:iam::{account_id}:role/{rid}"

        if resource_type == "AWS::IAM::Group":
            return f"arn:aws:iam::{account_id}:group/{rid}"

        return None
    
    def _index(self, finding: P1Finding) -> None:
        self._by_check_id[finding.check_id] = finding
        finding.principal_type = _resource_type_to_principal_type(finding.resource_type)

        if finding.resource_id:
            self._by_principal.setdefault(finding.resource_id, []).append(finding)
        if finding.principal_arn:
            self._by_principal.setdefault(finding.principal_arn, []).append(finding)

        if finding.principal_arn:
            self._by_arn.setdefault(finding.principal_arn, []).append(finding)

        if (
            finding.resource_id
            and finding.principal_type != PrincipalType.UNKNOWN
            and "," not in finding.resource_id
        ):
            key = (finding.principal_type, finding.resource_id)
            self._by_type_and_name.setdefault(key, []).append(finding)

        if finding.resource_id and "," not in finding.resource_id:
            self._by_bare_name.setdefault(finding.resource_id, []).append(finding)


    def findings_for_principal_typed(
        self,
        principal_arn: str,
        principal_name: str = "",
        principal_type: PrincipalType = PrincipalType.UNKNOWN,
    ) -> List[Tuple[P1Finding, MatchConfidence]]:
        results: Dict[str, Tuple[P1Finding, MatchConfidence]] = {}

        def _promote(finding: P1Finding, conf: MatchConfidence) -> None:
            existing = results.get(finding.check_id)
            if existing is None or confidence_rank(conf) > confidence_rank(existing[1]):
                results[finding.check_id] = (finding, conf)

        if principal_arn:
            for f in self._by_arn.get(principal_arn, []):
                _promote(f, MatchConfidence.ARN_EXACT)

        if principal_name and principal_type not in (PrincipalType.UNKNOWN, PrincipalType.SERVICE):
            for f in self._by_type_and_name.get((principal_type, principal_name), []):
                _promote(f, MatchConfidence.TYPE_LEAF)

            for key, findings in self._by_arn.items():
                if self._arn_leaf_matches(key, principal_type, principal_name):
                    for f in findings:
                        _promote(f, MatchConfidence.TYPE_LEAF)

            if principal_type == PrincipalType.FEDERATED:
                for f in self._by_type_and_name.get((PrincipalType.USER, principal_name), []):
                    _promote(f, MatchConfidence.NAME_ONLY)

        ambiguous_types = {
            PrincipalType.FEDERATED,
            PrincipalType.UNKNOWN,
            PrincipalType.SERVICE,
        }
        if principal_name and principal_type in ambiguous_types:
            for f in self._by_bare_name.get(principal_name, []):
                if f.check_id not in results:
                    _promote(f, MatchConfidence.NAME_ONLY)

        return list(results.values())

    @staticmethod
    def _arn_leaf_matches(
        key: str, principal_type: PrincipalType, principal_name: str
    ) -> bool:
        if not key.startswith("arn:"):
            return False
        key_type = canonical_principal_type(key)
        if key_type != principal_type:
            return False
        if key.endswith(":root") and principal_type == PrincipalType.ROOT:
            return principal_name == "root"
        if "/" in key:
            return key.split("/")[-1] == principal_name
        return False


    def findings_for_principal(self, principal_arn: str, principal_name: str = "") -> List[P1Finding]:
        results = list(self._by_principal.get(principal_arn, []))

        if principal_name:
            exact_name_matches = self._by_principal.get(principal_name, [])
            for f in exact_name_matches:
                if f not in results:
                    results.append(f)

            for key, findings in self._by_principal.items():
                if self._key_matches_principal_name(key, principal_name):
                    for f in findings:
                        if f not in results:
                            results.append(f)

        return results

    def _key_matches_principal_name(self, key: str, principal_name: str) -> bool:
        if not key or not principal_name:
            return False
        if key == principal_name:
            return True
        if key.startswith("arn:") and "/" in key:
            return key.split("/")[-1] == principal_name
        return False

    def get_by_check_id(self, check_id: str) -> Optional[P1Finding]:
        return self._by_check_id.get(check_id)

    def findings_by_severity(self, severity: str) -> List[P1Finding]:
        return [f for f in self.findings if f.severity.lower() == severity.lower()]

    def fail_count_by_severity(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts