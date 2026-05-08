from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple

PHASE1_ROOT = Path(__file__).resolve().parents[1]
RULES_ROOT = PHASE1_ROOT / "rules"
SCHEMA_PATH = RULES_ROOT / "metadata_schema.json"

BANNED_IN_AUTHORITATIVE = [
    re.compile(r"Rhino Security", re.IGNORECASE),
    re.compile(r"CloudGoat", re.IGNORECASE),
    re.compile(r"MITRE ATT", re.IGNORECASE),
    re.compile(r"aligns with", re.IGNORECASE),
]
BANNED_IN_CIS_CONTROL = [
    re.compile(r"aligns with", re.IGNORECASE),
]
ALLOWED_SEVERITIES = {"critical", "high", "medium", "low", "informational"}
REQUIRED_FIELDS = [
    "CheckID",
    "CheckTitle",
    "Severity",
    "Description",
    "Risk",
    "Remediation",
    "ServiceName",
    "ResourceType",
    "Categories",
    "SeverityBasis",
    "AuthoritativeSource",
    "CISControl",
    "NISTControl",
]


def _find_metadata_files() -> List[Path]:
    files: List[Path] = []
    for category_dir in ("rbac", "abac"):
        base = RULES_ROOT / category_dir
        if not base.exists():
            continue
        for path in base.iterdir():
            if path.is_dir():
                meta = path / "metadata.json"
                if meta.exists():
                    files.append(meta)
    return sorted(files)


def _validate_one(path: Path) -> List[str]:
    errors: List[str] = []
    try:
        data: Dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return [f"{path}: invalid JSON — {exc}"]

    for field in REQUIRED_FIELDS:
        if field not in data:
            errors.append(f"{path}: missing required field '{field}'")
            continue
        value = data[field]
        if field == "Categories":
            if not isinstance(value, list) or not value:
                errors.append(f"{path}: '{field}' must be a non-empty list")
        elif not isinstance(value, str) or not value.strip():
            errors.append(f"{path}: '{field}' must be a non-empty string")

    severity = data.get("Severity", "")
    if severity not in ALLOWED_SEVERITIES:
        errors.append(
            f"{path}: Severity '{severity}' not in {sorted(ALLOWED_SEVERITIES)}"
        )

    check_id = data.get("CheckID", "")
    expected_id = path.parent.name
    if check_id != expected_id:
        errors.append(
            f"{path}: CheckID '{check_id}' does not match directory '{expected_id}'"
        )

    auth_source = data.get("AuthoritativeSource", "")
    for pattern in BANNED_IN_AUTHORITATIVE:
        if pattern.search(auth_source):
            errors.append(
                f"{path}: AuthoritativeSource contains banned phrase matching "
                f"/{pattern.pattern}/ — move to ThreatReference"
            )

    cis_ctrl = data.get("CISControl", "")
    for pattern in BANNED_IN_CIS_CONTROL:
        if pattern.search(cis_ctrl):
            errors.append(
                f"{path}: CISControl contains banned phrase matching "
                f"/{pattern.pattern}/ — use explicit 'N/A — <reason>' or a numbered control"
            )

    resource_type = data.get("ResourceType", "")
    if not re.match(r"^AWS::[A-Za-z0-9]+::[A-Za-z0-9]+$", resource_type):
        errors.append(
            f"{path}: ResourceType '{resource_type}' does not match AWS::Service::Resource pattern"
        )

    return errors


def validate_all() -> Tuple[int, List[str]]:
    all_errors: List[str] = []
    files = _find_metadata_files()
    for meta_path in files:
        all_errors.extend(_validate_one(meta_path))
    return len(files), all_errors


def main() -> int:
    count, errors = validate_all()
    if errors:
        print(f"Validated {count} metadata files — {len(errors)} error(s):", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        return 1
    print(f"OK: {count} metadata files validated with zero errors.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
