from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict, List

PHASE2_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = PHASE2_ROOT.parent
DEFAULT_OUTPUT = PHASE2_ROOT / "outputs" / "phase2_attack_paths.json"
SCHEMA_PATH = PHASE2_ROOT / "schemas" / "attack_path_schema.json"

_VALID_RISK = {"CRITICAL", "HIGH"}
_VALID_NODE_TYPE = {"iam_user", "iam_role", "iam_group"}
_VALID_CONFIDENCE = {"HIGH", "MEDIUM", "LOW"}
_VALID_EDGE_TYPES = {
    "sts:AssumeRole",
    "abac:tag_conditioned_assume",
    "iam:CreatePolicyVersion",
    "iam:SetDefaultPolicyVersion",
    "iam:AttachRolePolicy",
    "iam:PutRolePolicy",
    "iam:UpdateAssumeRolePolicy",
    "iam:AttachUserPolicy",
    "iam:PutUserPolicy",
    "iam:MemberOf",
    "iam:AttachGroupPolicy",
    "iam:PutGroupPolicy",
    "iam:AddUserToGroup",
    "iam:CreateAccessKey",
    "iam:CreateLoginProfile",
    "iam:UpdateLoginProfile",
    "iam:PassRole_via_EC2",
    "iam:PassRole_via_Lambda",
    "iam:PassRole_via_Glue",
    "iam:PassRole_via_CloudFormation",
    "iam:PassRole_via_SageMaker",
    "iam:PassRole_via_DataPipeline",
    "iam:PassRole_via_AppRunner",
    "iam:PassRole_via_BedrockAgentCore",
    "iam:PassRole_via_CodeBuild",
    "iam:PassRole_via_ECS",
    "iam:PassRole_via_Glue_Job",
    "iam:PassRole_via_Lambda_Variant",
    "iam:PassRole_via_SageMaker_Job",
    "iam:PassRole_via_CloudFormation_StackSets",
    "iam:PassRole_via_EC2_Spot",
}
_REQUIRED_TOP = ["account_id", "graph_stats", "path_stats", "admin_nodes", "attack_paths"]
_REQUIRED_GRAPH_STATS = ["total_nodes", "admin_nodes", "total_edges", "user_nodes", "role_nodes"]
_REQUIRED_STEP = [
    "source_arn", "target_arn", "edge_type",
    "reason", "conditions", "is_abac_conditioned", "confidence",
]


def _err(errors: List[str], msg: str) -> None:
    errors.append(msg)


def _validate_path(path: Dict[str, Any], idx: int, errors: List[str]) -> None:
    required = ["path_id", "risk_level", "hop_count", "start_principal", "end_principal", "steps", "summary"]
    for f in required:
        if f not in path:
            _err(errors, f"attack_paths[{idx}]: missing '{f}'")
    if path.get("risk_level") not in _VALID_RISK:
        _err(errors, f"attack_paths[{idx}]: invalid risk_level '{path.get('risk_level')}'")
    hop_count = path.get("hop_count", 0)
    steps = path.get("steps", [])
    if not isinstance(steps, list) or len(steps) == 0:
        _err(errors, f"attack_paths[{idx}]: 'steps' must be a non-empty list")
    if isinstance(steps, list) and hop_count != len(steps):
        _err(
            errors,
            f"attack_paths[{idx}]: hop_count ({hop_count}) must equal len(steps) ({len(steps)})",
        )
    for sp in ("start_principal", "end_principal"):
        obj = path.get(sp, {})
        if not isinstance(obj, dict) or "arn" not in obj or "name" not in obj:
            _err(errors, f"attack_paths[{idx}]: '{sp}' must have 'arn' and 'name'")
    if isinstance(steps, list):
        for sidx, step in enumerate(steps):
            for f in _REQUIRED_STEP:
                if f not in step:
                    _err(errors, f"attack_paths[{idx}].steps[{sidx}]: missing '{f}'")
            et = step.get("edge_type")
            if et not in _VALID_EDGE_TYPES:
                _err(errors, f"attack_paths[{idx}].steps[{sidx}]: invalid edge_type '{et}'")
            conf = step.get("confidence")
            if conf not in _VALID_CONFIDENCE:
                _err(errors, f"attack_paths[{idx}].steps[{sidx}]: invalid confidence '{conf}'")


def validate(doc: Dict[str, Any]) -> List[str]:
    errors: List[str] = []
    for f in _REQUIRED_TOP:
        if f not in doc:
            _err(errors, f"missing top-level field '{f}'")
    account_id = doc.get("account_id", "")
    if not (isinstance(account_id, str) and account_id.isdigit() and len(account_id) == 12):
        _err(errors, f"account_id '{account_id}' is not a 12-digit string")
    gstats = doc.get("graph_stats", {})
    for f in _REQUIRED_GRAPH_STATS:
        if f not in gstats:
            _err(errors, f"graph_stats: missing '{f}'")
    for idx, p in enumerate(doc.get("attack_paths", [])):
        _validate_path(p, idx, errors)
    for idx, admin in enumerate(doc.get("admin_nodes", [])):
        nt = admin.get("type")
        if nt not in _VALID_NODE_TYPE:
            _err(errors, f"admin_nodes[{idx}]: invalid type '{nt}'")
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
    print(f"OK: {target} conforms to attack_path_schema.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
