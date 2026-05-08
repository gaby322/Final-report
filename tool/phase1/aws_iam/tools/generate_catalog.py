from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Dict, List

PHASE1_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = PHASE1_ROOT.parents[1]
RULES_ROOT = PHASE1_ROOT / "rules"
OUTPUT_PATH = REPO_ROOT / "docs" / "phase1_rule_catalog.md"

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}


def _load_rules() -> List[Dict]:
    rows: List[Dict] = []
    for category in ("rbac", "abac"):
        base = RULES_ROOT / category
        if not base.exists():
            continue
        for rule_dir in sorted(base.iterdir()):
            if not rule_dir.is_dir():
                continue
            meta = rule_dir / "metadata.json"
            if not meta.exists():
                continue
            data = json.loads(meta.read_text(encoding="utf-8"))
            data["_category"] = category.upper()
            rows.append(data)
    return rows


def _severity_key(row: Dict) -> tuple:
    return (
        SEVERITY_ORDER.get(row.get("Severity", "").lower(), 99),
        row.get("CheckID", ""),
    )


def _escape_pipes(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ")


def _summarize(text: str, limit: int = 160) -> str:
    text = text.replace("\n", " ").strip()
    if len(text) <= limit:
        return text
    return text[: limit - 1].rstrip() + "..."


def generate() -> str:
    rows = _load_rules()
    rows.sort(key=_severity_key)

    total = len(rows)
    by_sev: Dict[str, int] = {}
    by_cat: Dict[str, int] = {}
    for row in rows:
        sev = row.get("Severity", "").lower()
        by_sev[sev] = by_sev.get(sev, 0) + 1
        cat = row["_category"]
        by_cat[cat] = by_cat.get(cat, 0) + 1

    lines: List[str] = []
    lines.append("# Phase 1 Rule Catalog")
    lines.append("")
    lines.append(
        "Auto-generated from each rule's `metadata.json`. Do not edit by hand — "
        "regenerate with `python -m phase1.aws_iam.tools.generate_catalog`."
    )
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(f"- **Total rules:** {total}")
    lines.append(
        "- **By category:** " + ", ".join(
            f"{cat}: {count}" for cat, count in sorted(by_cat.items())
        )
    )
    lines.append(
        "- **By severity:** " + ", ".join(
            f"{sev}: {count}"
            for sev, count in sorted(by_sev.items(), key=lambda kv: SEVERITY_ORDER.get(kv[0], 99))
        )
    )
    lines.append("")
    lines.append("## Rules")
    lines.append("")
    lines.append(
        "| # | Category | Severity | CheckID | Title | CIS Control | NIST Control |"
    )
    lines.append(
        "|---|----------|----------|---------|-------|-------------|--------------|"
    )
    for idx, row in enumerate(rows, start=1):
        lines.append(
            "| {n} | {cat} | {sev} | `{cid}` | {title} | {cis} | {nist} |".format(
                n=idx,
                cat=row["_category"],
                sev=row.get("Severity", ""),
                cid=row.get("CheckID", ""),
                title=_escape_pipes(row.get("CheckTitle", "")),
                cis=_escape_pipes(row.get("CISControl", "")),
                nist=_escape_pipes(row.get("NISTControl", "")),
            )
        )
    lines.append("")
    lines.append("## Authoritative-Source Grounding")
    lines.append("")
    lines.append(
        "Each rule's `AuthoritativeSource` field cites only primary sources "
        "(CIS AWS Foundations Benchmark v3.0.0, AWS Security Hub FSBP, "
        "AWS official documentation, NIST SP 800-53 Rev. 5, NIST SP 800-162, "
        "NIST SP 800-63B). Secondary threat-intelligence references "
        "(e.g., MITRE ATT&CK, security research literature) appear in the "
        "optional `ThreatReference` field and never in `AuthoritativeSource`."
    )
    lines.append("")
    lines.append("| CheckID | Severity | Authoritative Source | Threat Reference |")
    lines.append("|---------|----------|----------------------|------------------|")
    for row in rows:
        lines.append(
            "| `{cid}` | {sev} | {src} | {threat} |".format(
                cid=row.get("CheckID", ""),
                sev=row.get("Severity", ""),
                src=_escape_pipes(_summarize(row.get("AuthoritativeSource", ""))),
                threat=_escape_pipes(_summarize(row.get("ThreatReference", "") or "—")),
            )
        )
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    content = generate()
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text(content, encoding="utf-8")
    print(f"Wrote {OUTPUT_PATH.relative_to(REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
