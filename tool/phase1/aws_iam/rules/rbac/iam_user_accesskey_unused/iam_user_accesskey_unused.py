from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta, timezone
from phase1.aws_iam.rules.base_check import RBACCheck

_UNUSED_THRESHOLD_DAYS = 45


class iam_user_accesskey_unused(RBACCheck):

    def execute(self) -> Optional[Dict[str, Any]]:
        stale_keys: List[str] = []
        never_used_keys: List[str] = []
        threshold = timedelta(days=_UNUSED_THRESHOLD_DAYS)
        now = datetime.now(timezone.utc)

        for user_name, entry in self.inventory.credential_report.items():
            for key_num, active_attr, last_used_attr in [
                (1, "access_key_1_active", "access_key_1_last_used_date"),
                (2, "access_key_2_active", "access_key_2_last_used_date"),
            ]:
                if getattr(entry, active_attr, "false") != "true":
                    continue
                last_used_str = getattr(entry, last_used_attr, None)
                key_label = f"{user_name}:key{key_num}"
                if not last_used_str or last_used_str in ("N/A", "no_information"):
                    never_used_keys.append(key_label)
                    continue
                try:
                    last_used = datetime.fromisoformat(
                        last_used_str.replace("Z", "+00:00")
                    )
                    if now - last_used >= threshold:
                        stale_keys.append(key_label)
                except ValueError:
                    never_used_keys.append(key_label)

        all_failures = stale_keys + never_used_keys
        if all_failures:
            violations: List[Dict[str, Any]] = []
            for k in stale_keys:
                user, keyn = k.split(":")
                violations.append({
                    "resource_type": "AWS::IAM::AccessKey",
                    "resource_id": k,
                    "name": k,
                    "detail": {"user": user, "key": keyn, "reason": f"unused>={_UNUSED_THRESHOLD_DAYS}d"},
                })
            for k in never_used_keys:
                user, keyn = k.split(":")
                violations.append({
                    "resource_type": "AWS::IAM::AccessKey",
                    "resource_id": k,
                    "name": k,
                    "detail": {"user": user, "key": keyn, "reason": "never_used"},
                })
            parts = []
            if stale_keys:
                parts.append(f"unused ≥{_UNUSED_THRESHOLD_DAYS} days: {', '.join(stale_keys)}")
            if never_used_keys:
                parts.append(f"never used: {', '.join(never_used_keys)}")
            return {
                "status": "FAIL",
                "status_extended": (
                    f"Active access keys violating CIS 1.12 ({_UNUSED_THRESHOLD_DAYS}-day inactivity threshold). "
                    + "; ".join(parts)
                ),
                "resource_type": "AWS::IAM::AccessKey",
                "resource_id": self.provider.identity.account_id,
                "category": "IAM",
                "evidence_summary": (
                    f"{len(all_failures)} active access key(s) have not been used "
                    f"within {_UNUSED_THRESHOLD_DAYS} days or have never been used"
                ),
                "evidence_details": {
                    "violations": violations,
                    "threshold_days": _UNUSED_THRESHOLD_DAYS,
                },
            }

        return {
            "status": "PASS",
            "status_extended": (
                f"All active access keys have been used within {_UNUSED_THRESHOLD_DAYS} days."
            ),
            "resource_type": "AWS::IAM::AccessKey",
            "resource_id": self.provider.identity.account_id,
            "category": "IAM",
            "evidence_summary": (
                f"All active access keys comply with the {_UNUSED_THRESHOLD_DAYS}-day usage requirement"
            ),
            "evidence_details": {"violations": [], "threshold_days": _UNUSED_THRESHOLD_DAYS},
        }
