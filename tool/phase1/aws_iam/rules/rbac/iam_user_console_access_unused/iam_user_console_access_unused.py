from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta, timezone
from phase1.aws_iam.rules.base_check import RBACCheck

_UNUSED_THRESHOLD_DAYS = 45


class iam_user_console_access_unused(RBACCheck):

    def execute(self) -> Optional[Dict[str, Any]]:
        stale_users: List[str] = []
        never_used_users: List[str] = []
        threshold = timedelta(days=_UNUSED_THRESHOLD_DAYS)
        now = datetime.now(timezone.utc)

        for user_name, entry in self.inventory.credential_report.items():
            if user_name == "<root_account>":
                continue
            if entry.password_enabled != "true":
                continue

            if not entry.password_last_used or entry.password_last_used in ("N/A", "no_information"):
                never_used_users.append(user_name)
                continue

            try:
                last_used = datetime.fromisoformat(
                    entry.password_last_used.replace("Z", "+00:00")
                )
                if now - last_used >= threshold:
                    stale_users.append(user_name)
            except ValueError:
                stale_users.append(user_name)

        all_failures = stale_users + never_used_users
        if all_failures:
            violations: List[Dict[str, Any]] = []
            for u in sorted(stale_users):
                violations.append({
                    "resource_type": "AWS::IAM::User",
                    "resource_id": getattr(self.inventory.users.get(u), "arn", u) if u in self.inventory.users else u,
                    "name": u,
                    "detail": {"reason": f"unused>={_UNUSED_THRESHOLD_DAYS}d"},
                })
            for u in sorted(never_used_users):
                violations.append({
                    "resource_type": "AWS::IAM::User",
                    "resource_id": getattr(self.inventory.users.get(u), "arn", u) if u in self.inventory.users else u,
                    "name": u,
                    "detail": {"reason": "never_used"},
                })
            parts = []
            if stale_users:
                parts.append(f"unused ≥{_UNUSED_THRESHOLD_DAYS} days: {', '.join(sorted(stale_users))}")
            if never_used_users:
                parts.append(f"never used: {', '.join(sorted(never_used_users))}")
            return {
                "status": "FAIL",
                "status_extended": (
                    f"Console access violating CIS 1.12 ({_UNUSED_THRESHOLD_DAYS}-day inactivity threshold). "
                    + "; ".join(parts)
                ),
                "resource_type": "AWS::IAM::User",
                "resource_id": self.provider.identity.account_id,
                "category": "IAM",
                "evidence_summary": (
                    f"{len(all_failures)} user(s) have not used console access within "
                    f"{_UNUSED_THRESHOLD_DAYS} days or have never logged in"
                ),
                "evidence_details": {
                    "violations": violations,
                    "threshold_days": _UNUSED_THRESHOLD_DAYS,
                },
            }

        return {
            "status": "PASS",
            "status_extended": (
                f"All users with console access have logged in within {_UNUSED_THRESHOLD_DAYS} days."
            ),
            "resource_type": "AWS::IAM::User",
            "resource_id": self.provider.identity.account_id,
            "category": "IAM",
            "evidence_summary": (
                f"All console-enabled users comply with the {_UNUSED_THRESHOLD_DAYS}-day usage requirement"
            ),
            "evidence_details": {"violations": [], "threshold_days": _UNUSED_THRESHOLD_DAYS},
        }
