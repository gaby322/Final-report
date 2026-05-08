from __future__ import annotations

import json
import random
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from botocore.exceptions import ClientError

from shared.aws.provider.aws_provider import AwsProvider


IAM_RELEVANT_EVENT_SOURCES = {
    "iam.amazonaws.com",
    "sts.amazonaws.com",
    "sso.amazonaws.com",
    "signin.amazonaws.com",
    "organizations.amazonaws.com",
    "identitystore.amazonaws.com",
}

DEFAULT_LOOKBACK_HOURS = 24

MAX_RESULTS_PER_PAGE = 50

_MAX_RETRIES = 5
_BASE_DELAY_SECONDS = 0.5


class CloudTrailCollector:

    def __init__(
        self,
        provider: AwsProvider,
        lookback_hours: int = DEFAULT_LOOKBACK_HOURS,
        output_path: Optional[Path] = None,
    ):
        self.provider = provider
        self.lookback_hours = lookback_hours
        self.output_path = output_path or (
            Path(__file__).parent / "outputs" / "cloudtrail_events.json"
        )
        self._client = provider.get_client("cloudtrail")

    def collect(self) -> List[Dict[str, Any]]:
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(hours=self.lookback_hours)

        print(
            f"[CloudTrailCollector] Collecting events from "
            f"{start_time.isoformat()} to {end_time.isoformat()}"
        )

        all_events: List[Dict[str, Any]] = []

        for source in IAM_RELEVANT_EVENT_SOURCES:
            events = self._lookup_by_source(source, start_time, end_time)
            all_events.extend(events)
            print(
                f"[CloudTrailCollector] {source}: {len(events)} event(s) collected"
            )

        seen_ids = set()
        deduplicated: List[Dict[str, Any]] = []
        for event in all_events:
            event_id = event.get("EventId", "")
            if event_id and event_id not in seen_ids:
                seen_ids.add(event_id)
                deduplicated.append(event)
            elif not event_id:
                deduplicated.append(event)

        print(
            f"[CloudTrailCollector] Total after deduplication: {len(deduplicated)} event(s)"
        )

        self._write_output(deduplicated)
        return deduplicated

    def _lookup_by_source(
        self,
        event_source: str,
        start_time: datetime,
        end_time: datetime,
    ) -> List[Dict[str, Any]]:
        events: List[Dict[str, Any]] = []
        kwargs: Dict[str, Any] = {
            "LookupAttributes": [
                {
                    "AttributeKey": "EventSource",
                    "AttributeValue": event_source,
                }
            ],
            "StartTime": start_time,
            "EndTime": end_time,
            "MaxResults": MAX_RESULTS_PER_PAGE,
        }

        while True:
            try:
                response = self._lookup_events_with_backoff(kwargs)
            except self._client.exceptions.InvalidTimeRangeException as exc:
                print(f"[CloudTrailCollector] Invalid time range for {event_source}: {exc}")
                break
            except Exception as exc:
                print(f"[CloudTrailCollector] Error querying {event_source}: {exc}")
                break

            for item in response.get("Events", []):
                raw_record = item.get("CloudTrailEvent")
                if raw_record:
                    try:
                        parsed = json.loads(raw_record)
                        events.append(parsed)
                    except (json.JSONDecodeError, TypeError):
                        events.append({"raw": raw_record})
                else:
                    events.append(item)

            next_token = response.get("NextToken")
            if not next_token:
                break
            kwargs["NextToken"] = next_token

        return events

    def _lookup_events_with_backoff(self, kwargs: Dict[str, Any]) -> Dict[str, Any]:
        throttle_codes = {"ThrottlingException", "Throttling", "RequestThrottled", "ServiceUnavailableException"}
        for attempt in range(_MAX_RETRIES):
            try:
                return self._client.lookup_events(**kwargs)
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code", "")
                if code in throttle_codes and attempt < _MAX_RETRIES - 1:
                    wait = (_BASE_DELAY_SECONDS * (2 ** attempt)) + random.uniform(0.0, 0.3)
                    print(f"[CloudTrailCollector] Throttled, retrying in {wait:.1f}s (attempt {attempt + 1}/{_MAX_RETRIES})")
                    time.sleep(wait)
                else:
                    raise
        raise RuntimeError("unreachable")

    def _write_output(self, events: List[Dict[str, Any]]) -> None:
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "CollectedAt": datetime.now(timezone.utc).isoformat(),
            "AccountId": self.provider.identity.account_id,
            "Region": self.provider.region,
            "LookbackHours": self.lookback_hours,
            "EventCount": len(events),
            "Records": events,
        }
        with self.output_path.open("w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, default=str)
        print(f"[CloudTrailCollector] Written to: {self.output_path}")