from __future__ import annotations


import json
import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class SCPCollector:

    def __init__(self, session: Any):
        
        self._client = session.client("organizations")


    def collect_effective_scps(self, account_id: str) -> List[Dict[str, Any]]:
       
        try:
            scp_documents: List[Dict[str, Any]] = []
            visited_policy_ids: set = set()

            target_ids = self._get_target_hierarchy(account_id)
            for target_id in target_ids:
                for policy_doc in self._scps_for_target(target_id, visited_policy_ids):
                    scp_documents.append(policy_doc)

            logger.info(
                "[SCPCollector] Collected %d effective SCP document(s) for account %s",
                len(scp_documents),
                account_id,
            )
            return scp_documents

        except self._client.exceptions.AWSOrganizationsNotInUseException:
            logger.info(
                "[SCPCollector] Account %s is not part of an AWS Organization — no SCPs apply.",
                account_id,
            )
            return []
        except self._client.exceptions.AccessDeniedException as exc:
            logger.warning(
                "[SCPCollector] Access denied when querying Organizations for account %s: %s. "
                "SCP analysis will be skipped.",
                account_id,
                exc,
            )
            return []
        except Exception as exc:
            logger.warning(
                "[SCPCollector] Unexpected error collecting SCPs for account %s: %s. "
                "SCP analysis will be skipped.",
                account_id,
                exc,
            )
            return []


    def _get_target_hierarchy(self, account_id: str) -> List[str]:
        
        targets: List[str] = [account_id]
        current_id = account_id

        while True:
            parents = self._client.list_parents(ChildId=current_id).get("Parents", [])
            if not parents:
                break
            parent = parents[0]
            parent_id = parent["Id"]
            targets.append(parent_id)
            if parent["Type"] == "ROOT":
                break
            current_id = parent_id

        return targets

    def _scps_for_target(
        self, target_id: str, visited: set
    ) -> List[Dict[str, Any]]:
       
        documents: List[Dict[str, Any]] = []
        paginator = self._client.get_paginator("list_policies_for_target")
        for page in paginator.paginate(
            TargetId=target_id, Filter="SERVICE_CONTROL_POLICY"
        ):
            for policy_summary in page.get("Policies", []):
                policy_id = policy_summary["Id"]
                if policy_id in visited:
                    continue
                visited.add(policy_id)
                doc = self._fetch_policy_document(policy_id, policy_summary.get("Name", policy_id))
                if doc is not None:
                    documents.append(doc)
        return documents

    def _fetch_policy_document(
        self, policy_id: str, policy_name: str
    ) -> Optional[Dict[str, Any]]:
        try:
            response = self._client.describe_policy(PolicyId=policy_id)
            content_str = response.get("Policy", {}).get("Content", "")
            if not content_str:
                return None
            doc = json.loads(content_str)
            doc["_scp_policy_id"] = policy_id
            doc["_scp_policy_name"] = policy_name
            return doc
        except Exception as exc:
            logger.warning(
                "[SCPCollector] Could not fetch document for SCP %s (%s): %s",
                policy_id,
                policy_name,
                exc,
            )
            return None
