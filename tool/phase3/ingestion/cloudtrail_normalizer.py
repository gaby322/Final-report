from __future__ import annotations


import json
import logging
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, FrozenSet, Iterable, List, Optional

logger = logging.getLogger(__name__)


class PrincipalType(str, Enum):
    USER = "USER"
    ROLE = "ROLE"
    GROUP = "GROUP"
    ROOT = "ROOT"
    FEDERATED = "FEDERATED"
    SERVICE = "SERVICE"
    UNKNOWN = "UNKNOWN"


def canonical_principal_type(
    principal_arn: Optional[str],
    session_issuer_arn: Optional[str] = None,
) -> PrincipalType:
    arn = (principal_arn or "").strip()

    if ":assumed-role/" in arn:
        if session_issuer_arn:
            return canonical_principal_type(session_issuer_arn, None)
        return PrincipalType.ROLE

    if arn.endswith(":root"):
        return PrincipalType.ROOT
    if ":user/" in arn:
        return PrincipalType.USER
    if ":role/" in arn:
        return PrincipalType.ROLE
    if ":group/" in arn:
        return PrincipalType.GROUP
    if ":federated-user/" in arn:
        return PrincipalType.FEDERATED
    if arn.endswith(".amazonaws.com") and ":" not in arn:
        return PrincipalType.SERVICE
    return PrincipalType.UNKNOWN


def expand_operator_identity_arns(caller_arn: str) -> FrozenSet[str]:
    if not caller_arn:
        return frozenset()
    arn = caller_arn.strip()
    if not arn:
        return frozenset()
    out = {arn.lower()}

    if ":assumed-role/" in arn:
        try:
            parts = arn.split(":")
            account_id = parts[4] if len(parts) > 4 else ""
            tail = arn.split(":assumed-role/", 1)[1]
            role_name = tail.split("/", 1)[0]
            if account_id and role_name:
                partition = parts[1] if len(parts) > 1 and parts[1] else "aws"
                role_arn = f"arn:{partition}:iam::{account_id}:role/{role_name}"
                out.add(role_arn.lower())
        except (IndexError, ValueError):
            pass

    return frozenset(out)


IAM_RELEVANT_SOURCES = {
    "iam.amazonaws.com",
    "sts.amazonaws.com",
    "sso.amazonaws.com",
    "signin.amazonaws.com",
    "organizations.amazonaws.com",
    "identitystore.amazonaws.com",
}

IAM_RELEVANT_ACTIONS = {
    "CreatePolicyVersion", "SetDefaultPolicyVersion",
    "AttachRolePolicy", "AttachUserPolicy", "AttachGroupPolicy",
    "PutRolePolicy", "PutUserPolicy", "PutGroupPolicy",
    "UpdateAssumeRolePolicy",
    "AssumeRole", "AssumeRoleWithSAML", "AssumeRoleWithWebIdentity",
    "GetSessionToken", "GetFederationToken",
    "CreateUser", "CreateRole", "DeleteUser", "DeleteRole",
    "CreateAccessKey", "DeleteAccessKey", "UpdateAccessKey",
    "CreateLoginProfile", "UpdateLoginProfile", "DeleteLoginProfile",
    "AddUserToGroup", "RemoveUserFromGroup",
    "TagUser", "TagRole", "UntagUser", "UntagRole",
    "TagResource", "UntagResource",
    "CreatePolicy", "DeletePolicy", "CreatePolicyVersion",
    "DetachRolePolicy", "DetachUserPolicy",
    "GetCredentialReport", "GenerateCredentialReport",
    "ListAttachedRolePolicies", "GetRolePolicy",
    "DeactivateMFADevice", "DeleteVirtualMFADevice",
    "EnableMFADevice",
    "CreateSAMLProvider", "UpdateSAMLProvider", "DeleteSAMLProvider",
    "AddRoleToInstanceProfile", "RemoveRoleFromInstanceProfile",
    "CreateInstanceProfile",
}


@dataclass
class NormalizedEvent:
    event_id: str
    event_name: str
    event_source: str
    event_time: str
    aws_region: str

    principal_arn: str
    principal_type: str
    principal_account_id: str
    assumed_role_arn: Optional[str] = None
    session_issuer_arn: Optional[str] = None

    target_resource_arn: Optional[str] = None
    target_resource_name: Optional[str] = None
    target_resource_type: Optional[str] = None

    source_ip: Optional[str] = None
    user_agent: Optional[str] = None
    error_code: Optional[str] = None
    error_message: Optional[str] = None

    policy_arn: Optional[str] = None
    policy_name: Optional[str] = None
    role_name: Optional[str] = None
    user_name: Optional[str] = None
    group_name: Optional[str] = None
    tag_key: Optional[str] = None
    tag_value: Optional[str] = None
    tags: Dict[str, str] = field(default_factory=dict)
    access_key_id: Optional[str] = None

    request_parameters: Dict[str, Any] = field(default_factory=dict)

    is_iam_relevant: bool = False
    is_error: bool = False
    read_only: bool = False

    _principal_type_canonical: Optional[PrincipalType] = None

    def principal_type_canonical(self) -> PrincipalType:
        if self._principal_type_canonical is None:
            self._principal_type_canonical = canonical_principal_type(
                self.principal_arn, self.session_issuer_arn
            )
        return self._principal_type_canonical

    def principal_display(self) -> str:
        if self.assumed_role_arn:
            return self.assumed_role_arn
        return self.principal_arn

    def to_summary(self) -> str:
        parts = [
            f"Event: {self.event_name}",
            f"Principal: {self.principal_display()}",
            f"Time: {self.event_time}",
            f"Region: {self.aws_region}",
        ]
        if self.target_resource_arn:
            parts.append(f"Target: {self.target_resource_arn}")
        if self.error_code:
            parts.append(f"Error: {self.error_code}")
        if self.source_ip:
            parts.append(f"Source IP: {self.source_ip}")
        return " | ".join(parts)


class CloudTrailNormalizer:
    def __init__(
        self,
        iam_only: bool = True,
        exclude_operator_arns: Optional[Iterable[str]] = None,
    ):
        self.iam_only = iam_only
        exclude = [a.strip().lower() for a in (exclude_operator_arns or []) if a]
        self.exclude_operator_arns: FrozenSet[str] = frozenset(exclude)

    def normalize_file(self, path: Path) -> List[NormalizedEvent]:
        with path.open("r", encoding="utf-8") as fh:
            raw = json.load(fh)

        if isinstance(raw, dict):
            records = raw.get("Records", raw.get("events", [raw]))
        elif isinstance(raw, list):
            records = raw
        else:
            return []

        events = []
        for record in records:
            event = self._normalize_record(record)
            if event:
                if not self.iam_only or event.is_iam_relevant:
                    events.append(event)
        return events

    def normalize_list(self, records: List[Dict[str, Any]]) -> List[NormalizedEvent]:
        events = []
        for record in records:
            event = self._normalize_record(record)
            if event:
                if not self.iam_only or event.is_iam_relevant:
                    events.append(event)
        return events

    def _normalize_record(self, record: Dict[str, Any]) -> Optional[NormalizedEvent]:
        if not isinstance(record, dict):
            return None

        event_name = record.get("eventName", "")
        event_source = record.get("eventSource", "")
        is_relevant = (
            event_source in IAM_RELEVANT_SOURCES
            or event_name in IAM_RELEVANT_ACTIONS
        )

        identity = record.get("userIdentity", {})
        principal_arn, principal_type, principal_account, assumed_role_arn, session_issuer_arn = \
            self._extract_principal(identity)

        if self.exclude_operator_arns and self._is_operator_event(
            principal_arn, assumed_role_arn, session_issuer_arn
        ):
            return None

        params = record.get("requestParameters") or {}
        target_arn, target_name, target_type = self._extract_target(event_name, params)

        error_code = record.get("errorCode")

        return NormalizedEvent(
            event_id=record.get("eventID", ""),
            event_name=event_name,
            event_source=event_source,
            event_time=str(record.get("eventTime", "")),
            aws_region=record.get("awsRegion", ""),
            principal_arn=principal_arn,
            principal_type=principal_type,
            principal_account_id=principal_account,
            assumed_role_arn=assumed_role_arn,
            session_issuer_arn=session_issuer_arn,
            target_resource_arn=target_arn,
            target_resource_name=target_name,
            target_resource_type=target_type,
            source_ip=record.get("sourceIPAddress"),
            user_agent=record.get("userAgent"),
            error_code=error_code,
            error_message=record.get("errorMessage"),
            policy_arn=params.get("policyArn"),
            policy_name=params.get("policyName"),
            role_name=params.get("roleName"),
            user_name=params.get("userName"),
            group_name=params.get("groupName"),
            tag_key=self._extract_tag_key(params),
            tag_value=self._extract_tag_value(params),
            tags=self._extract_all_tags(params),
            access_key_id=params.get("accessKeyId"),
            request_parameters=params,
            is_iam_relevant=is_relevant,
            is_error=bool(error_code),
            read_only=record.get("readOnly", False),
        )

    def _is_operator_event(
        self,
        principal_arn: str,
        assumed_role_arn: Optional[str],
        session_issuer_arn: Optional[str],
    ) -> bool:
        for arn in (principal_arn, assumed_role_arn, session_issuer_arn):
            if arn and arn.strip().lower() in self.exclude_operator_arns:
                return True
        return False

    def _extract_principal(self, identity: Dict[str, Any]):
        principal_type = identity.get("type", "Unknown")
        principal_arn = identity.get("arn", "") or ""
        principal_account = identity.get("accountId", "") or ""
        assumed_role_arn = None
        session_issuer_arn = None

        if principal_type == "AssumedRole":
            session_issuer = identity.get("sessionContext", {}).get("sessionIssuer", {})
            session_issuer_arn = session_issuer.get("arn")
            assumed_role_arn = session_issuer_arn
            if not principal_account:
                principal_account = session_issuer.get("accountId", "") or ""

        if not principal_arn:
            if principal_type == "AWSService":
                invoked_by = (identity.get("invokedBy") or "").strip()
                if invoked_by:
                    principal_arn = f"service:{invoked_by}"
            elif identity.get("principalId"):
                principal_arn = f"principalId:{identity.get('principalId')}"

        return principal_arn, principal_type, principal_account, assumed_role_arn, session_issuer_arn

    def _extract_target(self, event_name: str, params: Dict[str, Any]):
        target_arn = None
        target_name = None
        target_type = None

        if "roleArn" in params:
            target_arn = params["roleArn"]
            target_type = "IAMRole"
        elif "roleName" in params:
            target_name = params["roleName"]
            target_type = "IAMRole"
        elif "userName" in params:
            target_name = params["userName"]
            target_type = "IAMUser"
        elif "groupName" in params:
            target_name = params["groupName"]
            target_type = "IAMGroup"
        elif "policyArn" in params:
            target_arn = params["policyArn"]
            target_type = "IAMPolicy"

        return target_arn, target_name, target_type

    def _extract_tag_key(self, params: Dict[str, Any]) -> Optional[str]:
        tags = self._extract_all_tags(params)
        if tags:
            return next(iter(tags.keys()))
        return None
    
    def _extract_tag_value(self, params: Dict[str, Any]) -> Optional[str]:
        tags = self._extract_all_tags(params)
        if tags:
            return next(iter(tags.values()))
        return None

    def _extract_all_tags(self, params: Dict[str, Any]) -> Dict[str, str]:
        extracted: Dict[str, str] = {}

        tags = params.get("tags", {})
        if isinstance(tags, dict):
            for k, v in tags.items():
                if k is not None and v is not None:
                    extracted[str(k)] = str(v)

        tag_list = params.get("tagList", [])
        if isinstance(tag_list, list):
            for item in tag_list:
                if isinstance(item, dict):
                    k = item.get("key")
                    v = item.get("value")
                    if k is not None and v is not None:
                        extracted[str(k)] = str(v)

        return extracted