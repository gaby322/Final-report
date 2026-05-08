from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Dict, Optional, Set

import boto3
from botocore.exceptions import ClientError
from botocore.session import Session as BotocoreSession


@dataclass
class AwsIdentity:
    account_id: str
    partition: str
    region: str
    arn: str


class AwsProvider:
    def __init__(
        self,
        region: Optional[str] = None,
        profile: Optional[str] = None,
        role_arn: Optional[str] = None,
        session_name: str = "hybrid-framework-session",
        external_id: Optional[str] = None,
        aws_access_key_id: Optional[str] = None,
        aws_secret_access_key: Optional[str] = None,
        aws_session_token: Optional[str] = None,
    ):
        self.region = region or os.getenv("AWS_DEFAULT_REGION") or "us-east-1"
        self.profile = profile
        self.role_arn = role_arn
        self.external_id = external_id
        self.session_name = session_name
        self.aws_access_key_id = aws_access_key_id
        self.aws_secret_access_key = aws_secret_access_key
        self.aws_session_token = aws_session_token
        self._session = self._create_session()
        self._clients: Dict[str, Any] = {}
        self.identity = self._resolve_identity()

    def _create_session(self) -> boto3.Session:
        session_kwargs: Dict[str, Any] = {}
        if self.profile:
            session_kwargs["profile_name"] = self.profile
        if self.aws_access_key_id:
            session_kwargs["aws_access_key_id"] = self.aws_access_key_id
        if self.aws_secret_access_key:
            session_kwargs["aws_secret_access_key"] = self.aws_secret_access_key
        if self.aws_session_token:
            session_kwargs["aws_session_token"] = self.aws_session_token
        if self.region:
            session_kwargs["region_name"] = self.region
        session = boto3.Session(**session_kwargs)

        if self.role_arn:
            sts_client = session.client("sts")
            assume_kwargs: Dict[str, Any] = {
                "RoleArn": self.role_arn,
                "RoleSessionName": self.session_name,
            }
            if self.external_id:
                assume_kwargs["ExternalId"] = self.external_id
            try:
                response = sts_client.assume_role(**assume_kwargs)
                creds = response["Credentials"]
                session = boto3.Session(
                    aws_access_key_id=creds["AccessKeyId"],
                    aws_secret_access_key=creds["SecretAccessKey"],
                    aws_session_token=creds["SessionToken"],
                    region_name=self.region,
                )
            except ClientError as exc:
                raise RuntimeError(f"Unable to assume role {self.role_arn}: {exc}")

        return session

    def get_client(self, service_name: str, region_name: Optional[str] = None) -> Any:
        region = region_name or self.region
        key = f"{service_name}:{region}"
        if key not in self._clients:
            self._clients[key] = self._session.client(service_name, region_name=region)
        return self._clients[key]

    def _resolve_identity(self) -> AwsIdentity:
        sts = self.get_client("sts", region_name=self.region)
        identity = sts.get_caller_identity()
        arn = identity.get("Arn", "")
        account = identity.get("Account", "")
        partition = arn.split(":")[1] if ":" in arn else "aws"
        return AwsIdentity(account_id=account, partition=partition, region=self.region, arn=arn)

    def get_session(self) -> boto3.Session:
        return self._session

    def refresh_clients(self) -> None:
        self._clients.clear()

    def get_context(self) -> Dict[str, str]:
        return {
            "account_id": self.identity.account_id,
            "partition": self.identity.partition,
            "region": self.identity.region,
            "arn": self.identity.arn,
        }
