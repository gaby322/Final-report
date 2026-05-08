from __future__ import annotations

import csv
import random
import time
from io import StringIO
from typing import Dict, List

from botocore.exceptions import ClientError

from shared.aws.models import (
    AccessKeyMetadata,
    Certificate,
    CredentialReportEntry,
    Group,
    MFADevice,
    Policy,
    Role,
    ServiceSpecificCredential,
    User,
    PasswordPolicy,
)
from shared.core.storage import Inventory
from shared.aws.provider.aws_provider import AwsProvider


class IAMCollector:
    def __init__(self, provider: AwsProvider, inventory: Inventory):
        self.provider = provider
        self.inventory = inventory
        self.iam = provider.get_client("iam")
        self.org = provider.get_client("organizations")

    def collect_all(self) -> Inventory:
        self.collect_users()
        self.collect_roles()
        self.collect_groups()
        self.collect_policies()
        self.collect_account_summary()
        self.collect_virtual_mfa_devices()
        self.collect_credential_report()
        self.collect_password_policy()
        self.collect_server_certificates()
        self.collect_service_specific_credentials()
        return self.inventory

    def collect_users(self) -> None:
        paginator = self.iam.get_paginator("list_users")
        for page in paginator.paginate():
            for entry in page.get("Users", []):
                user_name = entry.get("UserName")
                user = User(
                    user_name=user_name,
                    arn=entry.get("Arn", ""),
                    user_id=entry.get("UserId", ""),
                    create_date=str(entry.get("CreateDate", "")),
                    path=entry.get("Path"),
                    tags=self._list_tags("user", user_name),
                )
                user.groups = self._list_groups_for_user(user_name)
                user.attached_policies = self._list_attached_user_policies(user_name)
                user.inline_policies = self._list_user_inline_policies(user_name)
                user.mfa_devices = self._list_mfa_devices(user_name)
                user.access_keys = self._list_access_keys(user_name)
                self.inventory.users[user_name] = user

    def collect_roles(self) -> None:
        paginator = self.iam.get_paginator("list_roles")
        for page in paginator.paginate():
            for entry in page.get("Roles", []):
                role_name = entry.get("RoleName")
                role = Role(
                    role_name=role_name,
                    arn=entry.get("Arn", ""),
                    role_id=entry.get("RoleId", ""),
                    create_date=str(entry.get("CreateDate", "")),
                    path=entry.get("Path"),
                    assume_role_policy_document=entry.get("AssumeRolePolicyDocument", {}),
                    tags=self._list_tags("role", role_name),
                )
                role.attached_policies = self._list_attached_role_policies(role_name)
                role.inline_policies = self._list_role_inline_policies(role_name)
                self.inventory.roles[role_name] = role

    def collect_groups(self) -> None:
        paginator = self.iam.get_paginator("list_groups")
        for page in paginator.paginate():
            for entry in page.get("Groups", []):
                group_name = entry.get("GroupName")
                group = Group(
                    group_name=group_name,
                    arn=entry.get("Arn", ""),
                    group_id=entry.get("GroupId", ""),
                    path=entry.get("Path"),
                    tags=self._list_tags("group", group_name),
                )
                group.members = self._list_group_members(group_name)
                group.attached_policies = self._list_attached_group_policies(group_name)
                group.inline_policies = self._list_group_inline_policies(group_name)
                self.inventory.groups[group_name] = group

    def collect_policies(self) -> None:
        paginator = self.iam.get_paginator("list_policies")
        for page in paginator.paginate(Scope="Local"):
            for entry in page.get("Policies", []):
                policy_arn = entry.get("Arn", "")
                policy = Policy(
                    policy_id=entry.get("PolicyId", ""),
                    name=entry.get("PolicyName", ""),
                    arn=policy_arn,
                    document=self._get_policy_document(policy_arn, entry.get("DefaultVersionId")),
                    default_version_id=entry.get("DefaultVersionId"),
                    is_attached=entry.get("AttachmentCount", 0) > 0,
                    attachment_count=entry.get("AttachmentCount", 0),
                )
                self.inventory.policies[policy_arn] = policy

    def collect_credential_report(self) -> None:
        try:
            self.iam.generate_credential_report()
        except Exception:
            pass
        try:
            report = self.iam.get_credential_report()
        except Exception:
            return
        content = report.get("Content", b"")
        if isinstance(content, bytes):
            content = content.decode("utf-8", errors="replace")
        elif not isinstance(content, str):
            content = str(content)

        if not content:
            return

        reader = csv.DictReader(StringIO(content))
        for row in reader:
            data = {k.strip(): (v.strip() if isinstance(v, str) else v) for k, v in row.items()}
            entry = CredentialReportEntry(
                user=data.get("user", ""),
                user_type=data.get("user_type", ""),
                arn=data.get("arn", ""),
                account_id=data.get("account_id", ""),
                password_enabled=data.get("password_enabled", "false"),
                password_last_changed=data.get("password_last_changed"),
                password_last_used=data.get("password_last_used"),
                mfa_active=data.get("mfa_active", "false"),
                access_key_1_active=data.get("access_key_1_active", "false"),
                access_key_1_last_rotated=data.get("access_key_1_last_rotated"),
                access_key_1_last_used_date=data.get("access_key_1_last_used_date"),
                access_key_2_active=data.get("access_key_2_active", "false"),
                access_key_2_last_rotated=data.get("access_key_2_last_rotated"),
                access_key_2_last_used_date=data.get("access_key_2_last_used_date"),
            )
            self.inventory.credential_report[entry.user] = entry

    def collect_password_policy(self) -> None:
        try:
            response = self.iam.get_account_password_policy()
            policy = response.get("PasswordPolicy", {})
            self.inventory.password_policy = PasswordPolicy(
                minimum_password_length=policy.get("MinimumPasswordLength"),
                require_symbols=policy.get("RequireSymbols"),
                require_numbers=policy.get("RequireNumbers"),
                require_uppercase_characters=policy.get("RequireUppercaseCharacters"),
                require_lowercase_characters=policy.get("RequireLowercaseCharacters"),
                allow_users_to_change_password=policy.get("AllowUsersToChangePassword"),
                expire_passwords=policy.get("ExpirePasswords"),
                max_password_age=policy.get("MaxPasswordAge"),
                password_reuse_prevention=policy.get("PasswordReusePrevention"),
            )
        except self.iam.exceptions.NoSuchEntityException:
            self.inventory.password_policy = PasswordPolicy()

    def collect_account_summary(self) -> None:
        try:
            self.inventory.account_summary = self.iam.get_account_summary()
        except Exception:
            self.inventory.account_summary = {}

    def collect_virtual_mfa_devices(self) -> None:
        virtual_mfa_devices = []
        paginator = self.iam.get_paginator("list_virtual_mfa_devices")
        for page in paginator.paginate():
            for device in page.get("VirtualMFADevices", []):
                virtual_mfa_devices.append(device)
        self.inventory.virtual_mfa_devices = virtual_mfa_devices

    def collect_organization_features(self) -> None:
        try:
            response = self.org.list_organizations_features()
            self.inventory.organization_features = response.get("EnabledFeatures", [])
        except Exception:
            self.inventory.organization_features = []

    def collect_server_certificates(self) -> None:
        paginator = self.iam.get_paginator("list_server_certificates")
        for page in paginator.paginate():
            for entry in page.get("ServerCertificateMetadataList", []):
                cert = Certificate(
                    certificate_id=entry.get("ServerCertificateId", ""),
                    certificate_arn=entry.get("Arn", ""),
                    upload_date=str(entry.get("UploadDate", "")),
                )
                self.inventory.certificates[cert.certificate_arn] = cert

    def collect_service_specific_credentials(self) -> None:
        for user_name in self.inventory.users:
            try:
                response = self.iam.list_service_specific_credentials(UserName=user_name)
            except Exception:
                continue

            for entry in response.get("ServiceSpecificCredentials", []):
                credential = ServiceSpecificCredential(
                    user_name=entry.get("UserName", ""),
                    service_name=entry.get("ServiceName", ""),
                    status=entry.get("Status", ""),
                    create_date=str(entry.get("CreateDate", "")),
                )
                self.inventory.service_specific_credentials.append(credential)

    def _list_tags(self, resource_type: str, resource_name: str) -> Dict[str, str]:
        if resource_type == "user":
            param_name = "UserName"
        elif resource_type == "role":
            param_name = "RoleName"
        elif resource_type == "group":
            param_name = "GroupName"
        else:
            return {}

        try:
            fn = getattr(self.iam, f"list_{resource_type}_tags")
            response = fn(**{param_name: resource_name})
            return {tag["Key"]: tag["Value"] for tag in response.get("Tags", [])}
        except Exception:
            return {}

    def _list_groups_for_user(self, user_name: str) -> List[str]:
        return [group["GroupName"] for group in self.iam.list_groups_for_user(UserName=user_name).get("Groups", [])]

    def _list_attached_user_policies(self, user_name: str) -> List[Policy]:
        return self._list_attached_policies("list_attached_user_policies", UserName=user_name)

    def _list_user_inline_policies(self, user_name: str) -> List[Policy]:
        return self._list_inline_policies("list_user_policies", UserName=user_name, UserName_policy=True)

    def _list_attached_role_policies(self, role_name: str) -> List[Policy]:
        return self._list_attached_policies("list_attached_role_policies", RoleName=role_name)

    def _list_role_inline_policies(self, role_name: str) -> List[Policy]:
        return self._list_inline_policies("list_role_policies", RoleName=role_name, RoleName_policy=True)

    def _list_attached_group_policies(self, group_name: str) -> List[Policy]:
        return self._list_attached_policies("list_attached_group_policies", GroupName=group_name)

    def _list_group_inline_policies(self, group_name: str) -> List[Policy]:
        return self._list_inline_policies("list_group_policies", GroupName=group_name, GroupName_policy=True)

    def _list_attached_policies(self, method_name: str, **kwargs) -> List[Policy]:
        policies: List[Policy] = []
        paginator = self.iam.get_paginator(method_name)
        for page in paginator.paginate(**kwargs):
            for entry in page.get("AttachedPolicies", []):
                arn = entry.get("PolicyArn", "")
                policies.append(Policy(policy_id="", name=entry.get("PolicyName", ""), document={}, arn=arn, is_attached=True))
        return policies

    def _list_inline_policies(self, method_name: str, **kwargs) -> List[Policy]:
        policies: List[Policy] = []
        response = getattr(self.iam, method_name)(**{k: v for k, v in kwargs.items() if not k.endswith("_policy")})
        for policy_name in response.get("PolicyNames", []):
            try:
                if "UserName" in kwargs:
                    policy_document = self.iam.get_user_policy(UserName=kwargs["UserName"], PolicyName=policy_name)
                elif "RoleName" in kwargs:
                    policy_document = self.iam.get_role_policy(RoleName=kwargs["RoleName"], PolicyName=policy_name)
                elif "GroupName" in kwargs:
                    policy_document = self.iam.get_group_policy(GroupName=kwargs["GroupName"], PolicyName=policy_name)
                else:
                    continue
                policy = Policy(
                    policy_id="",
                    name=policy_name,
                    document=policy_document.get("PolicyDocument", {}),
                )
                policies.append(policy)
            except Exception:
                continue
        return policies

    def _list_mfa_devices(self, user_name: str) -> List[MFADevice]:
        devices: List[MFADevice] = []
        for device in self.iam.list_mfa_devices(UserName=user_name).get("MFADevices", []):
            serial_number = device.get("SerialNumber", "")
            mfa_type = "hardware"
            try:
                mfa_type = serial_number.split(":")[5].split("/")[0]
            except Exception:
                mfa_type = "hardware"
            devices.append(MFADevice(serial_number=serial_number, type=mfa_type))
        return devices

    def _list_access_keys(self, user_name: str) -> List[AccessKeyMetadata]:
        keys: List[AccessKeyMetadata] = []
        response = self.iam.list_access_keys(UserName=user_name)
        for entry in response.get("AccessKeyMetadata", []):
            access_key_id = entry.get("AccessKeyId", "")
            last_used = self._get_access_key_last_used_safe(access_key_id)
            keys.append(
                AccessKeyMetadata(
                    user_name=user_name,
                    access_key_id=access_key_id,
                    status=entry.get("Status", ""),
                    created_date=str(entry.get("CreateDate", "")),
                    last_used_date=str(last_used.get("AccessKeyLastUsed", {}).get("LastUsedDate", "")),
                    last_used_service=last_used.get("AccessKeyLastUsed", {}).get("ServiceName"),
                )
            )
        return keys

    def _get_access_key_last_used_safe(self, access_key_id: str, max_retries: int = 4) -> Dict:
        for attempt in range(max_retries):
            try:
                return self.iam.get_access_key_last_used(AccessKeyId=access_key_id)
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code", "")
                if code in ("Throttling", "ThrottlingException", "RequestThrottled") and attempt < max_retries - 1:
                    time.sleep((2 ** attempt) + random.uniform(0.0, 0.5))
                    continue
                return {}
            except Exception:
                return {}
        return {}

    def _list_group_members(self, group_name: str) -> List[str]:
        return [user.get("UserName") for user in self.iam.get_group(GroupName=group_name).get("Users", [])]

    def _get_policy_document(self, policy_arn: str, version_id: str) -> Dict:
        try:
            policy = self.iam.get_policy(PolicyArn=policy_arn)
            document = self.iam.get_policy_version(
                PolicyArn=policy_arn, VersionId=version_id or policy.get("Policy", {}).get("DefaultVersionId")
            )
            return document.get("PolicyVersion", {}).get("Document", {})
        except Exception:
            return {}
