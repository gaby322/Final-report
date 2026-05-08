from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class Policy:
    policy_id: str
    name: str
    document: Dict
    arn: Optional[str] = None
    default_version_id: Optional[str] = None
    is_attached: bool = False
    attachment_count: int = 0


@dataclass
class MFADevice:
    serial_number: str
    type: str


@dataclass
class AccessKeyMetadata:
    user_name: str
    access_key_id: str
    status: str
    created_date: str
    last_used_date: Optional[str] = None
    last_used_service: Optional[str] = None


@dataclass
class PasswordPolicy:
    minimum_password_length: Optional[int] = None
    require_symbols: Optional[bool] = None
    require_numbers: Optional[bool] = None
    require_uppercase_characters: Optional[bool] = None
    require_lowercase_characters: Optional[bool] = None
    allow_users_to_change_password: Optional[bool] = None
    expire_passwords: Optional[bool] = None
    max_password_age: Optional[int] = None
    password_reuse_prevention: Optional[int] = None


@dataclass
class CredentialReportEntry:
    user: str
    user_type: str
    arn: str
    account_id: str
    password_enabled: str
    password_last_changed: Optional[str] = None
    password_last_used: Optional[str] = None
    mfa_active: str = "false"
    access_key_1_active: str = "false"
    access_key_1_last_rotated: Optional[str] = None
    access_key_1_last_used_date: Optional[str] = None
    access_key_2_active: str = "false"
    access_key_2_last_rotated: Optional[str] = None
    access_key_2_last_used_date: Optional[str] = None


@dataclass
class SAMLProvider:
    provider_name: str
    provider_arn: str
    valid_until: Optional[str] = None
    create_date: Optional[str] = None


@dataclass
class Certificate:
    certificate_id: str
    certificate_arn: str
    upload_date: Optional[str] = None
    valid_until: Optional[str] = None


@dataclass
class ServiceSpecificCredential:
    user_name: str
    service_name: str
    status: str
    create_date: Optional[str] = None


@dataclass
class User:
    user_name: str
    arn: str
    user_id: str
    create_date: Optional[str] = None
    path: Optional[str] = None
    tags: Dict[str, str] = field(default_factory=dict)
    attached_policies: List[Policy] = field(default_factory=list)
    inline_policies: List[Policy] = field(default_factory=list)
    groups: List[str] = field(default_factory=list)
    mfa_devices: List[MFADevice] = field(default_factory=list)
    access_keys: List[AccessKeyMetadata] = field(default_factory=list)


@dataclass
class Role:
    role_name: str
    arn: str
    role_id: str
    create_date: Optional[str] = None
    path: Optional[str] = None
    assume_role_policy_document: Optional[Dict] = field(default_factory=dict)
    tags: Dict[str, str] = field(default_factory=dict)
    attached_policies: List[Policy] = field(default_factory=list)
    inline_policies: List[Policy] = field(default_factory=list)


@dataclass
class Group:
    group_name: str
    arn: str
    group_id: str
    path: Optional[str] = None
    tags: Dict[str, str] = field(default_factory=dict)
    attached_policies: List[Policy] = field(default_factory=list)
    inline_policies: List[Policy] = field(default_factory=list)
    members: List[str] = field(default_factory=list)
