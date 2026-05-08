from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from shared.aws.models import (
    User,
    Role,
    Group,
    Policy,
    Certificate,
    ServiceSpecificCredential,
    AccessKeyMetadata,
    PasswordPolicy,
    CredentialReportEntry,
)


@dataclass
class Inventory:

    users: Dict[str, User] = field(default_factory=dict)
    roles: Dict[str, Role] = field(default_factory=dict)
    groups: Dict[str, Group] = field(default_factory=dict)
    policies: Dict[str, Policy] = field(default_factory=dict)
    credential_report: Dict[str, CredentialReportEntry] = field(default_factory=dict)
    password_policy: Optional[PasswordPolicy] = None
    certificates: Dict[str, Certificate] = field(default_factory=dict)
    service_specific_credentials: List[ServiceSpecificCredential] = field(default_factory=list)
    account_summary: Dict[str, Any] = field(default_factory=dict)
    virtual_mfa_devices: List[Dict[str, Any]] = field(default_factory=list)
    organization_features: List[str] = field(default_factory=list)

    def snapshot(self) -> "Inventory":
        return Inventory(
            users=self.users.copy(),
            roles=self.roles.copy(),
            groups=self.groups.copy(),
            policies=self.policies.copy(),
            credential_report=self.credential_report.copy(),
            password_policy=self.password_policy,
            certificates=self.certificates.copy(),
            service_specific_credentials=list(self.service_specific_credentials),
            account_summary=self.account_summary.copy(),
            virtual_mfa_devices=list(self.virtual_mfa_devices),
            organization_features=list(self.organization_features),
        )
