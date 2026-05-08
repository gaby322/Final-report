from typing import Dict, Any, Optional
from phase1.aws_iam.rules.base_check import RBACCheck


class iam_root_hardware_mfa_enabled(RBACCheck):
    def execute(self) -> Optional[Dict[str, Any]]:
        root_user = "<root_account>"
        root_entry = self.inventory.credential_report.get(root_user)

        if not root_entry:
            return {
                "status": "FAIL",
                "status_extended": "Root account not found in credential report.",
                "resource_type": "AWS::IAM::User",
                "resource_id": "root",
                "category": "IAM",
                "evidence_summary": "Root account credential report entry missing",
                "evidence_details": {},
            }

        has_credentials = (
            root_entry.password_enabled == "true"
            or root_entry.access_key_1_active == "true"
            or root_entry.access_key_2_active == "true"
        )

        if not has_credentials:
            return {
                "status": "PASS",
                "status_extended": "Root account has no active credentials to protect with hardware MFA.",
                "resource_type": "AWS::IAM::User",
                "resource_id": "root",
                "category": "IAM",
                "evidence_summary": "Root account has no active password or access keys",
                "evidence_details": {},
            }

        account_summary = self.inventory.account_summary.get("SummaryMap", {}) if self.inventory.account_summary else {}
        account_mfa_enabled = account_summary.get("AccountMFAEnabled", 0)
        virtual_mfa_devices = self.inventory.virtual_mfa_devices

        if account_mfa_enabled > 0:
            root_virtual_mfa = any(
                "root" in device.get("User", {}).get("Arn", "") for device in virtual_mfa_devices
            )
            if root_virtual_mfa:
                return {
                    "status": "FAIL",
                    "status_extended": "Root account has a virtual MFA device instead of hardware MFA.",
                    "resource_type": "AWS::IAM::User",
                    "resource_id": "root",
                    "category": "IAM",
                    "evidence_summary": "Root account is protected by virtual MFA rather than hardware MFA",
                    "evidence_details": {"virtual_mfa_devices": virtual_mfa_devices},
                }
            return {
                "status": "PASS",
                "status_extended": "Root account has hardware MFA enabled.",
                "resource_type": "AWS::IAM::User",
                "resource_id": "root",
                "category": "IAM",
                "evidence_summary": "Root account hardware MFA is active",
                "evidence_details": {
                    "AccountMFAEnabled": account_summary.get("AccountMFAEnabled", 0),
                    "MFADevices": account_summary.get("MFADevices", 0),
                    "MFADevicesInUse": account_summary.get("MFADevicesInUse", 0)
                    }
            }

        if root_entry.mfa_active == "true":
            return {
                "status": "PASS",
                "status_extended": "Root account has MFA enabled.",
                "resource_type": "AWS::IAM::User",
                "resource_id": "root",
                "category": "IAM",
                "evidence_summary": "Root account MFA is active",
                "evidence_details": {
                   "mfa_active": root_entry.mfa_active,
                   "AccountMFAEnabled": account_summary.get("AccountMFAEnabled", 0),
                   "MFADevices": account_summary.get("MFADevices", 0),
                   "MFADevicesInUse": account_summary.get("MFADevicesInUse", 0)
                   }
            }

        return {
            "status": "FAIL",
            "status_extended": "MFA is not enabled for the root account.",
            "resource_type": "AWS::IAM::User",
            "resource_id": "root",
            "category": "IAM",
            "evidence_summary": "Root account MFA is not enabled",
            "evidence_details": {
              "AccountMFAEnabled": account_summary.get("AccountMFAEnabled", 0),
              "MFADevices": account_summary.get("MFADevices", 0),
              "MFADevicesInUse": account_summary.get("MFADevicesInUse", 0)
            }
        }