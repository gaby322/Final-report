from typing import Dict, Any, Optional, List
from datetime import datetime
from phase1.aws_iam.rules.base_check import RBACCheck


class iam_no_expired_server_certificates_stored(RBACCheck):
    def execute(self) -> Optional[Dict[str, Any]]:
        violations: List[Dict[str, Any]] = []

        for cert_arn, cert in self.inventory.certificates.items():
            expired = False
            reason = ""
            if cert.valid_until:
                try:
                    valid_until = datetime.fromisoformat(cert.valid_until.replace('Z', '+00:00'))
                    if valid_until < datetime.now():
                        expired = True
                        reason = f"expired_on:{cert.valid_until}"
                except ValueError:
                    expired = True
                    reason = f"unparseable_valid_until:{cert.valid_until}"
            if expired:
                violations.append({
                    "resource_type": "AWS::IAM::ServerCertificate",
                    "resource_id": cert_arn,
                    "name": cert.certificate_id,
                    "detail": {"reason": reason, "valid_until": cert.valid_until},
                })

        if violations:
            names = ", ".join(v["name"] for v in violations)
            return {
                "status": "FAIL",
                "status_extended": f"Expired server certificates found: {names}",
                "resource_type": "AWS::IAM::ServerCertificate",
                "resource_id": self.provider.identity.account_id,
                "category": "IAM",
                "evidence_summary": f"{len(violations)} expired server certificates stored",
                "evidence_details": {"violations": violations},
            }

        return {
            "status": "PASS",
            "status_extended": "No expired server certificates stored",
            "resource_type": "AWS::IAM::ServerCertificate",
            "resource_id": self.provider.identity.account_id,
            "category": "IAM",
            "evidence_summary": "All server certificates are valid",
            "evidence_details": {"violations": []},
        }