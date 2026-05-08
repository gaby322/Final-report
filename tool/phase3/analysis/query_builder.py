from __future__ import annotations


from typing import List

from phase3.analysis.correlator import EvidenceBundle


_ACTION_DESCRIPTIONS: dict = {
    "AssumeRole": "role assumption privilege escalation cross-account trust",
    "AssumeRoleWithSAML": "SAML federation role assumption identity provider trust",
    "AssumeRoleWithWebIdentity": "web identity federation role assumption OIDC trust",
    "CreatePolicyVersion": "IAM policy version creation privilege escalation policy injection",
    "SetDefaultPolicyVersion": "IAM policy version escalation change default policy version",
    "AttachRolePolicy": "attach managed policy to role privilege escalation AdministratorAccess",
    "AttachUserPolicy": "attach managed policy to user privilege escalation",
    "AttachGroupPolicy": "attach managed policy to group privilege escalation",
    "PutRolePolicy": "inline policy injection role privilege escalation",
    "PutUserPolicy": "inline policy injection user privilege escalation",
    "UpdateAssumeRolePolicy": "trust policy modification role assumption bypass",
    "CreateUser": "new IAM user creation persistence cloud account",
    "CreateRole": "new IAM role creation persistence cloud account",
    "CreateAccessKey": "access key creation credential abuse persistence",
    "CreateLoginProfile": "console login profile creation persistence credential",
    "UpdateLoginProfile": "console login profile update credential abuse",
    "AddUserToGroup": "add user to group privilege escalation group policy",
    "AddRoleToInstanceProfile": "instance profile attachment role pivot EC2 PassRole",
    "DeactivateMFADevice": "MFA device deactivation multi-factor authentication bypass",
    "DeleteVirtualMFADevice": "virtual MFA device deletion authentication weakening",
    "CreateSAMLProvider": "SAML identity provider creation federation trust establishment",
    "UpdateSAMLProvider": "SAML provider modification federation trust manipulation",
    "TagUser": "IAM user tag modification ABAC attribute escalation",
    "TagRole": "IAM role tag modification ABAC attribute-based escalation",
    "UntagUser": "IAM user tag removal ABAC bypass defense evasion",
    "UntagRole": "IAM role tag removal ABAC bypass defense evasion",
    "GetCredentialReport": "credential report access account discovery enumeration",
    "GenerateCredentialReport": "credential report generation account discovery enumeration",
    "GetFederationToken": "federation token access temporary credential abuse",
    "GetSessionToken": "session token access credential abuse temporary credential",
}

_EDGE_DESCRIPTIONS: dict = {
    "sts:AssumeRole": "privilege escalation role assumption trust policy",
    "iam:PassRole_via_EC2": "PassRole privilege escalation EC2 instance profile",
    "iam:PassRole_via_Lambda": "PassRole privilege escalation Lambda function execution",
    "iam:PassRole_via_Glue": "PassRole privilege escalation Glue job service role",
    "iam:CreatePolicyVersion": "policy version privilege escalation policy injection",
    "iam:AttachRolePolicy": "attach policy privilege escalation managed policy",
    "iam:PutRolePolicy": "inline policy injection privilege escalation",
    "iam:UpdateAssumeRolePolicy": "trust policy modification privilege escalation",
    "iam:AttachUserPolicy": "attach user policy privilege escalation",
    "iam:CreateAccessKey": "access key creation credential theft persistence",
    "iam:AddUserToGroup": "group membership manipulation privilege escalation",
    "abac:tag_conditioned_assume": "ABAC tag condition bypass attribute escalation",
}

_CATEGORY_TERMS: dict = {
    "abac": "ABAC attribute-based access control tag escalation misconfiguration",
    "privilege-escalation": "privilege escalation IAM permission misconfiguration",
    "compliance": "IAM compliance CIS NIST least privilege best practice",
    "least-privilege": "least privilege overly permissive IAM policy",
    "tagging": "resource tagging ABAC tag enforcement",
    "critical": "critical IAM misconfiguration high severity risk",
    "security": "IAM security misconfiguration vulnerability",
    "iam": "IAM identity access management policy",
}

_TIER_FALLBACK_TERMS: dict = {
    "STATIC_STANDALONE": "static IAM posture misconfiguration",
    "DYNAMIC_STANDALONE": "dynamic IAM CloudTrail activity",
    "PARTIALLY_CORRELATED": "correlated IAM activity and escalation evidence",
    "STRONGLY_CORRELATED": "strongly correlated IAM exploitation path",
}


class QueryBuilder:

    @staticmethod
    def _readable_check_id(check_id: str) -> str:
        return check_id.replace("_", " ").replace("iam ", "IAM ").strip()

    def build(self, bundle: EvidenceBundle) -> str:
        terms: List[str] = []

        for edge_type in bundle.p2_edge_types[:3]:
            desc = _EDGE_DESCRIPTIONS.get(
                edge_type,
                edge_type.replace("_", " ").replace(":", " "),
            )
            terms.append(desc)

        event_name = bundle.event.event_name
        if event_name and event_name != "[StaticFinding]":
            event_desc = _ACTION_DESCRIPTIONS.get(event_name, event_name)
            terms.append(event_desc)

        for finding in bundle.p1_findings[:3]:
            if finding.check_id:
                terms.append(self._readable_check_id(finding.check_id))

        for cat in bundle.p1_categories[:2]:
            normalized_cat = cat.strip().lower()
            cat_term = _CATEGORY_TERMS.get(normalized_cat, normalized_cat)
            terms.append(cat_term)

        if bundle.mitre_mapping and not bundle.mitre_mapping.is_unmapped:
            m = bundle.mitre_mapping
            mitre_term = f"MITRE {m.tactic} {m.technique}"
            if m.sub_technique:
                mitre_term += f" {m.sub_technique}"
            terms.append(mitre_term)

        seen = set()
        unique_terms = []
        for t in terms:
            t_normalized = t.strip().lower()
            if t_normalized and t_normalized not in seen:
                seen.add(t_normalized)
                unique_terms.append(t.strip())

        if unique_terms:
            return " | ".join(unique_terms)

        for finding in bundle.p1_findings:
            if finding.check_id:
                return self._readable_check_id(finding.check_id)

        if event_name and event_name != "[StaticFinding]":
            return event_name

        fallback_terms: List[str] = []

        tier_term = _TIER_FALLBACK_TERMS.get(bundle.correlation_tier, "")
        if tier_term:
          fallback_terms.append(tier_term)

        if bundle.event.event_source:
          fallback_terms.append(bundle.event.event_source)

        if bundle.event.principal_type:
          fallback_terms.append(bundle.event.principal_type)

        if bundle.event.target_resource_type:
          fallback_terms.append(bundle.event.target_resource_type)

        return " | ".join(fallback_terms) if fallback_terms else "AWS IAM analysis"
    

    def build_action_query(self, actions: List[str]) -> str:
        terms = [_ACTION_DESCRIPTIONS.get(a, a) for a in actions if a]
        return " ".join(terms).strip() or "IAM action"