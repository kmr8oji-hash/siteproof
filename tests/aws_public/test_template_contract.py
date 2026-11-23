"""Offline candidate contract checks, NOT AWS schema/IAM/service validation.

Standard library only. No AWS, auth, network, deployment or dependency calls.
Mutation tests ensure safety changes fail the local contract instead of silently
passing a JSON syntax test. No existing AWS resource is observed or modified.
"""

from copy import deepcopy
import json
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[2]
DIR = ROOT / "infra" / "public_web"
KEYS = ["home/index.html", "home/styles.css", "home/app.js",
        "compare/index.html", "compare/styles.css", "compare/app.js"]
TYPES = {"AssetsBucket": "AWS::S3::Bucket", "OriginAccess": "AWS::CloudFront::OriginAccessControl",
         "WebCachePolicy": "AWS::CloudFront::CachePolicy", "WebHeadersPolicy": "AWS::CloudFront::ResponseHeadersPolicy",
         "Distribution": "AWS::CloudFront::Distribution", "AssetsPolicy": "AWS::S3::BucketPolicy",
         "RootRedirect": "AWS::CloudFront::Function"}
PSEUDO = {"AWS::AccountId", "AWS::Partition", "AWS::Region", "AWS::StackId", "AWS::StackName", "AWS::NoValue"}


def _pairs(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError("duplicate member")
        out[key] = value
    return out


def strict_json(raw):
    def reject(value):
        raise ValueError("non-finite JSON constant")
    return json.loads(raw, object_pairs_hook=_pairs, parse_constant=reject)


def reference_errors(template):
    errors = []
    symbols = set(template.get("Resources", {})) | set(template.get("Parameters", {})) | PSEUDO
    conditions = set(template.get("Conditions", {}))
    intrinsics = {"Fn::GetAtt", "Fn::Sub", "Fn::Join", "Fn::Select", "Fn::Split", "Fn::If", "Fn::Equals"}

    def visit(value):
        if isinstance(value, list):
            for child in value:
                visit(child)
        elif isinstance(value, dict):
            for key, child in value.items():
                if key.startswith("Fn::") and key not in intrinsics:
                    errors.append("unsupported intrinsic")
                if key == "Ref" and child not in symbols:
                    errors.append("unknown Ref")
                if key == "Fn::GetAtt":
                    allowed = {"AssetsBucket": {"Arn", "RegionalDomainName"}, "Distribution": {"DomainName"}, "RootRedirect": {"FunctionARN"}}
                    if not isinstance(child, list) or len(child) != 2 or child[1] not in allowed.get(child[0], set()):
                        errors.append("unknown GetAtt")
                if key == "Fn::Sub":
                    if not isinstance(child, str):
                        errors.append("unsupported Sub form")
                    elif any(name.split(".")[0] not in symbols for name in re.findall(r"\$\{([^}]+)\}", child)):
                        errors.append("unknown Sub symbol")
                if key == "Fn::If" and (not isinstance(child, list) or len(child) != 3 or child[0] not in conditions):
                    errors.append("unknown Condition")
                visit(child)
    try:
        visit(template)
    except (TypeError, KeyError, IndexError):
        errors.append("invalid reference structure")
    return errors


def audit(template):
    """Local safety allowlist, intentionally narrower than AWS's full grammar."""
    errors = []
    def need(condition, label):
        if not condition:
            errors.append(label)
    try:
        need(type(template) is dict, "root")
        need(template["AWSTemplateFormatVersion"] == "2010-09-09", "template version")
        need("Transform" not in template and "Mappings" not in template, "no macro/external lookup")
        res = template["Resources"]
        need(set(res) == set(TYPES), "seven resources including root canonicalization")
        for logical, kind in TYPES.items():
            need(res[logical]["Type"] == kind, "resource type:" + logical)
        params = template["Parameters"]
        need(set(params) == {"PublishEnabled"}, "no unexpected parameters")
        need(params["PublishEnabled"]["Type"] == "String" and params["PublishEnabled"]["Default"] == "false"
             and params["PublishEnabled"]["AllowedValues"] == ["false", "true"], "disabled default")
        need(template["Conditions"] == {"PublicationEnabled": {"Fn::Equals": [{"Ref": "PublishEnabled"}, "true"]}}, "publication condition")
        need(template["Metadata"]["ApprovedObjectKeys"] == KEYS, "asset metadata")
        bucket = res["AssetsBucket"]
        props = bucket["Properties"]
        need(set(props) == {"PublicAccessBlockConfiguration", "OwnershipControls", "BucketEncryption", "VersioningConfiguration", "Tags"}, "private bucket property allowlist")
        need(props["PublicAccessBlockConfiguration"] == dict.fromkeys(
            ["BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"], True), "all BPA")
        need(all(type(v) is bool for v in props["PublicAccessBlockConfiguration"].values()), "BPA bools")
        need(props["OwnershipControls"] == {"Rules": [{"ObjectOwnership": "BucketOwnerEnforced"}]}, "no ACL")
        need(props["BucketEncryption"] == {"ServerSideEncryptionConfiguration": [{"ServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]}, "encryption")
        need(props["VersioningConfiguration"] == {"Status": "Enabled"}, "versioning")
        need(bucket["DeletionPolicy"] == bucket["UpdateReplacePolicy"] == "Retain", "retain bucket")
        oac = res["OriginAccess"]["Properties"]["OriginAccessControlConfig"]
        need(oac["OriginAccessControlOriginType"] == "s3" and oac["SigningBehavior"] == "always"
             and oac["SigningProtocol"] == "sigv4", "OAC signing")
        dist = res["Distribution"]["Properties"]["DistributionConfig"]
        need(set(dist) == {"Enabled", "Comment", "DefaultRootObject", "HttpVersion", "IPV6Enabled", "PriceClass", "ViewerCertificate", "Origins", "DefaultCacheBehavior"}, "distribution property allowlist")
        need(dist["Enabled"] == {"Fn::If": ["PublicationEnabled", True, False]}, "enable gate")
        need(dist["DefaultRootObject"] == "home/index.html" and dist["PriceClass"] == "PriceClass_100", "root and price class")
        need(dist["ViewerCertificate"] == {"CloudFrontDefaultCertificate": True}, "no custom cert/domain")
        need(dist["Origins"] == [{"Id": "PrivateAssets", "DomainName": {"Fn::GetAtt": ["AssetsBucket", "RegionalDomainName"]},
                                  "OriginAccessControlId": {"Ref": "OriginAccess"},
                                  "S3OriginConfig": {"OriginAccessIdentity": ""}}], "private S3 origin")
        behavior = dist["DefaultCacheBehavior"]
        need(set(behavior) == {"TargetOriginId", "ViewerProtocolPolicy", "AllowedMethods", "CachedMethods", "Compress", "CachePolicyId", "ResponseHeadersPolicyId", "FunctionAssociations"}, "behavior allowlist")
        from infra.public_web.package_public import ROOT_REDIRECT
        redirect = res["RootRedirect"]["Properties"]
        need(redirect["FunctionCode"] == ROOT_REDIRECT and redirect["AutoPublish"] is True
             and redirect["FunctionConfig"]["Runtime"] == "cloudfront-js-2.0", "fixed root redirect")
        need(behavior["FunctionAssociations"] == [{"EventType": "viewer-request", "FunctionARN": {"Fn::GetAtt": ["RootRedirect", "FunctionARN"]}}], "viewer-request redirect association")
        need(behavior["TargetOriginId"] == "PrivateAssets" and behavior["ViewerProtocolPolicy"] == "redirect-to-https", "HTTPS")
        need(behavior["AllowedMethods"] == behavior["CachedMethods"] == ["GET", "HEAD"], "read-only methods")
        need(behavior["CachePolicyId"] == {"Ref": "WebCachePolicy"} and behavior["ResponseHeadersPolicyId"] == {"Ref": "WebHeadersPolicy"}, "policy attachment")
        cache = res["WebCachePolicy"]["Properties"]["CachePolicyConfig"]
        need((cache["MinTTL"], cache["DefaultTTL"], cache["MaxTTL"]) == (0, 60, 300), "bounded cache TTL")
        need(cache["ParametersInCacheKeyAndForwardedToOrigin"] == {
            "EnableAcceptEncodingBrotli": True, "EnableAcceptEncodingGzip": True,
            "CookiesConfig": {"CookieBehavior": "none"}, "HeadersConfig": {"HeaderBehavior": "none"},
            "QueryStringsConfig": {"QueryStringBehavior": "none"}}, "no user state forwarding")
        headers = res["WebHeadersPolicy"]["Properties"]["ResponseHeadersPolicyConfig"]
        need(set(headers) == {"Name", "SecurityHeadersConfig", "CustomHeadersConfig"}, "no CORS")
        sec = headers["SecurityHeadersConfig"]
        need(sec["ContentTypeOptions"] == {"Override": True}, "nosniff")
        need(sec["FrameOptions"] == {"FrameOption": "DENY", "Override": True}, "frame deny")
        need(sec["ReferrerPolicy"] == {"ReferrerPolicy": "no-referrer", "Override": True}, "referrer")
        need(sec["StrictTransportSecurity"] == {"AccessControlMaxAgeSec": 31536000, "IncludeSubdomains": False, "Preload": False, "Override": True}, "HSTS")
        csp = sec["ContentSecurityPolicy"]
        parts = [p.strip().split() for p in csp["ContentSecurityPolicy"].split(";") if p.strip()]
        need(len({p[0].lower() for p in parts}) == len(parts), "no duplicate CSP directives")
        directives = {p[0]: p[1:] for p in parts}
        need(csp["Override"] is True and directives == {
            "default-src": ["'none'"], "script-src": ["'self'"], "style-src": ["'self'"],
            "img-src": ["'self'", "data:", "blob:"], "connect-src": ["'none'"], "object-src": ["'none'"],
            "base-uri": ["'none'"], "frame-ancestors": ["'none'"], "form-action": ["'none'"]}, "CSP")
        need(headers["CustomHeadersConfig"]["Items"] == [
            {"Header": "Permissions-Policy", "Value": "camera=(), microphone=(), geolocation=()", "Override": True},
            {"Header": "Cross-Origin-Resource-Policy", "Value": "same-origin", "Override": True}], "privacy headers")
        policy = res["AssetsPolicy"]["Properties"]
        need(policy["Bucket"] == {"Ref": "AssetsBucket"}, "policy target")
        statements = policy["PolicyDocument"]["Statement"]
        need(len(statements) == 2, "no extra policy statements")
        allow, deny = statements
        need(allow["Effect"] == "Allow" and allow["Principal"] == {"Service": "cloudfront.amazonaws.com"}, "only CloudFront principal")
        need(allow["Action"] == "s3:GetObject", "least read action")
        need(allow["Resource"] == [{"Fn::Sub": "${AssetsBucket.Arn}/" + key} for key in KEYS], "six exact keys only")
        need(allow["Condition"] == {"StringEquals": {"AWS:SourceArn": {"Fn::Sub": "arn:${AWS::Partition}:cloudfront::${AWS::AccountId}:distribution/${Distribution}"}}}, "exact distribution and account")
        need(deny["Effect"] == "Deny" and deny["Principal"] == "*" and deny["Action"] == "s3:*", "TLS deny scope")
        need(deny["Resource"] == [{"Fn::GetAtt": ["AssetsBucket", "Arn"]}, {"Fn::Sub": "${AssetsBucket.Arn}/*"}]
             and deny["Condition"] == {"Bool": {"aws:SecureTransport": "false"}}, "TLS deny bucket and objects")
        need(set(template["Outputs"]) == {"AssetBucketName", "DistributionId", "CandidateDomain"}, "outputs")
        need("{{resolve:" not in json.dumps(template), "no dynamic secret lookup")
        errors.extend(reference_errors(template))
    except (KeyError, TypeError, ValueError, IndexError, AttributeError):
        errors.append("invalid structure")
    return errors


class TemplateContractTests(unittest.TestCase):
    def setUp(self):
        self.template = strict_json((DIR / "cloudformation.json").read_text(encoding="utf-8"))

    def reject_mutation(self, path, value):
        doc = deepcopy(self.template)
        cursor = doc
        for key in path[:-1]:
            cursor = cursor[key]
        cursor[path[-1]] = value
        self.assertTrue(audit(doc), path)

    def test_candidate_passes_offline_contract_only(self):
        self.assertEqual(audit(self.template), [])
        self.assertIn("NOT RUN", self.template["Description"])

    def test_json_duplicates_and_nonfinite_constants_are_rejected(self):
        for text in ('{"Resources":{},"Resources":{}}', '{"x":NaN}', '{"x":Infinity}'):
            with self.assertRaises(ValueError):
                strict_json(text)

    def test_references_are_internal_and_known(self):
        self.assertEqual(reference_errors(self.template), [])
        doc = deepcopy(self.template)
        doc["Outputs"]["CandidateDomain"]["Value"] = {"Ref": "MissingResource"}
        self.assertTrue(audit(doc))

    def test_unknown_sub_getatt_and_conditions_fail(self):
        for expression in ({"Fn::Sub": "${Missing.Arn}"}, {"Fn::GetAtt": ["AssetsBucket", "WebsiteURL"]},
                           {"Fn::If": ["MissingCondition", True, False]}, {"Fn::ImportValue": "other-stack"}):
            self.reject_mutation(["Outputs", "CandidateDomain", "Value"], expression)

    def test_no_additional_compute_identity_or_nested_stack(self):
        for kind in ("AWS::EC2::Instance", "AWS::Lambda::Function", "AWS::DynamoDB::Table", "AWS::IAM::Role", "AWS::CloudFormation::Stack"):
            doc = deepcopy(self.template)
            doc["Resources"]["Extra"] = {"Type": kind, "Properties": {}}
            self.assertTrue(audit(doc))

    def test_disabled_default_and_exact_conditional_boolean(self):
        self.reject_mutation(["Parameters", "PublishEnabled", "Default"], "true")
        self.reject_mutation(["Resources", "Distribution", "Properties", "DistributionConfig", "Enabled"], True)
        self.reject_mutation(["Conditions", "PublicationEnabled"], {"Fn::Equals": ["true", "true"]})

    def test_public_access_block_cannot_be_weakened_or_string_typed(self):
        base = ["Resources", "AssetsBucket", "Properties", "PublicAccessBlockConfiguration"]
        for key in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"):
            for value in (False, "true", 1):
                self.reject_mutation([*base, key], value)

    def test_acl_website_cors_and_explicit_bucket_name_are_forbidden(self):
        for key, value in (("AccessControl", "PublicRead"), ("WebsiteConfiguration", {}),
                           ("CorsConfiguration", {"CorsRules": []}), ("BucketName", "shared-existing-bucket")):
            self.reject_mutation(["Resources", "AssetsBucket", "Properties", key], value)

    def test_versioning_encryption_ownership_retention_required(self):
        self.reject_mutation(["Resources", "AssetsBucket", "Properties", "OwnershipControls"], {})
        self.reject_mutation(["Resources", "AssetsBucket", "Properties", "BucketEncryption"], {})
        self.reject_mutation(["Resources", "AssetsBucket", "Properties", "VersioningConfiguration", "Status"], "Suspended")
        self.reject_mutation(["Resources", "AssetsBucket", "DeletionPolicy"], "Delete")

    def test_oac_cannot_use_unsigned_or_custom_origin(self):
        base = ["Resources", "OriginAccess", "Properties", "OriginAccessControlConfig"]
        for key, value in (("SigningBehavior", "never"), ("SigningProtocol", "other"), ("OriginAccessControlOriginType", "lambda")):
            self.reject_mutation([*base, key], value)
        self.reject_mutation(["Resources", "Distribution", "Properties", "DistributionConfig", "Origins", 0, "DomainName"], "public.s3-website.example")

    def test_https_redirect_and_readonly_methods_required(self):
        base = ["Resources", "Distribution", "Properties", "DistributionConfig", "DefaultCacheBehavior"]
        self.reject_mutation([*base, "ViewerProtocolPolicy"], "allow-all")
        self.reject_mutation([*base, "AllowedMethods"], ["GET", "HEAD", "POST"])

    def test_policy_never_grants_public_write_list_or_prefix_wildcard(self):
        base = ["Resources", "AssetsPolicy", "Properties", "PolicyDocument", "Statement", 0]
        self.reject_mutation([*base, "Principal"], "*")
        for action in ("s3:*", "s3:PutObject", ["s3:GetObject", "s3:ListBucket"]):
            self.reject_mutation([*base, "Action"], action)
        self.reject_mutation([*base, "Resource"], [{"Fn::Sub": "${AssetsBucket.Arn}/public/*"}])

    def test_policy_is_bound_to_exact_distribution_account(self):
        base = ["Resources", "AssetsPolicy", "Properties", "PolicyDocument", "Statement", 0, "Condition"]
        self.reject_mutation(base, {})
        self.reject_mutation(base, {"ArnLike": {"AWS:SourceArn": "arn:aws:cloudfront::*:distribution/*"}})

    def test_tls_deny_covers_both_bucket_and_objects(self):
        base = ["Resources", "AssetsPolicy", "Properties", "PolicyDocument", "Statement", 1]
        self.reject_mutation([*base, "Condition"], {"Bool": {"aws:SecureTransport": "true"}})
        self.reject_mutation([*base, "Resource"], [{"Fn::GetAtt": ["AssetsBucket", "Arn"]}])

    def test_extra_allow_statement_is_rejected(self):
        doc = deepcopy(self.template)
        doc["Resources"]["AssetsPolicy"]["Properties"]["PolicyDocument"]["Statement"].append(
            {"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "*"})
        self.assertTrue(audit(doc))

    def test_response_policy_must_be_attached_and_network_closed(self):
        self.reject_mutation(["Resources", "Distribution", "Properties", "DistributionConfig", "DefaultCacheBehavior", "ResponseHeadersPolicyId"], {"Ref": "OriginAccess"})
        self.reject_mutation(["Resources", "WebHeadersPolicy", "Properties", "ResponseHeadersPolicyConfig", "SecurityHeadersConfig", "ContentSecurityPolicy", "ContentSecurityPolicy"], "default-src *; connect-src *")

    def test_no_cors_override_or_missing_security_headers(self):
        base = ["Resources", "WebHeadersPolicy", "Properties", "ResponseHeadersPolicyConfig"]
        self.reject_mutation([*base, "CorsConfig"], {"AccessControlAllowOrigins": {"Items": ["*"]}})
        for key in ("ContentTypeOptions", "FrameOptions", "ReferrerPolicy", "StrictTransportSecurity"):
            self.reject_mutation([*base, "SecurityHeadersConfig", key], {})

    def test_duplicate_csp_directives_cannot_hide_an_unsafe_first_value(self):
        path = ["Resources", "WebHeadersPolicy", "Properties", "ResponseHeadersPolicyConfig",
                "SecurityHeadersConfig", "ContentSecurityPolicy", "ContentSecurityPolicy"]
        original = self.template["Resources"]["WebHeadersPolicy"]["Properties"]["ResponseHeadersPolicyConfig"]["SecurityHeadersConfig"]["ContentSecurityPolicy"]["ContentSecurityPolicy"]
        for prefix in ("connect-src *; ", "CONNECT-SRC *; ", "script-src 'unsafe-inline'; "):
            self.reject_mutation(path, prefix + original)

    def test_cache_cannot_forward_user_state_or_extend_candidate_ttl(self):
        base = ["Resources", "WebCachePolicy", "Properties", "CachePolicyConfig"]
        self.reject_mutation([*base, "MaxTTL"], 86400)
        self.reject_mutation([*base, "ParametersInCacheKeyAndForwardedToOrigin", "CookiesConfig"], {"CookieBehavior": "all"})

    def test_no_live_secret_lookup_or_macro(self):
        self.reject_mutation(["Description"], "{{resolve:secretsmanager:not-a-real-secret}}")
        self.reject_mutation(["Transform"], "AWS::Include")

    def test_public_keys_are_only_six_reviewable_static_assets(self):
        self.assertEqual(self.template["Metadata"]["ApprovedObjectKeys"], KEYS)
        for key in KEYS:
            self.assertNotRegex(key, r"(?i)\.git|secret|fixture|\.db|sqlite|manifest|snapshot|\.py$")

    def test_docs_distinguish_candidate_live_pilot_and_snapshot_states(self):
        readme = (DIR / "README.md").read_text(encoding="utf-8")
        gate = (DIR / "deploy_gate.md").read_text(encoding="utf-8")
        cost = (DIR / "security_and_cost.md").read_text(encoding="utf-8")
        for text in (readme, gate, cost):
            self.assertIn("AWS LIVE NO-GO", text)
        for word in ("公式仕様", "NOT RUN", "UNKNOWN", "USER", "account", "Region", "SHA-256", "残留課金"):
            self.assertIn(word, gate)
        for word in ("Retain", "version", "請求額の保証された上限ではありません", "NOT CONFIGURED", "cache", "EC2"):
            self.assertIn(word, readme + cost)
        self.assertIn("正本", readme)
        self.assertIn("スナップショット", readme)
        self.assertIn("再armなし", gate)
        self.assertIn("Search Fabric AWS HOLD", gate)


if __name__ == "__main__":
    unittest.main()
