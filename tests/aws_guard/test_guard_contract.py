"""Offline contract checks for infra/ops_guard/template.json.

OFFLINE CANDIDATE / AWS LIVE NOT VERIFIED. This is NOT AWS schema, IAM or service
validation. Standard library only; no AWS, network or git calls.
"""

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[2]
TEMPLATE = ROOT / "infra" / "ops_guard" / "template.json"
AWS_A = ROOT / "infra" / "public_web" / "cloudformation.json"
# SHA-256 of the existing AWS-A template with CRLF line endings (computed once).
AWS_A_SHA256 = "bd0edc364c6b86ebba61e2dc0a8baf3d9868830942e45b16b3d149010ed9eb1f"

TYPES = {
    "AlertTopic": "AWS::SNS::Topic",
    "AlertTopicPolicy": "AWS::SNS::TopicPolicy",
    "AlertEmail": "AWS::SNS::Subscription",
    "CostBudget": "AWS::Budgets::Budget",
    "RequestsAlarm": "AWS::CloudWatch::Alarm",
    "BytesAlarm": "AWS::CloudWatch::Alarm",
    "ErrorRateAlarm": "AWS::CloudWatch::Alarm",
    "TrailBucket": "AWS::S3::Bucket",
    "TrailBucketPolicy": "AWS::S3::BucketPolicy",
    "Trail": "AWS::CloudTrail::Trail",
}
TRAIL = ("TrailBucket", "TrailBucketPolicy", "Trail")
ALARMS = {
    "RequestsAlarm": ("Requests", "Sum", 300, 1000, None),
    "BytesAlarm": ("BytesDownloaded", "Sum", 86400, 1073741824, None),
    "ErrorRateAlarm": ("5xxErrorRate", "Average", 300, 5, 1),
}
PSEUDO = {"AWS::AccountId", "AWS::Partition", "AWS::Region", "AWS::StackId", "AWS::StackName", "AWS::NoValue"}
GETATT = {"TrailBucket": {"Arn"}, "AlertTopic": {"TopicName"}}
FORBIDDEN_PREFIXES = ("AWS::IAM::", "AWS::Lambda::", "AWS::EC2::")
ACCT = {"Ref": "AWS::AccountId"}
TRAIL_ARN = {"Fn::Sub": "arn:${AWS::Partition}:cloudtrail:${AWS::Region}:${AWS::AccountId}:trail/siteproof-ops-guard-trail"}


def _pairs(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError("duplicate member")
        out[key] = value
    return out


def strict_json(raw):
    def reject(_value):
        raise ValueError("non-finite JSON constant")
    return json.loads(raw, object_pairs_hook=_pairs, parse_constant=reject)


def reference_errors(template):
    errors = []
    symbols = set(template.get("Resources", {})) | set(template.get("Parameters", {})) | PSEUDO
    conditions = set(template.get("Conditions", {}))
    intrinsics = {"Fn::GetAtt", "Fn::Sub", "Fn::If", "Fn::Equals"}
    resources = set(template.get("Resources", {}))

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
                    if not isinstance(child, list) or len(child) != 2 or child[0] not in resources \
                            or child[1] not in GETATT.get(child[0], set()):
                        errors.append("unknown GetAtt")
                if key == "Fn::Sub":
                    if not isinstance(child, str):
                        errors.append("unsupported Sub form")
                    else:
                        for name in re.findall(r"\$\{([^}]+)\}", child):
                            if name.split(".")[0] not in symbols:
                                errors.append("unknown Sub symbol")
                if key == "Fn::If" and (not isinstance(child, list) or len(child) != 3 or child[0] not in conditions):
                    errors.append("unknown Condition")
                visit(child)
    try:
        visit(template)
        for name, res in template.get("Resources", {}).items():
            cond = res.get("Condition")
            if cond is not None and cond not in conditions:
                errors.append("unknown resource Condition")
            deps = res.get("DependsOn", [])
            for dep in [deps] if isinstance(deps, str) else deps:
                if dep not in resources:
                    errors.append("unknown DependsOn")
    except (TypeError, KeyError, IndexError, AttributeError):
        errors.append("invalid reference structure")
    return errors


def walk(value):
    yield value
    if isinstance(value, dict):
        for child in value.values():
            yield from walk(child)
    elif isinstance(value, list):
        for child in value:
            yield from walk(child)


def audit(template):
    """Local safety allowlist, intentionally narrower than AWS's full grammar."""
    errors = []

    def need(condition, label):
        if not condition:
            errors.append(label)
    try:
        need(type(template) is dict, "root")
        need(template["AWSTemplateFormatVersion"] == "2010-09-09", "template version")
        need("Transform" not in template and "Mappings" not in template, "no macro/mappings")
        desc = template["Description"]
        need("OFFLINE CANDIDATE" in desc and "AWS LIVE NOT VERIFIED" in desc, "candidate marker in description")
        meta = template["Metadata"]
        need("AWS LIVE NOT VERIFIED" in meta.get("ReviewStatus", "").replace("_", " ") or "NOT_VERIFIED" in meta.get("ReviewStatus", ""), "candidate marker in metadata")
        need("us-east-1" in meta.get("RegionRequirement", ""), "us-east-1 requirement recorded")
        need("{{resolve:" not in json.dumps(template), "no dynamic lookup")
        res = template["Resources"]
        need(set(res) == set(TYPES), "exact resource set")
        for logical, kind in TYPES.items():
            need(res[logical]["Type"] == kind, "resource type:" + logical)
        for node in walk(template):
            if isinstance(node, dict) and isinstance(node.get("Type"), str) and node["Type"].startswith(FORBIDDEN_PREFIXES):
                errors.append("forbidden resource type")
        for r in res.values():
            need(not r["Type"].startswith(FORBIDDEN_PREFIXES), "no IAM/Lambda/EC2")
        need(all(r["Type"] != "AWS::CloudFormation::Stack" for r in res.values()), "no nested stack")

        # parameters
        params = template["Parameters"]
        need(set(params) == {"NotificationEmail", "MonthlyBudgetUsd", "PublicDistributionId", "EnableTrail"}, "exact parameter set")
        need(params["NotificationEmail"]["Type"] == "String" and "Default" not in params["NotificationEmail"], "email no default")
        b = params["MonthlyBudgetUsd"]
        need((b["Type"], b["Default"], b["MinValue"], b["MaxValue"]) == ("Number", 5, 1, 50), "budget parameter bounds")
        d = params["PublicDistributionId"]
        need(d["Type"] == "String" and d["AllowedPattern"] == "^E[A-Z0-9]{5,20}$" and "Default" not in d, "distribution id pattern")
        e = params["EnableTrail"]
        need(e["Type"] == "String" and e["Default"] == "false" and e["AllowedValues"] == ["false", "true"], "trail disabled by default")
        need(template["Conditions"] == {"TrailEnabled": {"Fn::Equals": [{"Ref": "EnableTrail"}, "true"]}}, "trail condition")

        # SNS
        topic = res["AlertTopic"]["Properties"]
        need("KmsMasterKeyId" not in topic, "no KMS key on topic")
        need("alias/" not in json.dumps(res["AlertTopic"]), "no KMS alias")
        need({"Key": "Project", "Value": "SiteProof"} in topic.get("Tags", []), "topic tagged")
        pol = res["AlertTopicPolicy"]["Properties"]
        need(pol["Topics"] == [{"Ref": "AlertTopic"}], "policy target")
        stm = pol["PolicyDocument"]["Statement"]
        need(len(stm) == 2, "exactly two topic statements")
        need({s["Principal"]["Service"] for s in stm} == {"cloudwatch.amazonaws.com", "budgets.amazonaws.com"}, "topic principals")
        for s in stm:
            need(s["Effect"] == "Allow" and set(s["Principal"]) == {"Service"} and isinstance(s["Principal"]["Service"], str), "topic principal shape")
            need(s["Action"] == "sns:Publish", "topic action publish only")
            need(s["Resource"] == {"Ref": "AlertTopic"}, "topic resource")
            need(s["Condition"] == {"StringEquals": {"aws:SourceAccount": ACCT}}, "SourceAccount condition")
        sub = res["AlertEmail"]["Properties"]
        need(sub == {"TopicArn": {"Ref": "AlertTopic"}, "Protocol": "email", "Endpoint": {"Ref": "NotificationEmail"}}, "email subscription")

        # Budget
        bp = res["CostBudget"]["Properties"]
        need(set(bp) == {"Budget", "NotificationsWithSubscribers"}, "no budget actions or extras")
        bud = bp["Budget"]
        need(bud["BudgetType"] == "COST" and bud["TimeUnit"] == "MONTHLY"
             and bud["BudgetLimit"] == {"Amount": {"Ref": "MonthlyBudgetUsd"}, "Unit": "USD"}, "budget definition")
        subs = [{"SubscriptionType": "SNS", "Address": {"Ref": "AlertTopic"}}]
        need(bp["NotificationsWithSubscribers"] == [
            {"Notification": {"NotificationType": "ACTUAL", "ComparisonOperator": "GREATER_THAN", "Threshold": 80, "ThresholdType": "PERCENTAGE"}, "Subscribers": subs},
            {"Notification": {"NotificationType": "FORECASTED", "ComparisonOperator": "GREATER_THAN", "Threshold": 100, "ThresholdType": "PERCENTAGE"}, "Subscribers": subs},
        ], "exactly two budget notifications")
        need("BudgetAction" not in json.dumps(template), "no budget action")

        # Alarms
        dims = [{"Name": "DistributionId", "Value": {"Ref": "PublicDistributionId"}}, {"Name": "Region", "Value": "Global"}]
        for name, (metric, stat, period, thr, evals) in ALARMS.items():
            a = res[name]["Properties"]
            need(a["Namespace"] == "AWS/CloudFront" and a["MetricName"] == metric, "alarm metric:" + name)
            need(a["Dimensions"] == dims, "alarm dimensions:" + name)
            need(a["Statistic"] == stat and a["Period"] == period and a["Threshold"] == thr, "alarm numbers:" + name)
            need(a["ComparisonOperator"] == "GreaterThanThreshold", "alarm comparison:" + name)
            if evals is not None:
                need(a["EvaluationPeriods"] == evals, "alarm evaluation periods:" + name)
            need(a["TreatMissingData"] == "notBreaching", "alarm missing data:" + name)
            need(a["AlarmActions"] == [{"Ref": "AlertTopic"}] and a["OKActions"] == [{"Ref": "AlertTopic"}], "alarm actions:" + name)
            need("candidate" in a["AlarmDescription"].lower(), "alarm threshold labelled candidate:" + name)

        # Trail (all conditional)
        for name in TRAIL:
            need(res[name].get("Condition") == "TrailEnabled", "conditional:" + name)
        for name in res:
            if name not in TRAIL:
                need("Condition" not in res[name], "unconditional:" + name)
        tb = res["TrailBucket"]
        tp = tb["Properties"]
        need(tb["DeletionPolicy"] == tb["UpdateReplacePolicy"] == "Retain", "trail bucket retain")
        need(tp["PublicAccessBlockConfiguration"] == dict.fromkeys(
            ["BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"], True), "trail bucket BPA")
        need(tp["OwnershipControls"] == {"Rules": [{"ObjectOwnership": "BucketOwnerEnforced"}]}, "trail bucket ownership")
        need(tp["BucketEncryption"] == {"ServerSideEncryptionConfiguration": [{"ServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]}, "trail bucket SSE")
        lc = tp["LifecycleConfiguration"]["Rules"]
        need(len(lc) == 1 and lc[0]["Status"] == "Enabled" and lc[0]["ExpirationInDays"] == 90, "trail bucket 90 day expiry")
        need(not {"AccessControl", "WebsiteConfiguration", "CorsConfiguration", "BucketName"} & set(tp), "trail bucket forbidden props")
        bp2 = res["TrailBucketPolicy"]["Properties"]
        need(bp2["Bucket"] == {"Ref": "TrailBucket"}, "trail policy target")
        s = bp2["PolicyDocument"]["Statement"]
        need(len(s) == 3, "three trail policy statements")
        s1, s2, s3 = s
        for st in (s1, s2):
            need(st["Effect"] == "Allow" and st["Principal"] == {"Service": "cloudtrail.amazonaws.com"}, "trail principal")
            need(st["Condition"] == {"StringEquals": {"aws:SourceArn": TRAIL_ARN}}, "trail SourceArn")
        need(s1["Action"] == "s3:GetBucketAcl" and s1["Resource"] == {"Fn::GetAtt": ["TrailBucket", "Arn"]}, "trail get acl")
        need(s2["Action"] == "s3:PutObject" and s2["Resource"] == {"Fn::Sub": "${TrailBucket.Arn}/AWSLogs/${AWS::AccountId}/*"}, "trail put object")
        need(s3["Effect"] == "Deny" and s3["Principal"] == "*" and s3["Action"] == "s3:*"
             and s3["Resource"] == [{"Fn::GetAtt": ["TrailBucket", "Arn"]}, {"Fn::Sub": "${TrailBucket.Arn}/*"}]
             and s3["Condition"] == {"Bool": {"aws:SecureTransport": "false"}}, "trail TLS deny")
        tr = res["Trail"]
        need(tr["DependsOn"] == "TrailBucketPolicy", "trail depends on bucket policy")
        trp = tr["Properties"]
        need(trp["IsLogging"] is True and trp["IsMultiRegionTrail"] is True
             and trp["IncludeGlobalServiceEvents"] is True and trp["EnableLogFileValidation"] is True, "trail flags")
        need(trp["S3BucketName"] == {"Ref": "TrailBucket"}, "trail bucket link")
        need("EventSelectors" not in trp and "AdvancedEventSelectors" not in trp and "InsightSelectors" not in trp, "management events only")
        need(not {"KMSKeyId", "CloudWatchLogsLogGroupArn", "SnsTopicName"} & set(trp), "no extra trail integrations")

        # Principals: Allow statements must not use "*"; only the TLS Deny may
        for node in walk(template):
            if isinstance(node, dict) and "Principal" in node:
                p = node["Principal"]
                if node.get("Effect") == "Allow":
                    need(p != "*" and p != {"AWS": "*"} and "*" not in json.dumps(p), "no wildcard allow principal")
                elif p != "*" or node.get("Sid") != "DenyInsecureTransport":
                    errors.append("unexpected principal")
        need(set(template["Outputs"]) == {"AlertTopicArn", "BudgetName"}, "outputs")
        errors.extend(reference_errors(template))
    except (KeyError, TypeError, ValueError, IndexError, AttributeError):
        errors.append("invalid structure")
    return errors


class GuardContractTests(unittest.TestCase):
    def setUp(self):
        self.template = strict_json(TEMPLATE.read_text(encoding="utf-8"))

    def mutate(self, path, value, delete=False):
        doc = deepcopy(self.template)
        cursor = doc
        for key in path[:-1]:
            cursor = cursor[key]
        if delete:
            del cursor[path[-1]]
        else:
            cursor[path[-1]] = value
        self.assertTrue(audit(doc), path)

    # ---- baseline ----
    def test_candidate_passes_offline_contract_only(self):
        self.assertEqual(audit(self.template), [])
        self.assertIn("AWS LIVE NOT VERIFIED", self.template["Description"])

    def test_strict_json_rejects_duplicates_and_nonfinite(self):
        for text in ('{"Resources":{},"Resources":{}}', '{"x":NaN}', '{"x":Infinity}'):
            with self.assertRaises(ValueError):
                strict_json(text)

    def test_exact_resource_set_and_types(self):
        res = self.template["Resources"]
        self.assertEqual({k: v["Type"] for k, v in res.items()}, TYPES)

    def test_exact_parameter_set(self):
        self.assertEqual(set(self.template["Parameters"]), {"NotificationEmail", "MonthlyBudgetUsd", "PublicDistributionId", "EnableTrail"})

    def test_references_resolve(self):
        self.assertEqual(reference_errors(self.template), [])

    def test_no_forbidden_types_anywhere(self):
        text = json.dumps(self.template)
        for prefix in FORBIDDEN_PREFIXES:
            self.assertNotIn(prefix, text)

    def test_aws_a_template_is_unchanged(self):
        # The pinned value (also recorded in the canonical release notes) is over the CRLF
        # form; normalise so an LF checkout of the same content gives the same answer.
        raw = AWS_A.read_bytes().replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")
        self.assertEqual(hashlib.sha256(raw).hexdigest(), AWS_A_SHA256)

    def test_guard_does_not_reference_aws_a_stack(self):
        text = json.dumps(self.template["Resources"])
        self.assertNotIn("ImportValue", text)
        self.assertNotIn("public_web", text)
        self.assertNotIn("AssetsBucket", text)

    # ---- mutations ----
    def test_mut_reference_unknown_ref(self):
        self.mutate(["Outputs", "AlertTopicArn", "Value"], {"Ref": "Missing"})

    def test_mut_unknown_getatt_sub_if_importvalue(self):
        for expr in ({"Fn::GetAtt": ["TrailBucket", "WebsiteURL"]}, {"Fn::Sub": "${Missing.Arn}"},
                     {"Fn::If": ["Nope", 1, 2]}, {"Fn::ImportValue": "other"}):
            self.mutate(["Outputs", "AlertTopicArn", "Value"], expr)

    def test_mut_unknown_resource_condition_and_dependson(self):
        self.mutate(["Resources", "Trail", "Condition"], "Missing")
        self.mutate(["Resources", "Trail", "DependsOn"], "Missing")

    def test_mut_forbidden_resource_types(self):
        for kind in ("AWS::IAM::Role", "AWS::IAM::User", "AWS::Lambda::Function", "AWS::EC2::Instance", "AWS::CloudFormation::Stack"):
            doc = deepcopy(self.template)
            doc["Resources"]["Extra"] = {"Type": kind, "Properties": {}}
            self.assertTrue(audit(doc), kind)

    def test_mut_transform_and_mappings(self):
        self.mutate(["Transform"], "AWS::Include")
        self.mutate(["Mappings"], {})

    def test_mut_candidate_marker_removed(self):
        self.mutate(["Description"], "SiteProof guard, verified and live.")

    def test_mut_region_requirement_removed(self):
        self.mutate(["Metadata", "RegionRequirement"], "any region")

    def test_mut_parameter_changes(self):
        self.mutate(["Parameters", "NotificationEmail", "Default"], "me@example.invalid")
        self.mutate(["Parameters", "MonthlyBudgetUsd", "MaxValue"], 5000)
        self.mutate(["Parameters", "PublicDistributionId", "AllowedPattern"], ".*")
        self.mutate(["Parameters", "EnableTrail", "Default"], "true")
        self.mutate(["Parameters", "Extra"], {"Type": "String"})

    def test_mut_topic_kms(self):
        self.mutate(["Resources", "AlertTopic", "Properties", "KmsMasterKeyId"], "alias/aws/sns")

    def test_mut_topic_tag_removed(self):
        self.mutate(["Resources", "AlertTopic", "Properties", "Tags"], [])

    def test_mut_topic_policy_principal_wildcard(self):
        base = ["Resources", "AlertTopicPolicy", "Properties", "PolicyDocument", "Statement", 0, "Principal"]
        self.mutate(base, "*")
        self.mutate(base, {"AWS": "*"})
        self.mutate(base, {"Service": "sns.amazonaws.com"})

    def test_mut_topic_policy_action(self):
        base = ["Resources", "AlertTopicPolicy", "Properties", "PolicyDocument", "Statement", 1, "Action"]
        self.mutate(base, "sns:*")
        self.mutate(base, ["sns:Publish", "sns:Subscribe"])

    def test_mut_topic_policy_source_account(self):
        base = ["Resources", "AlertTopicPolicy", "Properties", "PolicyDocument", "Statement", 0, "Condition"]
        self.mutate(base, {})
        self.mutate(base, {"StringEquals": {"aws:SourceAccount": "123456789012"}})
        self.mutate(base, {"StringLike": {"aws:SourceAccount": "*"}})

    def test_mut_topic_policy_extra_statement(self):
        doc = deepcopy(self.template)
        doc["Resources"]["AlertTopicPolicy"]["Properties"]["PolicyDocument"]["Statement"].append(
            {"Effect": "Allow", "Principal": "*", "Action": "sns:Publish", "Resource": {"Ref": "AlertTopic"}})
        self.assertTrue(audit(doc))

    def test_mut_subscription(self):
        self.mutate(["Resources", "AlertEmail", "Properties", "Protocol"], "https")
        self.mutate(["Resources", "AlertEmail", "Properties", "Endpoint"], "someone@example.invalid")

    def test_mut_budget_action_or_extra_notification(self):
        self.mutate(["Resources", "CostBudget", "Properties", "BudgetActions"], [])
        doc = deepcopy(self.template)
        n = doc["Resources"]["CostBudget"]["Properties"]["NotificationsWithSubscribers"]
        n.append(deepcopy(n[0]))
        self.assertTrue(audit(doc))
        self.mutate(["Resources", "CostBudget", "Properties", "NotificationsWithSubscribers", 1, "Notification", "Threshold"], 50)

    def test_mut_budget_definition(self):
        base = ["Resources", "CostBudget", "Properties", "Budget"]
        self.mutate([*base, "TimeUnit"], "DAILY")
        self.mutate([*base, "BudgetType"], "USAGE")
        self.mutate([*base, "BudgetLimit", "Unit"], "JPY")
        self.mutate([*base, "BudgetLimit", "Amount"], 100000)

    def test_mut_budget_subscriber(self):
        self.mutate(["Resources", "CostBudget", "Properties", "NotificationsWithSubscribers", 0, "Subscribers"],
                    [{"SubscriptionType": "EMAIL", "Address": "x@example.invalid"}])

    def test_mut_alarm_namespace_and_dimensions(self):
        for name in ALARMS:
            base = ["Resources", name, "Properties"]
            self.mutate([*base, "Namespace"], "AWS/S3")
            self.mutate([*base, "Dimensions"], [{"Name": "DistributionId", "Value": "EXAMPLE"}])
            self.mutate([*base, "Dimensions", 1, "Value"], "us-east-1")

    def test_mut_alarm_actions_missing(self):
        for name in ALARMS:
            self.mutate(["Resources", name, "Properties", "AlarmActions"], [])
            self.mutate(["Resources", name, "Properties", "OKActions"], [], delete=False)

    def test_mut_alarm_missing_data(self):
        for name in ALARMS:
            self.mutate(["Resources", name, "Properties", "TreatMissingData"], "breaching")
            self.mutate(["Resources", name, "Properties", "TreatMissingData"], None, delete=True)

    def test_mut_alarm_numbers(self):
        self.mutate(["Resources", "RequestsAlarm", "Properties", "Threshold"], 10 ** 9)
        self.mutate(["Resources", "BytesAlarm", "Properties", "Period"], 300)
        self.mutate(["Resources", "ErrorRateAlarm", "Properties", "EvaluationPeriods"], 3)
        self.mutate(["Resources", "ErrorRateAlarm", "Properties", "Statistic"], "Maximum")
        self.mutate(["Resources", "RequestsAlarm", "Properties", "ComparisonOperator"], "LessThanThreshold")

    def test_mut_trail_not_conditional(self):
        for name in TRAIL:
            self.mutate(["Resources", name, "Condition"], None, delete=True)

    def test_mut_trail_bucket_retention_and_bpa(self):
        self.mutate(["Resources", "TrailBucket", "DeletionPolicy"], "Delete")
        self.mutate(["Resources", "TrailBucket", "UpdateReplacePolicy"], "Delete")
        for key in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"):
            self.mutate(["Resources", "TrailBucket", "Properties", "PublicAccessBlockConfiguration", key], False)
        self.mutate(["Resources", "TrailBucket", "Properties", "OwnershipControls"], {})
        self.mutate(["Resources", "TrailBucket", "Properties", "LifecycleConfiguration", "Rules", 0, "ExpirationInDays"], 3650)

    def test_mut_trail_policy(self):
        base = ["Resources", "TrailBucketPolicy", "Properties", "PolicyDocument", "Statement"]
        self.mutate([*base, 2, "Condition"], {"Bool": {"aws:SecureTransport": "true"}})
        self.mutate([*base, 2, "Resource"], [{"Fn::GetAtt": ["TrailBucket", "Arn"]}])
        self.mutate([*base, 1, "Condition"], {})
        self.mutate([*base, 1, "Resource"], {"Fn::Sub": "${TrailBucket.Arn}/*"})
        self.mutate([*base, 0, "Principal"], "*")
        self.mutate([*base, 1, "Action"], "s3:*")

    def test_mut_trail_flags_and_selectors(self):
        base = ["Resources", "Trail", "Properties"]
        for key in ("IsLogging", "IsMultiRegionTrail", "IncludeGlobalServiceEvents", "EnableLogFileValidation"):
            self.mutate([*base, key], False)
        self.mutate([*base, "EventSelectors"], [{"DataResources": [{"Type": "AWS::S3::Object", "Values": ["arn:aws:s3"]}]}])
        self.mutate(["Resources", "Trail", "DependsOn"], "TrailBucket")

    def test_mut_dynamic_lookup(self):
        self.mutate(["Description"], "OFFLINE CANDIDATE AWS LIVE NOT VERIFIED {{resolve:ssm:/x}}")

    def test_mut_outputs(self):
        self.mutate(["Outputs", "Extra"], {"Value": "x"})


if __name__ == "__main__":
    unittest.main()
