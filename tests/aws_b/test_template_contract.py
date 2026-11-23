"""Offline contract checks for infra/aws_b/template.json.

OFFLINE CANDIDATE / AWS LIVE NOT VERIFIED. This is NOT AWS schema, IAM or service
validation. Mutation tests prove each safety property is actually enforced by `audit`.
"""
import json
import os
import unittest
from copy import deepcopy
from pathlib import Path

from src.aws_b.model import MonitorConfig, parse_event
from tests import cfn_contract as cfn

ROOT = Path(__file__).resolve().parents[2]
TEMPLATE = ROOT / "infra" / "aws_b" / "template.json"
TYPES = {
    "ProbeTable": "AWS::DynamoDB::Table", "ProbeLogGroup": "AWS::Logs::LogGroup",
    "ProbeRole": "AWS::IAM::Role", "ProbeFunction": "AWS::Lambda::Function",
    "ProbeAsyncConfig": "AWS::Lambda::EventInvokeConfig", "SchedulerRole": "AWS::IAM::Role",
    "ProbeSchedule": "AWS::Scheduler::Schedule",     # AWS-B Lite: no per-page alarm; see health.json
}
PARAMETERS = {"TargetId", "TargetHostname", "TargetPath", "PolicyVersion",
              "ExecutionGeneration", "AbsoluteEndAt", "ScheduleExpression", "ScheduleState",
              "AlertTopicArn", "CodeBucket", "CodeKey", "CodeObjectVersion", "LambdaRuntime",
              "LogRetentionDays", "UseReservedConcurrency", "MonitorGroup"}
GETATT = {"ProbeTable": {"Arn"}, "ProbeLogGroup": {"Arn"}, "ProbeRole": {"Arn"},
          "ProbeFunction": {"Arn"}, "SchedulerRole": {"Arn"}}
TOPIC = {"Ref": "AlertTopicArn"}


def audit(template):
    errors = []

    def need(condition, label):
        if not condition:
            errors.append(label)
    try:
        need(template["AWSTemplateFormatVersion"] == "2010-09-09", "template version")
        need("Transform" not in template and "Mappings" not in template, "no macro/mappings")
        need("AWS LIVE NOT VERIFIED" in template["Description"]
             and "NO-GO" in template["Description"], "candidate marker")
        res = template["Resources"]
        need(set(res) == set(TYPES), "exact resource set")
        for name, kind in TYPES.items():
            need(res[name]["Type"] == kind, "resource type " + name)
        need(set(template["Parameters"]) == PARAMETERS, "exact parameter set")
        need(template["Parameters"]["ScheduleState"]["Default"] == "DISABLED",
             "schedule defaults to DISABLED")
        need("Default" not in template["Parameters"]["AbsoluteEndAt"], "end must be chosen")
        need("Default" not in template["Parameters"]["TargetHostname"], "target must be chosen")
        errors.extend(cfn.reference_errors(template, GETATT))
        errors.extend(cfn.rule_assertion_errors(template))
        errors.extend(cfn.iam_wildcard_errors(template))
        need(not any(isinstance(n, dict) and ("ManagedPolicyArns" in n or "VpcConfig" in n
                                               or "PermissionsBoundary" in n)
                     for n in cfn.walk(res)), "no managed policies / VPC attachment")

        table = res["ProbeTable"]
        need(table.get("DeletionPolicy") == "Retain"
             and table.get("UpdateReplacePolicy") == "Retain", "table retained")
        tp = table["Properties"]
        need(tp["BillingMode"] == "PAY_PER_REQUEST", "on-demand billing")
        need(tp["KeySchema"] == [{"AttributeName": "pk", "KeyType": "HASH"},
                                 {"AttributeName": "sk", "KeyType": "RANGE"}], "key schema")
        need(tp["TimeToLiveSpecification"] == {"AttributeName": "expires_at", "Enabled": True},
             "ttl bounds retention")
        need("GlobalSecondaryIndexes" not in tp and "StreamSpecification" not in tp,
             "no index/stream")

        log = res["ProbeLogGroup"]["Properties"]
        need(log["LogGroupName"] == {"Fn::Sub": "/aws/lambda/${AWS::StackName}-probe"},
             "log group pre-created for the function")
        need(log["RetentionInDays"] == {"Ref": "LogRetentionDays"}, "log retention set")

        role = res["ProbeRole"]["Properties"]
        trust = cfn.statements(role["AssumeRolePolicyDocument"])
        need(len(trust) == 1 and trust[0]["Principal"] == {"Service": "lambda.amazonaws.com"}
             and trust[0]["Action"] == "sts:AssumeRole", "probe trust")
        need(len(role["Policies"]) == 1, "single inline policy")
        allowed = {}
        for statement in cfn.statements(role["Policies"][0]["PolicyDocument"]):
            need(statement["Effect"] == "Allow", "allow statements only")
            for action in cfn.actions(statement):
                allowed[action] = statement
        need(set(allowed) == {"dynamodb:UpdateItem", "dynamodb:PutItem", "sns:Publish",
                              "logs:CreateLogStream", "logs:PutLogEvents"},
             "probe role action allowlist")
        need(allowed.get("sns:Publish", {}).get("Resource") == TOPIC
             and list(cfn.actions(allowed.get("sns:Publish", {}))) == ["sns:Publish"],
             "sns publish limited to the one alert topic")
        ddb = allowed.get("dynamodb:UpdateItem", {})
        need(ddb.get("Resource") == {"Fn::GetAtt": ["ProbeTable", "Arn"]}, "ddb resource")
        need(ddb.get("Condition") == {"ForAllValues:StringEquals": {"dynamodb:LeadingKeys": [
            {"Fn::Sub": "CONTROL#${TargetId}"}, {"Fn::Sub": "RUN#${TargetId}"}]}},
            "ddb leading keys limited to own target")
        need(allowed.get("logs:PutLogEvents", {}).get("Resource")
             == {"Fn::GetAtt": ["ProbeLogGroup", "Arn"]}, "logs resource")

        fn = res["ProbeFunction"]["Properties"]
        need(fn["Handler"] == "src.aws_b.handler.lambda_handler", "handler path")
        need(fn["FunctionName"] == {"Fn::Sub": "${AWS::StackName}-probe"}, "function name")
        need(fn["Role"] == {"Fn::GetAtt": ["ProbeRole", "Arn"]}, "function role")
        need(isinstance(fn["Timeout"], int) and 10 <= fn["Timeout"] <= 30, "bounded timeout")
        need(fn["ReservedConcurrentExecutions"]
             == {"Fn::If": ["ReserveConcurrency", 1, {"Ref": "AWS::NoValue"}]},
             "reserved concurrency 1")
        need(set(fn["Code"]) == {"S3Bucket", "S3Key", "S3ObjectVersion"}, "pinned code version")
        env = fn["Environment"]["Variables"]
        need(env.get("TABLE_NAME") == {"Ref": "ProbeTable"}
             and env.get("TARGET_HOSTNAME") == {"Ref": "TargetHostname"}
             and env.get("ABSOLUTE_END_AT") == {"Ref": "AbsoluteEndAt"}
             and env.get("POLICY_VERSION") == {"Ref": "PolicyVersion"}
             and env.get("TARGET_ID") == {"Ref": "TargetId"}
             and env.get("TARGET_PATH") == {"Ref": "TargetPath"}
             and env.get("ALERT_TOPIC_ARN") == TOPIC
             and env.get("MONITOR_GROUP") == {"Ref": "MonitorGroup"}, "environment wiring")
        need(env.get("MAX_EVENT_AGE_SECONDS") == "60", "handler event age window")
        need(not any(k for k in env if "SECRET" in k or "KEY" in k or "TOKEN" in k),
             "no secrets in environment")

        asyncc = res["ProbeAsyncConfig"]["Properties"]
        need(asyncc["MaximumRetryAttempts"] == 0, "lambda async retries 0")
        need(asyncc["MaximumEventAgeInSeconds"] == 60, "lambda async event age 60")
        need(asyncc["FunctionName"] == {"Ref": "ProbeFunction"}
             and asyncc["Qualifier"] == "$LATEST", "async config target")

        sched_role = res["SchedulerRole"]["Properties"]
        strust = cfn.statements(sched_role["AssumeRolePolicyDocument"])
        need(len(strust) == 1
             and strust[0]["Principal"] == {"Service": "scheduler.amazonaws.com"}
             and strust[0].get("Condition") == {"StringEquals": {
                 "aws:SourceAccount": {"Ref": "AWS::AccountId"}}}, "scheduler trust scoped")
        sstat = cfn.statements(sched_role["Policies"][0]["PolicyDocument"])
        need(len(sched_role["Policies"]) == 1 and len(sstat) == 1
             and sstat[0]["Action"] == "lambda:InvokeFunction"
             and sstat[0]["Resource"] == {"Fn::GetAtt": ["ProbeFunction", "Arn"]},
             "scheduler may invoke only the probe")

        sched = res["ProbeSchedule"]["Properties"]
        need(sched["State"] == {"Ref": "ScheduleState"}, "schedule state parameter")
        need(sched["FlexibleTimeWindow"] == {"Mode": "OFF"}, "no flexible window")
        need(sched["ScheduleExpressionTimezone"] == "UTC", "utc")
        need(json.dumps(sched.get("EndDate", "")).count("AbsoluteEndAt") == 1,
             "schedule bounded by absolute end")
        # AWS (2026-11-20, stack update rolled back): CloudFormation rejects ActionAfterCompletion on AWS::Scheduler::Schedule
        # ("extraneous key ... is not permitted"). The end is enforced by EndDate + the handler's absolute end instead.
        need("ActionAfterCompletion" not in sched, "no property CloudFormation rejects")
        target = sched["Target"]
        need(target["RetryPolicy"] == {"MaximumRetryAttempts": 0,
                                       "MaximumEventAgeInSeconds": 60}, "scheduler retries 0")
        need(target["Arn"] == {"Fn::GetAtt": ["ProbeFunction", "Arn"]}
             and target["RoleArn"] == {"Fn::GetAtt": ["SchedulerRole", "Arn"]},
             "schedule target")
        need("DeadLetterConfig" not in target, "no queue in the minimal design")
        text = target["Input"]["Fn::Sub"]
        need("<aws.scheduler.scheduled-time>" in text and "${ExecutionGeneration}" in text
             and "${TargetId}" in text, "event carries slot, generation and target")
        need("hostname" not in text.lower() and "path" not in text.lower(),
             "event cannot carry a destination")

        need(not any(r["Type"] == "AWS::CloudWatch::Alarm" for r in res.values()),
             "no per-page alarm: a missing run is the shared heartbeat alarm's job (health.json)")
        need("Rules" not in template and "AlarmPeriodSeconds" not in template["Parameters"],
             "no alarm-period rule without per-page alarms")
        sp = template["Parameters"]["ScheduleExpression"]
        need(sp["Default"] == "rate(6 hours)" and "rate(12 hours)" in sp["AllowedValues"]
             and "rate(6 hours)" in sp["AllowedValues"], "6 and 12 hour schedules, 6 hours by default")
        for node in cfn.walk(res):
            if isinstance(node, dict) and str(node.get("Type", "")).startswith(
                    ("AWS::EC2::", "AWS::SQS::", "AWS::SNS::", "AWS::Budgets::",
                     "AWS::S3::", "AWS::ApiGateway")):
                errors.append("out-of-scope resource type")
    except (KeyError, TypeError, IndexError, AttributeError) as exc:
        errors.append("structure: %s %s" % (type(exc).__name__, exc))
    return errors


class TemplateContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.template = cfn.load(TEMPLATE)

    def mutated(self, change):
        template = deepcopy(self.template)
        change(template["Resources"], template)
        return audit(template)

    def test_lite_has_no_per_page_alarm_or_per_page_custom_metric_declaration(self):
        t = self.template
        self.assertEqual([r for r in t['Resources'].values() if r['Type'] == 'AWS::CloudWatch::Alarm'], [])
        self.assertNotIn('Default', t['Parameters']['AbsoluteEndAt'])
        self.assertEqual(t['Parameters']['ScheduleExpression']['Default'], 'rate(6 hours)')
        self.assertEqual(t['Parameters']['MonitorGroup']['Default'], 'siteproof-b')
        self.check(lambda r, t: r.update(ProbeFailureAlarm={'Type': 'AWS::CloudWatch::Alarm', 'Properties': {}}))

    def test_rule_helper_still_rejects_the_live_numeric_equals_operand_before_coercion(self):
        # Lite has no Rules block any more; the helper's regression knowledge stays covered on a synthetic template.
        synthetic = {'Parameters': {'Period': {'Type': 'Number', 'Default': 900}},
                     'Rules': {'R': {'Assertions': [{'Assert': {'Fn::Equals': [{'Ref': 'Period'}, 900]}}]}}}
        self.assertTrue(any('two string operands' in e for e in cfn.rule_assertion_errors(synthetic)))
        self.assertEqual(cfn.rule_assertion_errors(self.template), [])

    def test_candidate_passes_local_audit(self):
        self.assertEqual(audit(self.template), [])

    def test_strict_json_rejects_duplicate_members(self):
        with self.assertRaises(ValueError):
            cfn.strict_json('{"a": 1, "a": 2}')

    def test_scheduled_event_text_is_accepted_by_the_handler_parser(self):
        text = self.template["Resources"]["ProbeSchedule"]["Properties"]["Target"]["Input"]["Fn::Sub"]
        rendered = cfn.render_sub(text, {"TargetId": "preview", "ExecutionGeneration": 3})
        for timestamp in ("2026-11-20T03:00:00Z", "2026-11-20T03:00:00.000Z"):
            with self.subTest(timestamp=timestamp):
                body = rendered.replace("<aws.scheduler.scheduled-time>", timestamp)
                scheduled, reason = parse_event(json.loads(body))
                self.assertEqual(reason, "OK")
                self.assertEqual((scheduled.target_id, scheduled.execution_generation), ("preview", 3))
                self.assertEqual(scheduled.scheduled_slot, "2026-11-20T03:00:00Z")

    def test_environment_satisfies_handler_configuration(self):
        variables = self.template["Resources"]["ProbeFunction"]["Properties"]["Environment"]["Variables"]
        sample = {"TargetId": "preview", "TargetHostname": "d111111abcdef8.cloudfront.net",
                  "TargetPath": "/home/index.html", "PolicyVersion": "p1",
                  "AbsoluteEndAt": "2026-11-21T03:00:00Z", "ProbeTable": "stack-ProbeTable-ABC",
                  "AlertTopicArn": "arn:aws:sns:us-east-1:123456789012:siteproof-b-alerts",
                  "MonitorGroup": "siteproof-b"}
        env = {k: (sample[v["Ref"]] if isinstance(v, dict) else v) for k, v in variables.items()}
        config = MonitorConfig.from_env(env)
        self.assertEqual(config.max_event_age_seconds, 60)
        self.assertEqual((config.monitor_group, config.alert_topic_arn),
                         ("siteproof-b", "arn:aws:sns:us-east-1:123456789012:siteproof-b-alerts"))
        self.assertLess(config.probe_timeout_seconds + 4,
                        self.template["Resources"]["ProbeFunction"]["Properties"]["Timeout"])

    def test_three_layers_agree_on_the_event_age_window(self):
        res = self.template["Resources"]
        self.assertEqual(
            {res["ProbeAsyncConfig"]["Properties"]["MaximumEventAgeInSeconds"],
             res["ProbeSchedule"]["Properties"]["Target"]["RetryPolicy"]["MaximumEventAgeInSeconds"],
             int(res["ProbeFunction"]["Properties"]["Environment"]["Variables"]["MAX_EVENT_AGE_SECONDS"])},
            {60})

    def test_parameter_patterns_reject_unsafe_targets(self):
        import re
        host = re.compile(self.template["Parameters"]["TargetHostname"]["AllowedPattern"])
        for bad in ("127.0.0.1", "https://example.org", "example.org/path", "EXAMPLE.org",
                    "localhost", "*.example.org", "example.org:8443", ""):
            self.assertIsNone(host.fullmatch(bad), bad)
        self.assertIsNotNone(host.fullmatch("d111111abcdef8.cloudfront.net"))
        path = re.compile(self.template["Parameters"]["TargetPath"]["AllowedPattern"])
        for bad in ("home", "/a?b=1", "/a b", "/a#b", "//evil.example/@x\r\n"):
            self.assertIsNone(path.fullmatch(bad), bad)
        end = re.compile(self.template["Parameters"]["AbsoluteEndAt"]["AllowedPattern"])
        self.assertIsNone(end.fullmatch("2026-11-21T03:00:00+09:00"))

    def test_handler_module_exists_at_declared_path(self):
        handler = self.template["Resources"]["ProbeFunction"]["Properties"]["Handler"]
        module, _, function = handler.rpartition(".")
        self.assertTrue((ROOT / (module.replace(".", os.sep) + ".py")).is_file())
        self.assertEqual(function, "lambda_handler")

    # ---- mutations: each weakening must be reported ----
    def check(self, change):
        self.assertNotEqual(self.mutated(change), [])

    def test_mutation_scheduler_retry(self):
        self.check(lambda r, t: r["ProbeSchedule"]["Properties"]["Target"]["RetryPolicy"].update(MaximumRetryAttempts=3))

    def test_mutation_scheduler_event_age(self):
        self.check(lambda r, t: r["ProbeSchedule"]["Properties"]["Target"]["RetryPolicy"].update(MaximumEventAgeInSeconds=86400))

    def test_mutation_lambda_async_retry(self):
        self.check(lambda r, t: r["ProbeAsyncConfig"]["Properties"].update(MaximumRetryAttempts=2))

    def test_mutation_lambda_async_event_age(self):
        self.check(lambda r, t: r["ProbeAsyncConfig"]["Properties"].update(MaximumEventAgeInSeconds=21600))

    def test_mutation_schedule_default_enabled(self):
        self.check(lambda r, t: t["Parameters"]["ScheduleState"].update(Default="ENABLED"))

    def test_mutation_schedule_without_end(self):
        self.check(lambda r, t: r["ProbeSchedule"]["Properties"].pop("EndDate"))

    def test_mutation_property_cloudformation_rejects(self):
        self.check(lambda r, t: r["ProbeSchedule"]["Properties"].update(ActionAfterCompletion="DELETE"))

    def test_mutation_flexible_window(self):
        self.check(lambda r, t: r["ProbeSchedule"]["Properties"].update(FlexibleTimeWindow={"Mode": "FLEXIBLE", "MaximumWindowInMinutes": 15}))

    def test_mutation_event_without_generation(self):
        def change(r, t):
            target = r["ProbeSchedule"]["Properties"]["Target"]
            target["Input"] = {"Fn::Sub": target["Input"]["Fn::Sub"].replace("${ExecutionGeneration}", "1")}
        self.check(change)

    def test_mutation_event_with_destination(self):
        def change(r, t):
            target = r["ProbeSchedule"]["Properties"]["Target"]
            target["Input"] = {"Fn::Sub": target["Input"]["Fn::Sub"].replace("{\"schema\"", "{\"hostname\":\"x\",\"schema\"")}
        self.check(change)

    def test_mutation_unreserved_concurrency(self):
        self.check(lambda r, t: r["ProbeFunction"]["Properties"].pop("ReservedConcurrentExecutions"))

    def test_mutation_probe_role_delete_item(self):
        self.check(lambda r, t: r["ProbeRole"]["Properties"]["Policies"][0]["PolicyDocument"]["Statement"][0]["Action"].append("dynamodb:DeleteItem"))

    def test_mutation_probe_role_scan(self):
        self.check(lambda r, t: r["ProbeRole"]["Properties"]["Policies"][0]["PolicyDocument"]["Statement"][0]["Action"].append("dynamodb:Scan"))

    def test_mutation_probe_role_wildcard_action(self):
        self.check(lambda r, t: r["ProbeRole"]["Properties"]["Policies"][0]["PolicyDocument"]["Statement"][0].update(Action="dynamodb:*"))

    def test_mutation_probe_role_wildcard_resource(self):
        self.check(lambda r, t: r["ProbeRole"]["Properties"]["Policies"][0]["PolicyDocument"]["Statement"][0].update(Resource="*"))

    def test_mutation_probe_role_without_leading_keys(self):
        self.check(lambda r, t: r["ProbeRole"]["Properties"]["Policies"][0]["PolicyDocument"]["Statement"][0].pop("Condition"))

    def test_mutation_probe_role_create_log_group(self):
        self.check(lambda r, t: r["ProbeRole"]["Properties"]["Policies"][0]["PolicyDocument"]["Statement"][1]["Action"].append("logs:CreateLogGroup"))

    def test_mutation_probe_role_sns_publish_everywhere(self):
        self.check(lambda r, t: r["ProbeRole"]["Properties"]["Policies"][0]["PolicyDocument"]["Statement"][2].update(Resource="*"))

    def test_mutation_probe_role_sns_wildcard_action(self):
        self.check(lambda r, t: r["ProbeRole"]["Properties"]["Policies"][0]["PolicyDocument"]["Statement"][2].update(Action="sns:*"))

    def test_mutation_probe_role_sns_subscribe(self):
        self.check(lambda r, t: r["ProbeRole"]["Properties"]["Policies"][0]["PolicyDocument"]["Statement"][2].update(Action=["sns:Publish", "sns:Subscribe"]))

    def test_mutation_probe_role_cloudwatch_put_metric(self):
        self.check(lambda r, t: r["ProbeRole"]["Properties"]["Policies"][0]["PolicyDocument"]["Statement"].append({"Effect": "Allow", "Action": "cloudwatch:PutMetricData", "Resource": "*"}))

    def test_mutation_managed_policy(self):
        self.check(lambda r, t: r["ProbeRole"]["Properties"].update(ManagedPolicyArns=["arn:aws:iam::aws:policy/AdministratorAccess"]))

    def test_mutation_vpc_attachment(self):
        self.check(lambda r, t: r["ProbeFunction"]["Properties"].update(VpcConfig={"SubnetIds": ["subnet-1"], "SecurityGroupIds": ["sg-1"]}))

    def test_mutation_scheduler_role_broad_invoke(self):
        self.check(lambda r, t: r["SchedulerRole"]["Properties"]["Policies"][0]["PolicyDocument"]["Statement"][0].update(Resource="*"))

    def test_mutation_scheduler_trust_without_account(self):
        self.check(lambda r, t: r["SchedulerRole"]["Properties"]["AssumeRolePolicyDocument"]["Statement"][0].pop("Condition"))

    def test_mutation_table_delete_policy(self):
        self.check(lambda r, t: r["ProbeTable"].update(DeletionPolicy="Delete"))

    def test_mutation_table_without_ttl(self):
        self.check(lambda r, t: r["ProbeTable"]["Properties"].pop("TimeToLiveSpecification"))

    def test_mutation_log_group_without_retention(self):
        self.check(lambda r, t: r["ProbeLogGroup"]["Properties"].pop("RetentionInDays"))

    def test_mutation_secret_in_environment(self):
        self.check(lambda r, t: r["ProbeFunction"]["Properties"]["Environment"]["Variables"].update(API_TOKEN="x"))

    def test_mutation_unpinned_code(self):
        self.check(lambda r, t: r["ProbeFunction"]["Properties"]["Code"].pop("S3ObjectVersion"))

    def test_mutation_extra_resource(self):
        self.check(lambda r, t: r.update(Queue={"Type": "AWS::SQS::Queue"}))

    def test_mutation_dangling_reference(self):
        self.check(lambda r, t: r["ProbeFunction"]["Properties"].update(Role={"Fn::GetAtt": ["Missing", "Arn"]}))

    def test_mutation_transform(self):
        self.check(lambda r, t: t.update(Transform="AWS::Serverless-2016-10-31"))


if __name__ == "__main__":
    unittest.main()
