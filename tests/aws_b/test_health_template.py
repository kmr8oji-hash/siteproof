"""Offline contract for infra/aws_b/health.json, the one aggregate heartbeat alarm of AWS-B Lite.

OFFLINE CANDIDATE / AWS LIVE NOT VERIFIED. This is not AWS schema validation and not evidence of how
CloudWatch evaluates the alarm; see the Evaluation note in the template and test_notify.HeartbeatAlarmModel.
"""
import json
import unittest
from copy import deepcopy
from pathlib import Path

from tests import cfn_contract as cfn
from tests.aws_b.support import Harness
from tests.aws_b.test_notify import PASS

ROOT = Path(__file__).resolve().parents[2]
HEALTH = ROOT / "infra" / "aws_b" / "health.json"
PROBE = ROOT / "infra" / "aws_b" / "template.json"
TOPIC = {"Ref": "AlertTopicArn"}


def audit(template, emitted):
    errors = []

    def need(condition, label):
        if not condition:
            errors.append(label)
    try:
        need(template["AWSTemplateFormatVersion"] == "2010-09-09", "template version")
        need("NO-GO" in template["Description"] and "AWS LIVE NOT VERIFIED" in template["Description"],
             "candidate marker")
        need("Transform" not in template and "Rules" not in template, "no macro, no rules")
        res = template["Resources"]
        need(set(res) == {"HeartbeatAlarm"} and res["HeartbeatAlarm"]["Type"] == "AWS::CloudWatch::Alarm",
             "exactly one alarm and nothing else")
        need(set(template["Parameters"]) == {"AlertTopicArn", "MonitorGroup", "ExpectedPages",
                                             "HeartbeatPeriodSeconds", "AlarmActionsEnabled"}, "parameters")
        p = res["HeartbeatAlarm"]["Properties"]
        # the alarm reads exactly what the handler emits, in a namespace Lambda itself never writes to
        need((p["Namespace"], p["MetricName"]) == emitted, "metric emitted by the handler")
        need(not p["Namespace"].startswith("AWS/"), "no AWS/Lambda Invocations")
        need(p["Dimensions"] == [{"Name": "MonitorGroup", "Value": {"Ref": "MonitorGroup"}}], "group dimension")
        need(p["Statistic"] == "Sum" and p["ComparisonOperator"] == "LessThanThreshold", "sum below expected")
        need(p["Threshold"] == {"Ref": "ExpectedPages"}, "threshold is the page count")
        need(p["Period"] == {"Ref": "HeartbeatPeriodSeconds"}, "period equals schedule interval")
        need(p["EvaluationPeriods"] == 3 and p["DatapointsToAlarm"] == 2, "2 of 3 periods")
        need(p["TreatMissingData"] == "breaching", "silence is a failure")
        need(p["AlarmActions"] == [TOPIC] and p["OKActions"] == [TOPIC], "existing topic, both directions")
        need(p["ActionsEnabled"] == {"Ref": "AlarmActionsEnabled"}, "actions can be switched off at a planned stop")
        need(template["Parameters"]["HeartbeatPeriodSeconds"]["AllowedValues"] == [900, 21600, 43200], "6 h / 12 h (+15 min trial only)")
        need(template["Parameters"]["AlarmActionsEnabled"]["Default"] == "true", "actions on by default")
        errors.extend(cfn.reference_errors(template, {}))
        errors.extend(cfn.iam_wildcard_errors(template))
    except (KeyError, TypeError, IndexError, AttributeError) as exc:
        errors.append("structure: %s %s" % (type(exc).__name__, exc))
    return errors


def emitted_metric():
    h = Harness(notify=True)
    h.run_slot(0, PASS)
    directive = h.lines[0]["_aws"]["CloudWatchMetrics"][0]
    return directive["Namespace"], directive["Metrics"][0]["Name"], directive["Dimensions"][0][0]


class HealthTemplate(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.template = cfn.load(HEALTH)
        cls.namespace, cls.metric, cls.dimension = emitted_metric()

    def audit(self, template):
        return audit(template, (self.namespace, self.metric))

    def mutated(self, change):
        template = deepcopy(self.template)
        change(template["Resources"]["HeartbeatAlarm"]["Properties"], template)
        return self.audit(template)

    def test_candidate_passes_local_audit(self):
        self.assertEqual(self.audit(self.template), [])

    def test_handler_and_alarm_agree_on_metric_dimension_and_group_default(self):
        self.assertEqual((self.namespace, self.metric, self.dimension),
                         ("SiteProof/Monitor", "ProbeCompleted", "MonitorGroup"))
        probe = cfn.load(PROBE)
        self.assertEqual(probe["Parameters"]["MonitorGroup"]["Default"],
                         self.template["Parameters"]["MonitorGroup"]["Default"])
        self.assertEqual(probe["Parameters"]["MonitorGroup"]["AllowedPattern"],
                         self.template["Parameters"]["MonitorGroup"]["AllowedPattern"])

    def test_period_options_match_the_probe_schedule_options(self):
        probe = cfn.load(PROBE)["Parameters"]["ScheduleExpression"]["AllowedValues"]
        self.assertIn("rate(6 hours)", probe)
        self.assertIn("rate(12 hours)", probe)
        allowed = self.template["Parameters"]["HeartbeatPeriodSeconds"]["AllowedValues"]
        self.assertEqual(allowed, [15 * 60, 6 * 3600, 12 * 3600])
        self.assertIn("rate(15 minutes)", probe)           # the 900 s trial value pairs with the existing trial schedule

    def test_alarm_name_is_what_the_stopper_is_given(self):
        props = self.template["Resources"]["HeartbeatAlarm"]["Properties"]
        self.assertEqual(props["AlarmName"], {"Fn::Sub": "${AWS::StackName}-heartbeat"})
        self.assertEqual(self.template["Outputs"]["HeartbeatAlarmName"]["Value"], {"Ref": "HeartbeatAlarm"})
        stopper = cfn.load(ROOT / "infra" / "aws_b" / "stopper.json")
        self.assertIn("HeartbeatAlarmName", stopper["Parameters"])

    def test_documents_the_limits_instead_of_claiming_exact_detection(self):
        meta = self.template["Metadata"]
        self.assertIn("LIVE-unverified", meta["Evaluation"])
        self.assertIn("isolated missed run is tolerated", meta["Evaluation"])
        self.assertIn("planned stop", meta["PlannedStop"].lower())
        self.assertIn("PAGE stop", meta["PlannedStop"])
        self.assertIn("ExpectedPages", meta["PlannedStop"])

    # ---- mutations: each weakening must be reported ----
    def check(self, change):
        self.assertNotEqual(self.mutated(change), [])

    def test_mutation_missing_data_not_breaching(self):
        self.check(lambda p, t: p.update(TreatMissingData="notBreaching"))

    def test_mutation_missing_data_ignored(self):
        self.check(lambda p, t: p.update(TreatMissingData="missing"))

    def test_mutation_lambda_invocations_instead_of_heartbeat(self):
        self.check(lambda p, t: p.update(Namespace="AWS/Lambda", MetricName="Invocations"))

    def test_mutation_threshold_not_page_count(self):
        self.check(lambda p, t: p.update(Threshold=1))

    def test_mutation_one_period_of_one(self):
        self.check(lambda p, t: p.update(EvaluationPeriods=1, DatapointsToAlarm=1))

    def test_mutation_no_recovery_notice(self):
        self.check(lambda p, t: p.update(OKActions=[]))

    def test_mutation_no_alarm_action(self):
        self.check(lambda p, t: p.update(AlarmActions=[]))

    def test_mutation_actions_cannot_be_disabled(self):
        self.check(lambda p, t: p.pop("ActionsEnabled"))

    def test_mutation_extra_resource(self):
        self.check(lambda p, t: t["Resources"].update(Topic={"Type": "AWS::SNS::Topic"}))


class TrialPolicyPlan(unittest.TestCase):
    """fixture_plan (in the repo, generator independent): trial IAM follows the Lite alarm layout."""
    TRIAL = "20261113-120000"

    def names(self):
        from src.aws_b.fixture_plan import fixture_names
        prefix = "siteproof-b-" + self.TRIAL
        pages = {t: {"stack": prefix + "-" + t, "function": prefix + "-" + t + "-probe", "table": prefix + "-" + t + "-runs",
                     "schedule": prefix + "-" + t + "-schedule", "probe_role": prefix + "-" + t + "-probe-role",
                     "scheduler_role": prefix + "-" + t + "-scheduler-role"} for t in ("noxiworks-home", "ttn-home")}
        return {"prefix": prefix, "pages": pages, "fixture": fixture_names(self.TRIAL),
                "topic_arn": "arn:aws:sns:us-east-1:123456789012:" + prefix + "-alerts"}

    def statements(self, policy_name):
        from src.aws_b.fixture_plan import policies
        return policies(self.names())[policy_name]["Statement"]

    def test_alarm_permissions_name_only_the_one_heartbeat_alarm(self):
        alarm = "arn:aws:cloudwatch:us-east-1:123456789012:alarm:siteproof-b-" + self.TRIAL + "-health-heartbeat"
        found = []
        for name in ("trial-fixture-deploy-policy.json", "trial-cleanup-policy.json"):
            for st in self.statements(name):
                actions = st["Action"] if isinstance(st["Action"], list) else [st["Action"]]
                if any(a.startswith("cloudwatch:") for a in actions):
                    found.append((actions, st["Resource"]))
        self.assertEqual(found[0], (["cloudwatch:EnableAlarmActions"], alarm))               # nothing else may be re-enabled
        self.assertEqual(found[1][0], ["cloudwatch:DeleteAlarms"])
        # delete: the heartbeat alarm first, then only the orphaned pre-Lite per-page alarms (3 per page)
        self.assertEqual(found[1][1][0], alarm)
        legacy = found[1][1][1:]
        self.assertEqual(len(legacy), 3)                   # two pages + the fixture monitor stack policies() appends
        self.assertTrue(all(a.endswith("-*") and a.count("siteproof-b-" + self.TRIAL) == 1 for a in legacy), legacy)  # this trial's stacks only
        self.assertEqual(len(found), 2)
        stacks = [st["Resource"] for st in self.statements("trial-cleanup-policy.json") if st["Action"] == ["cloudformation:DeleteStack"]][0]
        self.assertTrue(any(r.endswith("-health/*") for r in stacks))

    def test_fixture_probe_boundary_allows_publish_to_this_trials_topic_only(self):
        from src.aws_b.fixture_plan import template
        boundary = template(self.TRIAL, "2026-11-14T03:10:00Z")["Resources"]["TrialProbeBoundary"]["Properties"]["PolicyDocument"]
        publish = [st for st in boundary["Statement"] if st["Action"] == "sns:Publish"]
        self.assertEqual([st["Resource"] for st in publish],
                         ["arn:aws:sns:us-east-1:123456789012:siteproof-b-" + self.TRIAL + "-alerts"])

    def test_policies_refuse_a_placeholder_account(self):
        from unittest.mock import patch
        import src.aws_b.fixture_plan as plan
        names = {**self.names(), "account": "210987654321", "topic_arn": "arn:aws:sns:us-east-1:210987654321:siteproof-b-" + self.TRIAL + "-alerts"}
        with patch.object(plan, "ACCOUNT", "123456789012"):
            with self.assertRaises(ValueError):
                plan.policies(names)
        with patch.object(plan, "ACCOUNT", "210987654321"):
            text = json.dumps(plan.policies(names))
        self.assertNotIn("123456789012", text)
        self.assertIn("210987654321", text)

    def test_no_operator_policy_manages_policy_versions_the_user_applies_the_boundary_once(self):
        from src.aws_b.fixture_plan import policies, boundary_document, template
        every = policies(self.names())
        operator = [n for n in every if n != "trial-fixture-boundary-update-policy.json"]
        for name in operator:
            for st in every[name]["Statement"]:
                actions = st["Action"] if isinstance(st["Action"], list) else [st["Action"]]
                self.assertFalse([a for a in actions if a in ("iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion",
                                                              "iam:DeletePolicyVersion")], (name, actions))
        document = every["trial-fixture-boundary-update-policy.json"]
        self.assertEqual(document, boundary_document(self.TRIAL))
        self.assertEqual(document, template(self.TRIAL, "2026-11-27T03:00:00Z")["Resources"]["TrialProbeBoundary"]["Properties"]["PolicyDocument"])
        actions = [st["Action"] if isinstance(st["Action"], list) else [st["Action"]] for st in document["Statement"]]
        self.assertEqual(actions, [["dynamodb:PutItem", "dynamodb:UpdateItem"], ["logs:CreateLogStream", "logs:PutLogEvents"], ["sns:Publish"]])
        self.assertEqual(document["Statement"][2]["Resource"], "arn:aws:sns:us-east-1:123456789012:siteproof-b-" + self.TRIAL + "-alerts")

    def test_changeset_policy_is_the_minimum_for_a_preview_and_scoped_to_this_trial(self):
        from src.aws_b.fixture_plan import policies
        (statement,) = policies(self.names())["trial-changeset-policy.json"]["Statement"]
        self.assertEqual(set(statement["Action"]), {"cloudformation:CreateChangeSet", "cloudformation:DescribeChangeSet",
                                                    "cloudformation:ExecuteChangeSet", "cloudformation:DeleteChangeSet"})
        resources = statement["Resource"]
        self.assertTrue(all(r != "*" and "siteproof-b-" + self.TRIAL in r or "siteproof-lite-" in r for r in resources), resources)
        self.assertTrue(any(r.endswith("-health/*") for r in resources))
        self.assertFalse(any("-http-fixture/" in r and "aws-b-http-fixture" not in r for r in resources))   # the fixture response stack is not updated
        self.assertEqual(statement["Condition"]["Null"], {"cloudformation:RoleArn": "true"})


if __name__ == "__main__":
    unittest.main()
