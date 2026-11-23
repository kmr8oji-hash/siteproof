"""Offline contract checks for infra/aws_c (guard plane, single-use worker, bootstrap).

OFFLINE CANDIDATE / AWS LIVE NOT VERIFIED. NOT AWS schema, IAM or service validation.
Mutation tests prove each safety property is enforced by the local audit.
"""
import json
import os
import re
import unittest
from copy import deepcopy
from pathlib import Path

from src.aws_c.watchdog import TAG_KEY, WatchdogConfig
from tests import cfn_contract as cfn

ROOT = Path(__file__).resolve().parents[2]
DIR = ROOT / "infra" / "aws_c"
ALL_ROLES = ("WorkerRole", "WatchdogRole", "WatchdogSchedulerRole", "ControllerRole")
GUARD_TYPES = {
    "EvidenceBucket": "AWS::S3::Bucket", "EvidenceBucketPolicy": "AWS::S3::BucketPolicy",
    "ControlTable": "AWS::DynamoDB::Table", "SigningKey": "AWS::KMS::Key",
    "WorkerRole": "AWS::IAM::Role", "WorkerInstanceProfile": "AWS::IAM::InstanceProfile",
    "WatchdogLogGroup": "AWS::Logs::LogGroup", "WatchdogRole": "AWS::IAM::Role",
    "WatchdogFunction": "AWS::Lambda::Function",
    "WatchdogAsyncConfig": "AWS::Lambda::EventInvokeConfig",
    "WatchdogSchedulerRole": "AWS::IAM::Role",
    "WatchdogDeadlineSchedule": "AWS::Scheduler::Schedule",
    "WatchdogPeriodicSchedule": "AWS::Scheduler::Schedule",
    "ControllerLogGroup": "AWS::Logs::LogGroup", "ControllerRole": "AWS::IAM::Role",
    "ControllerFunction": "AWS::Lambda::Function",
    "WatchdogAttentionAlarm": "AWS::CloudWatch::Alarm",
    "WatchdogSilentAlarm": "AWS::CloudWatch::Alarm",
    "WatchdogErrorAlarm": "AWS::CloudWatch::Alarm",
}
GUARD_GETATT = {name: {"Arn"} for name in (
    "EvidenceBucket", "ControlTable", "SigningKey", "WorkerRole", "WatchdogLogGroup",
    "WatchdogRole", "WatchdogFunction", "WatchdogSchedulerRole", "ControllerLogGroup",
    "ControllerRole", "ControllerFunction")}
TOPIC = {"Ref": "AlertTopicArn"}
RUN_KEYS = {"ForAllValues:StringEquals": {"dynamodb:LeadingKeys": [
    {"Fn::Sub": "PILOT#${PilotRunId}"}]}}
FORBIDDEN_EC2 = ("ec2:RunInstances", "ec2:StartInstances", "ec2:StopInstances",
                 "ec2:RebootInstances", "ec2:CreateTags", "ec2:DeleteTags",
                 "ec2:ModifyInstanceAttribute", "ec2:AssociateIamInstanceProfile")


def role_actions(role):
    out = {}
    for policy in role["Properties"]["Policies"]:
        for statement in cfn.statements(policy["PolicyDocument"]):
            for action in cfn.actions(statement):
                out[action] = statement
    return out


def audit_guard(template):
    errors = []

    def need(condition, label):
        if not condition:
            errors.append(label)
    try:
        need("Transform" not in template and "Mappings" not in template, "no macro/mappings")
        need("AWS LIVE NOT VERIFIED" in template["Description"]
             and "NO-GO" in template["Description"]
             and "NO EC2 instance" in template["Description"], "candidate marker")
        res = template["Resources"]
        need(set(res) == set(GUARD_TYPES), "exact resource set")
        for name, kind in GUARD_TYPES.items():
            need(res[name]["Type"] == kind, "resource type " + name)
        need(not any(str(r.get("Type", "")).startswith(("AWS::EC2::", "AWS::AutoScaling::",
                                                         "AWS::SQS::", "AWS::Budgets::"))
                     for r in res.values()), "guard plane creates no compute/queue/budget")
        for name in ("PilotRunId", "HardDeadlineUtc", "GuardEndAt"):
            need("Default" not in template["Parameters"][name], name + " must be chosen")
        need(template["Parameters"]["EnableKmsSigning"]["Default"] == "false",
             "signing key off by default")
        errors.extend(cfn.reference_errors(template, GUARD_GETATT))
        errors.extend(cfn.iam_wildcard_errors(
            template, allowed_star_actions={"ec2:DescribeInstances",
                                            "ecr:GetAuthorizationToken"},
            exempt_sids={"AccountAdministersKeyThroughIam"}))
        need(not any(isinstance(n, dict) and ("ManagedPolicyArns" in n or "VpcConfig" in n)
                     for n in cfn.walk(res)), "no managed policies / VPC attachment")

        bucket = res["EvidenceBucket"]
        need(bucket.get("DeletionPolicy") == "Retain"
             and bucket.get("UpdateReplacePolicy") == "Retain", "evidence bucket retained")
        bp = bucket["Properties"]
        need(bp["PublicAccessBlockConfiguration"] == {
            "BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True}, "public access fully blocked")
        need(bp["VersioningConfiguration"] == {"Status": "Enabled"}, "versioning")
        need(bp["OwnershipControls"] == {"Rules": [{"ObjectOwnership": "BucketOwnerEnforced"}]},
             "no ACLs")
        need("LifecycleConfiguration" not in bp and "WebsiteConfiguration" not in bp
             and "CorsConfiguration" not in bp, "no expiry/website/cors on evidence")
        policy = {s.get("Sid"): s for s in cfn.statements(
            res["EvidenceBucketPolicy"]["Properties"]["PolicyDocument"])}
        need(set(policy) == {"DenyInsecureTransport", "DenyUnconditionalWrites"},
             "bucket policy statements")
        need(all(s["Effect"] == "Deny" for s in policy.values()), "bucket policy only denies")
        need(policy["DenyUnconditionalWrites"]["Action"] == "s3:PutObject"
             and policy["DenyUnconditionalWrites"]["Principal"] == "*"
             and policy["DenyUnconditionalWrites"]["Condition"]
             == {"Null": {"s3:if-none-match": "true"}}, "writes must be conditional")
        need(policy["DenyInsecureTransport"]["Condition"]
             == {"Bool": {"aws:SecureTransport": "false"}}, "tls only")

        table = res["ControlTable"]
        need(table.get("DeletionPolicy") == "Retain", "control table retained")
        need(table["Properties"]["BillingMode"] == "PAY_PER_REQUEST", "on-demand")

        key = res["SigningKey"]
        need(key.get("Condition") == "KmsEnabled", "signing key conditional")
        need(key["Properties"]["KeySpec"] == "ECC_NIST_P256"
             and key["Properties"]["KeyUsage"] == "SIGN_VERIFY", "asymmetric sign/verify key")
        key_statements = cfn.statements(key["Properties"]["KeyPolicy"])
        need(len(key_statements) == 1 and key_statements[0]["Principal"] == {"AWS": {
            "Fn::Sub": "arn:${AWS::Partition}:iam::${AWS::AccountId}:root"}},
            "key policy delegates to this account's IAM only")

        for name in ALL_ROLES:
            allowed = role_actions(res[name])
            need(not any(a in allowed for a in FORBIDDEN_EC2), name + " cannot start/run/stop")
            need(not any(a.startswith(("iam:", "sts:", "organizations:")) for a in allowed),
                 name + " has no identity permissions")
            need(not any("Delete" in a for a in allowed), name + " cannot delete")
            need(len(res[name]["Properties"]["Policies"]) == 1, name + " single policy")

        worker = role_actions(res["WorkerRole"])
        need(set(worker) == {"s3:PutObject", "s3:GetObject", "s3:GetObjectAttributes",
                             "s3:GetObjectVersion", "dynamodb:GetItem", "dynamodb:UpdateItem",
                             "ecr:GetAuthorizationToken", "ecr:BatchGetImage",
                             "ecr:GetDownloadUrlForLayer", "ecr:BatchCheckLayerAvailability",
                             "kms:Sign"}, "worker action allowlist")
        need(worker["s3:PutObject"]["Resource"]
             == {"Fn::Sub": "${EvidenceBucket.Arn}/runs/${PilotRunId}/*"},
             "worker writes only its own run prefix")
        need(worker["dynamodb:UpdateItem"].get("Condition") == RUN_KEYS,
             "worker journals only its own run")
        need(worker["ecr:BatchGetImage"]["Resource"] == {"Ref": "EcrRepositoryArn"},
             "worker pulls one repository")
        need(worker["kms:Sign"]["Resource"] == {"Fn::GetAtt": ["SigningKey", "Arn"]},
             "worker signs with one key")
        need(not any(a.startswith("ec2:") or a.startswith("lambda:") for a in worker),
             "worker has no ec2/lambda permission")
        trust = cfn.statements(res["WorkerRole"]["Properties"]["AssumeRolePolicyDocument"])
        need(len(trust) == 1 and trust[0]["Principal"] == {"Service": "ec2.amazonaws.com"},
             "worker trust")
        need(res["WorkerInstanceProfile"]["Properties"]["Roles"] == [{"Ref": "WorkerRole"}],
             "instance profile carries the worker role only")

        dog = role_actions(res["WatchdogRole"])
        need(set(dog) == {"ec2:DescribeInstances", "ec2:TerminateInstances",
                          "dynamodb:GetItem", "dynamodb:UpdateItem", "logs:CreateLogStream",
                          "logs:PutLogEvents"}, "watchdog action allowlist")
        terminate = dog["ec2:TerminateInstances"]
        need(terminate.get("Condition") == {"StringEquals": {
            "ec2:ResourceTag/" + TAG_KEY: {"Ref": "PilotRunId"}}},
            "terminate limited to the pilot-run tag")
        need(terminate["Resource"] == {"Fn::Sub": "arn:${AWS::Partition}:ec2:${AWS::Region}:"
                                                  "${AWS::AccountId}:instance/*"},
             "terminate limited to instances in this account and region")
        need(dog["dynamodb:UpdateItem"].get("Condition") == RUN_KEYS, "watchdog journal scope")

        ctl = role_actions(res["ControllerRole"])
        need(set(ctl) == {"dynamodb:PutItem", "dynamodb:GetItem", "logs:CreateLogStream",
                          "logs:PutLogEvents"}, "controller action allowlist")
        need(ctl["dynamodb:PutItem"].get("Condition") == {
            "ForAllValues:StringEquals": {"dynamodb:LeadingKeys": [
                "SLOT", {"Fn::Sub": "PILOT#${PilotRunId}"}]}}, "controller key scope")

        sched_role = res["WatchdogSchedulerRole"]["Properties"]
        strust = cfn.statements(sched_role["AssumeRolePolicyDocument"])
        need(strust[0]["Principal"] == {"Service": "scheduler.amazonaws.com"}
             and strust[0].get("Condition") == {"StringEquals": {
                 "aws:SourceAccount": {"Ref": "AWS::AccountId"}}}, "scheduler trust scoped")
        need(role_actions(res["WatchdogSchedulerRole"])["lambda:InvokeFunction"]["Resource"]
             == {"Fn::GetAtt": ["WatchdogFunction", "Arn"]}, "scheduler invokes watchdog only")

        fn = res["WatchdogFunction"]["Properties"]
        need(fn["Handler"] == "src.aws_c.watchdog.lambda_handler", "watchdog handler")
        env = fn["Environment"]["Variables"]
        need(env == {"PILOT_RUN_ID": {"Ref": "PilotRunId"},
                     "HARD_DEADLINE_UTC": {"Ref": "HardDeadlineUtc"},
                     "TABLE_NAME": {"Ref": "ControlTable"}}, "watchdog target fixed in config")
        need(set(fn["Code"]) == {"S3Bucket", "S3Key", "S3ObjectVersion"}, "pinned code")
        need(res["WatchdogAsyncConfig"]["Properties"]["MaximumRetryAttempts"] == 2,
             "watchdog invocations are retried")
        cfnn = res["ControllerFunction"]["Properties"]
        need(cfnn["Handler"] == "src.aws_c.controller.lambda_handler"
             and cfnn["Role"] == {"Fn::GetAtt": ["ControllerRole", "Arn"]}, "controller wiring")

        deadline = res["WatchdogDeadlineSchedule"]["Properties"]
        need(deadline["State"] == "ENABLED" and deadline["FlexibleTimeWindow"] == {"Mode": "OFF"},
             "deadline schedule armed and exact")
        need(deadline["ScheduleExpression"] == {"Fn::Join": ["", ["at(", {"Fn::Select": [
            0, {"Fn::Split": ["Z", {"Ref": "HardDeadlineUtc"}]}]}, ")"]]},
            "one-time schedule at the hard deadline")
        need(deadline["ScheduleExpressionTimezone"] == "UTC", "utc")
        need(deadline["Target"]["RetryPolicy"]["MaximumRetryAttempts"] >= 5,
             "deadline delivery retried")
        periodic = res["WatchdogPeriodicSchedule"]["Properties"]
        need(periodic["State"] == "ENABLED" and periodic["ScheduleExpression"] == "rate(5 minutes)",
             "periodic heartbeat")
        need(json.dumps(periodic.get("EndDate", "")).count("GuardEndAt") == 1,
             "periodic schedule bounded")
        for schedule in (deadline, periodic):
            need(schedule["Target"]["Arn"] == {"Fn::GetAtt": ["WatchdogFunction", "Arn"]},
                 "schedule targets watchdog")
            need("hard_deadline" not in schedule["Target"]["Input"].lower()
                 and "instance" not in schedule["Target"]["Input"].lower(),
                 "event cannot carry a target or deadline")

        silent = res["WatchdogSilentAlarm"]["Properties"]
        need(silent["TreatMissingData"] == "breaching" and silent["MetricName"] == "WatchdogRun"
             and silent["ComparisonOperator"] == "LessThanThreshold"
             and silent["AlarmActions"] == [TOPIC], "silent watchdog alarms")
        attention = res["WatchdogAttentionAlarm"]["Properties"]
        need(attention["MetricName"] == "WatchdogAttention"
             and attention["AlarmActions"] == [TOPIC], "attention alarm")
        need(res["WatchdogErrorAlarm"]["Properties"]["AlarmActions"] == [TOPIC], "error alarm")
        outputs = template["Outputs"]
        need({"EvidenceBucketName", "ControlTableName", "WorkerInstanceProfileName"}
             <= set(outputs), "outputs the worker stack needs")
    except (KeyError, TypeError, IndexError, AttributeError) as exc:
        errors.append("structure: %s %s" % (type(exc).__name__, exc))
    return errors


def audit_worker(template):
    errors = []

    def need(condition, label):
        if not condition:
            errors.append(label)
    try:
        need("Transform" not in template and "Mappings" not in template, "no macro/mappings")
        need("AWS LIVE NOT VERIFIED" in template["Description"]
             and "NO-GO" in template["Description"], "candidate marker")
        res = template["Resources"]
        need({n: r["Type"] for n, r in res.items()} == {
            "WorkerSecurityGroup": "AWS::EC2::SecurityGroup",
            "WorkerInstance": "AWS::EC2::Instance"}, "exactly one instance and its group")
        for name in ("PilotRunId", "HardDeadlineUtc", "ImageId", "WorkerInstanceProfileName",
                     "RuntimeImageDigest", "WorkerBundleSha256", "WorkerBundleObjectVersion"):
            need("Default" not in template["Parameters"][name], name + " must be chosen")
        errors.extend(cfn.reference_errors(template, {}))
        need(not any(isinstance(n, dict) and "Statement" in n for n in cfn.walk(res)),
             "worker stack defines no IAM")

        group = res["WorkerSecurityGroup"]["Properties"]
        need(group["SecurityGroupIngress"] == [], "no inbound rule")
        egress = group["SecurityGroupEgress"]
        need(len(egress) == 1 and (egress[0]["IpProtocol"], egress[0]["FromPort"],
                                   egress[0]["ToPort"], egress[0]["CidrIp"])
             == ("tcp", 443, 443, "0.0.0.0/0") and "CidrIpv6" not in egress[0],
             "outbound https over ipv4 only")

        instance = res["WorkerInstance"]
        p = instance["Properties"]
        need(p["InstanceInitiatedShutdownBehavior"] == "terminate", "os shutdown terminates")
        need(p["MetadataOptions"]["HttpTokens"] == "required"
             and p["MetadataOptions"]["HttpPutResponseHopLimit"] == 1, "imdsv2, hop limit 1")
        need("KeyName" not in p, "no ssh key")
        need(p["IamInstanceProfile"] == {"Ref": "WorkerInstanceProfileName"},
             "profile comes from the guard stack")
        need(p["DisableApiTermination"] is False, "watchdog can terminate")
        need(p["CreditSpecification"] == {"CPUCredits": "standard"}, "no unlimited credits")
        interfaces = p["NetworkInterfaces"]
        need(len(interfaces) == 1 and interfaces[0]["GroupSet"] == [
            {"Ref": "WorkerSecurityGroup"}] and interfaces[0]["DeleteOnTermination"] is True,
            "single interface in the worker group")
        need("SecurityGroupIds" not in p and "SecurityGroups" not in p and "SubnetId" not in p,
             "no second network definition")
        volumes = p["BlockDeviceMappings"]
        need(len(volumes) == 1 and volumes[0]["Ebs"]["DeleteOnTermination"] is True
             and volumes[0]["Ebs"]["Encrypted"] is True and volumes[0]["Ebs"]["VolumeSize"] <= 50,
             "one encrypted volume removed on termination")
        tags = {t["Key"]: t["Value"] for t in p["Tags"]}
        need(tags.get(TAG_KEY) == {"Ref": "PilotRunId"}, "pilot-run tag the watchdog relies on")
        need(p["PropagateTagsToVolumeOnCreation"] is True, "volume tagged for inventory")
        need(set(template["Parameters"]["InstanceType"]["AllowedValues"])
             <= {"t3.small", "t3.medium"}, "small instance types only")
        need(template["Parameters"]["MaxRuntimeMinutes"]["MaxValue"] <= 90, "bounded runtime")
        need("CreationPolicy" not in instance and "AWS::CloudFormation::Init"
             not in json.dumps(instance.get("Metadata", {})), "no cfn-init / signal")
        need(set(p["UserData"]) == {"Fn::Base64"} and set(p["UserData"]["Fn::Base64"])
             == {"Fn::Sub"}, "user data form")
        errors.extend(audit_script(p["UserData"]["Fn::Base64"]["Fn::Sub"],
                                   set(template["Parameters"])))
    except (KeyError, TypeError, IndexError, AttributeError) as exc:
        errors.append("structure: %s %s" % (type(exc).__name__, exc))
    return errors


def audit_script(script, parameters):
    errors = []
    lines = [line.strip() for line in script.split("\n")]
    commands = [line for line in lines if line and not line.startswith("#")]
    if not script.startswith("#!/bin/bash\n"):
        errors.append("shebang")
    if not commands or not re.fullmatch(
            r'shutdown -h \+\$\{MaxRuntimeMinutes\} "[^"$`]*"', commands[0]):
        errors.append("dead-man timer must be the first command")
    if "trap finish EXIT" not in commands or "shutdown -h now" not in commands:
        errors.append("every exit path must power off")
    if commands.index("trap finish EXIT") > 8 if "trap finish EXIT" in commands else True:
        errors.append("exit trap must be installed before any work")
    if any("shutdown -c" in line or "systemctl mask" in line for line in commands):
        errors.append("timer must never be cancelled")
    for name in re.findall(r"\$\{([^}]+)\}", script):
        if name not in parameters | cfn.PSEUDO:
            errors.append("unknown substitution " + name)
    forbidden = ("curl ", "wget ", "apt-get", "apt ", "dnf ", "yum ", "pip ", "| sh", "| bash",
                 "--privileged", "--no-sandbox", "ssh", "authorized_keys", "aws_secret",
                 "AWS_SECRET", "password=", "set -x", "start-instances", "run-instances",
                 "reboot", "docker run", "chmod 777", ":latest")
    for word in forbidden:
        if any(word in line for line in commands):
            errors.append("forbidden in bootstrap: " + word.strip())
    if '"$DOCKER_BIN" pull "$RUNTIME_IMAGE"' not in script or "@${RuntimeImageDigest}" not in script:
        errors.append("image must be pulled by digest")
    if 'VersionId=os.environ["BUNDLE_VERSION"]' not in script or "bundle hash mismatch" not in script:
        errors.append("bundle must be version-pinned and hash-verified")
    if "python3 -B -m src.aws_c.worker_entry" not in script:
        errors.append("worker entry")
    if script.index("shutdown -h +") > script.index("export "):
        errors.append("timer after configuration")
    return errors


class GuardContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.template = cfn.load(DIR / "guard.template.json")

    def check(self, change):
        template = deepcopy(self.template)
        change(template["Resources"], template)
        self.assertNotEqual(audit_guard(template), [])

    def statement(self, r, role, index):
        return r[role]["Properties"]["Policies"][0]["PolicyDocument"]["Statement"][index]

    def test_candidate_passes_local_audit(self):
        self.assertEqual(audit_guard(self.template), [])

    def test_no_role_anywhere_can_start_run_stop_or_reboot_an_instance(self):
        text = json.dumps(self.template)
        for action in FORBIDDEN_EC2:
            self.assertNotIn(action, text)
        self.assertEqual(text.count("ec2:TerminateInstances"), 1)

    def test_handlers_exist_and_environment_satisfies_watchdog_config(self):
        for name in ("WatchdogFunction", "ControllerFunction"):
            handler = self.template["Resources"][name]["Properties"]["Handler"]
            module = handler.rpartition(".")[0]
            self.assertTrue((ROOT / (module.replace(".", os.sep) + ".py")).is_file())
        config = WatchdogConfig.from_env({"PILOT_RUN_ID": "pilot-20261201-a",
                                          "HARD_DEADLINE_UTC": "2026-12-01T03:00:00Z",
                                          "TABLE_NAME": "t"})
        self.assertEqual(config.pilot_run_id, "pilot-20261201-a")
        pattern = re.compile(self.template["Parameters"]["PilotRunId"]["AllowedPattern"])
        self.assertIsNotNone(pattern.fullmatch("pilot-20261201-a"))
        for bad in ("a", "Pilot", "run id", "run/1", "*"):
            self.assertIsNone(pattern.fullmatch(bad))

    def test_tag_key_matches_between_code_iam_and_worker_template(self):
        worker = cfn.load(DIR / "worker.template.json")
        keys = [t["Key"] for t in worker["Resources"]["WorkerInstance"]["Properties"]["Tags"]]
        self.assertIn(TAG_KEY, keys)
        self.assertIn("ec2:ResourceTag/" + TAG_KEY, json.dumps(self.template))

    def test_mutation_watchdog_start_instances(self):
        self.check(lambda r, t: self.statement(r, "WatchdogRole", 0).update(Action=["ec2:DescribeInstances", "ec2:StartInstances"]))

    def test_mutation_watchdog_stop_instead_of_terminate(self):
        self.check(lambda r, t: self.statement(r, "WatchdogRole", 1).update(Action="ec2:StopInstances"))

    def test_mutation_terminate_without_tag_condition(self):
        self.check(lambda r, t: self.statement(r, "WatchdogRole", 1).pop("Condition"))

    def test_mutation_terminate_any_resource(self):
        self.check(lambda r, t: self.statement(r, "WatchdogRole", 1).update(Resource="*"))

    def test_mutation_terminate_wrong_tag(self):
        self.check(lambda r, t: self.statement(r, "WatchdogRole", 1).update(Condition={"StringEquals": {"ec2:ResourceTag/Project": "SiteProof"}}))

    def test_mutation_worker_run_instances(self):
        self.check(lambda r, t: self.statement(r, "WorkerRole", 3).update(Action=["ecr:GetAuthorizationToken", "ec2:RunInstances"]))

    def test_mutation_worker_delete_object(self):
        self.check(lambda r, t: self.statement(r, "WorkerRole", 0)["Action"].append("s3:DeleteObject"))

    def test_mutation_worker_whole_bucket(self):
        self.check(lambda r, t: self.statement(r, "WorkerRole", 0).update(Resource={"Fn::Sub": "${EvidenceBucket.Arn}/*"}))

    def test_mutation_worker_put_item(self):
        self.check(lambda r, t: self.statement(r, "WorkerRole", 2)["Action"].append("dynamodb:PutItem"))

    def test_mutation_worker_journal_any_key(self):
        self.check(lambda r, t: self.statement(r, "WorkerRole", 2).pop("Condition"))

    def test_mutation_worker_pass_role(self):
        self.check(lambda r, t: self.statement(r, "WorkerRole", 3).update(Action=["ecr:GetAuthorizationToken", "iam:PassRole"]))

    def test_mutation_worker_any_repository(self):
        self.check(lambda r, t: self.statement(r, "WorkerRole", 4).update(Resource="*"))

    def test_mutation_controller_gets_ec2(self):
        self.check(lambda r, t: self.statement(r, "ControllerRole", 0)["Action"].append("ec2:TerminateInstances"))

    def test_mutation_controller_update_item(self):
        self.check(lambda r, t: self.statement(r, "ControllerRole", 0)["Action"].append("dynamodb:UpdateItem"))

    def test_mutation_bucket_allows_unconditional_put(self):
        self.check(lambda r, t: r["EvidenceBucketPolicy"]["Properties"]["PolicyDocument"]["Statement"].pop(1))

    def test_mutation_bucket_public_allow(self):
        self.check(lambda r, t: r["EvidenceBucketPolicy"]["Properties"]["PolicyDocument"]["Statement"].append({"Sid": "Public", "Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "*"}))

    def test_mutation_bucket_not_retained(self):
        self.check(lambda r, t: r["EvidenceBucket"].update(DeletionPolicy="Delete"))

    def test_mutation_bucket_unversioned(self):
        self.check(lambda r, t: r["EvidenceBucket"]["Properties"].pop("VersioningConfiguration"))

    def test_mutation_bucket_expiry_rule(self):
        self.check(lambda r, t: r["EvidenceBucket"]["Properties"].update(LifecycleConfiguration={"Rules": [{"Status": "Enabled", "ExpirationInDays": 1}]}))

    def test_mutation_public_access_block(self):
        self.check(lambda r, t: r["EvidenceBucket"]["Properties"]["PublicAccessBlockConfiguration"].update(BlockPublicPolicy=False))

    def test_mutation_deadline_schedule_disabled(self):
        self.check(lambda r, t: r["WatchdogDeadlineSchedule"]["Properties"].update(State="DISABLED"))

    def test_mutation_deadline_schedule_not_at_deadline(self):
        self.check(lambda r, t: r["WatchdogDeadlineSchedule"]["Properties"].update(ScheduleExpression="rate(1 day)"))

    def test_mutation_periodic_unbounded(self):
        self.check(lambda r, t: r["WatchdogPeriodicSchedule"]["Properties"].pop("EndDate"))

    def test_mutation_watchdog_deadline_from_event(self):
        self.check(lambda r, t: r["WatchdogFunction"]["Properties"]["Environment"]["Variables"].pop("HARD_DEADLINE_UTC"))

    def test_mutation_watchdog_no_retry(self):
        self.check(lambda r, t: r["WatchdogAsyncConfig"]["Properties"].update(MaximumRetryAttempts=0))

    def test_mutation_silent_alarm_ignores_missing(self):
        self.check(lambda r, t: r["WatchdogSilentAlarm"]["Properties"].update(TreatMissingData="notBreaching"))

    def test_mutation_guard_creates_instance(self):
        self.check(lambda r, t: r.update(Instance={"Type": "AWS::EC2::Instance"}))

    def test_mutation_guard_budget_as_stop_mechanism(self):
        self.check(lambda r, t: r.update(Budget={"Type": "AWS::Budgets::BudgetsAction"}))

    def test_mutation_default_deadline(self):
        self.check(lambda r, t: t["Parameters"]["HardDeadlineUtc"].update(Default="2030-01-01T00:00:00Z"))

    def test_mutation_signing_on_by_default(self):
        self.check(lambda r, t: t["Parameters"]["EnableKmsSigning"].update(Default="true"))

    def test_mutation_key_policy_foreign_account(self):
        self.check(lambda r, t: r["SigningKey"]["Properties"]["KeyPolicy"]["Statement"][0].update(Principal={"AWS": "*"}))

    def test_mutation_managed_policy(self):
        self.check(lambda r, t: r["WorkerRole"]["Properties"].update(ManagedPolicyArns=["arn:aws:iam::aws:policy/AmazonS3FullAccess"]))


class WorkerContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.template = cfn.load(DIR / "worker.template.json")
        cls.script = (DIR / "user_data.sh").read_text(encoding="utf-8").replace("\r\n", "\n")

    def check(self, change):
        template = deepcopy(self.template)
        change(template["Resources"], template)
        self.assertNotEqual(audit_worker(template), [])

    def instance(self, r):
        return r["WorkerInstance"]["Properties"]

    def with_script(self, transform):
        def change(r, t):
            data = self.instance(r)["UserData"]["Fn::Base64"]
            data["Fn::Sub"] = transform(data["Fn::Sub"])
        return change

    def test_candidate_passes_local_audit(self):
        self.assertEqual(audit_worker(self.template), [])

    def test_template_user_data_is_identical_to_the_reviewed_script(self):
        embedded = self.template["Resources"]["WorkerInstance"]["Properties"]["UserData"]["Fn::Base64"]["Fn::Sub"]
        self.assertEqual(embedded, self.script)

    def test_script_shell_variables_never_use_brace_form(self):
        parameters = set(self.template["Parameters"]) | cfn.PSEUDO
        self.assertTrue(set(re.findall(r"\$\{([^}]+)\}", self.script)) <= parameters)
        self.assertNotIn("${!", self.script)

    def test_script_exports_everything_the_worker_entry_reads(self):
        import inspect
        import src.aws_c.worker_entry as entry
        wanted = set(re.findall(r'env(?:\.get\(|\[)"([A-Z0-9_]+)"', inspect.getsource(entry.main)))
        exported = set(re.findall(r"^export ([A-Z0-9_]+)=", self.script, re.M))
        self.assertTrue(wanted <= exported, wanted - exported)

    def test_stack_policy_denies_every_update(self):
        policy = cfn.load(DIR / "worker.stack-policy.json")
        self.assertEqual(policy, {"Statement": [{"Effect": "Deny", "Action": "Update:*",
                                                 "Principal": "*", "Resource": "*"}]})

    def test_parameters_shared_with_guard_use_the_same_patterns(self):
        guard = cfn.load(DIR / "guard.template.json")
        for name in ("PilotRunId", "HardDeadlineUtc"):
            self.assertEqual(self.template["Parameters"][name]["AllowedPattern"],
                             guard["Parameters"][name]["AllowedPattern"])
        digest = re.compile(self.template["Parameters"]["RuntimeImageDigest"]["AllowedPattern"])
        self.assertIsNone(digest.fullmatch("latest"))

    def test_mutation_shutdown_behaviour_stop(self):
        self.check(lambda r, t: self.instance(r).update(InstanceInitiatedShutdownBehavior="stop"))

    def test_mutation_imdsv1(self):
        self.check(lambda r, t: self.instance(r)["MetadataOptions"].update(HttpTokens="optional"))

    def test_mutation_imds_hop_limit(self):
        self.check(lambda r, t: self.instance(r)["MetadataOptions"].update(HttpPutResponseHopLimit=2))

    def test_mutation_ssh_key(self):
        self.check(lambda r, t: self.instance(r).update(KeyName="my-key"))

    def test_mutation_inbound_rule(self):
        self.check(lambda r, t: r["WorkerSecurityGroup"]["Properties"].update(SecurityGroupIngress=[{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "CidrIp": "0.0.0.0/0"}]))

    def test_mutation_all_egress(self):
        self.check(lambda r, t: r["WorkerSecurityGroup"]["Properties"].update(SecurityGroupEgress=[{"IpProtocol": "-1", "CidrIp": "0.0.0.0/0"}]))

    def test_mutation_ipv6_egress(self):
        self.check(lambda r, t: r["WorkerSecurityGroup"]["Properties"]["SecurityGroupEgress"].append({"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "CidrIpv6": "::/0"}))

    def test_mutation_volume_kept_after_termination(self):
        self.check(lambda r, t: self.instance(r)["BlockDeviceMappings"][0]["Ebs"].update(DeleteOnTermination=False))

    def test_mutation_unencrypted_volume(self):
        self.check(lambda r, t: self.instance(r)["BlockDeviceMappings"][0]["Ebs"].update(Encrypted=False))

    def test_mutation_missing_run_tag(self):
        self.check(lambda r, t: self.instance(r).update(Tags=[{"Key": "Project", "Value": "SiteProof"}]))

    def test_mutation_termination_protection(self):
        self.check(lambda r, t: self.instance(r).update(DisableApiTermination=True))

    def test_mutation_unlimited_credits(self):
        self.check(lambda r, t: self.instance(r).update(CreditSpecification={"CPUCredits": "unlimited"}))

    def test_mutation_second_instance(self):
        self.check(lambda r, t: r.update(Second=deepcopy(r["WorkerInstance"])))

    def test_mutation_autoscaling_group(self):
        self.check(lambda r, t: r.update(Group={"Type": "AWS::AutoScaling::AutoScalingGroup"}))

    def test_mutation_inline_iam(self):
        self.check(lambda r, t: r.update(Role={"Type": "AWS::IAM::Role", "Properties": {"AssumeRolePolicyDocument": {"Statement": []}}}))

    def test_mutation_default_image(self):
        self.check(lambda r, t: t["Parameters"]["ImageId"].update(Default="ami-00000000"))

    def test_mutation_large_instance_type(self):
        self.check(lambda r, t: t["Parameters"]["InstanceType"]["AllowedValues"].append("m5.4xlarge"))

    def test_mutation_script_timer_not_first(self):
        self.check(self.with_script(lambda s: s.replace('shutdown -h +${MaxRuntimeMinutes} "siteproof pilot hard stop"\n', "", 1).replace("umask 077\n", 'umask 077\nshutdown -h +${MaxRuntimeMinutes} "siteproof pilot hard stop"\n', 1)))

    def test_mutation_script_without_exit_trap(self):
        self.check(self.with_script(lambda s: s.replace("trap finish EXIT\n", "")))

    def test_mutation_script_cancels_timer(self):
        self.check(self.with_script(lambda s: s + "shutdown -c\n"))

    def test_mutation_script_installs_packages(self):
        self.check(self.with_script(lambda s: s.replace("systemctl start docker", "apt-get install -y docker.io && systemctl start docker")))

    def test_mutation_script_pipes_download_to_shell(self):
        self.check(self.with_script(lambda s: s + "curl https://example.org/x | bash\n"))

    def test_mutation_script_pulls_by_tag(self):
        self.check(self.with_script(lambda s: s.replace("@${RuntimeImageDigest}", ":latest")))

    def test_mutation_script_skips_bundle_hash(self):
        self.check(self.with_script(lambda s: s.replace('    sys.exit("bundle hash mismatch")\n', "    pass\n")))

    def test_mutation_script_unknown_substitution(self):
        self.check(self.with_script(lambda s: s + "echo ${UNKNOWN_SHELL_VAR}\n"))

    def test_mutation_script_no_sandbox(self):
        self.check(self.with_script(lambda s: s + "export CHROMIUM_FLAGS=--no-sandbox\n"))


if __name__ == "__main__":
    unittest.main()
