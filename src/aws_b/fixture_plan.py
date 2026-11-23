"""Pure local fixture IaC and trial-scoped IAM generation. Never constructs AWS clients."""
import json
import os
from pathlib import Path

TARGET = 'aws-b-http-fixture'
ACCOUNT = os.environ.get('SITEPROOF_AWS_ACCOUNT_ID', '123456789012')  # set the real account id when generating live policies
REGION = 'us-east-1'


def fixture_names(trial):
    prefix = 'siteproof-b-' + trial
    return {'stack': prefix + '-http-fixture', 'function': prefix + '-http-fixture',
        'role': prefix + '-fixture-probe-role', 'log_group': '/aws/lambda/' + prefix + '-fixture-probe',
        'boundary': 'SiteProof-AWSB-' + trial + '-FixtureProbeBoundary',
        'target_id': TARGET, 'monitor_stack': prefix + '-' + TARGET}


def boundary_document(trial):
    """The fixture monitor's Permissions Boundary. AWS-B Lite adds sns:Publish to this trial's own alert topic only.

    Used by template() for new trials. For the ALREADY deployed fixture boundary it is written to
    trial-fixture-boundary-update-policy.json for the USER to apply as ONE new policy version (see policies()); the operator
    is deliberately not given iam:CreatePolicyVersion for it.
    """
    monitor = fixture_names(trial)['monitor_stack']
    table_arn = 'arn:aws:dynamodb:' + REGION + ':' + ACCOUNT + ':table/' + monitor + '-runs'
    topic = 'arn:aws:sns:' + REGION + ':' + ACCOUNT + ':siteproof-b-' + trial + '-alerts'
    return {'Version': '2012-10-17', 'Statement': [
        {'Effect': 'Allow', 'Action': ['dynamodb:PutItem', 'dynamodb:UpdateItem'],
         'Resource': table_arn, 'Condition': {'ForAllValues:StringEquals': {
             'dynamodb:LeadingKeys': ['CONTROL#' + TARGET, 'RUN#' + TARGET]},
             'Null': {'dynamodb:LeadingKeys': 'false'}}},
        {'Effect': 'Allow', 'Action': ['logs:CreateLogStream', 'logs:PutLogEvents'],
         'Resource': 'arn:aws:logs:' + REGION + ':' + ACCOUNT + ':log-group:/aws/lambda/' + monitor + '-probe:*'},
        {'Effect': 'Allow', 'Action': 'sns:Publish', 'Resource': topic}]}


def template(trial, end_at):
    n = fixture_names(trial)
    fn = {'Fn::GetAtt': ['FixtureFunction', 'Arn']}
    boundary = 'arn:aws:iam::' + ACCOUNT + ':policy/SiteProof-AWSB-ProbeBoundary'
    log_arn = 'arn:aws:logs:' + REGION + ':' + ACCOUNT + ':log-group:' + n['log_group'] + ':*'
    document = lambda statements: {'Version': '2012-10-17', 'Statement': statements}
    resources = {
        'TrialProbeBoundary': {'Type': 'AWS::IAM::ManagedPolicy', 'Properties': {
            'ManagedPolicyName': n['boundary'], 'PolicyDocument': boundary_document(trial)}},
        'FixtureLogGroup': {'Type': 'AWS::Logs::LogGroup', 'Properties': {
            'LogGroupName': n['log_group'], 'RetentionInDays': 7}},
        'FixtureRole': {'Type': 'AWS::IAM::Role', 'Properties': {'RoleName': n['role'],
            'PermissionsBoundary': boundary,
            'AssumeRolePolicyDocument': document([{'Effect': 'Allow',
                'Principal': {'Service': 'lambda.amazonaws.com'}, 'Action': 'sts:AssumeRole'}]),
            'Policies': [{'PolicyName': 'FixtureLogsOnly', 'PolicyDocument': document([
                {'Effect': 'Allow', 'Action': ['logs:CreateLogStream', 'logs:PutLogEvents'], 'Resource': log_arn}])}]}},
        'FixtureFunction': {'Type': 'AWS::Lambda::Function', 'DependsOn': 'FixtureLogGroup', 'Properties': {
            'FunctionName': n['function'], 'Runtime': 'python3.13', 'Handler': 'index.handler',
            'Role': {'Fn::GetAtt': ['FixtureRole', 'Arn']}, 'Timeout': 3, 'MemorySize': 128,
            'ReservedConcurrentExecutions': 1, 'LoggingConfig': {'LogGroup': n['log_group']},
            'Environment': {'Variables': {'FIXTURE_HTTP_STATUS': '200', 'ABSOLUTE_END_AT': end_at}},
            'Code': {'ZipFile': Path(__file__).with_name('http_fixture.py').read_text('utf-8')},
            'Tags': [{'Key': 'Project', 'Value': 'SiteProof'}, {'Key': 'Component', 'Value': 'AWS-B-Fixture'}, {'Key': 'Trial', 'Value': trial}]}},
        'FixtureUrl': {'Type': 'AWS::Lambda::Url', 'Properties': {'TargetFunctionArn': fn,
            'AuthType': 'NONE', 'InvokeMode': 'BUFFERED'}},
        'FixtureUrlPermission': {'Type': 'AWS::Lambda::Permission', 'Properties': {
            'FunctionName': fn, 'Action': 'lambda:InvokeFunctionUrl', 'Principal': '*',
            'FunctionUrlAuthType': 'NONE'}},
        'FixtureInvokeViaUrlPermission': {'Type': 'AWS::Lambda::Permission', 'Properties': {
            'FunctionName': fn, 'Action': 'lambda:InvokeFunction', 'Principal': '*',
            'InvokedViaFunctionUrl': True}},
    }
    for r in resources.values():
        r.update(DeletionPolicy='Retain', UpdateReplacePolicy='Retain')
    return {'AWSTemplateFormatVersion': '2010-09-09',
        'Description': 'Temporary public GET-only HTTP fixture; management is IAM only; not a cost cap.',
        'Resources': resources}  # URL is read explicitly with GetFunctionUrlConfig, not printed as a stack output.


def policies(names):
    """Add to existing Deploy/Operate only. Do not replace common policies/boundaries."""
    if names.get('account') and names['account'] != ACCOUNT:
        # ACCOUNT comes from SITEPROOF_AWS_ACCOUNT_ID and defaults to a placeholder: policies built on it would carry ARNs that match nothing
        raise ValueError('set SITEPROOF_AWS_ACCOUNT_ID to the plan account before generating policies')
    n = names['fixture']; pages = list(names['pages'].values())
    if not any(p['stack'] == n['monitor_stack'] for p in pages):
        pages.append({'stack': n['monitor_stack'], 'function': n['monitor_stack'] + '-probe',
            'table': n['monitor_stack'] + '-runs', 'schedule': n['monitor_stack'] + '-schedule',
            'probe_role': n['monitor_stack'] + '-probe-role', 'scheduler_role': n['monitor_stack'] + '-scheduler-role'})
    arn = lambda service, resource: 'arn:aws:' + service + ':' + REGION + ':' + ACCOUNT + ':' + resource
    iam = lambda kind, name: 'arn:aws:iam::' + ACCOUNT + ':' + kind + '/' + name
    fn = arn('lambda', 'function:' + n['function'])
    boundary = iam('policy', n['boundary'])
    role = iam('role', n['monitor_stack'] + '-probe-role')
    # AWS-B Lite: no per-page alarms; ONE shared heartbeat alarm in its own stack (infra/aws_b/health.json).
    health = names.get('health') or {'stack': names['prefix'] + '-health', 'alarm': names['prefix'] + '-health-heartbeat'}
    heartbeat_alarm = arn('cloudwatch', 'alarm:' + health['alarm'])
    # Pre-Lite stacks left their 3 alarms per page behind (DeletionPolicy Retain keeps a resource removed from the template).
    # They are NOT created any more; deleting the orphans is the only permission kept for them. One <stack>-* pattern per page
    # (still this trial's own stacks only): the 18 exact ARNs would push the policy over the 6144-character IAM limit.
    legacy_alarms = [arn('cloudwatch', 'alarm:' + p['stack'] + '-*') for p in pages]
    def allow(actions, resources, **extra):
        return {'Effect': 'Allow', 'Action': actions, 'Resource': resources, **extra}
    deploy = [
        allow(['lambda:CreateFunction','lambda:GetFunction','lambda:GetFunctionConfiguration',
               'lambda:UpdateFunctionConfiguration','lambda:UpdateFunctionCode','lambda:PutFunctionConcurrency',
               'lambda:GetFunctionConcurrency','lambda:CreateFunctionUrlConfig','lambda:GetFunctionUrlConfig',
               'lambda:UpdateFunctionUrlConfig','lambda:ListFunctionUrlConfigs','lambda:AddPermission','lambda:GetPolicy','lambda:TagResource',
               'lambda:ListTags','lambda:GetRuntimeManagementConfig','lambda:GetFunctionCodeSigningConfig'], fn),
        allow(['iam:CreatePolicy','iam:GetPolicy','iam:GetPolicyVersion','iam:ListPolicyVersions'], boundary),
        allow(['iam:CreateRole','iam:PutRolePolicy','iam:PutRolePermissionsBoundary'], role,
              Condition={'StringEquals': {'iam:PermissionsBoundary': boundary}}),
        allow(['dynamodb:PutItem','dynamodb:UpdateItem','dynamodb:GetItem','dynamodb:Query'],
              arn('dynamodb','table/' + n['monitor_stack'] + '-runs'),
              Condition={'ForAllValues:StringEquals': {'dynamodb:LeadingKeys': ['CONTROL#' + TARGET, 'RUN#' + TARGET]},
                         'Null': {'dynamodb:LeadingKeys': 'false'}}),
        allow(['cloudwatch:EnableAlarmActions'], heartbeat_alarm),
        {'Effect': 'Deny', 'Action': 'lambda:InvokeFunction', 'Resource': fn,
         'Condition': {'BoolIfExists': {'lambda:InvokedViaFunctionUrl': 'false'}}},
    ]
    cleanup = [
        allow(['cloudwatch:DeleteAlarms'], [heartbeat_alarm] + legacy_alarms),
        allow(['scheduler:DeleteSchedule'], [arn('scheduler','schedule/default/' + p['schedule']) for p in pages]),
        allow(['lambda:DeleteFunction'], [arn('lambda','function:' + p['function']) for p in pages] + [fn]),
        allow(['lambda:DeleteFunctionUrlConfig','lambda:RemovePermission','lambda:GetPolicy','lambda:GetFunctionUrlConfig'], fn),
        allow(['dynamodb:DeleteTable'], [arn('dynamodb','table/' + p['table']) for p in pages]),
        allow(['logs:DeleteLogGroup'], [arn('logs','log-group:/aws/lambda/' + p['function'] + ':*') for p in pages] + [arn('logs','log-group:' + n['log_group'] + ':*')]),
        allow(['sns:DeleteTopic'], names['topic_arn']),
        allow(['cloudformation:DeleteStack'], [arn('cloudformation','stack/' + p['stack'] + '/*') for p in pages] + [arn('cloudformation','stack/' + n['stack'] + '/*'),
                                                                          arn('cloudformation','stack/' + health['stack'] + '/*')]),
    ]
    roles = [iam('role', p[k]) for p in pages for k in ('probe_role','scheduler_role')] + [iam('role', n['role'])]
    role_cleanup = [allow(['iam:GetRole','iam:ListRolePolicies','iam:GetRolePolicy','iam:ListAttachedRolePolicies',
                          'iam:ListInstanceProfilesForRole','iam:DeleteRolePolicy','iam:DeleteRole'], roles),
                    allow(['iam:ListEntitiesForPolicy','iam:ListPolicyVersions','iam:GetPolicy','iam:DeletePolicy'], boundary)]
    # CloudFormation change sets (preview before every stack update). Only the monitor stacks and the health stack, only the four actions
    # the preview needs, same "operator's own credentials" condition as the existing UpdateStack grant. No ListChangeSets, no stack deletion.
    # Whether IAM wants the stack ARN, the change-set ARN or both for each action is LIVE-unverified: check with the Policy Simulator first.
    stacks = [arn('cloudformation', 'stack/' + p['stack'] + '/*') for p in pages] + [arn('cloudformation', 'stack/' + health['stack'] + '/*')]
    change_sets = [arn('cloudformation', 'changeSet/siteproof-lite-*/*')]
    changeset = [
        allow(['cloudformation:CreateChangeSet', 'cloudformation:DescribeChangeSet', 'cloudformation:ExecuteChangeSet',
               'cloudformation:DeleteChangeSet'], stacks + change_sets,
              Condition={'Null': {'cloudformation:RoleArn': 'true'}, 'StringEquals': {'aws:RequestedRegion': REGION}}),
    ]
    # NOT an operator policy: the USER (admin) applies it once as a new default version of the existing fixture boundary
    # (aws iam create-policy-version --set-as-default). The CloudFormation stack that owns the policy is not updated.
    return {**{name: {'Version': '2012-10-17', 'Statement': statements} for name, statements in
               [('trial-fixture-deploy-policy.json', deploy), ('trial-cleanup-policy.json', cleanup),
                ('trial-role-cleanup-policy.json', role_cleanup), ('trial-changeset-policy.json', changeset)]},
            'trial-fixture-boundary-update-policy.json': boundary_document(names['prefix'][len('siteproof-b-'):])}
