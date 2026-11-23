# AWS-B Lite 導入手順（第三者向け・公開ファイルのみ）

**状態：この手順は第三者の環境で一度も実行されていません（未実証）。** AWS CLIの例は、公開リポジトリのテンプレート（`infra/aws_b/`）とコード（`src/aws_b/`）の内容から導いたもので、本書の作成時にAWSには何も実行していません。

- 作者が実AWSで行ったStage A（2026-11-21）は、**非公開の運用スクリプトと、非公開の生成スクリプトが出力したテンプレート**を使ったLIVE実証です。公開テンプレートそのものをAWSに適用した実績はありません（`validate-template` も未実施）。
- 6時間・12時間間隔は **LIVE未検証**です（Stage Aは15分間隔）。AWSの実請求額は **UNKNOWN**です。
- 結果の要約と未検証事項は [AWS_B_LITE.md](AWS_B_LITE.md)、費用の目安は [SYNTHETICS_COMPARISON.md](SYNTHETICS_COMPARISON.md) を参照してください。
- 確定できない操作は、推測でコマンドを作らず、「§13 不足している操作」にまとめました。

> **必ず先に読んでください（安全）**
> - **AWS資源には料金が発生します。** 無料枠の適用可否は未確認です。**AWS Budgetsは通知であり、課金のhard capではありません。** 予算を設定しても、支出は止まりません。
> - **監視を開始するときは、必ず停止期限（`AbsoluteEndAt`）を設定します。** 期限は、Lambdaの絶対期限（環境変数）とSchedulerの `EndDate` の**両方**に使われます（同じパラメータ1つから設定されるため一致します）。期限だけ別に書き換えない（Lambdaの環境変数やSchedulerを直接編集しない）でください。期限は課金の上限ではありません。
> - **監視の停止と、AWS資源の削除は別の操作です。** 停止してもテーブル、ログ、Alarm、S3、SNSは残り、費用が続くことがあります。
> - **CloudFormationの `Retain` 資源は、スタックを削除しても残ります**（`ProbeTable`）。削除は自分で行います（§12）。
> - **S3のバージョニングを有効にするため、削除には全バージョンの削除が必要です。**
> - 削除・停止の対象は、**この手順で自分が作った資源だけ**です。資源名は必ず `<PREFIX>` 付きの完全な名前で指定し、ワイルドカードで一括削除しません。**既存のSNSトピック・S3・Lambda等を流用しません。**

## 0. この手順で作るもの

| 資源 | 数 | 備考 |
|---|---:|---|
| ページ別の監視スタック（`infra/aws_b/template.json`） | ページ数 N | 各スタックに DynamoDB（**Retain**）、Lambda（arm64・256MB・20秒）、IAMロール2、ロググループ、Scheduler |
| healthスタック（`infra/aws_b/health.json`） | 1 | 集約Heartbeat Alarm 1本（`<PREFIX>-health-heartbeat`） |
| コード用S3バケット（バージョニング付き） | 1 | テンプレートには含まれない。手動で作る |
| 通知用SNSトピックとメール購読 | 1 | テンプレートには含まれない。手動で作る |

## 1. 必要なAWSアカウント・CLI・権限

- AWSアカウント（検証用を推奨）。**リージョンは `us-east-1` のみ**を想定しています（他のリージョンは未検討）。
- AWS CLI v2、Python 3（バンドル作成用。標準ライブラリのみ）。シェルは bash 系を想定します（PowerShell 5.1ではJSONの引用符が崩れるため、JSONはすべて `file://` で渡します）。
- **ルートユーザーは使いません。** デプロイ用のIAMユーザーまたはロール（一時的な認証情報を推奨）を使います。長期のアクセスキーをリポジトリやファイルに置かないでください。
- 必要な権限は§5を参照してください。

以降のプレースホルダー（`< >`）は、実際の値に置き換えます。**実際のアカウントID・メールアドレスなどをこのリポジトリのファイルに書き込まないでください。**

```bash
export AWS_REGION=us-east-1
PREFIX=siteproof-<name>        # 小文字・数字・ハイフン。短くする（Lambda関数名 <PREFIX>-<TARGET_ID>-probe は64文字以内）。すべての資源名の先頭に使う
ACCOUNT_ID=<ACCOUNT_ID>        # aws sts get-caller-identity --query Account --output text で確認
BUCKET=<PREFIX>-code-<ACCOUNT_ID>     # グローバルで一意。例：siteproof-<name>-code-<ACCOUNT_ID>
```

作業用のファイル（パラメータJSONなど）は、リポジトリの外の新しいフォルダに置きます。

```bash
mkdir ~/siteproof-aws-b && cd ~/siteproof-aws-b
```

## 2. Lambdaバンドルを作る

```bash
# リポジトリのルートで。出力先は「まだ存在しない」フォルダ
python3 -B tools/build_bundles.py ~/siteproof-aws-b/bundle
```

`lambda-bundle.zip`（AWS-Bのコード。`src/aws_b/notify.py` を含む）と `bundle-manifest.json` ができます。AWSには何も送りません。アップロード前に `bundle-manifest.json` のSHA-256を控えてください。`worker-bundle.zip` は使いません。

## 3. コード用S3バケット（バージョニング）

```bash
aws s3api create-bucket --bucket "$BUCKET"          # us-east-1では LocationConstraint 不要
aws s3api put-bucket-versioning --bucket "$BUCKET" --versioning-configuration Status=Enabled
aws s3api put-public-access-block --bucket "$BUCKET" \
  --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
aws s3api put-object --bucket "$BUCKET" --key siteproof/lambda-bundle.zip \
  --body ~/siteproof-aws-b/bundle/lambda-bundle.zip --query VersionId --output text
```

最後のコマンドが表示する **VersionId** を `<VERSION_ID>` として控えます（テンプレートの必須パラメータ `CodeObjectVersion`。Lambdaは、このバージョンのコードに固定されます）。コードを更新したら、新しいバージョンをアップロードし、`CodeObjectVersion` を更新します。旧バージョンはロールバック用に残します。

## 4. SNSトピックとメール購読

```bash
TOPIC_ARN=$(aws sns create-topic --name "$PREFIX-alerts" --query TopicArn --output text)
aws sns subscribe --topic-arn "$TOPIC_ARN" --protocol email --notification-endpoint <YOUR_EMAIL>
```

届いた確認メールのリンクを開いて購読を確認します（自分のメールだけに使い、アドレスをリポジトリへ書かないでください）。確認後、次で購読が有効か確認します。

```bash
aws sns list-subscriptions-by-topic --topic-arn "$TOPIC_ARN" --query 'Subscriptions[].SubscriptionArn'
# PendingConfirmation と出る間は未確認
```

healthのAlarmがSNSへ送れるよう、**トピックポリシー**を設定します（テンプレートは既存トピックを前提とし、`cloudwatch.amazonaws.com` の許可が必要です）。`topic-policy.json`：

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "OwnAlarmsOnly",
      "Effect": "Allow",
      "Principal": {"Service": "cloudwatch.amazonaws.com"},
      "Action": "sns:Publish",
      "Resource": "<TOPIC_ARN>",
      "Condition": {
        "StringEquals": {"aws:SourceAccount": "<ACCOUNT_ID>"},
        "ArnLike": {"aws:SourceArn": "arn:aws:cloudwatch:us-east-1:<ACCOUNT_ID>:alarm:<PREFIX>-*"}
      }
    }
  ]
}
```

```bash
aws sns set-topic-attributes --topic-arn "$TOPIC_ARN" --attribute-name Policy \
  --attribute-value file://topic-policy.json
```

- この `ArnLike` は、healthスタック名が `<PREFIX>-` で始まることを前提にしています（Alarm名は `<スタック名>-heartbeat`）。
- Lambdaの通知（`sns:Publish`）は、テンプレートが作るprobeロールのIAMポリシーで許可されます。トピックポリシーに追記は不要です。

## 5. IAM（最小権限）

### 5.1 テンプレートが作る実行ロール（公開ファイルで確定）

| ロール | 許可 |
|---|---|
| probeロール | DynamoDB `UpdateItem`・`PutItem`（自分のテーブルのみ、キー条件つき）、Logs `CreateLogStream`・`PutLogEvents`（自分のロググループのみ）、`sns:Publish`（`AlertTopicArn` の1トピックのみ） |
| Schedulerロール | `lambda:InvokeFunction`（自分のprobe関数のみ。信頼は同一アカウントのScheduler） |

読み取り（`GetItem`）、削除、他テーブル、他の宛先への書込みは許可していません。ロール名はCloudFormationが自動生成します。

### 5.2 あなた（運用者）に必要な操作の種類（**ポリシー文書は未提供・未検証**）

公開リポジトリには、運用者用のIAMポリシー文書を含めていません（作者のものはアカウント情報を含み非公開）。次は、テンプレートの資源種別と本書のコマンドから**導いた操作の種類**で、**最小権限であることの保証ではありません**。**IAMのPolicy Simulatorで確認してから**、自分の環境に合うポリシーを作ってください。

| 手順 | 必要な操作の種類（目安） |
|---|---|
| §3 | S3：バケット作成、バージョニング、パブリックアクセスブロック、オブジェクトの書込み |
| §4 | SNS：トピック作成、購読、トピック属性の設定 |
| §6 | CloudFormation：スタックと変更セットの作成・実行・記述・削除（`CAPABILITY_IAM` を使うため、IAMロールの作成・ポリシー付与・`PassRole`・削除も必要）。テンプレートの資源の作成：Lambda、DynamoDB、Scheduler、Logs、CloudWatch Alarm |
| §8以降 | DynamoDB：自分のテーブルへの `PutItem`・`UpdateItem`・`GetItem`・`Query`。Lambda：予約同時実行数の設定・取得。Scheduler：`GetSchedule`。CloudWatch：Alarmの記述。Logs：読取 |
| §12 | 上記の削除系操作（スタック削除、`dynamodb:DeleteTable`、S3のバージョン削除、`sns:DeleteTopic`） |

管理者権限で一時的に実行する場合も、**自分で作った資源だけ**を対象にしてください。

## 6. CloudFormationで構築する

作業ディレクトリに、パラメータのファイルを作ります。**値は全部プレースホルダーです。**

### 6.1 healthスタックを先に作る（通知は無効にしておく）

`params-health.json`：

```json
[
  {"ParameterKey": "AlertTopicArn", "ParameterValue": "<TOPIC_ARN>"},
  {"ParameterKey": "MonitorGroup", "ParameterValue": "<PREFIX>"},
  {"ParameterKey": "ExpectedPages", "ParameterValue": "<N>"},
  {"ParameterKey": "HeartbeatPeriodSeconds", "ParameterValue": "21600"},
  {"ParameterKey": "AlarmActionsEnabled", "ParameterValue": "false"}
]
```

- `ExpectedPages`：armするページ数 N。
- `HeartbeatPeriodSeconds`：スケジュール間隔と同じ秒数。テンプレートが受け付ける値は **900（15分）／21600（6時間）／43200（12時間）** だけです。ページ側の `ScheduleExpression` を同じ間隔にしてください。これ以外の間隔の組み合わせは設計されていません。
- `MonitorGroup`：**すべてのページスタックと同じ値**にします。
- 初期は `AlarmActionsEnabled=false`（最初の欠測で誤報を出さないため）。

```bash
aws cloudformation validate-template --template-body file://infra/aws_b/health.json
aws cloudformation create-stack --stack-name "$PREFIX-health" \
  --template-body file://infra/aws_b/health.json --parameters file://params-health.json
aws cloudformation wait stack-create-complete --stack-name "$PREFIX-health"
```

（`validate-template` は、リポジトリのルートで実行します。）

### 6.2 ページ別スタックを作る（スケジュールは無効のまま）

監視対象ごと（N回）に `params-<TARGET_ID>.json` を作ります。**例（1ページ）**：

```json
[
  {"ParameterKey": "TargetId", "ParameterValue": "<TARGET_ID>"},
  {"ParameterKey": "TargetHostname", "ParameterValue": "<HOSTNAME>"},
  {"ParameterKey": "TargetPath", "ParameterValue": "/"},
  {"ParameterKey": "PolicyVersion", "ParameterValue": "p1"},
  {"ParameterKey": "ExecutionGeneration", "ParameterValue": "1"},
  {"ParameterKey": "AbsoluteEndAt", "ParameterValue": "<END_AT>"},
  {"ParameterKey": "ScheduleExpression", "ParameterValue": "rate(6 hours)"},
  {"ParameterKey": "ScheduleState", "ParameterValue": "DISABLED"},
  {"ParameterKey": "AlertTopicArn", "ParameterValue": "<TOPIC_ARN>"},
  {"ParameterKey": "CodeBucket", "ParameterValue": "<BUCKET>"},
  {"ParameterKey": "CodeKey", "ParameterValue": "siteproof/lambda-bundle.zip"},
  {"ParameterKey": "CodeObjectVersion", "ParameterValue": "<VERSION_ID>"},
  {"ParameterKey": "MonitorGroup", "ParameterValue": "<PREFIX>"}
]
```

| パラメータ | 内容・制約（テンプレートの定義） |
|---|---|
| `TargetId` | 論理名（英数字・`._-`、64文字まで）。スタックごとに異なる値にする。SiteProofアプリの画面に結果を出すなら、登録したサイトのページID（§9.1） |
| `TargetHostname` | **自分が管理する**HTTPSサイトのホスト名だけ（URL・ワイルドカード・IPアドレスは不可）。必須 |
| `TargetPath` | 先頭`/`の絶対パス。クエリ不可。既定は `/home/index.html` なので、トップページなら `/` を指定 |
| `ExecutionGeneration` | 1から始める。armの値と**一致**させる |
| `PolicyVersion` | 既定 `p1`。armの値と**一致**させる |
| `AbsoluteEndAt` | **停止期限**（UTC、`YYYY-MM-DDTHH:MM:SSZ`、必須）。**最初は短く（例：24時間後）**。Lambdaの絶対期限とSchedulerの `EndDate` に使われる |
| `ScheduleExpression` | `rate(15 minutes)`・`rate(6 hours)`・`rate(12 hours)` を使う（healthの周期と合わせる）。ほかに5・10・30分、1時間も定義上は許されるが、healthは未対応 |
| `ScheduleState` | **最初は `DISABLED`**（スタック作成だけでは監視は始まらない） |
| `CodeBucket` / `CodeKey` / `CodeObjectVersion` | §3の値（3つとも必須） |
| `MonitorGroup` | healthと同じ値 |
| `UseReservedConcurrency` | 既定 `true`（同時実行を1に固定）。アカウントの同時実行クォータが低く確保できない場合だけ `false`（保護が外れる逸脱として記録） |
| `LambdaRuntime` / `LogRetentionDays` | 既定のまま（`python3.13`、14日） |

停止期限の例（UTC、24時間後）：

```bash
date -u -d '+24 hours' +%Y-%m-%dT%H:%M:%SZ      # GNU date。macOSは date -u -v+24H +%Y-%m-%dT%H:%M:%SZ
```

```bash
aws cloudformation validate-template --template-body file://infra/aws_b/template.json
aws cloudformation create-stack --stack-name "$PREFIX-<TARGET_ID>" \
  --template-body file://infra/aws_b/template.json \
  --parameters file://params-<TARGET_ID>.json --capabilities CAPABILITY_IAM
aws cloudformation wait stack-create-complete --stack-name "$PREFIX-<TARGET_ID>"
```

### 6.3 スタックの出力を控える（削除時に必要）

**スタックを削除すると出力は見えなくなります。** 作成直後に、テーブル名などを控えてください。

```bash
aws cloudformation describe-stacks --stack-name "$PREFIX-<TARGET_ID>" \
  --query 'Stacks[0].Outputs[].[OutputKey,OutputValue]' --output text
# TableName / FunctionName / ScheduleName / MonitorGroup
```

関数名は `<スタック名>-probe`、ロググループは `/aws/lambda/<スタック名>-probe` です。**この時点ではprobeは0回です**（スケジュールは無効で、CONTROL項目もありません）。

## 7. 更新の共通手順（変更セットで確認してから実行）

`update-stack` では、**指定しなかったパラメータは既定値に戻ります**（必須パラメータは指定が必要）。**全パラメータを `UsePreviousValue` で書き、変えるものだけ値を書きます。** 例：ページスタックの `ScheduleState` を `ENABLED` にする `params-update.json`：

```json
[
  {"ParameterKey": "TargetId", "UsePreviousValue": true},
  {"ParameterKey": "TargetHostname", "UsePreviousValue": true},
  {"ParameterKey": "TargetPath", "UsePreviousValue": true},
  {"ParameterKey": "PolicyVersion", "UsePreviousValue": true},
  {"ParameterKey": "ExecutionGeneration", "UsePreviousValue": true},
  {"ParameterKey": "AbsoluteEndAt", "UsePreviousValue": true},
  {"ParameterKey": "ScheduleExpression", "UsePreviousValue": true},
  {"ParameterKey": "ScheduleState", "ParameterValue": "ENABLED"},
  {"ParameterKey": "AlertTopicArn", "UsePreviousValue": true},
  {"ParameterKey": "CodeBucket", "UsePreviousValue": true},
  {"ParameterKey": "CodeKey", "UsePreviousValue": true},
  {"ParameterKey": "CodeObjectVersion", "UsePreviousValue": true},
  {"ParameterKey": "LambdaRuntime", "UsePreviousValue": true},
  {"ParameterKey": "LogRetentionDays", "UsePreviousValue": true},
  {"ParameterKey": "UseReservedConcurrency", "UsePreviousValue": true},
  {"ParameterKey": "MonitorGroup", "UsePreviousValue": true}
]
```

healthスタックは5パラメータ（`AlertTopicArn`・`MonitorGroup`・`ExpectedPages`・`HeartbeatPeriodSeconds`・`AlarmActionsEnabled`）を同じ形で書きます。

```bash
STACK=<更新するスタック名>; TEMPLATE=<infra/aws_b/template.json または health.json>
aws cloudformation create-change-set --stack-name "$STACK" --change-set-name chg-1 \
  --change-set-type UPDATE --template-body file://$TEMPLATE \
  --parameters file://params-update.json --capabilities CAPABILITY_IAM
aws cloudformation wait change-set-create-complete --stack-name "$STACK" --change-set-name chg-1
aws cloudformation describe-change-set --stack-name "$STACK" --change-set-name chg-1 \
  --query 'Changes[].ResourceChange.[Action,LogicalResourceId,Replacement]' --output text
```

**確認：** 期待どおりの資源の `Modify` だけであること（`Replacement` が `True` の資源や `Remove` があれば、実行せず `delete-change-set` で破棄する）。`AbsoluteEndAt`・`ExecutionGeneration` に想定外の差がないこと。

```bash
aws cloudformation execute-change-set --stack-name "$STACK" --change-set-name chg-1
aws cloudformation wait stack-update-complete --stack-name "$STACK"
```

## 8. 初回arm（制御項目の作成）

スタックができただけでは、probeは動きません。**制御項目（CONTROL）を作る**まで、Lambdaは接続の前に拒否します。armは条件付き（既存項目を上書きしない）で、`src/aws_b/store.py` の `build_arm_request` と同じ内容です。`arm-<TARGET_ID>.json`：

```json
{
  "pk": {"S": "CONTROL#<TARGET_ID>"},
  "sk": {"S": "HEAD"},
  "enabled": {"BOOL": true},
  "execution_generation": {"N": "1"},
  "policy_version": {"S": "p1"},
  "target_hostname": {"S": "<HOSTNAME>"},
  "armed_at": {"S": "<NOW_UTC>"}
}
```

```bash
aws dynamodb put-item --table-name <TABLE> --item file://arm-<TARGET_ID>.json \
  --condition-expression "attribute_not_exists(pk)"
```

- `execution_generation`・`policy_version`・`target_hostname` は、スタックの `ExecutionGeneration`・`PolicyVersion`・`TargetHostname` と**完全に一致**させます。1つでも違うと、すべての実行が拒否されます（安全側）。
- `<NOW_UTC>` は `date -u +%Y-%m-%dT%H:%M:%SZ` の値です。

## 9. スケジュールを有効にして、結果と通知を確認する

§7の手順で、各ページスタックの `ScheduleState` を `ENABLED` にします。

**結果の確認：**

```bash
# 最新のHEAD（最後のslot、観測状態、未送信の通知）
aws dynamodb get-item --table-name <TABLE> \
  --key '{"pk":{"S":"CONTROL#<TARGET_ID>"},"sk":{"S":"HEAD"}}'
# 直近の実行記録（新しい順に3件）
aws dynamodb query --table-name <TABLE> --key-condition-expression 'pk = :p' \
  --expression-attribute-values '{":p":{"S":"RUN#<TARGET_ID>"}}' --scan-index-forward false --limit 3
# ログ
aws logs tail "/aws/lambda/$PREFIX-<TARGET_ID>-probe" --since 1h
```

期待：`RUN#` の項目の `outcome` が `PASS`、`state` が `RECORDED`。HEADの `obs_state` が `PASS`、`ntf_pending` が `[]`。（`get-item`/`query` はJSONを引数に渡すため、PowerShell 5.1では引用符に注意し、`file://` を使ってください。）

**通知の確認（任意・Liteの導入前は未確認）：** 最初のPASSは通知されません（状態遷移だけが通知されます。初回のFAIL・UNKNOWNは通知されます）。通知の動作を見たいときは、1ページの `TargetPath` を一時的に存在しないパスにして（§7の手順）、`FAIL` の通知メールが1通届くことを確認し、元の値に戻して復旧通知を確認します（`RUNBOOK_AWS_B.md` §4のB7に対応）。**この手順の実行は、自分の管理するサイトだけに行い、確認後は必ず元に戻してください。**

### 9.1 結果をSiteProofに取り込む（任意。手順は合成データだけで確認済み・実AWSの出力では未確認）

SiteProofアプリで登録した自分のサイトのHOME・履歴・DETAILに、AWS-Bの結果を表示する手順です（AWSには接続せず、保存したファイルを取り込みます）。**取り込むまで、HOMEのHTTP結果は「未取得／未確認」で、他人（作者）のAWS記録は表示されません。**

1. **TargetIdを合わせる。** §6.2の `TargetId` には、アプリで登録したサイトの**ページID**を使います。`<データ>/sites/<site-id>/targets.json` の `pages[0].target_id`（例：`site-xxxxxxxx-p1`）です。`TargetHostname`・`TargetPath` も、登録したURLと同じにします（§6.2）。
2. **AWSの出力を保存する**（読み取り専用の2コマンド。`<TABLE>` は§6.3で控えた名前）。

```bash
mkdir -p export/e1/<TARGET_ID>
aws dynamodb get-item --table-name <TABLE> \
  --key '{"pk":{"S":"CONTROL#<TARGET_ID>"},"sk":{"S":"HEAD"}}' > export/e1/<TARGET_ID>/head.json
aws dynamodb query --table-name <TABLE> --key-condition-expression 'pk = :p' \
  --expression-attribute-values '{":p":{"S":"RUN#<TARGET_ID>"}}' --scan-index-forward false --limit 56 \
  > export/e1/<TARGET_ID>/runs.json
```

3. `export/e1/manifest.json` を作ります。`exported_at` は、上のコマンドを実行したUTC時刻です（結果の「取得時刻」になり、古いPASSは時間が経つと「未確認」になります）。

```json
{"schema": "siteproof.aws-b-export.v1", "source": "AWS_EXPORT", "target_ids": ["<TARGET_ID>"], "exported_at": "<NOW_UTC>"}
```

4. **取り込む**（リポジトリのルートで。`<SITE>` は `<データ>/sites/<site-id>`）。ドライブ指定は不要で、Windows以外でも動きます。

```bash
python3 -B -m src.noxiworks.archive import-export --archive <SITE>/aws-archive \
  --targets <SITE>/targets.json --capture-plan <SITE>/capture_plan.json export/e1
```

アプリが起動していれば、数秒でHOME・履歴・DETAILに反映されます（起動していなければ、次の起動時）。繰り返し取り込むと、新しい結果だけが追加されます（既存の記録は書き換えません）。`--targets`・`--capture-plan` を省くと、作者のページ設定が使われ、自分のサイトは対象になりません。

**healthの通知を有効にする：** 全ページのHeartbeatが `ExpectedPages` に達し、Alarmが `OK` になってから（目安：3周期。6時間間隔では18時間以上かかります。**6h/12hでの動作はLIVE未検証**）、healthスタックの `AlarmActionsEnabled` を `true` にします（§7）。

```bash
aws cloudwatch describe-alarms --alarm-names "$PREFIX-health-heartbeat" \
  --query 'MetricAlarms[].[StateValue,ActionsEnabled]' --output text
```

注意：CloudWatch Alarmの評価の位相によっては、**欠測1回でも発報する場合があります**（Stage Aの発見）。

## 10. 安全な停止

停止には3つの層があり、**どれか1つでprobeの開始は止まります。** すべて行い、読み戻して確認してください。期限（`AbsoluteEndAt`）に達すると自動でも止まります（独立Stopperは**未適用**で、自動停止は完全ではありません）。

1. **healthの通知を止める**（計画停止は欠測になるため。止めずに停止すると警報メールが出ます）：healthスタックの `AlarmActionsEnabled` を `false` に更新（§7）。一部のページだけを恒久的に止める場合は、`ExpectedPages` を減らします（共有Alarmの通知は止めません）。
2. **制御項目を無効にし、世代を+1する**（`src/aws_b/store.py` の `build_stop_request` と同じ。`<GEN>` は現在の世代）。`stop-<TARGET_ID>.json`（式の値）：

```json
{":false": {"BOOL": false}, ":gen": {"N": "<GEN>"}, ":next": {"N": "<GEN+1>"}, ":at": {"S": "<NOW_UTC>"}}
```

```bash
aws dynamodb update-item --table-name <TABLE> \
  --key '{"pk":{"S":"CONTROL#<TARGET_ID>"},"sk":{"S":"HEAD"}}' \
  --update-expression "SET #en = :false, #gen = :next, #st = :at" \
  --condition-expression "attribute_exists(pk) AND #gen = :gen" \
  --expression-attribute-names '{"#en":"enabled","#gen":"execution_generation","#st":"stopped_at"}' \
  --expression-attribute-values file://stop-<TARGET_ID>.json
```

3. **Schedulerを無効にする**：ページスタックの `ScheduleState` を `DISABLED` に更新（§7）。
4. **予約同時実行数を0にする**：

```bash
aws lambda put-function-concurrency --function-name "$PREFIX-<TARGET_ID>-probe" --reserved-concurrent-executions 0
```

**読み戻し確認**（すべて自分で確認します。自動の確認スクリプトは公開していません）：

```bash
aws dynamodb get-item --table-name <TABLE> --key '{"pk":{"S":"CONTROL#<TARGET_ID>"},"sk":{"S":"HEAD"}}' \
  --query 'Item.[enabled.BOOL,execution_generation.N,stopped_at.S]'        # false, 世代+1, 時刻
aws scheduler get-schedule --name <ScheduleName> --query State              # DISABLED
aws lambda get-function-concurrency --function-name "$PREFIX-<TARGET_ID>-probe"   # 0
```

その後しばらくして `RUN#` に新しい項目が増えていないこと、Lambdaの起動が止まっていることを確認してください。

**停止後の再開はこの手順では扱いません**（§13）。

## 11. 停止後の残置資源の確認

停止しても、次は残り、費用が発生しえます。

- DynamoDBテーブル（**Retain**。`RUN#` はTTLで14日後に消えるが、テーブルは残る）
- ページスタック・healthスタック、Lambda、ロググループ、Scheduler、CloudWatch Alarm
- S3バケット（全バージョン）、SNSトピックと購読
- CloudWatchのカスタムメトリクス（`SiteProof/Monitor`）：削除できません。停止後の課金の扱いは確認していません（**UNKNOWN**）。

必要な記録は、この時点でエクスポートします（`aws dynamodb query` の結果をファイルへ）。実請求は数日後にCost Explorerで確認します（反映に遅れがあります）。

## 12. 撤収（削除）

**停止（§10）を確認してから行います。削除は元に戻せません。自分で作った資源だけを、完全な名前で指定してください。**

```bash
# 1) スタック削除（ページごと、最後にhealth）。Retain資源（ProbeTable）は残る
aws cloudformation delete-stack --stack-name "$PREFIX-<TARGET_ID>"
aws cloudformation wait stack-delete-complete --stack-name "$PREFIX-<TARGET_ID>"
aws cloudformation delete-stack --stack-name "$PREFIX-health"
aws cloudformation wait stack-delete-complete --stack-name "$PREFIX-health"

# 2) Retainされたテーブル（§6.3で控えた名前だけ）。内容を確認してから削除
aws dynamodb delete-table --table-name <TABLE>
```

3. **S3バケット**（バージョニング有効のため、全バージョンと削除マーカーを消してからバケットを削除）：

```bash
aws s3api list-object-versions --bucket "$BUCKET" --query 'Versions[].{Key:Key,VersionId:VersionId}' --output json
# 内容を確認し、Versions と DeleteMarkers のそれぞれについて、次の形のJSONを作って削除する
#   {"Objects":[{"Key":"...","VersionId":"..."}]}
aws s3api delete-objects --bucket "$BUCKET" --delete file://versions.json
aws s3api delete-bucket --bucket "$BUCKET"
```

4. **SNSトピック**（購読も一緒に消えます）：`aws sns delete-topic --topic-arn "$TOPIC_ARN"`

5. **残りがないことの確認**（名前の先頭が `<PREFIX>` のものだけを一覧する。**一覧にないものは削除しない**）：

```bash
aws cloudformation list-stacks --stack-status-filter CREATE_COMPLETE UPDATE_COMPLETE DELETE_FAILED --query "StackSummaries[?starts_with(StackName,'$PREFIX')].StackName"
aws dynamodb list-tables --query "TableNames[?contains(@,'$PREFIX')]"
aws logs describe-log-groups --log-group-name-prefix "/aws/lambda/$PREFIX" --query 'logGroups[].logGroupName'
aws scheduler list-schedules --name-prefix "$PREFIX" --query 'Schedules[].Name'
aws cloudwatch describe-alarms --alarm-name-prefix "$PREFIX" --query 'MetricAlarms[].AlarmName'
aws iam list-roles --query "Roles[?contains(RoleName,'$PREFIX')].RoleName"
aws s3api list-buckets --query "Buckets[?starts_with(Name,'$PREFIX')].Name"
aws sns list-topics --query "Topics[?contains(TopicArn,'$PREFIX')].TopicArn"
```

6. 数日後に請求を再確認します。**削除してもゼロ課金とは限りません**（メトリクスの扱いなど）。

## 13. 不足している操作（公開ファイルだけでは確定できない・提供していない）

| 項目 | 状態 |
|---|---|
| 運用者用のIAMポリシー文書 | **未提供**。§5.2は操作の種類の目安で、検証していない |
| **停止後の再開（再arm）** | **公開の手順なし。** armは既存項目を上書きしない（`attribute_not_exists`）ため、§8は停止後には使えません。世代の引き上げと再armは非公開スクリプトで行っていました。再開したい場合は、新しいスタック（新しいテーブル）として構築し直してください |
| 停止の自動読み戻し・全ページ一括の操作 | 公開スクリプトなし（§10は手作業の確認コマンド。網羅性の保証なし）。**独立Stopper（`src/aws_b/stopper.py`）は未適用**で、デプロイ不可 |
| 公開テンプレートそのものの適用実績 | **なし。** Stage Aは、生成スクリプトが出力したテンプレート（全資源に `Retain` を付与する等、公開版と同一ではない）で実施した。公開テンプレートは `Retain` が `ProbeTable` のみのため、スタック削除でほかの資源は消える。`validate-template` も未実施 |
| 6時間・12時間間隔 | **LIVE未検証**（Stage Aは15分）。Alarmの評価に24時間以上かかる |
| 障害通知の試験 | §9は手順の流用で、Lite向けの公開手順としては未確認（Stage Aは一時fixtureで実施。fixtureの構築は公開手順に含めない） |
| 予算・費用の上限 | AWS Budgetsの作成手順は含めない（通知であり、hard capではない）。実請求額は **UNKNOWN** |
| カスタムメトリクスの停止後の課金 | **UNKNOWN** |
| リージョン | `us-east-1` のみを想定。他は未検討 |
| SiteProofへの結果の取り込み（§9.1） | 合成データでのみ確認。実AWSの出力（`aws dynamodb` の保存結果）での取り込みは**未確認**。自動で取り込む機能はない（手動の取り込みコマンド） |
| 第三者の環境での再現 | **未実証** |
