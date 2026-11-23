# AWS-B → HOME：5ページ版のオフライン接続とLIVE準備

## 2026-11-13：実用監視のオフライン実装Checkpoint

2026-11-12のAWS-B限定LIVE・撤収はPASS（正本24、Trial 20261112-111514）。以下の継続運用・更新機能はオフライン実装済みであり、AWS継続運用PASSではない。AWS-C LIVE NO-GOは維持する。末尾の旧LIVE準備は当時の履歴であり、次の実行承認では本節を優先する。

### 期限・Alarm

- IaCの既定は15分（ScheduleExpression=`rate(15 minutes)`、AlarmPeriodSeconds=900）。CloudFormation Ruleで両者の不一致を拒否。旧5分Trialは300秒を指定すれば利用できる。HOMEの従来設定6時間も21600秒と対応する。
- AbsoluteEndAtは必須・既定値なし。Schedule EndDate、Lambda期限、世代・重複拒否は再利用。継続する日数・期限は今回決定していない。停止と資源撤収は別手順。
- 1ページ3 Alarmを維持。ProbeFailureAlarmは保存済み・確定したHTTP FAIL（2/3期間）。UNKNOWN・未保存はHTTPのOK値を出さず、欠測はINSUFFICIENT_DATAにする。
- 互換の論理ID UnpersistedAlarmは既存ProbeUnknown系列で監視不明・未保存・欠測を検知（2/3期間、欠測breaching）。Lambda ErrorsはFunctionErrorAlarmで分離。3件ともALARM/OKで既存SNSへ通知する設計。CloudWatchの実際の評価・通知到達は次のLIVEで未確認分だけ測る。
- 停止後の欠測は意図どおりhealth Alarmになり得る。計画停止時は対象Alarmの通知アクション停止を運用承認に含める。通知停止は監視停止・削除の代替ではない。

### 1コマンド更新

保存済みexportからの更新（AWSアクセスなし）：

```powershell
py -3.15 -B -m src.noxiworks --refresh --aws-b-input D:\PATH\EXPORT --out D:\PATH\NEW_MANAGED_HOME
```

以後は同じコマンド・同じoutを使用できる。`NEW_MANAGED_HOME/latest.html`を開く。保存済みAWS exportはHISTORICAL、合成入力はデモを維持する。CSS・6画面・リンクを検証した新世代のみ入口を原子的に切り替え、前世代は保存する。読取失敗ページはUNKNOWN、未取得はNOT_FETCHED。生成失敗時は入口をUNKNOWNの失敗表示にし、前回のUPへ自動遷移しない。中途出力も削除しない。

AWSからの更新用入口（本Taskでは実行禁止、次の別USER承認後のみ）：

```powershell
py -3.15 -B -m src.noxiworks --refresh-config D:\PATH\refresh.json --aws-read --out D:\PATH\NEW_MANAGED_HOME
```

refresh.jsonは`schema: siteproof.aws-b-refresh.v1`、`profile: siteproof-live`、`region: us-east-1`、`interval_seconds: 900`、`tables: {target_id: 実テーブル名}`。既存5 IDを過不足なく、異なる5テーブルへ指定する。秘密情報・URL・認証情報は入れない。

既存のD専用認証セッション（AWS_CONFIG_FILE / AWS_SHARED_CREDENTIALS_FILE / AWS_LOGIN_CACHE_DIRECTORY / USERPROFILEがD:）が必要。既存AWS CLIのみを使用し、DynamoDB公式us-east-1 endpointへのQuery/GetItemを各5回、ConsistentRead・最大56行で読む。Scan・書込・監視起動・資格情報作成はない。SDK追加インストールは不要。CLI側の認証更新も含めたD限定性・利用主体・IAMはLIVE開始前に確認する。

観測時刻、取得時刻、HTML生成時刻、HOME閲覧時刻を分離。取得結果は取得時点のスナップショットであり、自動更新・ブラウザからのAWS接続はない。鮮度は設定間隔の2倍でSTALE。閲覧時の現在状態はUNKNOWNを維持し、HOMEの閲覧時刻だけローカル時計で表示する。定期更新登録・常駐処理は未実施。

### 費用項目と次LIVE承認

- 過去16 Alarmは5ページ×3件=15件と、模擬通知経路用1件。継続運用の基本は15件、模擬通知専用Alarmは常用に再作成しない。標準Alarmの保持課金を確認する。
- カスタム系列は既存ProbeFailure / ProbeUnknown / Unpersisted / Rejectedを再利用。TargetIdのみの次元で最大4×5=20系列。新しい系列は追加しない。EMFはCloudWatch Logsへ出し、取込・保存とメトリクスの費用を区別する。
- 15分×5ページは予定480実行/日。Lambdaの要求・GB秒、Scheduler配信、DynamoDBオンデマンド読書込・容量・TTL、Logs取込/保持、SNS送信/配送、保持S3の容量・版・リクエストを測る。手動HOME更新1回はQuery/GetItem各5回。金額・無料枠・実請求はUNKNOWN。
- 次LIVEは対象5 URL/ID、us-east-1、稼働期限（明示UTC、60分Trialか別の期限か）、呼出上限・費用枠、siteproof-operatorの限定権限、D専用認証、テーブル対応表、SNSローカル通知先・受信確認、停止（制御/世代/Scheduler/同時実行0）、Alarm通知停止、残存確認・撤収承認を一括で確定する。
- 既存HTTP 200・保存・SNS模擬通知・停止/撤収の過去証拠は再利用する。追加LIVEでは未確認の周期/Alarm整合、最新読取→HOME、HTTP 503→復旧の実通知、期限・停止、使用量を確認する。実HTTP503用の本人管理fixtureとそのURL/隔離/変更権限は別途必要。本番5ページを故意に停止しない。
- 新IaC・RuleのAWS受理、実CloudWatch評価・通知、D認証の継承、現在の権限・クォータ・リソース競合はオフラインでは確認できない。次のLIVEの最小Start Gateで確認する。

## 旧オフライン接続・限定Trial準備（履歴）


状態：OFFLINE CONNECTED。AWS LIVE NO-GO / LOCAL隔離未検証 / C-02 OPEN。以下のAWSコマンドは未実行であり、別途USER承認後だけ実行する。既存単一CloudFront用Runbookの異常パス変更は、今回の5URLの枠には含めない。

## オフラインの最短経路

```powershell
# カレント：<worktree>
py -3.15 -B -m src.noxiworks.aws_b_data --fixture-output NEW_D_FIXTURE_DIR
py -3.15 -B -m src.noxiworks --aws-b-input NEW_D_FIXTURE_DIR --out NEW_D_DEMO_DIR
py -3.15 -B -m src.noxiworks --out NEW_D_NORMAL_DIR
```

fixtureは既存handler.run→DynamoStore条件付き保存→GetItem/Query相当JSON→export_http→HOMEを通る。ProbeResultのみ注入し、DNS/HTTPは実行しない。重複配送は同じhandlerで拒否する。デモ表示を維持し、AWS_EXPORTへのfixture再ラベルを拒否する。既存src/aws_bは未変更。

取込フォルダーは `manifest.json` と `<target_id>/head.json`、`<target_id>/runs.json`。manifestはschema=`siteproof.aws-b-export.v1`、source=`AWS_EXPORT`または`FIXTURE`、target_ids（設定IDの配列）、exported_at（UTC）を持つ。headはGetItemの`Item`（未取得なら空オブジェクト）、runsはQueryの`Items`配列。未登録ID・別ページのpk・不足ファイル・シンボリックリンクを拒否する。manifestに載っていないページは未取得UNKNOWN。

任意のcontext.jsonには既存snapshot契約のTLS/ドメイン/画像比較データを置ける。既存データを維持しHTTPだけを置換する。TLSは保存済みtls_not_afterからホスト単位へ集約。workers.devは提供元管理で登録期限の対象外。登録期限の実取得は未実装。履歴は取り込んだ直近56slot/ページの範囲。AWS_EXPORTも出所未認証の取込であり、AWS実測の認証済み表示にはしない。

## 必要資源と承認枠（候補）

- Region候補：us-east-1。既存targets.jsonの3サイト・5URL/IDのみ。生成された5つのplansは対象ID・ホスト・パスをAllowedValuesで固定する。
- 各ページ：DynamoDB 1テーブル、Lambda 1関数（Python 3.13・256MB・20秒・予約同時実行1）、Scheduler 1、ロググループ、IAMのprobe/schedulerロール、Alarm 3。共通：private/versioning有効S3コードバケットと承認済みSNS通知先。必要なら既存ops_guardのBudget USD5（実績80%/予測100%通知）。HOME用読取り権限はGetItem/Queryだけで、probeロールに読取り権限を追加しない。
- 通常設定は6時間。初回LIVEだけ5分を別パラメータとして指定。共通AbsoluteEndAtは試験準備開始から最大60分のUTC、延長しない。5ページで予定最大60回＋手動検証最大8回。予約同時実行1/関数を確保できない場合は開始しない。
- 通知・予算は課金停止上限ではない。実費・単価は未照合。有人監視、通知受信確認後のみarmする。権限拡張、固定URL外への接続、異常呼出数、期限超過、通知不達、安全拒否の不成立があれば全5ページを停止する。AWS-Cは起動しない。

## LIVEコマンドの最小順序（未実行）

実リソース名・Region・SNS ARN・通知先・期限・費用枠をUSERにまとめて提示し、承認後にだけ以下を実行する。認証情報の作成・変更、既存公開サービス停止は含めない。

1. `py -3.15 -B tools/build_bundles.py NEW_D_BUNDLE_DIR`でローカルバンドルとSHAを保存。承認後、lambda-bundle.zipだけを専用S3へ `aws s3api put-object` しVersionIdを記録する。
2. 各ページの `plans/<target_id>/aws-b.template.json` とパラメータJSON（CodeBucket/CodeKey/CodeObjectVersion/AlertTopicArn/AbsoluteEndAt、ScheduleExpression=rate(5 minutes)、ScheduleState=DISABLED）を用意する。

```powershell
aws cloudformation validate-template --template-body file://TEMPLATE.json --region REGION
aws cloudformation create-stack --stack-name STACK --template-body file://TEMPLATE.json --parameters file://PARAMETERS.json --capabilities CAPABILITY_IAM --region REGION
aws cloudformation wait stack-create-complete --stack-name STACK --region REGION
aws cloudformation describe-stacks --stack-name STACK --region REGION --output json
```

3. 各スタック出力からTableName/FunctionName/ScheduleNameを確定する。`src.aws_b.store.build_arm_request`で条件付きPutItemのJSONをD側へ生成し、`aws dynamodb put-item --cli-input-json file://ARM.json --region REGION`。世代は1、既存CONTROLを上書きしない。Schedulerは既存RunbookのCloudFormationパラメータ更新でENABLEDにする。未知のURLや異常パスには変更しない。
4. read-key.jsonは `{"pk":{"S":"CONTROL#TARGET_ID"},"sk":{"S":"HEAD"}}`、run-values.jsonは ` {":pk":{"S":"RUN#TARGET_ID"}}` としてD側に生成する。対象ごとに次の2コマンドで新しい読取りフォルダーへ保存する（PowerShellはUTF-8のSet-Contentを使用）。

```powershell
aws dynamodb get-item --table-name TABLE --key file://read-key.json --consistent-read --region REGION --output json | Set-Content -Encoding utf8 TARGET_DIR/head.json
aws dynamodb query --table-name TABLE --key-condition-expression 'pk = :pk' --expression-attribute-values file://run-values.json --no-scan-index-forward --limit 56 --consistent-read --region REGION --output json | Set-Content -Encoding utf8 TARGET_DIR/runs.json
# 明示的なAWS_EXPORT manifestをD側に作成してからローカル生成
py -3.15 -B -m src.noxiworks --aws-b-input EXPORT_DIR --out NEW_D_HOME_DIR
```

5. 停止は全ページへ適用する。`build_stop_request(table,target_id,expected_generation=1,stopped_at=実際の停止UTC)`の条件付きUpdateItemを使い、enabled=falseと世代2を同時に記録する。同じ旧世代イベントを再送しprobe_started=falseを証拠化する。

```powershell
aws dynamodb update-item --cli-input-json file://STOP.json --region REGION
aws lambda put-function-concurrency --function-name FUNCTION --reserved-concurrent-executions 0 --region REGION
# 同じテンプレート・全既存パラメータを維持し、ScheduleStateだけDISABLEDへ更新
aws cloudformation update-stack --stack-name STACK --use-previous-template --parameters file://DISABLE_PARAMETERS.json --capabilities CAPABILITY_IAM --region REGION
```

CONTROL停止、予約同時実行0、Schedule無効化の3層。1層が失敗しても他層の操作を試み、成功を偽装しない。実行中の1回はLambda最大20秒で終わる。AbsoluteEndAt以降はhandlerも拒否する。ログ/DDB/通知・停止後拒否の出力を保存する。Retainテーブル・コードS3・Alarm等の残存課金を棚卸しし、削除は別途承認とする。

LIVE前の残り：実テーブル名等の確定、AWS受理/IAM/Schedulerの実効、SNS到達、実TLS・費用の検証。失敗・復旧のHTTP実測は対象サービスを変更しない範囲のみ。合成fixtureでの成功をLIVEの成功へ読み替えない。
