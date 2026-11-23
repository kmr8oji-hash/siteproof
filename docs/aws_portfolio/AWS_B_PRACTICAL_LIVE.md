# AWS-B 実用LIVE：6ページ＋一時HTTP fixture（実行前・承認待ち）

> 公開版について：本書が使う `docs/aws_portfolio/AWS_B_IAM_20261112/`（IAMポリシーとテンプレート生成スクリプト `prepare-live-templates.py`）は、AWSアカウント情報を含むため公開していません。公開版のリポジトリだけでは、本書の手順は実行できません。

本書と生成JSONはオフライン成果。AWS API・公開・課金・SNS配送は未実行。AWS-C LIVE NO-GO、C-02 OPEN、品質UNKNOWNを維持する。通常の `targets.json` は3サイト5URLのまま。

## 確定した構成

|資源|通常5ページ|fixture追加分|今回合計|
|---|---:|---:|---:|
|AWS-B Probe Lambda / DynamoDB / Scheduler|各5|各1|各6|
|Probe/Scheduler IAMロール|10|2|12|
|CloudWatch Alarm|15|3|18|
|Probe Logs|5|1|6|
|fixture応答Lambda / Function URL|0|各1|各1|
|fixture応答ロール / Logs|0|各1|各1|
|URL公開Permission（リソースポリシー文）|0|2|2|
|fixture監視専用Permissions Boundary|0|1|1|
|Lambda非同期設定|5|1|6|
|専用SNS / 新TrialコードS3|各1|追加なし|各1|
|CloudFormationスタック|5|監視1＋fixture1|7|

したがってLambda7、ロール13、Logs7。6監視スタック60構成資源＋fixtureスタック7資源＋S3/SNS2＝69構成要素（非同期設定・Permissionを含む）。USERが付与する一時Operatorポリシー3件は別途。旧Trialの保持S3・証拠は変更しない。

fixtureは128MB、timeout3秒、予約同時実行1、固定本文・GET `/`のみ。POST等405、その他パス・queryは404。環境変数 `FIXTURE_HTTP_STATUS` の200/503で切替。期限後410、設定不正503。本文・アプリログへ環境変数や受信イベントを出力しない。コードに外向き通信処理はない。VPCによる通信隔離を主張しない。

Function URLは `AuthType=NONE` の匿名公開。`InvokeFunctionUrl`＋`FunctionUrlAuthType=NONE` と、`InvokeFunction`＋`InvokedViaFunctionUrl=true` の2つの公開許可だけ。Operatorのfixture直接Invokeは追加ポリシーでDenyする。他主体の既存管理権限まで撤去するものではない。CORSは設定しないが、CORSをアクセス制限とは扱わない。

公開はfixture作成時から撤収までで、準備時間も費用対象。URLを知った第三者もGET可能。公開URLは秘密・認証の代替ではない。絶対期限はAWS-Bの新規probeを止めるが、URL自体を自動削除しない。第三者による呼出しと期限後410応答も課金され得る。URL撤収・fixture同時実行0には終了時の管理操作が必要で、費用のhard capはない。

## 承認後の生成・構築順序（今は実行しない）

1. 新Trial、us-east-1、siteproof-operator／D専用認証、予定開始UTC、24時間の費用枠と公開リスク、停止・削除をUSERが一括承認する。SNSメールは安全なローカル入力のみ。
2. 既存生成器で、開始予定を十分先のUTCに固定して事前計画を生成する。同じTrial・開始予定・終了期限を後段でも使う。期限延長はしない。

```powershell
py -3.15 -B docs/aws_portfolio/AWS_B_IAM_20261112/prepare-live-templates.py --out D:\<新規事前計画> --trial-id <YYYYMMDD-HHmmss> --start-at <開始UTC-Z> --duration-minutes 1440 --with-fixture
```

URL未発行の段階では監視5件の計画と `http-fixture.template.json`、6件分を含む追加IAM／撤収ポリシーを生成する。仮URLでデプロイしない。既存60分 `--end-at` も利用可能。

3. USERが既存Deploy/Operateに、生成された次の3ポリシーだけを追加する。旧A/Bや共通ポリシーの改変・流用はしない。
   - `trial-fixture-deploy-policy.json`：fixture関数のCreate/Get/Update、URL Create/Get/Update/List、AddPermission/GetPolicy、同時実行設定、Tag。新境界のCreate/Get、6番目Probeロールの境界付きCreate/Put、6番目テーブルのCONTROL/RUNに限るPut/Update/Get/Query、今回18 AlarmのEnableAlarmActions。fixture直接InvokeのDeny。
   - `trial-cleanup-policy.json`：今回18 Alarm、6 Schedule、7関数、fixture URL/Permission、6テーブル、7 Logs、SNS1、7スタックの削除だけ。
   - `trial-role-cleanup-policy.json`：対象13ロールの依存読取・インラインポリシー／ロール削除、新境界1件の参照・削除だけ。S3削除、共有ポリシー・USER削除権限なし。
   既存限定PassRole・ログ・CloudFormation権限は再利用。新境界はfixtureスタックで作り、6番目Probeだけに使用する。fixture応答ロールは既存ProbeBoundaryとの交差で自分のLogs書込だけを許可する。
4. **構築前**にUSERのIAM管理画面／Policy Simulatorで新Trial全ARNのCreate/Read/Stop/Deleteを確認する。Region、LeadingKeys、PermissionsBoundary、PassedToServiceの必要なcontextを指定し、SCP等の明示Denyも確認する。Simulatorは将来のサービス依存成功の保証ではない。実効権限・依存に不明点があれば作成前STOP。操作主体自身への無断権限追加はしない。
5. 認証主体確認、同名資源／同じTargetIdの別Trial監視との競合確認、生成テンプレートの `cloudformation validate-template`。AWS上の新しいURL/Permissionプロパティ受理はここで初めて検証する。
6. fixtureスタックだけを先に作成（CAPABILITY_NAMED_IAM、on-failure DO_NOTHING）。URLのGetFunctionUrlConfig応答はD側の非公開JSONへ直接保存し、通常ログへURLを表示しない。

```powershell
aws lambda get-function-url-config --function-name <今回fixture関数> --profile siteproof-live --region us-east-1 --output json > D:\<非公開領域>\fixture-url.json
py -3.15 -B docs/aws_portfolio/AWS_B_IAM_20261112/prepare-live-templates.py --out D:\<別の新規最終計画> --trial-id <同じTrial> --start-at <同じ開始UTC-Z> --duration-minutes 1440 --fixture-url-file D:\<非公開領域>\fixture-url.json
```

FunctionArnが同じTrialのfixture関数と一致し、URLがus-east-1のFunction URLそのもの・root pathであることを検証する。ここで6監視計画・`trial-config.json`・`refresh-config.json`が成立する。URLは通常の設定ファイルへ登録しない。

7. 既存バンドルを新Trial専用S3へ固定VersionIdで保存。最終計画から6スタックをSchedule無効・世代1で作成する。起動前に期限が有効であること、全Schedule/Alarmが15分/900秒、予約同時実行1であることを確認する。
8. 新設18 Alarmの通知を一時Disableし、その後SNS購読設定・USERによるリンク確認。条件付きarm、予定開始から監視開始。初期欠測はサイト障害と混同せず、正常3期間を確認後EnableAlarmActions。実障害試験は通知有効化後のみ。

## HTTP200 → 503 → 200

fixture関数に対してのみ `get-function-configuration` でRevisionIdと全Environmentを取得し、D側JSONに保存する。ABSOLUTE_END_AT等を保持し、FIXTURE_HTTP_STATUSだけ503に変更する。`update-function-configuration --environment file://... --revision-id ...` → `wait function-updated-v2` → GetFunctionConfigurationでLastUpdateStatus=Successfulと設定値を確認。公開HTTP管理API・SetAlarmState・模擬メトリクスは使わない。

15分ごとの実probeで503を3評価期間以上観測し、DynamoDBのRECORDED/FAILとProbeFailure Alarmの実ALARM、USERメール受信を確認する。同手順で200へ戻し、実probeのPASS、実OK遷移、復旧メール受信を確認する。固定時間内の配送やexactly-once配送は保証しない。健康状態・HTTP失敗・Lambdaエラーを区別し、欠測／UNKNOWNを復旧としない。

```powershell
py -3.15 -B -m src.noxiworks --refresh-config D:\<最終計画>\refresh-config.json --aws-read --out D:\<新規HOME更新領域>
```

同じoutで手動更新でき、`latest.html`を開く。6テーブルへQuery/GetItem各6回。読取失敗・未取得fixtureはUNKNOWN。HTTP取得時点と閲覧時点、SAMPLEと実AWS取込を分離する。自動更新・タスク登録はしない。

## 終了・保全・撤収

- 同じ絶対期限で6監視の新規HTTP開始を拒否する。実行者が途絶えても既存EndDate／Lambda期限は維持される。fixture URLの公開残存は別途扱う。
- CONTROL無効＋世代1→2、Schedule無効、6Probe関数同時実行0。実行中・遅延処理、ログ、拒否結果を確認し、18 Alarm通知をDisableする。
- fixture URL削除、2 PermissionをGetPolicyで特定してRemovePermission、fixture同時実行0。新Trial関数以外には操作しない。すでに配信中のSNSメールの取り消しは保証しない。
- D側へ6ページのHTTP履歴・状態遷移、Alarm履歴、通知受信確認、HOME、制御/世代/期限、Lambda REPORT・メトリクス、テンプレート・コード・URL設定／許可ポリシーを保存してSHA-256を記録する。資格情報やメール本文の個人情報は含めない。
- 全資源Retainのため、スタック削除だけでは撤収されない。今回の正確な名前／ARNを取得し、Alarm18→Schedule6→7関数と非同期設定6→ロール13と付随インライン→新境界1→DynamoDB6/Logs7/SNS1→空になったスタック7を既存方式で削除・消滅確認する。URL/Permissionは関数削除前に確認・撤収する。未知の参照・Managed Policy付与・Instance ProfileがあればSTOPする。
- AWS側の履歴・ログ・購読は失われる。保全未完了なら削除しない。旧S3と新TrialコードS3、D側の全証拠は保持する。新S3の後日削除は別承認。一時Operatorポリシー3件はUSERが解除・削除する。
- ローカルのTrial設定は証拠として保存し、通常監視へ取り込まない。通常設定は元の5URLのまま。

## 費用・LIVE承認の最終入力

6ページ×96予定＝576 Probe起動/24h、fixtureの予定GET96回を加え、Lambda計672起動が正常時の予定量（重複等の物理起動や第三者アクセス上限ではない）。既存4系列×6Targetで最大24カスタムメトリクス、標準Alarm18。新しいメトリクス名・fixture専用Alarmは増やさない。

Alarm保持、メトリクス、7Lambda要求/GB秒、6Scheduler配信、DynamoDB読書込/容量、Logs取込/保持、SNS配送、新旧S3保存/版/リクエストが費用項目。旧未照合単価を仮置きするとAlarm18×USD0.10＋最大24系列×USD0.30＝月額USD9相当、24h単純按分USD0.30相当。他の従量費・税は別。現行単価・無料枠・課金粒度・実請求額はUNKNOWNで、見積上限ではない。新規NAT/EC2/API Gateway/DBは追加しない。

USERが承認する最終入力は、新Trial/予定開始UTCから24h/us-east-1、固定5URL＋発行されるFunction URL root、公開NONEと第三者呼出リスク、追加IAM3件と境界1件、通知先ローカル入力と購読/受信確認、200→503→200環境変数更新、費用枠（提案USD5・強制上限なし）、停止／保全／上記限定削除、新旧S3保持。実際のURLは新Trial関数ARNに結び付いたGetFunctionUrlConfig応答からのみ採用する。

参照：D側に保存されたAWS公式Service Referenceのlambda.json（2026-11-12参照記録、SHA-256はreference-manifest.json）。InvokeFunctionUrl／FunctionUrlAuthTypeとInvokeFunction／InvokedViaFunctionUrlをオフライン照合。現在のAWS受理・実効IAM・公開URL応答・Alarm発火・SNS配送・実請求は未検証。APIは承認後のStart Gateで初めて実行する。
