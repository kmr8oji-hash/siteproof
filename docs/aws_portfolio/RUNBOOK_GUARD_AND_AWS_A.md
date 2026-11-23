# 運用ガード導入と AWS-A 未検証項目の実測 Runbook

状態: **OFFLINE CANDIDATE / AWS LIVE NOT VERIFIED**。この文書の手順は一度も実行されていない。コマンドは例であり、AWS の仕様確認は未了。

## 1. 前提と承認境界

- この文書は**何も承認しない**。実行は、別途 USER の明示的な承認を得た後に限る。
- AWS-A の既存スタック (`infra/public_web/cloudformation.json`) は、ガードスタックによって変更されてはならない。ガードスタックは配信 ID を文字列で受け取るだけである。
- 例のコマンドのプレースホルダ (`<STACK>`, `<DIST_ID>`, `<EMAIL>`, `<PROFILE>`) は実値に置換する。実際のアカウント ID・認証情報をこの文書やリポジトリに書かない。
- Region は us-east-1 のみ。
- 予算は通知であり、支出の上限や停止機構ではない。しきい値は候補値で未承認。
- 各ステップで想定外の結果が出たら中断し、結果をそのまま記録する。

## 2. ガードスタックのデプロイ手順

承認後のみ。すべて例。

```
aws cloudformation validate-template --template-body file://infra/ops_guard/template.json --region us-east-1 --profile <PROFILE>

aws cloudformation create-change-set --stack-name <STACK> --change-set-name guard-initial --change-set-type CREATE \
  --template-body file://infra/ops_guard/template.json --region us-east-1 --profile <PROFILE> \
  --parameters ParameterKey=NotificationEmail,ParameterValue=<EMAIL> \
               ParameterKey=PublicDistributionId,ParameterValue=<DIST_ID> \
               ParameterKey=MonthlyBudgetUsd,ParameterValue=5 \
               ParameterKey=EnableTrail,ParameterValue=false

aws cloudformation describe-change-set --stack-name <STACK> --change-set-name guard-initial --region us-east-1 --profile <PROFILE>
```

1. validate-template が通るか確認する。通らなければ失敗として記録し、テンプレートは修正しない。差分を報告する。
2. change set の内容を人間が確認する。作成される種別が SNS, Budgets, CloudWatch Alarm のみ (EnableTrail=false) であること、既存 AWS-A リソースに変更がないことを確認する。
3. 承認があれば `aws cloudformation execute-change-set` を実行する。
4. 確認メールの購読リンクをクリックする (手動)。クリックまで通知は届かない。
5. EnableTrail=true は、既存 trail がないことを確認し、別途承認を得てから。

## 3. AWS-A 未検証項目の実測手順

### 3.1 アラームの実発火と通知到達

- 手順: `aws cloudwatch set-alarm-state --alarm-name <ALARM> --state-value ALARM --state-reason "manual test" --region us-east-1` を実行。続けて `--state-value OK` で戻す。3 本それぞれ、または代表 1 本で実施し、実施範囲を記録する。
- 取得する証拠: set-alarm-state 前後の `describe-alarms` 出力、`describe-alarm-history` 出力、受信メールの日時と件名 (本文のアカウント ID は伏せる)。
- 成功条件: ALARM と OK の両方でメールが届く。
- 失敗時の記録: メールが届かない場合は、購読の確認状態 (`list-subscriptions-by-topic`)、トピックポリシー、迷惑メールフォルダ、時刻を記録する。SNS 暗号化は無効のまま。原因は推測で断定しない。
- 注意: set-alarm-state は状態を一時的に変えるだけで、メトリクスに基づく実際の評価 (実トラフィックでしきい値超過) の検証にはならない。実際の評価は NOT_TESTED として別記する。

### 3.2 Budgets 通知

- 強制発火はできない。実コスト・予測コストが条件に達したときだけ通知される。
- 選択肢: (a) 一時的に極端に低い上限 (最低値) のテスト用予算を別に作り、実コストが閾値を超えるのを待つ。作成は別承認、終了後に削除する。(b) 実施しない場合、結果は `NOT_TESTED` と記録する。
- 取得する証拠: `aws budgets describe-budget` と `describe-notifications-for-budget` の出力、受信メール。
- 成功条件: 閾値を超えた後に通知メールが届く。
- 失敗時の記録: 届かない場合、請求データの遅延 (数時間〜日単位) の可能性があるため、待った時間も含めて記録し、直ちに失敗と断定しない。

### 3.3 HTTPS / ルート 302 / 直接 S3 拒否 / 非許可キー拒否 / セキュリティヘッダ

読み取りのみ。承認後に実施。`<DOMAIN>` は CloudFront ドメイン、`<BUCKET_DOMAIN>` は S3 のリージョナルドメイン。

```
curl -sI http://<DOMAIN>/                  # HTTPS へリダイレクトされること
curl -sI https://<DOMAIN>/                 # 302 かつ Location: /home/index.html
curl -sI https://<DOMAIN>/home/index.html  # 200 とセキュリティヘッダ
curl -sI https://<BUCKET_DOMAIN>/home/index.html  # 403 (直接アクセス拒否)
curl -sI https://<DOMAIN>/not-allowed.txt  # 許可リスト外。拒否されること
```

- 取得する証拠: 各レスポンスのステータス行とヘッダ全文 (日時付き)。
- 成功条件: HTTP が HTTPS にリダイレクトされる。ルートが 302 で `/home/index.html` へ。S3 直接が拒否される。許可リスト外キーが 200 で返らない。CSP, HSTS, X-Frame-Options 等がテンプレートの定義と一致する。
- 失敗時の記録: 期待と異なるステータス・ヘッダをそのまま保存する。キャッシュ (TTL 最大 300 秒) の影響を考え、時刻を併記する。

### 3.4 配信の無効化 → 伝播時間 → 再有効化

**これは稼働中の AWS-A スタックのパラメータ `PublishEnabled` を変更する。ガードスタックの承認とは別に、専用の明示的承認が必要。**

- 手順: 承認後、AWS-A スタックの `PublishEnabled` を `false` に更新 (change set で確認)。更新開始時刻を記録。`curl -sI https://<DOMAIN>/home/index.html` を一定間隔で実行し、応答が変わるまでの時間を測る。その後 `true` に戻し、再び応答が回復するまでの時間を測る。
- 取得する証拠: change set、各 curl の時刻付き結果、`describe-stack-events`、`cloudfront get-distribution` の Status 推移。
- 成功条件: 無効化後に配信が停止し、再有効化後に復旧する。それぞれの所要時間が記録される。
- 失敗時の記録: 途中で止まった時点の状態、エラーメッセージ、スタックの状態 (UPDATE_ROLLBACK 等) を記録し、手動で状態を変えない。復旧が必要なら再度承認を求める。
- 注意: 伝播にかかる時間は未確認。数分〜十数分と記憶しているが、実測するまで不明。

## 4. 停止・残余資源確認

- 棚卸し: タグ `Project=SiteProof` によるリソース検索 (`aws resourcegroupstaggingapi get-resources --tag-filters Key=Project,Values=SiteProof`) と、スタック単位 (`aws cloudformation list-stack-resources --stack-name <STACK>`) の両方で確認し、差異を記録する。タグの付かないリソースがある点に注意。
- スタック削除後に残りうるもの:
  - Retain 指定の S3 バケット (TrailBucket、AWS-A の AssetsBucket) と、その中のオブジェクトおよびバージョン。
  - CloudWatch Logs のロググループ (存在する場合)。
  - SNS 購読 (未確認のものは一定期間後に消えるか未確認)。
  - 削除に失敗した Budget。
- 請求は遅延反映される。削除してもコストがゼロになるとは限らない。削除後も数日後に Cost Explorer / 請求ダッシュボードで確認する。
- Retain バケットの削除は、中身を確認した上で別承認を得て行う。

## 5. 証拠の保存形式

- CLI 出力は JSON で保存し、ファイル名に UTC の時刻を含める (例: `20260101T000000Z_describe-alarms.json`)。
- 各ファイルの SHA-256 一覧 (`sha256sum` 形式) を併せて保存する。
- 認証情報・アクセスキー・アカウント ID・メールアドレスは保存・公開しない。保存前に伏せ字へ置換し、置換した事実を記録する。
- 公開用資料には実リソース ID を含めない。

## 6. 未確認事項

- テンプレートが AWS に受理されるか (validate-template 未実行)。
- SNS 暗号化なし構成で CloudWatch / Budgets からの通知が届くか。
- アラームしきい値の妥当性 (候補値)。
- 既存の org / アカウント trail の有無。
- us-east-1 要件の正確な範囲。
- Budgets の更新・置換の挙動。
- 配信無効化・再有効化の伝播時間。
- コストの見積り (記憶による推定、未検証・要公式確認)。
