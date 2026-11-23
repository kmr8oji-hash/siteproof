# SiteProof 運用ガードスタック (ops_guard)

状態: **OFFLINE CANDIDATE / AWS LIVE NOT VERIFIED**。AWS がこのテンプレートを受理したことは確認していない。デプロイは未実施・未承認。

## 目的

AWS-A (CloudFront + private S3, `infra/public_web/cloudformation.json`) には監視・予算・通知・監査ログが含まれない。それらを手作業ではなく別スタックで IaC 化する候補。AWS-A のスタックは変更も import もしない。配信 ID は文字列パラメータで受け取る。

## リソース

| 論理 ID | 種別 | 備考 |
|---|---|---|
| AlertTopic | SNS Topic | KMS 暗号化なし (下記 未解決事項) |
| AlertTopicPolicy | SNS TopicPolicy | `sns:Publish` のみ。cloudwatch / budgets サービスのみ。`aws:SourceAccount` 条件付き |
| AlertEmail | SNS Subscription | email。手動の確認クリックが必須 |
| CostBudget | Budgets Budget | 月次 COST。ACTUAL>80% と FORECASTED>100% の 2 通知。budget action なし |
| RequestsAlarm / BytesAlarm / ErrorRateAlarm | CloudWatch Alarm | AWS/CloudFront, Requests 5分1000, BytesDownloaded 日次1GiB, 5xxErrorRate 5分5% |
| TrailBucket / TrailBucketPolicy / Trail | S3 / S3 Policy / CloudTrail | `EnableTrail=true` のときのみ。管理イベントのみ、データイベントなし。バケットは Retain、90日で期限切れ |

IAM / Lambda / EC2 / Transform / Mappings は使わない。

## パラメータ

NotificationEmail (既定なし), MonthlyBudgetUsd (既定 5, 1〜50), PublicDistributionId (`^E[A-Z0-9]{5,20}$`), EnableTrail (既定 `false`)。

## 重要な方針

- 予算は**通知**であり、支出上限でも停止機構でもない。budget action は意図的に入れない (Commander 判断)。
- アラームのしきい値は**候補値**であり、承認済みの値ではない。
- us-east-1 のみでデプロイする想定 (CloudFront メトリクスは us-east-1)。

## 証明されていないこと

- AWS によるテンプレート受理 (validate-template / change set / 作成) は未実行。
- アラームが実際に発火して通知メールが届くこと。
- Budgets 通知の実発火。
- SNS トピックポリシー・バケットポリシーの AWS 側での評価結果。
- オフラインテスト (`tests/aws_guard`) は独自 allowlist による契約チェックであり、AWS のスキーマや IAM 検証ではない。

## 未解決事項 (公式ドキュメントでの確認が必要)

1. SNS 暗号化: AWS マネージド `aws/sns` キーで暗号化したトピックには CloudWatch アラームが publish できない、と記憶している。そのため KMS を設定していない。カスタマーマネージドキーを使う場合の鍵ポリシーは未検討。
2. AWS::Budgets::Budget は一部プロパティが更新時に置換または更新不可になる可能性がある。要確認。
3. 組織または既存アカウントに trail が既にあるか。ある場合 `EnableTrail=false` のままにする。
4. us-east-1 要件 (CloudFront メトリクス、Budgets の API リージョン) の正確な条件。
5. email 購読は確認メールのクリックまで有効にならない。未確認の間は通知が届かない。
6. Budgets から SNS への publish に必要なトピックポリシーの正確な形式。
7. Trail 名を固定 (`siteproof-ops-guard-trail`) しているため、同名の trail があると衝突する。

## コスト (推定・未検証・要公式確認)

以下は記憶に基づく**推定**であり、いずれも **未検証・要公式確認**。

- CloudWatch アラーム: 標準解像度で 1 本あたり約 0.10 USD/月 (3 本で約 0.30 USD/月)。
- CloudTrail: 最初の管理イベント trail は無料。ただし S3 保管料は課金される。
- Budgets: 最初の 2 件は無料。
- SNS email 通知は少量なら僅少。

削除してもコストがゼロになるとは限らない (Retain バケット、請求の遅延反映)。手順は `docs/aws_portfolio/RUNBOOK_GUARD_AND_AWS_A.md` を参照。

## オフラインテスト

```
py -3.15 -B -m unittest discover -s tests/aws_guard -p "test_*.py" -v
```
