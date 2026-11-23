# 実AWSへ進む前のGate

**現在: AWS LIVE NO-GO / USER APPROVAL REQUIRED / NOT EXECUTED**

静的テストPASSは次の項目を完了にしません。未記入やUNKNOWNを承認と解釈しません。`PublishEnabled=true`も権限付与やUSER承認ではありません。

## 実施前の確認記録

| 必須事項 | 現状／必要な具体的記録 |
|---|---|
| AWS account / partition / Region / 実施者 | UNKNOWN。既存権限の確認、責任者、実施日時、commercial partitionの対象範囲を固定 |
| Source / artifact | 統合commit、template hash、公開6ファイルのsource commit・SHA-256・byte数・MIME・配置key、USERの内容審査 |
| リソース・権限 | 本候補7資源（RootRedirect CloudFront Functionを含む）、正確な操作一覧、deployment/publisher権限、SourceArn、BPA/OAC/TLS、既存資源との非干渉 |
| 公式仕様との最終照合 | NOT RUN。各resource/property/intrinsic、OAC、policy condition、default-disabled配信、quota、名前一意性・長さ、Region/partition対応 |
| AWS template validation / change set | NOT RUN。明示承認された環境で後続実施し、結果と対象hashを保存。ここで実行済みとしない |
| 料金見積もり | UNKNOWN。公式料金・traffic・地域・転送量・version保持・通知/ログ費用・最悪ケース・停止遅延を記録 |
| 予算通知・アクセス量対策 | NOT CONFIGURED。通知先、閾値、到達試験、確認頻度、停止担当、WAF等の要否。通知は請求額の保証された上限ではない |
| ログ・監視・privacy | NOT CONFIGURED。方式・権限・Region・保持・個人情報取扱いを承認。必要な追加資源は別allowlistで審査 |
| 停止・撤収 | NOT EXECUTED。disabled伝播、invalidation費用、削除順、Retain bucketの全version等、ログ資源と残留課金の担当・期限 |
| 実測・証拠記録 | NOT RUN。HTTPS、S3直接拒否、未列挙キー拒否、OAC、headers/CSP、404/403、local image compare非送信、ログ/通知到達、停止復旧を対象・時刻・実施者付きで記録 |
| USER明示承認 | NOT GRANTED FOR LIVE。account/Region/実施者/資源/権限/費用/公開ファイル/停止条件/操作範囲に対する承認原文を記録 |

## 最終配布物の審査（オフライン抽出だけでは未完了）

統合後の6ファイルで`package_public.py`の通常モードを新規出力先へ実行し、manifestの`navigation_complete=true`、6キー・SHA-256・byte数・MIME・template hash・source commitをUSERが審査します。pre-integrationモードの出力を承認済みreleaseへ昇格しません。payloadだけが候補で、review_manifest.json、DB、証拠、fixture、Git情報、ユーザーJSON/画像、Secretsは公開禁止です。既知の鍵形式の静的拒否は完全な機密検知ではないため本文審査を省略しません。

`/`→`/home/index.html`固定302候補を通したブラウザURLでCSS・JS・Compareリンクが6キー内へ解決されることを静的検査します。DefaultRootObjectだけを根拠に成功としません。現行AWS仕様（CloudFront Function/FunctionARN/AutoPublish/runtime、viewer-request関連付け、生成応答のHTTPS/security headers）との最終照合はNOT RUNです。実AWS受理・表示はUNKNOWNのままです。

旧`public/`キー、古い配布物、edge cache、version/delete marker/multipart、関数関連付けと残留課金を撤収一覧へ含めます。policy変更は削除やcache消去ではありません。自動同期・自動削除・実AWS操作は実装していません。

## 公式参照候補（このBatchでは未取得・未照合）

- https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cloudfront-originaccesscontrol.html
- https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cloudfront-distribution.html
- https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cloudfront-cachepolicy.html
- https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cloudfront-responseheaderspolicy.html
- https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-s3-bucket.html
- https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/private-content-restricting-access-to-s3.html

リンクは後続の確認先候補であり、現行仕様をこのBatchで検証したという出典ではありません。新規依存を導入せず、今回はJSON・参照・安全条件のPython静的検査だけを行います。

## 維持するGate

- AWS LIVE NO-GO、AWS C-02 DEFERRED / OPEN。
- ARCH-LEAN Pilot: 初回EC2起動1回、再armなし。本フロントエンドをPilot正式採用と扱わない。
- LOCAL-ISOLATION NOT VERIFIED、Production Profile Trust Source OPEN。
- DB rollback再許可リスクOPEN、UNATTESTED / UNKNOWN / NOT_RUN、S1 CAPTURE PASS / CHANGED拒否。
- formal T01–T21 UNKNOWN、v0.7 NOT ADOPTED / NOT FROZEN。
- Git push NOT AUTHORIZED、Obsidian正本変更 NOT AUTHORIZED、Search Fabric AWS HOLD変更禁止。

全Gateを満たしても、今回のオフライン承認から実AWS実行へ自動進行しません。実AWS、実Browser、外部サイト、認証・課金操作、次Batchは別の明示承認が必要です。
