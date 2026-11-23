# セキュリティ・費用・公開停止の設計候補

**AWS LIVE NO-GO / OFFLINE CANDIDATE / 実測・請求額・配信状態 UNKNOWN**

## 権限と公開境界

S3はBlock Public AccessとACL無効化を維持します。CloudFrontのservice principalに、SourceArnで固定したaccount/distributionからの指定6キーのGetObjectだけを許可します。ListBucket・PutObject・DeleteObject・GetObjectVersionはCloudFrontへ付与しません。非TLSのDenyはbucketと全objectへ適用します。IAM操作者権限をこのtemplateから発行しません。

将来のdeployment roleとasset publisherは別の最小権限設計が必要です。操作者のidentity policy、SCP、permission boundary、変更セット、object content審査は未検証です。account所有者等の権限をBucket Policyで全面的に封じたとは主張しません。

OAC署名やAES256は公開assetの出所認証ではありません。取り込むJSONは未認証レポート、画像差分は局所的な画素差です。UNATTESTED / UNKNOWN / NOT_RUN、S1 CAPTURE PASS / CHANGED拒否、Production Profile Trust Source OPENを維持します。DB rollback再許可リスクOPENも本構成では解消しません。

## キャッシュ・HTTP境界

- HTTPS redirect、HSTS 1年（subdomains/preloadなし）、nosniff、frame DENY、no-referrer。
- CSPはself script/styleとローカル表示用blob/data画像に限定し、connect/object/base/form/frame embeddingを拒否します。CORSは追加しません。
- cookie/header/queryをoriginへ転送せず、TTLは0/60/300秒の候補です。認証付き動的コンテンツは載せません。
- 未承認キーの403/404を200のSPA画面へ置き換えません。default root以外のdirectory indexも生成しません。
- DefaultRootObjectは`home/index.html`ですが、URL `/`のままでは相対assetがrootへ解決されます。RootRedirect（7番目の資源、CloudFront Function候補）は`/`のみ固定302で`/home/index.html`へ移動し、no-storeを返します。任意host/queryを転記しません。実AWSでの関数・HTTPS・security headers適用順は未検証です。
- PriceClass_100は配信地域・遅延・費用の選択であり、予算上限ではありません。日本からの遅延・cache hit率はUNKNOWNです。

## ログ・監視

アクセスログ、alert配送、予算通知は**NOT CONFIGURED**です。templateに設定があると誤認しないでください。公開前に以下を明示承認します。

1. CloudFrontのRequests、BytesDownloaded、4xx/5xx、cache hit、S3 request/storage等の収集対象・閾値・担当者・確認頻度。CloudFront global metricのRegionとalarm配送の仕様は公式確認が必要です。
2. access logの要否。採用する場合は現行の配送方式、保存先、最小権限、暗号化、保持期限、削除、費用、配信遅延を設計します。legacy loggingとBucketOwnerEnforcedの互換性を推測せず、今回のasset bucketを無断でACL有効化しません。
3. ログのclient IP・URL・user agent等は個人情報になり得ます。利用目的、収集最小化、アクセス権限、保存期間を承認します。ユーザー画像/JSON本文をログへ出しません。
4. 実通知の到達試験、当番、費用異常時の停止判断、通知欠落時のfallbackを実測します。ログ/metricは即時・完全配送を保証しません。

## 費用モデル

このBatchはAWS見積もりを取得しておらず、数値の月額予測・無料枠適用はUNKNOWNです。live承認時点の公式料金とRegion・traffic仮定で計算します。

| 費用項目 | 見積もり入力／残留要因 |
|---|---|
| CloudFront | 配信先地域、request数、転送量、cache hit、invalidations、採用料金プラン |
| S3 | 現行版＋非現行版のbyte-month、PUT/GET/LIST、必要な転送。Retainとversioningで残る |
| ログ | 将来採用する収集・配送・保存・検索・削除の量と保持期間 |
| 監視・通知 | 採用alarm/metric、配送、予算通知の方式・頻度 |
| 運用 | asset版更新、cache失効、事故対応、残留資源確認 |
| RootRedirect | CloudFront Functionのrequest処理回数・公開版・配信関連付け。無料・無課金とは仮定しない |

静的配信だけでも大量request/転送による費用が発生し得ます。queryをcache keyに入れなくてもrequest課金は防げません。WAF/rate limitingは今回未構成であり、必要なら費用を含む別設計・承認が必要です。

**費用通知は請求額の保証された上限ではありません。** 予算閾値・通知先・到達試験・応答時間を決めても、集計/通知/停止の遅延や停止までの利用で超過し得ます。disabledや削除操作も即時・ゼロ費用保証ではありません。強制されたbilling capがあると表示しません。

## 公開停止と撤収（設計のみ・NOT EXECUTED）

異常時の操作権限・実施者・USER承認と証拠記録を事前に定めます。この文書はAWS操作の実行承認ではありません。

1. 新規公開・更新を止める。漏えい対象のsource/key/version/hash、distribution IDを記録し、画像/個人情報を報告本文へコピーしない。
2. CloudFrontをdisabledへ変更し、伝播状態を実測する。必要なinvalidationは料金・範囲を承認して実施する。origin Allowを外してもedge cacheは即時消えません。
3. disabled/invalidatedでも、既に保存されたブラウザcache・ダウンロード・第三者コピーは回収できません。秘密情報を誤公開した場合、削除だけで解決とせず別途失効等の承認手続きをとります。
4. CloudFrontをdisabled・伝播完了後に削除する計画です。削除完了・関連OAC/cache/header policyの残留と参照を確認します。失敗時は自動再作成・無断修復しません。
5. **AssetsBucketはDeletionPolicy / UpdateReplacePolicyがRetain**です。stack削除だけでは消えません。非現行version・delete marker・未完了multipart uploadも確認し、必要な保全期間と明示承認の後で空にして削除する計画です。現行版だけ消して撤収完了としません。
6. 将来追加したログ保存先・alarm・通知・DNS/証明書等は別管理です。今回のtemplate外資源を誤削除せず、一覧と所有者を確認します。残留請求を後日も確認します。

配布対象はS3の`home/`・`compare/`直下の6キーだけに移行する候補です。旧`public/`キーや非現行versionがS3から自動削除されるとは扱いません。policyで新規読取りを外しても過去のedge cacheは残り得ます。旧root object・旧prefix・関数関連付けとcacheの実測を公開前Gateで審査します。review_manifest.jsonはアップロード対象外です。

この手順を実行済み、公開停止済み、費用停止済みとは申告しません。
