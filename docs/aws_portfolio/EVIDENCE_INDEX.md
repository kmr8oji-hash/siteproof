# 証拠索引(過去の成功・失敗・BLOCKED・STOPを含む)

区分: **今回実測**=2026-11-11〜のこのworktreeでの実行結果。**過去報告**=既存のExecutor/USER報告で今回再測定していないもの。**静的**=ファイルの存在・内容を読んだだけのもの。原本はどれも変更・移動・削除していない。

## 0. AWS実証の証拠区分(2026-11-12 AWS-B限定LIVE・2026-11-13時点)

区分: **実測(保存済み)**=実行時に保存されたAWS API出力・ログ・DynamoDB出力(今回の資料作成でAWSを再照会していない)。**USER確認**=USERの受信・操作確認。**USER報告**=USER報告のみでAPI再検証なし。**Executor報告**=Executor報告で一次証拠の所在確認なし。**設計・実装のみ**=テンプレート／コード／オフラインテストで、AWS上での動作は未確認。

| 項目 | 区分 | 内容・限界 |
|---|---|---|
| AWS-A: CloudFront＋S3の公開 | Executor報告(11-03) | 7資源、6ファイル163,400 bytes。一次証拠の所在はUNKNOWN。今回再測定なし |
| AWS-B: 限定LIVE | 実測(保存済み) | 2026-11-12、15分間隔・最大60分。予定2 slotを実行。継続監視ではない |
| EventBridge Schedulerによる定期実行 | 実測(保存済み) | 11:25・11:40 JSTの2 slot |
| LambdaによるHTTP監視 | 実測(保存済み) | 18実行、7.74 GB秒(REPORT値)。実請求額はUNKNOWN |
| DynamoDBへの保存・読取 | 実測(保存済み) | 3サイト・5ページ・各2回HTTP 200、計10件。最終応答130〜191ms |
| 保存結果→HOME反映 | 実測(保存済み)＋ローカル生成 | ページごとに分離したローカルプレビュー。公開サイトへは未デプロイ |
| SNS 模擬ALARM／OK通知 | USER確認 | 両メールの受信確認。模擬通知であり、**実際の障害からの自動通知は未実証**。Alarm自体の実発火も未実証 |
| 停止制御 | 実測(保存済み) | CONTROL無効・世代2・Scheduler無効・予約同時実行0。停止後の新規HTTP監視開始なし(11:42:39 JST停止完了) |
| AWS資源の撤収 | 実測(保存済み) | 52資源＋CloudFormation 5スタックDELETE_COMPLETE |
| 一時IAMポリシー2件の削除 | USER報告 | API再検証なし |
| 証拠の保全 | 実測(ローカル) | 591ファイルをコピーし、元・先のSHA-256一致を記録 |
| 保持S3バケット1件 | 実測(保存済み) | 存在確認済み。全バージョン一覧・総保存量はUNKNOWN |
| 実際のAWS請求額・無料枠適用 | **未検証(UNKNOWN)** | 請求額ゼロとは断定しない |
| Alarm→SNSの実障害通知、Budgets閾値通知 | **未検証** | NOT_TESTED |
| AWS-C(EC2 Worker) | 設計・実装のみ | LIVE NO-GO。実証済みではない |
| 運用ガード(Budgets・CloudFront Alarm) | 設計・実装のみ | LIVE未検証 |

**保存場所**: 実証拠は公開リポジトリには含まれず、ローカルの `.local/aws-b-live-executor-20261112-01/`(LIVE結果・DynamoDB出力・HOME・SNS確認・停止・使用量)、`.local/aws-b-preservation-20261112-131348/`(591ファイルの保全コピーとSHA照合)、`.local/aws-b-cleanup-resume-20261112-155342/`(削除結果)にある。GitHubから参照できるリンクではない。AWSアカウントの識別子・通知先は公開資料に転記しない。

**境界**: HTTP 200は稼働確認のみで、描画品質・画像比較・Baseline承認・TLS／ドメイン期限のPASSではない。現在の監視状態はUNKNOWN(資源は撤収済み)。以降の §1〜§5 は2026-11-11〜の過去記録であり、AWS-B／AWS-Cの「未デプロイ／LIVE NO-GO」の記述は、当時の履歴として維持する。AWS-Bについては本節(§0)を最新とする。

## 1. 今回実測(このworktree)

| 内容 | 結果 | 保存場所(git管理外) |
|---|---|---|
| 既存テストの基準実行(HEAD `b52bd38`、Python 3.15.1、モジュール別プロセス) | 1,396実行 / 1,395 PASS / 1 FAIL / 0 SKIP | `.local/aws-portfolio-01/baseline-r2/` |
| 上記の1 FAIL | `tests/bff/test_runtime_view.py` の1件。HTMLに `/local/runtime.js` を期待するが、M5で `/local/workspace.js` へ統合済み。既存の不整合で、今回の変更によるものではない | 同上のログ |
| 新規テスト(aws_guard / aws_b / aws_c) | `TEST_RESULTS.md` 参照 | `.local/aws-portfolio-01/full-*/` |
| 既存M5由来証拠の再検証(`.local/user-ux-gate-01/review-data` の**コピー**71ファイル) | 既存 `plan_recovery` 経由で CONSISTENT、指摘0 | コピーはscratchpad。原本は未変更 |

## 2. 過去報告(今回再測定なし)

| 時期 | 内容 | 状態 | 出所 |
|---|---|---|---|
| 10-25 | S0/S1統合 310 PASS | PASS_WITH_NOTES | 非公開のローカル証拠（`review-evidence/SITEPROOF-LOCAL-MAIN-INTEGRATION-01/`） |
| 10-30 | 10スイート 1,154 PASS | 過去記録 | 正本 `12_PUBLIC_STATIC_RELEASE.md` |
| 11-03 | AWS-A 公開(7資源、6ファイル163,400 bytes) | PUBLIC_PASS(Executor報告) | 正本12。**一次証拠の所在はUNKNOWN** |
| 11-03 | SNS→メール試験配送 | PASS(USER提示) | 正本12 |
| 11-03 | Alarm実発火、Budgets閾値通知、配信停止の伝播 | **NOT_TESTED** | 正本12 |
| 11-06 | M4 オフライン統合(グループ延べ383。重複あり) | PASS | `src/comparison/M4_VALIDATION.md` |
| 11-06 | M5 Chromium/プロファイル/UI(限定範囲) | 限定PASS。`PROFILE_UNATTESTED` / 品質UNKNOWN維持 | `src/comparison/M5_VALIDATION.md`、`.local/m5-*` |
| 11-07〜08 | G1 Provider オフライン Self-test 107件 | PASS(合成のみ。実隔離UNKNOWN) | `handoffs\SiteProof\g1-b-20261107\live-fixture-01\`、worktree `siteproof-g1-provider-01`(未追跡24ファイル) |
| 11-08 | UDP53 fixture(IPv4、正10/負0) | UDP53_FIXTURE_PASS(全体はUNKNOWN) | `...\udp53-fixture-01\` |
| 11-09 | コンテナ通信の限定試験(TCP/DNS v4/v6、合成Proxy) | PASS WITH NOTES候補(全体はUNKNOWN) | `...\offline-asset-resume-03\` |

## 3. 失敗・BLOCKED・STOP(保全対象。PASSへ書き換えない)

| 時期 | 事象 | 分類 | 学び(AWS側へ反映した点) | 出所 |
|---|---|---|---|---|
| 10-23 | 正本初期コミットのWhitespace検査 FAIL(限定例外で受理) | FAIL/例外 | 検査結果は書き換えず例外として記録 | 正本00 |
| 10-25 | PF-05(HTTPラベルの指す先) | OPEN / NON-BLOCKING | 未修正のまま | 正本03 |
| 11-06 | M5: BuildKitが `--network=none` でもレジストリのメタデータ照会を実行 | RED → 後続で再開 | AWS-Cはイメージを**ダイジェスト指定**で取得し、起動時に何もビルド・インストールしない | `src/comparison/M5_HANDOFF.md` |
| 11-06 | M5 run-01: 制御行の512KiB上限超過 | FAIL(修正済み) | 上限は上げずに分割で対応 | 同上 |
| 11-06 | M5 run-02: 履歴未更新による欠損画像検査の失敗 | FAIL(修正済み) | — | 同上 |
| 11-06 | M5 run-03: 承認操作のTimeout(原因の細部はUNKNOWN) | FAIL / 一部UNKNOWN | 再現した機序のみ記録。断定しない | `M5_VALIDATION.md` |
| 11-06 | M5 resume-04: fixture証明書が「まだ有効でない」(時計) | STOP(迂回なし) | TLS検証は無効化しない。AWS-B/Cとも同じ方針 | 同上 |
| 11-08 | Hyper-V: ホストIFのDNS候補が残存 | YELLOW / 裁定待ち | — | `...\hyperv-bootstrap-01\COMMANDER_YELLOW.json` |
| 11-09 | Docker Engineのdebペイロード不在 | BLOCKED | 実行時の外部取得に依存しない設計(準備済みイメージ必須) | `...\engine-isolation-01\` |
| 11-09 | UAC取消(3回) | BLOCKED | 人の操作に依存する工程は自動化できない。AWS側は承認枠＋Runbookで事前定義 | `...\container-isolation-closeout-01\`、`kuma-isolated-poc-03\` |
| 11-09 | veth片付け時の想定外エラーで終了コード1 | fail-closed → 修正版で再実行 | 「停止できたか」と「後始末が済んだか」を分けて記録(AWS-CのTERMINATE_REQUESTED / VERIFIED / UNCERTAIN) | `...\container-isolation-closeout-02\`, `-03\` |
| 11-09 | Kuma: イメージ取得は検証済み、実行・GUI・隔離は NOT RUN | 未完 | Local監視は一時保留 | `...\kuma-isolated-poc-0{1,2,3}\` |

## 4. 維持しているGate(今回変更なし)

(AWS-B LIVEは2026-11-12に限定実証済み・撤収済み。§0を参照。以下は当時の記録。)
v0.7 / v0.8: NOT ADOPTED / NOT FROZEN。v0.8.1: DRAFT / NOT ADOPTED / NOT FROZEN。LOCAL-ISOLATION: NOT VERIFIED。formal T01〜T21: UNKNOWN。M5 PROFILE_UNATTESTED: OPEN。AWS-B LIVE: NO-GO。AWS-C Worker Pilot: NO-GO。C-02: DEFERRED / OPEN。Search Fabric側のGateは対象外で不変。

## 5. 保全上の注意

- M5証拠 `.local/`(2,199ファイル)はgit管理外の単一コピー。
- M2/M3原証拠はDocker named volume内(過去報告。今回はDocker未操作のため未確認)。
- G1の24ファイルは未追跡。

## FAST TRACK追加証拠

- `.local/aws-portfolio-01/fast-track-01/summary.json`: 限定16/16 PASS、AWS接続0、外部通信0、既存FAILは記録のみ。
- `.local/aws-portfolio-01/fast-track-01/bundles/bundle-manifest.json`: 配備ZIPと全構成ファイルのSHA-256。未アップロード。
- AWS実イベント・通知配送・実請求: 未取得。AWS-Aは過去報告のまま、AWS-B/CはLIVE NO-GO、C-02 DEFERRED/OPEN。
