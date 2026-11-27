# 実サイトE2E 実施計画（未実施・USER承認待ち）

署名付き監視許可による一般サイトの実撮影を、本人管理サイト1件で初めて実測するための計画です。**この文書の作成時点（2026-11-20）では、実サイトへのアクセス、Dockerの実行、署名鍵の作成は行っていません。** 下の「USERの承認が必要な操作」がすべて承認されるまで開始しません。

## 1. 対象

| 項目 | 内容 |
|---|---|
| 対象サイト | Hello, My Saitama（本人管理・Cloudflare Workers） |
| 対象URL | `https://hello-my-saitama.kmr8oji.workers.dev/`（トップページのみ） |
| 許可ホスト | `hello-my-saitama.kmr8oji.workers.dev`、ポート443だけ |
| 選んだ理由 | 本人管理で、AWS-BのHTTP監視で HTTP 200 の記録があり、リダイレクトの記録がない。TTN（これまでの限定例外の対象）以外のサイトで、署名付き許可による一般化の経路を確認できる |
| 撮影前の条件 | ハーネスは撮影前のHEADが「HTTP 200・Locationなし・TLS検証OK」でなければ停止する。リダイレクトがある場合は撮影しない（その場合は結果を記録し、対象を見直す） |

## 2. 所有権の確認（CLOUDFLARE_ACCOUNT_CONTROL）

2026-11-21に、well-known-file から変更した（HMSの本番切替はNO-GOとなったため。Commanderの裁定）。HMS側の変更は不要。

1. USERの承認のもと、既存のWrangler認証でCloudflare APIをREAD-ONLY（GETだけ）で確認する：Workerがアカウントにあること、アカウントのworkers.devサブドメイン、Workerのworkers.dev公開設定、カスタムドメイン。
2. 結果から証拠ファイル `<データ>\sites\<site>\real\ownership-evidence.json` を作る（アカウントIDはSHA-256だけを記録。生の応答は非公開の `.local` に保存）。
3. `tools/permit_draft.py --cloudflare-evidence` が、証拠の値・確認日時・SHA-256を許可の `ownership` に記入する。
4. アプリの撮影前チェックと撮影ハーネス（Dockerを呼ぶ前）が、ホスト＝`<Worker>.<サブドメイン>.workers.dev` と、証拠ファイルの一致を確認する（[REAL_CAPTURE.md](REAL_CAPTURE.md) の「所有権の確認方法」）。
5. SiteProofは、この確認のために対象サイトへ通信しない。

## 3. 撮影の条件

| 項目 | 内容 |
|---|---|
| プロファイル | Desktop 1440×900（ページ全体）、Mobile 390×844（ページ全体）。ライト配色、アニメーション停止、Service Worker無効（既存の撮影ランタイムの設定） |
| 安定性の判定 | 既定のポリシー（3回同じ画像・0.8秒以上の間隔・最大6回・4.5秒）。安定しなければ「判定不能」とし、Baselineは作らない |
| 監視許可の有効期間 | 3日間（例：承認日の 00:00 UTC から3日後の 00:00 UTC まで） |
| 最大実行回数 | 3回（1回目：初回撮影とBaseline作成、2回目：自動比較、3回目：予備） |
| Baselineの扱い | `AUTO_INITIAL_THEN_COMPARE` |
| 監視間隔 | 24時間（自動の2回目は翌日）。当日中に確認する場合は、HOMEの補助操作「今すぐ再検査」で2回目を実行する |

## 4. Dockerイメージと固定する情報

| 項目 | 値（2026-11-20の作業ツリーで算出） |
|---|---|
| 撮影イメージ | `sha256:9c88112b42070369876fdb24476af283b3908a3fdc630b66fedacf4f20c4d2c8`（ハーネスの `M5_IMAGE`。SP-D54で使ったもの。pull・buildはしない。ローカルにない場合は中止して報告する） |
| ブラウザbundleのmanifest | `c23dbb3ed42b…`（`tools/permit_draft.py` が算出。SP-D54と同じ） |
| 固定するファイル | ハーネスの `IDENTITY_FILES` 16件（ハーネス、Worker、ブローカー、reaper、通信ルール、許可の検証コード、対象設定の読み込みコードなど）。`tools/permit_draft.py` がそのときの値を入れる |
| 対象設定 | サイトの `targets.json`・`capture_plan.json`。登録後に `tools/permit_draft.py` がハッシュを入れる |

固定したファイルは、許可に署名した後に変更すると撮影が拒否されます。署名は、作業ツリーを確定してから行ってください。

## 5. 許可する通信

- 撮影ハーネスのブローカーが、許可ホストのDNSを解決し、**1つのIPv4アドレスの443番ポートだけ**を、撮影window（TTL 100秒、上限120秒）の間だけ開く。
- Desktop・Mobileそれぞれで、HEADを1回送り、その後ページを読み込む（プロキシ経由）。
- 外部のリソース（他のホストのフォント・スクリプト・画像など）はブロックされる。読み込めないものがある場合は記録され、判定に影響することがある。
- 撮影の前のGATE-A〜Cでは外部への通信がないことを確認する（DNSだけを許可した状態でTCP接続0）。
- AWS・その他のサイトには通信しない。

## 6. 手順

| # | 担当 | 操作 |
|---|---|---|
| 1 | USER | 署名用の鍵を作成する：`ssh-keygen -t ed25519 -f %USERPROFILE%\.ssh\siteproof_permit`（パスフレーズ付き。データフォルダの外） |
| 2 | 実行者 | E2E用のデータフォルダを新規作成する（例：`.local\real-e2e-hms-01`。公開対象外）。`py -3.15 -B -m src.noxiworks.app --data <そのフォルダ>` で起動し、サイトを登録する（URLは上記・Desktop/Mobile・間隔24時間） |
| 3 | USER | `<データ>\trust\allowed_signers` に1行を置く：`site-owner namespaces="siteproof-monitoring-permit" <公開鍵>`。推奨：このファイルを読み取り専用にする |
| 4 | 実行者 | 2章の所有権の確認（READ-ONLY）と証拠ファイルの作成（2026-11-21に実施済み） |
| 5 | 実行者 | `py -3.15 -B tools/permit_draft.py --data <データ> --permit-id hms-e2e-1 --days 3 --max-runs 3 --cloudflare-evidence [--valid-from <UTC>] --out <新規ファイル>` で未署名の下書きを作る |
| 6 | USER | 下書きの内容（対象・期間・回数・撮影イメージ）を確認して `<データ>\sites\<site>\real\permit.json` に保存し、署名する：`ssh-keygen -Y sign -n siteproof-monitoring-permit -f %USERPROFILE%\.ssh\siteproof_permit permit.json` |
| 7 | 実行者 | HOMEの「実サイト監視の準備」が5/5になったことを確認する（なっていなければ、欠けている条件を報告して止まる） |
| 8 | 自動 | 次の検査（登録時の予定は即時）で1回目の実撮影が実行される。ハーネスは署名・対象・識別情報を確認し、撮影回数を1回分記録してからコンテナを起動する。安定していれば初期Baselineを自動作成する（「自動作成（未確認）」） |
| 9 | 実行者 | 1回目の結果（撮影画像・Baseline・GATEの記録・通信の記録）を確認し、USERに報告する |
| 10 | 実行者 | 承認された時刻に、補助操作「今すぐ再検査」で2回目を実行する（追加の承認なしで、同じBaselineとの比較になる） |
| 11 | 実行者 | 2回目の比較結果（変更なし／変更あり／判定不能）、Baselineが変わっていないこと、撮影回数が2/3であることを確認する |
| 12 | 実行者 | 監視を停止する（補助操作「監視を停止」）。必要なら `permit.json` を別名にして許可を無効にする |

## 7. 証拠の保存場所

| 内容 | 場所 |
|---|---|
| 各回の撮影（S3-1Tの出力：GATE・撮影window・通信の記録、run結果、PNG、ワークスペース、export-sha256） | `<データ>\sites\<site>\real\runs\<run_id>\<run_id>\` |
| 失敗した撮影の記録（削除しない・画面には出さない） | `<データ>\sites\<site>\real\runs\<run_id>-failed\` |
| 初期Baseline（register_baseline の形式） | `<データ>\sites\<site>\real\registry\`、作成元：`real\registry-origin.json` |
| 撮影回数の記録 | `<データ>\trust\permit-ledger\hms-e2e-1.jsonl` |
| 監視ログ | `<データ>\sites\<site>\monitor-log.jsonl` |
| 画面 | HOME・差分レビュー・履歴・通知（実撮影だけを表示） |

## 8. 失敗時の停止と復旧

- ハーネスのGATEに失敗した場合：最初のページ読み込みの前に停止する（通信windowは閉じたまま）。記録は `-failed` に残る。撮影回数は1回分消費する。
- 撮影中に失敗した場合：ハーネスがwindowを閉じ（ホスト側→reaperの順）、自分が作ったコンテナ・ネットワークを片付け、既存のDockerリソースが変わっていないことを確認する。
- 監視をすぐ止める：HOMEの補助操作「監視を停止」。許可を無効にする：`permit.json` を別名にする、または `allowed_signers` から鍵の行を外す（次の撮影から拒否）。
- 片付けの確認：`docker ps -a` と `docker network ls` で、ハーネスのラベルが付いたリソースが残っていないことを確認する（残っていれば報告し、USERの指示で削除する）。
- 証拠は削除しない。

## 9. USERの承認が必要な操作

1. **実サイトへのアクセス**：`https://hello-my-saitama.kmr8oji.workers.dev/`（ホスト1つ・443番）に対して、上記の期間内に最大3回のハーネス実行（各回 Desktop・Mobile の HEAD とページ読み込み）。
2. **所有権の確認**：Cloudflare APIのREAD-ONLY確認（2026-11-21に承認・実施済み）。
3. **署名鍵**：USERの署名用の鍵の作成と、`trust\allowed_signers` への公開鍵の配置。
4. **監視許可**：下書きの確認と、USERの鍵での署名（対象・期間3日・回数3回・Baselineの扱い）。
5. **Docker**：Docker Desktopの起動と、固定した撮影イメージ（`sha256:9c88112b…`）によるハーネスのコンテナ（Worker・NET_ADMIN権限のブローカー・reaper）の作成・実行・片付け。イメージのpull・buildはしない。
6. **実行の時刻**：1回目と2回目を行う日時。
7. **結果の扱い**：E2Eの記録の保存先（`.local` 配下、公開しない）と、ObsidianやREADMEへの反映の可否（別途）。

## 10. 実測の前に残る問題

- **撮影ハーネスの許可モードは一度も実行していない。** コードの確認とオフラインのテストダブルでのみ検証している。初回の実行で、想定していない箇所が止まる可能性がある（その場合はGATEで止まり、通信は行わない設計）。
- 外部のリソースを読み込むページでは、読み込みの失敗が記録され、判定不能になる可能性がある（Hello, My Saitama の構成は未確認）。
- ハーネスは作業ツリーの未コミットの変更を記録する（拒否はしない）。署名の前に作業ツリーを確定する必要がある。
- 撮影回数の記録・信頼する鍵・PCの時計は、このPCに書き込める人なら変更できる（[REAL_CAPTURE.md](REAL_CAPTURE.md) の「信頼の範囲」）。
- 新しい許可への更新では、既存のBaselineを引き継げない（新しい許可では新しいBaselineを作る設計が必要）。
