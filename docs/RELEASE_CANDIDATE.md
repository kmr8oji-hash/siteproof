# SiteProof 実用版 Release Candidate 1（RC1）

2026-11-26。対象：Windows 11・Python 3.15。ブランチ `siteproof/portfolio-02`（RC1のチェックポイントのコミット。下の「Gitへの統合」）。

この文書は、RC1で**何ができて、何を確認済みで、何が未確認か**と、**USERが実環境で行う受入確認の手順**をまとめたものです。使い方の詳細は [USER_GUIDE.md](USER_GUIDE.md)、導入・復元は [INSTALL.md](INSTALL.md) です。

## 1. 含まれる機能と確認の状態

| 機能 | 状態 | 確認の範囲 |
|---|---|---|
| 画像監視（Desktop・Mobileの撮影、Baselineとの比較、承認・更新） | 実装済み | オフラインのテスト。実サイト1件で、最新の構成の実撮影・初期Baseline作成・タスクによる予定の比較を確認（2026-11-26、5.2） |
| HTTP監視（ステータス・応答時間・TLS証明書の期限） | 実装済み・**外部通信は無効** | オフラインのテスト・隔離fixture 18/18・本人管理サイト（workers.dev）で限定試験4回を実測（2026-11-26・すべて HTTP 200・隔離違反なし。RELEASE_CANDIDATE.md 5.2） |
| 障害・復旧・判定不能の検知、TLS期限の警告（14日・3日・期限切れ） | 実装済み | オフラインのテスト |
| アプリ内通知 | 実装済み | オフラインのテスト・GUIの通し確認（代役の撮影） |
| メール通知（SMTP） | 実装済み・**送信は無効に戻してある** | 模擬送信のテスト、実送信1通（Gmail・STARTTLS、USERが受信を確認、2026-11-27） |
| 複数サイト（20まで）・複数ページ（1サイト5まで） | 実装済み | オフラインのテスト。追加ページはHTTP監視だけ（画像の撮影はトップページだけ） |
| 所有権の確認 | workers.dev（Cloudflare）・DNSのTXT | workers.devは実環境で使用済み。DNSのTXTは**照会が無効**（オフラインのテストだけ） |
| Windowsのバックグラウンド監視（タスク スケジューラ） | 実装済み | 実環境でタスクを登録し、画像1回・HTTP2回の予定の検査と解除を確認（2026-11-26、5.2） |
| バックアップ・復元 | 実装済み | オフラインのテスト |
| 導入環境の確認（`tools/doctor.py`・画面の「導入環境の確認」） | 実装済み | このPCで実行（読み取りだけ） |
| 日本語UI | 実装済み | HTTPの理由コードも日本語で表示（RC1で追加） |

## 2. RC1での修正

- **HTTP隔離の判定**：許可したアドレスに接続した結果が時間切れのとき、判定不能（UNKNOWN）にしていた不具合を修正しました。Broker・Proxy・OSの規則がすべて正常で、Proxyが許可された1つのIPに1回だけ接続して失敗した場合だけを**障害**（`CONNECT_TIMEOUT`／`CONNECT_FAILED`）とし、隔離の仕組みの異常や証拠の不足は従来どおり**判定不能**です（`src/noxiworks/http_isolation.py` の `connect_failure`）。
- **Proxyの接続期限**を5秒に短縮しました（Workerの8秒より先に、Proxyが結果を決めて記録する。以前は同じ8秒で競合していた）。
- **TLS失敗の記録**：Workerが失敗の種類を、fixtureの相手が自分側のエラーを記録するようにしました（判定には使わない）。run-03で1回だけ起きた `server_error` の TLS_FAILED の原因は **UNKNOWN** です（単独の再実行と run-04 ではPASS）。
- **HTTPの理由の日本語表示**：画面の最終観測・履歴と、通知の本文に、理由コードの日本語訳を出します（コードはそのまま記録します）。
- **文書**：所有権の確認方法（DNSのTXTに対応済み・照会は無効）の記述の誤り、`REAL_CAPTURE.md` などで壊れていたパス表記、README・利用ガイドの古い状態の記述を直しました。
- **全サイトの状態のHOME**で、ヘッダーが「最後の監視 未取得」「監視結果は未取得です」のままだった誤表示を修正しました（各サイトの実際の観測の最新時刻を表示）。
- テストの実行ツールが、テストの出力と結果行が同じ行になると結果を読めなかった問題を修正しました。GUIの通し確認の台本を、現在の画面（準備6項目・「正常に監視中」）に合わせました。
- 画像撮影の許可に固定されたファイル（`IDENTITY_FILES`）と撮影バンドルは**変更していません**（署名済みの撮影許可はそのまま使えます）。

## 3. 外部通信のスイッチ（すべて無効のまま）

| スイッチ | 場所 | 有効にする条件 |
|---|---|---|
| `HTTP_EXTERNAL_ENABLED = False` | `src/noxiworks/http_monitor.py` | USERの承認＋HTTPの許可への署名（[HTTP_BOUNDARY.md](HTTP_BOUNDARY.md) のM3） |
| `NOTIFY_EXTERNAL_ENABLED = False` | `src/noxiworks/smtp_notify.py` | USERの承認＋資格情報の登録＋通知の許可への署名（[NOTIFICATIONS.md](NOTIFICATIONS.md)） |
| `OWNERSHIP_DNS_ENABLED = False` | `tools/dns_ownership.py` | USERの承認（実DNSの照会） |

## 4. 導入・起動・停止

1. Python 3.15・OpenSSH（Windows標準）・Docker Desktop（実撮影とHTTP検査に必要）を用意します。固定イメージ `sha256:9c88112b…` が必要です（[INSTALL.md](INSTALL.md) の2）。
2. `SiteProof.cmd`（ダブルクリック）。データの保存先は `SiteProof.cmd --data D:\SiteProofData --remember` で固定できます。
3. 足りないものの確認：`py -3.15 -B tools/doctor.py --data <データ>`（読み取りだけ）。
4. 停止：画面の各「停止」ボタン → `SiteProof.cmd` のウィンドウを閉じる（`Ctrl+C`）。バックグラウンド監視を登録していれば、画面の「解除」で外します。
5. バックアップ：`py -3.15 -B tools/backup_data.py --data <データ> --dest <保存先>`。復元は**新しいフォルダ**へ：`py -3.15 -B tools/restore_backup.py --backup <バックアップ> --dest <新しいフォルダ>`（復元した側の監視とメールはすべて停止した状態で始まります）。

## 5. USERによる受入確認の手順（実環境）

A〜Cは外部通信なしで行えます。D以降は、実サイト・実DNS・実メール・Windowsタスクを使うため、**それぞれUSERの承認と操作が必要**です。結果は PASS・FAIL・UNKNOWN・NOT_RUN で記録してください。

| # | 確認 | 手順 | 合格の目安 | 結果（2026-11-26） |
|---|---|---|---|---|
| A1 | 起動 | 新しいデータフォルダで `SiteProof.cmd --data <新しいフォルダ>` | HOMEが開き、「はじめの手順」が出る | PASS（実際のアプリ・`SiteProof.cmd`・新しいフォルダ） |
| A2 | 導入環境 | 画面の「導入環境の確認」、または `tools/doctor.py` | Python・OpenSSH・Docker・固定イメージがOK | PASS（画面の「導入環境の確認」：4項目OK） |
| A3 | 登録 | 「サイトを追加」で本人管理サイトを登録、「ページを追加」で2ページ目 | 実サイトへのアクセスなし。準備の不足が一覧で出る | PASS（準備 1/6・不足6行。最初の検査は REAL_NOT_READY で止まり撮影0件。2ページ目を追加） |
| A4 | 複数サイト | 2つ目のサイトを登録 | HOMEが「全サイトの状態」になり、設定・履歴が混ざらない | PASS（2サイトの一覧。サイトの画面に別サイトの設定なし） |
| B1 | バックアップ | 画面の「保存容量・整理・バックアップ」→バックアップ | 照合に合格したと表示 | PASS（33ファイル・確認済み） |
| B2 | 復元 | `tools/restore_backup.py` で新しいフォルダへ → そのフォルダで起動 | 監視がすべて停止した状態で、同じサイトが見える | PASS（33ファイル照合済み。2サイト・2ページ、監視はすべて停止・理由 RESTORED を画面に表示） |
| C1 | 合成デモ | `http://127.0.0.1:8765/demo/` で3種類の検査 | 変更なし・変更あり・判定不能 | PASS（変更なし・変更あり・判定不能） |
| D1 | 画像監視（最新構成） | 監視許可に署名（`--max-runs 1 --manual-only` 推奨）→「今すぐ再検査」 | 撮影→Baseline自動作成→再検査で「変更なし」 | PASS（2026-11-26：手動の実撮影1回 → 初期Baselineを自動作成。下の5.2） |
| D2 | HTTP監視（M3） | `tools/http_grant.py --trial` に署名 → `HTTP_EXTERNAL_ENABLED = True` → 手動検査（最大5回）→ `False` に戻す | 正常の観測。`ISOLATION_VIOLATION`・片付け残りがない。回数が台帳と一致 | PASS（限定試験：手動1回 HTTP 200、60秒以内の再実行は通信せずに拒否・回数に数えない。5.2） |
| D3 | DNSのTXTで所有権 | `OWNERSHIP_DNS_ENABLED` を承認のうえ有効化 → 発行 → DNSに登録 → 確認 | 「確認済み」になる | NOT_RUN（対象の独自ドメインのサイトが決まるまで保留） |
| D4 | メール | 資格情報の登録・署名・有効化 → テスト通知 | 受信できる（「送信受付済み」は受信の保証ではない） | PASS（2026-11-27：テスト通知1通をGmailへ送信・送信受付・**USER本人が受信を確認**。5.3） |
| D5 | バックグラウンド | 画面の「アプリを閉じても監視する」→ アプリを閉じて30分待つ → 再起動 | 閉じている間の検査が履歴にある。「解除」でタスクが消える | PASS（画像のタスクが予定の撮影1回・HTTPのタスクが2回。解除済み。5.2） |
| D6 | 障害・復旧 | （任意）本人管理サイトを一時的に503にする | 「障害を検知」→ 戻すと「復旧」、通知が1回ずつ | 省略候補・NOT_RUN（障害・復旧の判定は、隔離fixtureの server_error〔FAIL / HTTP_503〕とオフラインのテストで確認済み。実サイトでは未確認として記録） |

A〜Cは、実際のアプリ（代役なし）を新しいデータフォルダで起動し、ヘッドレスFirefoxで画面を操作して確認しました（`tests/ui/acceptance_ac.py`。
登録したのは `*.example.com` の仮のホストだけで、所有権の確認と署名付きの許可がないため、アプリはそのホストに一切通信しません）。
同じ確認は `SiteProof.cmd --data <新しいフォルダ> --no-browser --port 8797` を起動したうえで
`py -3.15 -B tests/ui/acceptance_ac.py --url http://127.0.0.1:8797/ --data <そのフォルダ> --out <新しいフォルダ>` で繰り返せます。

### 5.1 D1〜D6：USERが行う操作と承認（まとめ）

**前提**：Docker Desktopを起動しておく。作業用のデータフォルダは、以前の実環境確認で使ったもの（`<実環境データ>` = `.local\real-e2e-bg-01`、
サイト `hello-my-saitama.kmr8oji.workers.dev`。所有権の確認記録と信頼する鍵が残っている）を使うと、Cloudflareへの確認をやり直さずに済みます。
Sprint 03で `permit.py` が変わったため、**以前の許可は使えません（署名し直しが必要）**。

**承認していただく事項（項目ごとに個別。まとめて承認しても、実行は1項目ずつ）**

| # | 承認事項 | 通信・変更の範囲 | 戻し方 |
|---|---|---|---|
| D1 | 実鍵（`~\.ssh\siteproof_permit`）での画像監視の許可への署名と、本人管理サイト1件への実撮影1回 | `hello-my-saitama…workers.dev` のトップページだけ（DNS1件・IPv4の443番1つ） | 許可は1回で使い切り。自動監視は始まらない |
| D2 | HTTP監視の限定試験の許可への署名と、`HTTP_EXTERNAL_ENABLED = True` への一時変更（ソースの1行） | 同じホストの `/` に最大5回（60秒以上あける） | 試験後に `False` に戻す（台帳と `http-audit.jsonl` を確認） |
| D3 | `OWNERSHIP_DNS_ENABLED = True` への一時変更と、TXTレコード1件の照会 | `_siteproof-challenge.<ホスト>` のTXTだけ | 確認後に `False` に戻す。**workers.devではTXTを置けないため、DNSを管理している独自ドメインのサイトが必要**（ない場合は NOT_RUN のまま） |
| D4 | Windowsの資格情報マネージャーへのSMTPの資格情報の登録、通知の許可への署名、`NOTIFY_EXTERNAL_ENABLED = True` への一時変更 | 許可に書いた1つのメールサーバーへ、テスト通知1通 | `False` に戻す。資格情報は自分で削除できる |
| D5 | Windowsのタスク スケジューラへのタスク登録（このサイト・画像の1つ） | D1と同じ範囲。許可の回数の中だけ | 画面の「解除」（または `background_monitor.py remove`） |
| D6 | （任意）自分のサイトを一時的に503にする | 自分のサイトの変更 | 元に戻す |

**手順**（`<実環境データ>` は上のフォルダ。コマンドは作業フォルダ `siteproof-portfolio-02` で実行）

1. **D1 画像監視**（あなたのウィンドウで。鍵のパスフレーズを入力）
   `py -3.15 -B tools/setup_monitoring.py --data <実環境データ> --days 1 --max-runs 1 --manual-only`
   → `SiteProof.cmd --data <実環境データ>` → そのサイトの画面で **「今すぐ再検査」**。
   合格：撮影が完了し、初期Baselineが「自動作成（未確認）」で作られる。比較の「変更なし」まで見る場合は `--max-runs 2` にして、もう1回「今すぐ再検査」。
2. **D2 HTTP監視（限定試験）**
   `py -3.15 -B tools/http_grant.py --data <実環境データ> --trial --hours 2 --max-requests 5`
   → `src/noxiworks/http_monitor.py` の `HTTP_EXTERNAL_ENABLED = True`（Opusに変更を依頼してもよい）→ アプリを起動し直し、**「今すぐ検査」** を数回（60秒以内の2回目は通信せずに拒否されることも確認）→ `False` に戻す。
   合格：状態「正常」・HTTP 200・TLS期限の表示。`ISOLATION_VIOLATION` なし。`http-audit.jsonl` の行数と台帳（`trust\http-ledger\`）の回数が一致。
3. **D3 DNSのTXT**（独自ドメインのサイトがある場合だけ）
   アプリで登録 → 画面の「確認用の記録を発行」→ 表示された名前・値をDNSに登録 → `OWNERSHIP_DNS_ENABLED = True` → `py -3.15 -B tools/dns_ownership.py check --data <データ> --site <site id>` → `False` に戻す。
   合格：画面の所有権が「確認済み」。
4. **D4 メール**
   資格情報：`cmdkey /generic:SiteProof-SMTP-main /user:<SMTPのユーザー> /pass`（パスワードは入力を求められる）
   → `py -3.15 -B tools/notify_grant.py --data <実環境データ> --host <SMTPサーバー> --port 587 --sender <送信元> --recipient <受信先> --credential-ref SiteProof-SMTP-main --days 7`
   → `NOTIFY_EXTERNAL_ENABLED = True` → 画面の「全サイト共通」と「このサイト」のスイッチ → **テスト通知** → `False` に戻す。
   合格：受信できる（画面の「送信受付済み」だけでは受信の証明にならない）。
5. **D5 バックグラウンド**（D1の後、回数に余裕のある許可で）
   `py -3.15 -B tools/setup_monitoring.py --data <実環境データ> --days 1 --max-runs 4`（自動監視あり）→ 画面の間隔を15分 → **「アプリを閉じても監視する」** → アプリを閉じて30分以上待つ → 起動して履歴を確認 → **「解除」**。
   合格：閉じている間の検査が履歴にあり、解除後 `py -3.15 -B tools/background_monitor.py status --data <実環境データ>` にタスクが残っていない。
6. **D6 障害・復旧**（任意。D2の限定試験中に行う）
   サイトを一時的に503にして「今すぐ検査」→ 戻して「今すぐ検査」。合格：「障害を検知」→「復旧」、アプリ内通知がそれぞれ1回。
   行わない場合は、隔離fixtureの `server_error`（FAIL / HTTP_503）とオフラインのテストで代えます（実環境では未確認として記録）。

### 5.2 実環境受入確認の結果（2026-11-26・D1・D2・D5）

対象：`hello-my-saitama.kmr8oji.workers.dev` のトップページだけ（本人管理・所有権は CLOUDFLARE_ACCOUNT_CONTROL の既存記録を再利用）。データ：`.local\real-e2e-bg-01`。
署名：画像監視の許可（1日・最大2回、`--manual-only`）とHTTPの限定試験の許可（2時間・最大5回・60秒以上）を、USERが鍵 `siteproof_permit_cp2` で署名。

| 時刻（UTC） | 何が | 結果 |
|---|---|---|
| 13:44〜13:47 | D1 画面の「今すぐ再検査」（実撮影1回目） | **初期Baselineを自動作成**。Desktop・Mobile とも撮影完了・安定（STABLE）。コンテナの残りなし |
| 13:55 | D2 画面の「今すぐ検査」（HTTP 1回目） | **正常・HTTP 200**・313 ms・TLS期限 2027-02-19。許可したIP 1つだけに1回接続、接続先の一致、遮断なし、規則は閉じた状態に一致、片付け残りなし |
| 13:56 | 「HTTP監視を開始」→ アプリの予定の検査（2回目） | 正常・HTTP 200 |
| 13:56 | 60秒以内に「今すぐ検査」 | **通信せずに拒否**（前回から60秒以上必要）。台帳は増えない |
| 14:05 | D5 HTTPのWindowsタスク（3回目） | 正常・HTTP 200（タスクの終了コード 0） |
| 14:15〜14:19 | D5 画像のWindowsタスク（実撮影2回目＝予定の検査） | 新しいBaselineと比較：**画像の変更なし（0px）**・安定。総合は「判定不能」（外部リソースの遮断。既知の制限）。アプリ内通知1件 |
| 14:20 | D5 HTTPのWindowsタスク（4回目） | 正常・HTTP 200 |
| 14:20〜14:22 | 撤収 | タスク2件を解除、「このサイトの監視をすべて停止」、`HTTP_EXTERNAL_ENABLED = False` に戻した |

回数：画像 2/2（使い切り。画面は「許可回数を使い切って停止」）、HTTP 4/5（台帳4行・監査4行・履歴4行が一致）。`ISOLATION_VIOLATION`・片付けの残り・許可にない通信先・回数の不一致は **なし**。
撮影1回ごとに証拠のDocker volumeが1つ残ります（撮影の仕組みの仕様。削除はしていません）。証拠：`siteproof-private-backups\rc1-real-acceptance-20261126`、実データの事後バックアップ `siteproof-backup-20261126T143249Z`（892ファイル・照合済み）。

**Baselineの移動・作り直しと保全の記録**（2026-11-27に照合）
- 以前のBaseline（許可 `cp2-bg-1`、2026-11-21作成、登録簿の `export-sha256.json` = `ec727b47…`）は、`real\registry` → `real\registry-history\cp2-bg-1` へ**移動**（削除なし）。作成記録 `registry-origin.json`（cp2-bg-1）は `real\baseline-archive\cp2-bg-1\` に保管（`README.txt` に経緯）。
- 照合：移動後の13ファイルのうち12ファイルは、作業前のバックアップ `siteproof-backup-20261126T133059Z` とSHA-256が一致。残る `workspace\siteproof.sqlite` は、バックアップ側がSQLiteのバックアップ機能で取った写し（ページ配置が違う）のためバイトは異なるが、**論理内容（全テーブルのダンプのSHA-256）は一致**。移動後のファイルは元のファイルそのもので、自身の `export-sha256.json` と一致（アプリの照合に合格）。
- 過去の撮影：2026-11-21 の2件（`-00-real`・`-01-real`）は残っており、以前のBaselineとの比較として引き続き表示される。2026-11-26 の2件（`-02-real` 初期Baseline作成・`-03-real` 予定の比較）を追加。
- 新しいBaseline：許可 `site-5c09908c-20261126T134214Z` の初期Baseline（`export-sha256.json` = `a5b4c471…`、状態は「自動作成・未確認」。USERの正式承認は未実施）。
- 以前の許可（`permit.json.disabled`）は残している。事後のバックアップ `siteproof-backup-20261126T143249Z`（892ファイル・照合済み）。

**この確認で見つけて直した不具合**（いずれもテストを追加）
- **起動時の停止**：保存済みの撮影1件が、その比較に使ったBaselineと照合できないと、アプリが起動せずに終了していた（1サイトのとき）。ページの作成に失敗しても起動し、そのサイトの画面に理由を表示するようにした（`src/noxiworks/app.py`）。
- **予定の前倒し**：監視中に「今すぐ検査」を早く押して拒否されると、次の予定の検査が「許可の最短間隔（60秒）後」に前倒しされていた（実際に、予定より14分早い検査が入るところだったため、アプリを止めて回数を守った）。拒否は予定を遅らせるだけにした（`src/noxiworks/http_monitor.py`）。

**運用上の注意（今回わかったこと）**
- 以前の許可を外した（`.disabled`）状態で新しい許可に署名すると、以前のBaselineは引き継がれず、撮影は「Baselineが別の監視許可で作成されています」で止まります（安全側）。今回は以前のBaselineを `real\registry-history\cp2-bg-1` へ移し（削除なし）、新しい許可で初期Baselineを作り直しました。引き継ぐ場合は、以前の許可を `permit.json` に戻してから `setup_monitoring.py` で更新してください。
- 実撮影の許可は `targets.json`（検査間隔を含む）を固定します。**画面で画像監視の間隔を変えると、許可と一致しなくなり撮影が止まります**（署名し直しが必要）。

### 5.3 D4 メール（SMTP）の実送信：安全条件とUSERの最小の操作

**安全条件**（すべて満たすときだけ送る。実装済み・オフラインで検証済み）
- メールの経路は、HTTP検査のような**OSでの隔離ではなく、アプリの中の確認**です：署名で固定した1つのサーバー（ホスト・ポート465=TLS／587=STARTTLS）だけ、DNSの回答の全件検証（私設・特殊なアドレスは拒否）と接続先の一致、STARTTLSが無ければログインも送信もしない。この差を承知のうえで承認してください。
- 送信元・宛先（1〜5件）・期間・通数の上限は、あなたの鍵で署名した通知の許可そのもの。画面からは変えられない。
- 接続の**前に**台帳へ1行記録し、合計・24時間の上限を超えない。結果が不明なものは再送しない。テスト送信は画面で押したときだけ・1分に1回。
- 資格情報は送る瞬間だけWindowsの資格情報マネージャーから読み、ファイル・ログに残さない。SiteProofは資格情報を書き込まない。
- 試験の間、画像監視・HTTP監視・バックグラウンドのタスクは止めておく（送るのはテスト通知1通だけ）。

**USERの最小の操作**（推奨：送信専用のアカウントか、アプリ専用パスワード。普段のパスワードは使わない）
1. 資格情報の登録（あなたのウィンドウで。パスワードは入力を求められる）：
   `cmdkey /generic:SiteProof-SMTP-main /user:<SMTPのユーザー名> /pass`
2. 通知の許可への署名（試験用の最小の範囲）：
   `py -3.15 -B tools/notify_grant.py --data .local\real-e2e-bg-01 --host <SMTPサーバー> --port 587 --sender <送信元> --recipient <自分の受信先> --credential-ref SiteProof-SMTP-main --days 1 --max-total 3 --max-per-day 3 --key $HOME\.ssh\siteproof_permit_cp2`
3. Opusへ「送信を承認」と伝える → Opusが `NOTIFY_EXTERNAL_ENABLED = True` に一時変更し、画面で「全サイト共通」と「このサイト」をオン → **テスト通知1通** → 両方オフ・`False` に戻す。
4. 受信を確認してOpusに伝える（画面の「送信受付済み」は受信の証明ではない）。不要なら `cmdkey /delete:SiteProof-SMTP-main` で資格情報を削除。

合格：テスト通知1通を受信。台帳1行・`deliveries.jsonl` に ATTEMPT と ACCEPTED。中止：REFUSED（許可・資格情報・宛先）、認証の失敗、上限超過。どれも再試行しない。

**結果（2026-11-27）：PASS。**
- 1回目（許可 `notify-20261127T012545Z`、合計1通）：**失敗**（TEMPORARY / DISCONNECTED）。Gmailがログインを拒否して接続を切ったところ、Python標準の `smtplib.login` が次の認証方式を試して「接続切れ」になり、本当の理由（ログインの拒否）が隠れていた。メールは送られていない。再試行なし。
- **不具合として修正**：認証方式を1つだけ使う（PLAIN、無ければLOGIN）。拒否は `AUTH_FAILED`（再試行しない）になる。以前は「一時的な失敗」として、通常の通知では5分後・30分後にログインを繰り返すところだった（`src/noxiworks/smtp_notify.py`、テスト追加）。
- USERがアプリ専用パスワードで資格情報を登録し直し、新しい許可（`notify-20261127T013228Z`、合計1通）に署名。
- 2回目：**送信受付（ACCEPTED / SMTP 250）**、件名「[SiteProof] テスト送信」。**USER本人が受信を確認。**
- 通常の自動通知（全サイト共通・このサイト）は一度も有効にしていない。送信のたびに `NOTIFY_EXTERNAL_ENABLED` を直後に `False` に戻した。各許可の台帳は1行ずつ（上限どおり）。

**中止の条件**：`ISOLATION_VIOLATION`、片付けの残り（`left_behind`）、許可にない通信先、回数の不一致。どれかが出たら、スイッチを `False` に戻して止め、結果をOpusに渡してください。

## 6. 既知の制限（RC1では対応しない）

- 実撮影の許可の署名後に画像監視の間隔を変えると、許可と一致しなくなる（署名し直しが必要）。
- 追加ページの画像撮影（画像はトップページだけ）。サイト・ページの変更・削除。
- 総合品質は常に UNKNOWN（撮影プロファイルは未認証）。外部リソースが遮断されたページの比較は判定不能。
- HTTP監視はIPv4だけ・HTTPSだけ・リダイレクトは追わない。Webhookは未実装。
- 所有権の確認は workers.dev と DNSのTXTだけ（確認用ファイルは未対応）。
- 実サイトでの撮影・隔離は、作者の本人管理サイト1件でだけ確認（一般のサイトは未検証）。
- 固定イメージを別のPCへ移す手順は未実測（IDが変わる可能性がある）。`Dockerfile` からの作り直しは同じIDにならない。
- バックグラウンド監視の実登録、日本語パスでのDocker撮影、macOSは未検証。
- 正式な LOCAL-ISOLATION の合格ではありません（Dockerとカーネル、管理者権限を持つローカルの攻撃者は対象外）。
- AWS-B Lite は期限つきのTrial（停止期限 2026-11-27 12:00 JST）。独立Stopperは未適用。

## 7. テストと実測の記録

| 記録 | 結果 |
|---|---|
| HTTP隔離fixture（`tests/runtime/validate_http_iso.py`） | run-02：14 PASS・1 FAIL・3 NOT_RUN → run-03：2 PASS・1 FAIL（server_error、原因UNKNOWN）・15 NOT_RUN → **run-04：18/18 PASS（GREEN）** |
| オフラインのテスト一式（`tools/run_offline_tests.py`） | 下の「RC1のテスト結果」 |

### RC1のテスト結果

- 全体（125モジュール、`.local/rc1-offline-tests/summary.json`）：実行 2,506・合格 2,498。合格しなかったものの内訳：
  - TEMPがC:のときだけ失敗する3モジュール（`tests/test_noxiworks.py`・`tests/aws_b/test_live_fixture.py`・`test_live_generator.py`）→ テストのプロセス内だけTEMPをD:にして再実行し、16/16・3/3・3/3 合格（Windows全体の設定は変更していない）。
  - `tests/ui/test_http_monitor.py`：テストは33/33合格だったが、テストの出力と結果行が同じ行になり、実行ツールが読めなかった → 実行ツールを修正し、33/33 合格を確認。
  - `tests/aws_c/test_worker_entry.py` の1件：未コミットの変更があると失敗する確認（コミット後に解消）。**これだけが残る失敗**です。
- 修正後の再確認：`tests/ui` の44モジュール 831/831 合格。
- GUIの通し確認（実際のアプリ・新しいデータフォルダ・ヘッドレスFirefox。撮影・セットアップの窓・タスク登録は代役で、外部通信なし）：
  - `tests/ui/firefox_gui.py`：14/14（登録→初回セットアップ→自動の初回撮影とBaseline→再検査→REVIEW・ACTIVITY→バックグラウンドの登録ボタン）。`.local/rc1-gui-03`
  - 複数サイト・ページ追加・DNSのTXTの発行・HTTPパネル：12/12。`.local/rc1-gui-multi-02`
- バックアップ→照合→復元（GUIの確認で作ったデータ）：116ファイル、不足・不一致・余分 0、復元した側の監視3件はすべて停止（RESTORED）。
- 導入環境の確認（`tools/doctor.py`、このPC）：Python・OpenSSH・Docker CLI・Docker Desktop・固定イメージ すべてOK。

## 8. 正式リリースまで

| 項目 | 状態 |
|---|---|
| 中核機能（画像監視・HTTP監視・バックグラウンド） | 実環境で受入確認済み（D1・D2・D5） |
| メールの実送信（D4） | PASS（テスト通知1通・受信確認済み） |
| 独自ドメインのDNS確認（D3） | 対象サイトが決まるまでNOT_RUN |
| 意図的な503（D6） | 省略候補 |
| Gitへの統合・正本同期・Project添付 | 準備済み・USERの承認待ち（下の9と、引き継ぎパッケージ） |

日常の運用は [USER_GUIDE.md](USER_GUIDE.md) の「13. 日常の運用」です。

## 9. Gitへの統合

- RC1は、このファイルを含む**単一のチェックポイントのコミット**として `siteproof/portfolio-02` に保存しました（作者はGitHubのnoreplyアドレス）。**push・mainへのmerge・外部公開は行っていません**。
- ライセンスは Apache License 2.0（`LICENSE`）、第三者の素材の帰属は `NOTICE` のとおりです。
- 永続バックアップ：`<非公開のバックアップフォルダ>\practical-rc1-final-*`（最新のもの。`MANIFEST.json` に全ファイルのSHA-256と照合結果、`NOTES.txt` に復元方法）。分割コミットの案は同じフォルダの `rc1-git-plan.md`。
- コミットに含めないもの：`.local/`（実測の証拠・実サイトの撮影画像を含む。`.gitignore` 済み）、`docs/aws_portfolio/AWS_B_IAM_20261112/`（実アカウントID。`.gitignore` 済み）、`__pycache__`。
- 秘密情報の確認：コミット候補に、鍵・トークン・実アカウントID・個人のメールアドレス・個人のパスは見つかっていません（テスト用の合成値だけ）。
- `tests/aws_c/test_worker_entry.py` の `test_existing_launcher_file_is_unmodified` は、`src/runtime` などに未コミットの変更があると失敗します（RC1のコミット後は19/19で合格）。

**統合の手順（準備済み・USERの承認後に実行）**
1. 実環境受入確認の修正と記録（5ファイル）を、RC1の上に1つのコミットとして追加する（作者はnoreplyアドレス）。
2. `main` へ統合：このリポジトリの `main`（`b52bd38`）は `siteproof/portfolio-02` の祖先で、`main` 側に新しいコミットはない。**fast-forward**（`git merge --ff-only siteproof/portfolio-02`）で統合でき、マージコミットも衝突も生じない。
3. このリポジトリにはリモートがない（pushの先がない）。公開リポジトリ `github.com/kmr8oji-hash/siteproof` は、別に作る公開用の写し（秘密情報・実測証拠・アカウント情報を除いたもの）から更新する。公開の更新は、公開用の写しの作成・確認とUSERの承認を経て行う。
