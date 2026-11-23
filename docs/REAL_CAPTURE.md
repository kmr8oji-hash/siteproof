# 実サイトの自動監視（署名付き監視許可）

SiteProofが実サイトを撮影するのは、**利用者が自分の鍵で署名した監視許可**が、登録したサイトと今の撮影構成に一致するときだけです。許可の範囲（対象・期間・回数）の中では、初回撮影 → Baseline自動作成 → 同じBaselineとの定期比較が、追加の承認なしで続きます。許可の範囲を外れると、撮影ハーネスを起動せずに止まります。

実装：`src/noxiworks/permit.py`（許可の検証）、`src/noxiworks/real_capture.py`（アダプター）、`src/noxiworks/site_monitor.py`（自動監視）、`tests/runtime/validate_s3t.py` ほか（撮影ハーネスの許可モード）。

> 実サイトでの確認は、利用者が自分のサイト・自分の許可で、承認を受けて行います（確認の計画書は公開していません）。
>
> **2026-11-21：本人管理サイト1件（Hello, My Saitama、workers.dev）で実サイトE2Eを実施しました。** 署名付き許可（CLOUDFLARE_ACCOUNT_CONTROL）→ GATE-A〜C → 実撮影（Desktop・Mobile、STABLE）→ Baselineの自動作成 → 2回目の撮影とBaselineとの比較（変化ピクセル 0）まで、許可モードのハーネスで動作しました。比較の判定は「判定不能」（このサイトのトップページが外部の天気・地図に接続し、それを遮断したため。仕様どおり）。実測で見つかった不具合（ハーネスの起動方法、許可モードでの安定性の照合、Baseline作成時の安定ショットの判定、大きなページの画像サイズ上限）は修正済みです。

## 使い方（初回セットアップ・バックグラウンド監視）

**起動**：プロジェクトフォルダの `SiteProof.cmd` をダブルクリック（Python 3.12以降を確認し、なければ案内を表示。すでに起動中なら画面を開くだけ）。

**画面から（通常）**：アプリでサイトを登録 → HOMEの「実サイト監視の準備」で **初回セットアップを開始**（workers.devは自動でCloudflareの確認、それ以外は確認方法を選んで「自分で確認しました」にチェック）→ 別ウィンドウで許可の内容を確認し「y」で署名 → 画面を更新。必要なら **Docker Desktopを起動**・**アプリを閉じても監視する** のボタン。
セットアップ中・完了・失敗はHOMEに表示され、完了するとHOMEが自動で更新されます。監視許可の期限と残り回数を表示し、残り7日以下または5回以下で警告します。更新は同じパネルの **監視設定を更新**（前回の所有権の確認記録を再利用でき、Baselineは署名付きで引き継ぎます）。
アプリはボタンに応じて既存のツールを別プロセスで起動するだけです。鍵・パスフレーズ・署名の確認はアプリを通らず、利用者のウィンドウで行います。

結果の表示：**画像比較**（Baselineとのピクセル比較そのもの：変更なし／変更あり／未実施）と、**検査品質**（その比較を判定に使えるか：問題なし／判定不能と理由）を分けて表示します。例：外部リソースが遮断されたページは「画像比較：変更なし（0px）／検査品質：判定不能（撮影に必要な通信が遮断されました…）」で、全体の判定は判定不能のままです。

**コマンドから（同じ処理）**：

```powershell
# 1. 初回セットアップ（利用者が自分のシェルで1回。登録・鍵・信頼する鍵・所有権の確認・許可の署名・準備の確認をまとめて行う）
py -3.15 -B tools/setup_monitoring.py --data <データ> --url https://my-worker.my-sub.workers.dev/ --ownership cloudflare --days 30
#    workers.dev 以外：--ownership well-known-file --verified-at <自分で確認したUTC時刻>（または dns-txt）
#    アプリで登録済みなら --url は不要。署名の前に内容を表示して確認を求める（ssh-keygen が鍵のパスフレーズを尋ねる）
# 2. 監視：アプリを起動する（開いている間は自動監視）か、アプリを閉じていても監視するタスクを登録する
py -3.15 -B tools/background_monitor.py install --data <データ>     # 15分ごとに「予定の検査があれば1回」。status / remove もある
# 3. 更新：期限が近づいたら、同じセットアップをもう一度（--ownership を省くと既存の証拠を使う。Baselineは署名付きで引き継ぐ）
```

- `setup_monitoring.py` は利用者の鍵で署名します。アプリ（`src/`）は鍵を持たず、署名もしません（認可の境界は変わりません）。
- 撮影回数の上限は、期間と検査間隔から自動で決めます（予定の回数＋手動の再検査・失敗の分）。
- `background_monitor.py tick` は、予定の検査があるときだけ動きます。Docker Desktopが応答しないときは起動を待ってから実行します。

## 署名の仕組み

- 署名と検証はOpenSSH（`ssh-keygen -Y sign` / `-Y verify`、Ed25519のSSHSIG、名前空間 `siteproof-monitoring-permit`）で行います。SiteProofは暗号処理を実装していません。検証には、OSに付属する `ssh-keygen`（Windows：`C:\Windows\System32\OpenSSH`、macOS・Linux：`/usr/bin`）を優先して使います（PATHに置かれた別の `ssh-keygen` で検証を偽装されないため）。
- 信頼する公開鍵：`<データ>\trust\allowed_signers`（OpenSSHの allowed_signers 形式）。利用者が置きます。
- 監視許可：`<データ>\sites\<site>\real\permit.json` と `permit.json.sig`。利用者が作成・署名して置きます。
- **SiteProofは許可を発行できません。** 秘密鍵を持たず、署名する処理もありません。許可や信頼する鍵を書き込むAPIもありません（テストで確認しています）。

```powershell
# 利用者が行う（SiteProofは行わない）
ssh-keygen -t ed25519 -f $HOME\.ssh\siteproof_permit           # 署名用の鍵（初回のみ）
# trust\allowed_signers の1行：site-owner namespaces="siteproof-monitoring-permit" ssh-ed25519 AAAA...
ssh-keygen -Y sign -n siteproof-monitoring-permit -f $HOME\.ssh\siteproof_permit permit.json   # permit.json.sig ができる
```

## 監視許可の内容（すべて署名の対象）

```json
{
  "schema": "siteproof.monitoring-permit.v1",
  "permit_id": "my-site-2026-11",
  "issued_by": "site-owner",
  "issued_at": "2026-11-21T00:00:00Z",
  "site":   {"site_id": "site-xxxxxxxx", "origin": "https://example.com", "host": "example.com"},
  "target": {"target_id": "site-xxxxxxxx-p1", "url": "https://example.com/"},
  "target_files": {"targets.json": "<SHA-256>", "capture_plan.json": "<SHA-256>"},
  "valid_from": "2026-11-21T00:00:00Z",
  "valid_until": "2026-12-21T00:00:00Z",
  "max_runs": 720,
  "ownership": {"method": "well-known-file", "verified_at": "2026-11-20T12:00:00Z"},
  "identity": {"files": {"<IDENTITY_FILES の各ファイル>": "<SHA-256>"}, "image_id": "sha256:...", "bundle_manifest_sha256": "..."},
  "baseline_policy": "AUTO_INITIAL_THEN_COMPARE"
}
```

- `target_files` は、そのサイトの `targets.json` と `capture_plan.json` のハッシュです。**設定ファイルのURLだけを書き換えても、ハッシュが変わるため撮影しません。** 新しい対象には新しい署名が必要です。
- `identity` は撮影ハーネスの `--expect` になります。撮影ハーネス・Worker・通信ブローカー・reaper・通信ルール・許可の検証コード・対象設定の読み込みコードを固定します。ハーネスは、固定したファイル一覧が自分の `IDENTITY_FILES` と完全に一致することを要求します。
- `ownership`：所有権の確認方法と確認日時（下の「所有権の確認方法」）。
- `baseline_policy`：`AUTO_INITIAL_THEN_COMPARE` なら、許可の範囲内の最初の安定した撮影からBaselineを作り、以後はそのBaselineと比較します。`NONE` ならBaselineを作らず、撮影もしません。

## 所有権の確認方法

| 方法 | 使える対象 | 許可に記録するもの |
|---|---|---|
| `well-known-file` | すべて | 方法・確認日時（利用者が自分のサイトに確認用ファイルを置いて確認する） |
| `dns-txt` | すべて | 方法・確認日時（利用者がDNSのTXTレコードで確認する） |
| `CLOUDFLARE_ACCOUNT_CONTROL` | **Cloudflare Workersの `<Worker名>.<サブドメイン>.workers.dev` だけ**（カスタムドメインは不可） | 方法・確認日時・アカウントIDのSHA-256・Worker名・サブドメイン・証拠ファイルのIDとSHA-256 |

`CLOUDFLARE_ACCOUNT_CONTROL` は、そのWorkerを持つCloudflareアカウントを利用者が管理していることを、利用者が自分の認証で確認した記録です。workers.devのサブドメインはアカウントごとに一意なので、ホスト名がそのアカウントのWorkerを指すときだけ所有権の確認になります。SiteProofはこの確認のためにCloudflareへ通信しません。

```json
"ownership": {
  "method": "CLOUDFLARE_ACCOUNT_CONTROL",
  "verified_at": "2026-11-21T00:00:00Z",
  "cloudflare": {"account_id_sha256": "<アカウントIDのSHA-256>", "worker": "my-worker", "workers_dev_subdomain": "my-sub"},
  "evidence": {"evidence_id": "cf-check-1", "sha256": "<real/ownership-evidence.json のSHA-256>"}
}
```

証拠ファイル `<データ>\sites\<site>
eal\ownership-evidence.json`（利用者が置く）：

```json
{
  "schema": "siteproof.ownership-evidence.cloudflare-account-control.v1",
  "evidence_id": "cf-check-1",
  "method": "CLOUDFLARE_ACCOUNT_CONTROL",
  "checked_at": "2026-11-21T00:00:00Z",
  "account_id_sha256": "<アカウントIDのSHA-256>",
  "worker": "my-worker",
  "workers_dev_subdomain": "my-sub",
  "host": "my-worker.my-sub.workers.dev",
  "checks": {"worker_in_account": true, "account_workers_dev_subdomain": "my-sub"},
  "sources": ["確認に使った操作・記録（自由記述）"]
}
```

次のどれかに当てはまると、所有権は「未確認」になり、撮影しません。

- ホストが `<worker>.<workers_dev_subdomain>.workers.dev` と完全に一致しない（別のWorker・別のサブドメイン・カスタムドメイン）
- アカウントIDのハッシュ・Worker名・サブドメインのどれかがない（アカウントIDのハッシュだけでは成立しない）
- 証拠ファイルがない、またはSHA-256が許可に固定した値と違う（署名の後に証拠を書き換えた）
- 証拠の内容（ID・アカウント・Worker・サブドメイン・ホスト・確認日時・確認結果）が許可の記録と違う
- 確認日時が未来

アプリの撮影前チェックと撮影ハーネス（`validate_s3t.py` の `permit_preflight`。Dockerを一切呼ぶ前）が、同じ `permit.ownership_problems` で確認します。ハーネスが拒否した場合は `permit-preflight.json` に理由を残して終了コード2で止まり、撮影回数も消費しません。`tools/permit_draft.py --cloudflare-evidence` は、置かれた証拠ファイルから `ownership` を記入します（拒否される証拠では下書きを作りません）。

## 撮影の前に確認すること（毎回）

| # | 条件 | 確認の内容 |
|---|---|---|
| 1 | 本人管理サイトの確認 | 署名付き許可に、確認方法（well-known-file・dns-txt・CLOUDFLARE_ACCOUNT_CONTROL）と確認日時がある。CLOUDFLARE_ACCOUNT_CONTROLは、ホスト名と証拠ファイルの一致も確認する。自己申告だけでは成立しない |
| 2 | 監視許可 | 署名が正しい（信頼する鍵・名前空間・内容の改変なし）。サイト・ページ・ホストが登録内容と一致する。対象設定ファイルのハッシュが一致する。有効期間内。撮影回数が残っている（`trust/permit-ledger/<permit_id>.jsonl`。撮影ハーネスが排他ロックのもとで、コンテナを起動する前に1回分を記録する。アプリは読むだけ。再起動・並列実行・失敗後も数え直さない） |
| 3 | 撮影構成の同一性 | 許可が固定するファイルが今と同じ。撮影イメージIDがある。Baselineがあるときは、そのBaselineがこの許可で作られ、作成時から変わっていない |
| 4 | 撮影環境 | Docker CLIと ssh-keygen がある |
| 5 | 撮影ハーネスの対応 | トップページ（/）である（ハーネスとブローカーは、許可された1ホストのトップページだけを扱う） |

## 撮影ハーネスの許可モード（一般サイトへの対応）

アダプターは `validate_s3t.py --permit … --trust … --target-dir …` で起動します。ハーネスは、コンテナを起動する前に次を確認します。

- 署名と所有権の記録（Dockerを呼ぶ前。上の「所有権の確認方法」）
- 有効期間
- 対象設定ファイルのハッシュ
- 対象設定に書かれたページ・サイト・ホストが許可と一致すること
- `--expect` が、許可の identity（比較時はBaselineの固定値を加えたもの）と完全に一致すること

確認した2ファイルは、証拠フォルダに複製し、ハッシュを照合し直してから、信頼されたコンテナ（Worker・ブローカー・reaper）にだけ読み取り専用でマウントします。Workerはコンテナ内でもう一度ハッシュを照合します。

DNS（1つのIPv4:443だけを許可）、ブローカー、プロキシ、リダイレクトの拒否、接続先・ブラウザの監査、通信window、reaperの各ゲートは変更していません。ゲートを適用する対象が、署名された対象になっただけです。

`--permit` を付けない場合は、これまでのTTN トップページ用の構成のままです。

## 未解決の事項（実サイトE2Eの前に必要なこと）

1. **撮影ハーネスの許可モードの実地検証**：Dockerを使うGATE-A〜C・撮影windowを、承認を受けて実行し、許可モードで通信制限が維持されることを確認する。
2. **所有権の確認手順**：確認用ファイルまたはDNSの照合は実サイトへのアクセスを伴うため、その方法と承認が必要。workers.devのホストは `CLOUDFLARE_ACCOUNT_CONTROL` で、実サイトにアクセスせずに確認できる（2026-11-21追加。合成データのオフラインテストでだけ確認済み）。撮影ハーネスも、Dockerを呼ぶ前に署名と所有権の記録（CLOUDFLARE_ACCOUNT_CONTROLでは証拠ファイルも）を同じコードで確認する（`permit_preflight`）。
3. **利用者の署名鍵の作成と配置**：今回は合成鍵だけを使った。
4. **撮影イメージ**：許可に固定する撮影イメージの準備（Dockerイメージのビルドは別承認）と、ブラウザbundleのmanifest値。
5. **許可の更新**：「監視設定を更新」（セットアップの再実行）でBaselineを署名付きで引き継ぎます（上の「使い方」）。引き継がずに別の許可で作ったBaselineでは撮影しません。更新の実サイトでの通し確認は未実施です。
6. **信頼の範囲（ローカルの攻撃者への限界）**：信頼する鍵のファイル（allowed_signers）、撮影回数の記録（permit-ledger）、PCの時計は、このPCのファイルや設定を書き換えられる人なら差し替え・リセットできる。撮影ハーネスを直接実行する人が自分の鍵と信頼ファイルを用意することも防げない（その人はDockerを直接使えるので、SiteProofが追加の権限を与えるわけではない）。PCの管理者を信頼する前提。推奨：信頼する鍵のファイルだけを、利用者アカウントでは読み取り専用にする（例：`icacls <データ>\trust\allowed_signers /inheritance:r /grant:r "%USERNAME%:R" /grant:r "Administrators:F"`）。`trust\permit-ledger` フォルダは撮影ハーネスが書き込むため、書き込み可能のままにする。署名用の秘密鍵は、データフォルダの外にパスフレーズ付きで置く。
7. **撮影回数の数え方**：撮影ハーネスが、署名・対象・識別情報を確認した後、コンテナを起動する前に、排他ロックのもとで1回分を記録する（上限なら拒否）。ハーネスを直接実行しても上限を超えない。失敗した撮影も1回として数える。
8. **対象ページ**：トップページ（/）のみ対応。

## 参考：これまでの実撮影（2026-11-19に1回、SP-D54）

USERが承認した限定例外（署名なしの識別ファイル）として、TTN トップページを Desktop・Mobile で撮影し、承認済みBaseline v1 と比較しました。結果はどちらも変更なし（差分0ピクセル）でした。この経路（`--permit` なし）は残しています。
