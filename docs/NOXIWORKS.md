# 更新: 3サイト・5ページ（設定のみで対象追加）

`targets.json`のsites/pagesにNoxiWorks（2）、Hello, My Saitama（2）、Tokyo Trouble Navi（1）を登録。HTTP6時間・撮影24時間。settings()がサイト設定を各ページへ展開し、AWS-Bは5つの固定target、AWS-Cはcreate_runtimes(NEW_DIR)→prepare_batches(runtimes)で3つの既存M1保存領域へ分離する。各撮影入力はACCEPTEDまで、起動・実撮影は未実行。単一サイトを扱う場合だけcreate_runtime(..., site_configs()[site_id])を使う。

TLSは3ホスト単位。registration_domain=nullとregistration_managed_by=Cloudflareを持つサイトは提供元管理であり、workers.devの登録期限を取り込まない。既存JSON形式とtarget_idは保持。HOMEの4メニューとPenpot由来CSSを維持。AWS LIVE NO-GO、LOCAL隔離未検証、C-02 OPEN。

以下は初期2ページ版の手順・経緯として保持。現在の対象一覧は設定を正とする。

# NoxiWorks 2ページ監視（オフライン製品版）

初期対象は `src/noxiworks/targets.json` のHOMEとTaxi紹介ページ。HTTPは6時間、画像は24時間を暫定既定値とする。対象追加は同ファイルのpagesに追加。登録UI・実行ボタンはない。

```powershell
# 新しい出力先だけ。既存ファイル・証拠を上書きしない
py -3.15 -B -m src.noxiworks --out .local/noxiworks-empty-01
py -3.15 -B -m src.noxiworks --sample --out .local/noxiworks-sample-01
# 取込済みデータのHOME。ネットワークは使わない
py -3.15 -B -m src.noxiworks --snapshot LOCAL_SNAPSHOT.json --assets LOCAL_ASSET_DIR --out .local/noxiworks-import-01
# 今回の機能だけ
py -3.15 -B -m unittest -v tests.test_noxiworks
```

出力 `index.html` をローカルで開く。既存HOMEのCSSを再利用。通常版はUNKNOWN、sample版は合成データ・合成画像・合成Baseline承認と常時明記する。sampleは新規SQLiteだけを使い、既存証拠に触れない。画面は生成時点の静的表示。更新時は別出力先へ再生成する。

- **AWS-B連携**: `monitor_config(page, table=..., absolute_end_at=...)` と `run_page(page,event,deps)` は既存ハンドラ・DynamoStoreを再利用。ページ別target_idでclaim/結果/世代/停止を分離。出力plansは既存テンプレートからページごとのスタックを生成し、6時間に設定する。初期LIVEの既存Runbookやテンプレートは変更しない。AbsoluteEndAtなど必須項目と別途LIVE承認なしに稼働させない。
- **取込**: `export_http({target_id: explicitly_supplied_DynamoStore})` が既存head/recent_runsを読む。AWSクライアントの自動生成なし。実AWS読取りは未承認なので未実行。`snapshot.json`のschemaは`siteproof.noxiworks.v1`、sourceは`EMPTY`/`FIXTURE`/`AWS_EXPORT`。AWS_EXPORTは出所未認証のローカル取込であり、AWS実測を認証したとは扱わない。履歴は最大56件/ページ（通常14日）で永続台帳ではない。
- **期限**: TLSは既存結果の`tls_not_after`と`finished_at`からホスト単位へ集約。明示入力は`tls[hostname]`、ドメインは`domains[domain]`。各値は`scope, expires_at, observed_at, source`を持つUTC秒文字列。鮮度はTLS48時間、ドメイン30日。欠損・未来観測・期限不明・鮮度不足はUNKNOWN。自動更新予定を期限延長へ読み替えない。RDAP/登録期限の実取得は未実装・未アクセス。
- **AWS-C/M5連携**: `collect_comparison(existing_ComparisonService, page, completed_job_id, observed_at)` がページID/URLを照合し、既存Baseline承認・S1 manifest・PNG比較を再利用する。戻り値の観測を`changes[target_id]`に、画像bytesを`assets/target_id/{current,baseline,diff}.png`に新規保存してHOMEへ渡す。既存証拠の作業コピーで行う。撮影・承認・AWS起動はしない。Baseline未設定/未承認はUNKNOWN。差分ありは要確認であり不具合確定ではない。profile未認証を品質PASSへ昇格させない。出力のdetails.jsonに比較結果・manifest参照を含む。画像は既存比較結果のSHA-256と照合して同梱し、任意URLをリンク化しない。
- **残るLIVE項目**: 2スタックのScheduler/Lambda/IAM実動作、通知経路、TLS実取得、AWS-C実宛先隔離後の2ページ撮影とS3公開・Terminate・費用。現行AWS-C bootstrapはfixture専用のまま。毎日自動撮影のScheduler接続と本サイト許可はLIVE前の別工程。AWS-B/C LIVE NO-GO、C-02 DEFERRED/OPEN。

停止は既存Runbookどおり、ページごとにenabled=false＋世代更新、Schedule無効化、Lambda同時実行0。共通停止時は両ページへ適用。公開AWS-Aは未変更。commit/push/merge、AWS/外部通信、Docker/VM起動は未実行。

撮影ジョブの準備: `capture.create_runtime(NEW_WORKSPACE)` → `capture.prepare_batch(runtime)` は2ページのJobIntentとBaseline pinを既存M1/M5へ登録し、ACCEPTEDで停止する。所有ページはOWNER_SITE_UNATTESTEDと記録し、fixtureと偽らない。実行には既存RuntimeService.runへ隔離済みchannel factory/ProxyLeaseを明示注入する必要があり、本作業では未実行。既存Playwright起動・隔離・S1・比較・cleanupを再利用し、OS直結の撮影フォールバックは作らない。
