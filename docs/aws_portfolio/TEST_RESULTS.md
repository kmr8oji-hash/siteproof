# テスト結果(今回の実測と、過去報告・未実行の区別)

> **履歴注記(2026-11-13)**: 本文はAWS-B限定LIVE実証**前**の記録で、当時の状態(未デプロイ／LIVE NO-GO等)を保存している。AWS-Bは2026-11-12に限定LIVE実証を完了し、同日に対象Trialの停止・撤収を実施した。継続本番監視は未開始。最新の実証結果は [EVIDENCE_INDEX.md](EVIDENCE_INDEX.md) §0 を参照。過去の記録本文は書き換えていない。

## 1. 今回の実測(最終実行)

- 実行日: 2026-11-11 以降のセッション / worktree `siteproof-aws-portfolio-fable-01` / base `b52bd38`(未commitの新規ファイルを含む)
- 実行方法: `py -3.15 -B tools/run_offline_tests.py --out .local/aws-portfolio-01/full-final`
- Python 3.15.1、テストモジュール70本を1本ずつ別プロセスで実行。スキップ・除外の指定なし。
- ログと `summary.json`: `.local/aws-portfolio-01/full-final/`(git管理外)

| スイート | 区分 | 実行 | PASS | FAIL | ERROR | SKIP |
|---|---|---:|---:|---:|---:|---:|
| aws_public | 既存 | 44 | 44 | 0 | 0 | 0 |
| baseline | 既存 | 45 | 45 | 0 | 0 | 0 |
| bff | 既存 | 59 | 58 | **1** | 0 | 0 |
| comparison | 既存 | 58 | 58 | 0 | 0 | 0 |
| core | 既存 | 63 | 63 | 0 | 0 | 0 |
| integration | 既存 | 172 | 172 | 0 | 0 | 0 |
| isolation | 既存 | 351 | 351 | 0 | 0 | 0 |
| offline_view | 既存 | 40 | 40 | 0 | 0 | 0 |
| profile_context | 既存 | 161 | 161 | 0 | 0 | 0 |
| runtime | 既存 | 48 | 48 | 0 | 0 | 0 |
| storage | 既存 | 112 | 112 | 0 | 0 | 0 |
| ui | 既存 | 243 | 243 | 0 | 0 | 0 |
| **既存 小計** | | **1,396** | **1,395** | **1** | 0 | 0 |
| aws_guard | 新規 | 36 | 36 | 0 | 0 | 0 |
| aws_b | 新規 | 110 | 110 | 0 | 0 | 0 |
| aws_c | 新規 | 161 | 161 | 0 | 0 | 0 |
| **新規 小計** | | **307** | **307** | 0 | 0 | 0 |
| **合計** | | **1,703** | **1,702** | **1** | 0 | 0 |

### 失敗1件について

`tests/bff/test_runtime_view.py::RuntimeViewTests::test_runtime_unavailable_is_not_empty_success_and_assets_local_only`

- テストはHTMLに `/local/runtime.js` があることを期待する。現行HTMLはM5の改修で5本のスクリプトを `/local/workspace.js` 1本にまとめている。
- 作業開始前の基準実行(新規ファイルが無い状態)でも同じ失敗。今回の変更が原因ではない。
- 既存ファイルの修正は承認範囲外のため未修正。テストの削除・無効化もしていない。

### 既存件数との照合

既存1,396件は、事前レビューでの静的計数(`def test_` の数)と一致した。今回はそれを実際に実行した結果である。

## 2. 新規テストの内訳

| ファイル | 件数 | 主な内容 |
|---|---:|---|
| `tests/aws_guard/test_guard_contract.py` | 36 | ガードのテンプレート契約、変異テスト、AWS-Aテンプレートが不変であること |
| `tests/aws_b/test_handler.py` | 31 | 重複・逆順・遅延・絶対期限・停止競合・世代・保存失敗・イベント検証・メトリクス |
| `tests/aws_b/test_claim_mutations.py` | 4 | 確保条件式の各節を外すと不安全な挙動が実際に起きること |
| `tests/aws_b/test_model_store_view.py` | 18 | 設定検証、リクエスト生成、表示投影(UP/DOWN/UNKNOWN/STALE/STOPPED) |
| `tests/aws_b/test_probe.py` | 19 | 宛先拒否(private/loopback/link-local/IPv6等)、peer不一致、リダイレクト非追従、読取り上限 |
| `tests/aws_b/test_template_contract.py` | 38 | テンプレート契約、コードとの整合、変異31件 |
| `tests/aws_c/test_control_controller.py` | 17 | スロット一度きり、遷移、Controllerの入力制限 |
| `tests/aws_c/test_watchdog.py` | 18 | 期限、対象の曖昧さ、API失敗、DynamoDB不通でもTerminateすること |
| `tests/aws_c/test_evidence_publish.py` | 31 | write-once、読戻し、改ざん検出、再実行の冪等性、署名の配線 |
| `tests/aws_c/test_worker_entry.py` | 19 | 開始条件、隔離失敗時の証拠保全、Linuxランチャー、既存ファイル不変 |
| `tests/aws_c/test_template_contract.py` | 68 | ガード面・Worker・起動スクリプトの契約、変異58件 |
| `tests/aws_c/test_bundles.py` | 8 | バンドルの決定性、許可リスト、アーカイブ単体でのimport |

## 3. 追加で実測したこと

| 内容 | 結果 |
|---|---|
| 既存M5由来証拠(`.local/user-ux-gate-01/review-data`)のコピー71ファイルを、`src/aws_c/evidence.verify_local`(既存 `plan_recovery` 経由)で検証 | CONSISTENT、指摘0。原本は未変更 |
| AWS-Bの確保条件式を一時的に弱めてテストを実行(手動の変異確認) | 弱めた3通りすべてでテストが失敗することを確認 |

## 4. 実行していないもの(NOT RUN)

| 対象 | 理由 |
|---|---|
| `tests/runtime/validate.py`、`validate_m5.py` などDockerを使う実ランタイム検証 | Docker起動は承認範囲外 |
| `src/aws_b/probe.TlsTransport`、`system_resolver`、`socket_dialer`(実ソケット・実TLS) | 外部通信は承認範囲外。HTTPの枠読みは `socket.socketpair()` で確認 |
| `src/aws_c/worker_entry.run_validation_harness` の実Docker実行、`LinuxDockerLauncher` の実エンジン接続 | 同上。ランチャーは呼出しを差し替えて検査 |
| boto3を使う各 `lambda_handler` / `main` の実AWS呼出し | AWS操作は承認範囲外 |
| `infra/aws_c/user_data.sh` の実行 | 静的検査のみ |
| CloudFormationの `validate-template`、デプロイ | AWS操作は承認範囲外 |
| G1 Providerの107テスト(別worktree、未追跡) | 既存worktreeは対象外。存在と件数のみ確認 |
| VM・Hyper-V関連の一切 | 承認範囲外 |

## 5. オフラインテストが示さないこと

- 擬似クライアント(`tests/aws_fakes.py`)はAWSの実挙動の証拠ではない。条件付き書込み、チェックサム、タグ条件、署名の実動作はLIVEで確認する。
- テンプレートの契約テストは構造検査であり、AWSによる受理ではない。
- Local(Windows/WSL2)での隔離PASSは、EC2での隔離PASSではない。

## 6. 過去の報告値(参考。今回の結果と合算しない)

310(10-25)、1,154(10-30)、M4 延べ383(重複あり)、M5の各グループ(重複あり・合算禁止)、G1 107(合成のみ)。出所は `EVIDENCE_INDEX.md`。

## FAST TRACK 2026-11-11（追加実測）

AWS-B限定15件＋配備ZIP単独import 1件、計16/16 PASS（実行時間0.372秒、Python 3.15.1）。正常記録、失敗/UNKNOWN、重複、停止世代/競合、絶対期限、DynamoDB遅延、ACK喪失、宛先拒否、redirect非追従、テンプレート契約、予定時刻表記を確認。新規テストメソッドは期限再確認の1件だけ。全1,703件は再実行しない。既知の既存FAIL 1件は対象外。

証拠: `.local/aws-portfolio-01/fast-track-01/summary.json` と `bundles/bundle-manifest.json`。Python 3.13構文互換はASTで確認したが、実ランタイム実行・AWS受理・IAM・Scheduler配信・通知・費用は未検証。AWS-B/C NO-GO維持。
